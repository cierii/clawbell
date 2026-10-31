//! Bounded Streamable HTTP upstream. Session identity is scoped to one relay;
//! redirects, automatic retry/replay and interactive reverse requests are denied.
use crate::{
    Direction, Envelope, Error, Gate, Limits,
    stdio::{self, Wire},
};
use futures_util::StreamExt;
use reqwest::{
    Method,
    header::{ACCEPT, CONTENT_TYPE},
    header::{HeaderMap, HeaderValue},
};
use std::net::IpAddr;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    task::JoinSet,
};

/// Owner-configured endpoint with DNS pinned to checked socket addresses.
/// It intentionally cannot be constructed from server/tool output.
pub struct Target {
    endpoint: crate::network::Endpoint,
    session: tokio::sync::Mutex<HttpSession>,
    stateful: bool,
}
#[derive(Default)]
struct HttpSession {
    initialized: bool,
    id: Option<String>,
    version: Option<String>,
    closed: bool,
}
impl Target {
    /// Resolve once and pin every connection address. Private addresses require
    /// an exact owner exception. Link-local/metadata and unspecified addresses
    /// are always refused. Plain HTTP is allowed only for explicit loopback.
    ///
    /// # Errors
    /// Rejects credentials, query/fragment, redirects, unresolved or unsafe targets.
    pub async fn connect(
        url: &str,
        private_exception: Option<IpAddr>,
        limits: Limits,
    ) -> Result<Self, Error> {
        Ok(Self {
            endpoint: crate::network::Endpoint::connect(url, private_exception, limits).await?,
            session: tokio::sync::Mutex::new(HttpSession::default()),
            stateful: false,
        })
    }
    /// Enable session-aware Streamable HTTP on an owner-configured broker endpoint.
    /// OAuth credentials remain in that endpoint, never JSON-RPC or sandbox env.
    #[must_use]
    pub fn streamable(endpoint: crate::network::Endpoint) -> Self {
        Self {
            endpoint,
            session: tokio::sync::Mutex::new(HttpSession::default()),
            stateful: true,
        }
    }
    async fn post(&self, wire: Wire, limits: Limits) -> Result<Vec<Vec<u8>>, Error> {
        let message = Envelope::parse(&wire.bytes, Direction::Client, limits.message_bytes)?;
        let request_id = if message.method().is_some() {
            message.id().cloned()
        } else {
            None
        };
        let initializing = message.method() == Some("initialize");
        {
            let mut session = self.session.lock().await;
            if session.closed {
                return Err(Error::Closed);
            }
            if let Some(version) = &wire.version {
                session.version = Some(version.clone());
            }
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(version) = wire.version {
            headers.insert(
                "mcp-protocol-version",
                HeaderValue::from_str(&version).map_err(|_| Error::Protocol)?,
            );
        }
        if let Some(id) = &self.session.lock().await.id {
            headers.insert(
                "mcp-session-id",
                HeaderValue::from_str(id).map_err(|_| Error::Protocol)?,
            );
        }
        let response = self
            .endpoint
            .send(Method::POST, headers, wire.bytes, limits)
            .await?;
        self.accept_session(&response, initializing).await?;
        if request_id.is_none() {
            if response.status() != reqwest::StatusCode::ACCEPTED {
                return Err(Error::Protocol);
            }
            let body = bounded_body(response, limits).await?;
            return if body.is_empty() {
                Ok(Vec::new())
            } else {
                Err(Error::Protocol)
            };
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::Transport);
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_owned();
        let messages = match content_type.as_str() {
            "application/json" => vec![bounded_body(response, limits).await?],
            "text/event-stream" => {
                self.response_events(
                    response,
                    request_id.as_ref().ok_or(Error::Protocol)?,
                    limits,
                )
                .await?
            }
            _ => return Err(Error::Protocol),
        };
        let mut found = false;
        for bytes in &messages {
            let envelope = Envelope::parse(bytes, Direction::Server, limits.message_bytes)?;
            if found {
                return Err(Error::Protocol);
            }
            if envelope.method().is_none() {
                if envelope.id() != request_id.as_ref() {
                    return Err(Error::Protocol);
                }
                found = true;
            } else if envelope.id().is_some() {
                // Stateless SSE cannot support interactive reverse requests while buffered.
                return Err(Error::Protocol);
            }
        }
        if !found {
            return Err(Error::Protocol);
        }
        Ok(messages)
    }
    async fn session_headers(&self, cursor: Option<&str>) -> Result<HeaderMap, Error> {
        let session = self.session.lock().await;
        if !self.stateful || session.closed || !session.initialized {
            return Err(Error::Protocol);
        }
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        if let Some(id) = &session.id {
            headers.insert(
                "mcp-session-id",
                HeaderValue::from_str(id).map_err(|_| Error::Protocol)?,
            );
        }
        if let Some(version) = &session.version {
            headers.insert(
                "mcp-protocol-version",
                HeaderValue::from_str(version).map_err(|_| Error::Protocol)?,
            );
        }
        if let Some(cursor) = cursor {
            headers.insert(
                "last-event-id",
                HeaderValue::from_str(cursor).map_err(|_| Error::Protocol)?,
            );
        }
        Ok(headers)
    }
    async fn get(&self, cursor: Option<&str>, limits: Limits) -> Result<reqwest::Response, Error> {
        let response = self
            .endpoint
            .send(
                Method::GET,
                self.session_headers(cursor).await?,
                Vec::new(),
                limits,
            )
            .await?;
        self.accept_session(&response, false).await?;
        Ok(response)
    }
    // Only GET is retried. The original effectful POST is never replayed.
    async fn response_events(
        &self,
        response: reqwest::Response,
        id: &serde_json::Value,
        limits: Limits,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let mut stream = EventStream::new(response);
        let mut messages = Vec::new();
        let mut cursor = None;
        let mut seen = std::collections::HashSet::new();
        let mut total = 0;
        for attempt in 0..=3 {
            while let Some(event) = stream.next(limits).await? {
                track_cursor(&event, &mut cursor, &mut seen)?;
                if let Some(bytes) = event.data {
                    total += bytes.len();
                    if total > limits.message_bytes || messages.len() >= limits.queue {
                        return Err(Error::Limit);
                    }
                    let envelope =
                        Envelope::parse(&bytes, Direction::Server, limits.message_bytes)?;
                    if envelope.id().is_some() && envelope.method().is_some() {
                        return Err(Error::Protocol);
                    }
                    let complete = envelope.method().is_none();
                    if complete && envelope.id() != Some(id) {
                        return Err(Error::Protocol);
                    }
                    messages.push(bytes);
                    if complete {
                        return Ok(messages);
                    }
                }
            }
            if attempt == 3 || !self.stateful || cursor.is_none() {
                return Err(Error::Protocol);
            }
            let response = self.get(cursor.as_deref(), limits).await?;
            require_sse(&response)?;
            stream = EventStream::new(response);
        }
        Err(Error::Protocol)
    }
    async fn listen(
        &self,
        events: mpsc::Sender<stdio::Event>,
        limits: Limits,
    ) -> Result<(), Error> {
        let mut cursor = None;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..=3 {
            let response = self.get(cursor.as_deref(), limits).await?;
            if response.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED && cursor.is_none() {
                return Ok(());
            }
            require_sse(&response)?;
            let mut stream = EventStream::new(response);
            while let Some(event) = tokio::time::timeout(limits.idle_timeout, stream.next(limits))
                .await
                .map_err(|_| Error::Timeout)??
            {
                track_cursor(&event, &mut cursor, &mut seen)?;
                if let Some(bytes) = event.data {
                    let envelope =
                        Envelope::parse(&bytes, Direction::Server, limits.message_bytes)?;
                    // GET notifications still pass the complete protocol/policy/DLP
                    // gate. Responses belong exclusively to their POST/resume stream.
                    if envelope.method().is_none() || envelope.id().is_some() {
                        return Err(Error::Protocol);
                    }
                    events
                        .try_send(Ok((Direction::Server, bytes)))
                        .map_err(|_| Error::Limit)?;
                }
            }
            if cursor.is_none() {
                return Err(Error::Closed);
            }
        }
        Err(Error::Limit)
    }
    /// Terminate this exact remote session once, without replaying any operations.
    /// The composition root's durable session intent covers transport lifecycle.
    /// # Errors
    /// Refuses changed identities, redirects and unexpected status/body.
    pub async fn close(&self, limits: Limits) -> Result<(), Error> {
        let headers = {
            let mut session = self.session.lock().await;
            if session.id.is_none() {
                session.closed = true;
                return Ok(());
            }
            drop(session);
            self.session_headers(None).await?
        };
        self.session.lock().await.closed = true;
        let response = self
            .endpoint
            .send(Method::DELETE, headers, Vec::new(), limits)
            .await?;
        self.accept_session(&response, false).await?;
        if !matches!(
            response.status(),
            reqwest::StatusCode::OK
                | reqwest::StatusCode::NO_CONTENT
                | reqwest::StatusCode::METHOD_NOT_ALLOWED
        ) {
            return Err(Error::Transport);
        }
        if !bounded_body(response, limits).await?.is_empty() {
            return Err(Error::Protocol);
        }
        Ok(())
    }
    async fn accept_session(
        &self,
        response: &reqwest::Response,
        initializing: bool,
    ) -> Result<(), Error> {
        let returned_session = response
            .headers()
            .get("mcp-session-id")
            .map(|value| {
                let value = value.to_str().map_err(|_| Error::Protocol)?;
                if value.is_empty()
                    || value.len() > 256
                    || !value.bytes().all(|c| (0x21..=0x7e).contains(&c))
                {
                    return Err(Error::Protocol);
                }
                Ok(value.to_owned())
            })
            .transpose()?;
        {
            let mut session = self.session.lock().await;
            if initializing {
                if session.initialized || (!self.stateful && returned_session.is_some()) {
                    return Err(Error::Protocol);
                }
                session.initialized = true;
                session.id = returned_session;
            } else if returned_session.is_some() && returned_session != session.id {
                return Err(Error::Protocol);
            }
        }
        Ok(())
    }
}
pub(crate) async fn bounded_body(
    response: reqwest::Response,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    tokio::time::timeout(limits.request_timeout, async {
        if response
            .content_length()
            .is_some_and(|n| n > limits.message_bytes as u64)
        {
            return Err(Error::Limit);
        }
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Error::Transport)?;
            if bytes.len() + chunk.len() > limits.message_bytes {
                return Err(Error::Limit);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| Error::Timeout)?
}
struct Event {
    data: Option<Vec<u8>>,
    id: Option<String>,
}
struct EventStream {
    response: reqwest::Response,
    buffer: Vec<u8>,
    first: bool,
}
fn require_sse(response: &reqwest::Response) -> Result<(), Error> {
    if response.status() != reqwest::StatusCode::OK
        || response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|s| s.split(';').next().map(str::trim) != Some("text/event-stream"))
    {
        return Err(Error::Protocol);
    }
    Ok(())
}
fn track_cursor(
    event: &Event,
    cursor: &mut Option<String>,
    seen: &mut std::collections::HashSet<String>,
) -> Result<(), Error> {
    if event.data.is_some() && event.id.is_none() {
        *cursor = None;
    }
    if let Some(id) = &event.id {
        if id.is_empty() {
            *cursor = None;
        } else {
            if seen.len() >= 65_536 || !seen.insert(id.clone()) {
                return Err(Error::Protocol);
            }
            *cursor = Some(id.clone());
        }
    }
    Ok(())
}
impl EventStream {
    fn new(response: reqwest::Response) -> Self {
        Self {
            response,
            buffer: Vec::new(),
            first: true,
        }
    }
    async fn next(&mut self, limits: Limits) -> Result<Option<Event>, Error> {
        loop {
            // Detect SSE blank lines at the byte layer, including CR-only and
            // mixed endings, before UTF-8 decoding or inspection.
            if let Some(end) = event_end(&self.buffer) {
                let frame: Vec<_> = self.buffer.drain(..end).collect();
                let frame = if self.first {
                    frame.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&frame)
                } else {
                    &frame
                };
                self.first = false;
                let text = std::str::from_utf8(frame).map_err(|_| Error::InvalidMessage)?;
                let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
                let mut id = None;
                for line in normalized.lines() {
                    if line == "id" {
                        id = Some(String::new());
                    }
                    if let Some(value) = line.strip_prefix("id:") {
                        let value = value.strip_prefix(' ').unwrap_or(value);
                        if value.len() > 1024 || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
                        {
                            return Err(Error::Protocol);
                        }
                        id = Some(value.to_owned());
                    }
                }
                let data = parse_sse(frame, limits)?.into_iter().next();
                return Ok(Some(Event { data, id }));
            }
            match self.response.chunk().await {
                Ok(Some(chunk)) => {
                    if self.buffer.len() + chunk.len() > limits.message_bytes {
                        return Err(Error::Limit);
                    }
                    self.buffer.extend_from_slice(&chunk);
                }
                // Resume from the last complete event, never a partial event.
                Ok(None) | Err(_) => return Ok(None),
            }
        }
    }
}
fn event_end(bytes: &[u8]) -> Option<usize> {
    for i in 0..bytes.len() {
        if bytes[i] != b'\n' && bytes[i] != b'\r' {
            continue;
        }
        let next = i + if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            2
        } else {
            1
        };
        if matches!(bytes.get(next), Some(b'\r' | b'\n')) {
            return Some(
                next + if bytes[next] == b'\r' && bytes.get(next + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                },
            );
        }
    }
    None
}
fn parse_sse(bytes: &[u8], limits: Limits) -> Result<Vec<Vec<u8>>, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidMessage)?;
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut messages = Vec::new();
    let mut data = String::new();
    for line in normalized.lines() {
        if line.is_empty() {
            if !data.is_empty() {
                data.pop();
                messages.push(data.as_bytes().to_vec());
                data.clear();
                if messages.len() > limits.queue {
                    return Err(Error::Limit);
                }
            }
        } else if let Some(rest) = line.strip_prefix("data:") {
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
            data.push('\n');
        } else if line == "data" {
            data.push('\n');
        } else if line.starts_with("event:")
            && !matches!(line.trim_start_matches("event:").trim(), "" | "message")
        {
            return Err(Error::Protocol);
        }
    }
    if !data.is_empty() {
        return Err(Error::InvalidMessage);
    }
    Ok(messages)
}

/// Bridge client STDIO to an owner-approved HTTP endpoint.
/// Every response is buffered and inspected; partial data is never forwarded.
///
/// # Errors
/// Rejects unauthorized session changes/reverse requests, denial, overflow and timeouts.
pub async fn relay<R, W, G>(
    read: R,
    write: W,
    target: Target,
    gate: &mut G,
    limits: Limits,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    G: Gate,
{
    if !gate.permits_remote() {
        return Err(Error::Denied);
    }
    let limits = limits.validate()?;
    let (events, incoming) = mpsc::channel(limits.queue);
    let (client_tx, client_rx) = mpsc::channel(limits.queue);
    let (server_tx, mut server_rx) = mpsc::channel::<Wire>(limits.queue);
    let mut tasks = JoinSet::new();
    stdio::reader(&mut tasks, read, Direction::Client, events.clone(), limits);
    stdio::writer(&mut tasks, write, client_rx, limits);
    let target = std::sync::Arc::new(target);
    let worker_target = target.clone();
    tasks.spawn(async move {
        let target = worker_target;
        let mut posts = JoinSet::new();
        loop {
            tokio::select! {
                wire = server_rx.recv() => {
                    let Some(wire) = wire else { return Ok(()); };
                    if posts.len() >= limits.pending { return Err(Error::Limit); }
                    // Initialized is a transport barrier: do not dequeue another
                    // POST until its empty 202 response has been fully validated.
                    let initialized = Envelope::parse(&wire.bytes, Direction::Client, limits.message_bytes)?
                        .method() == Some("notifications/initialized");
                    if initialized {
                        while let Some(result) = posts.join_next().await {
                            result.map_err(|_| Error::Transport)??;
                        }
                        let messages = tokio::time::timeout(limits.request_timeout, target.post(wire, limits))
                            .await.map_err(|_| Error::Timeout)??;
                        if !messages.is_empty() { return Err(Error::Protocol); }
                        if target.stateful {
                            let target = target.clone(); let events = events.clone();
                            posts.spawn(async move { target.listen(events, limits).await });
                        }
                        continue;
                    }
                    let target = target.clone(); let events = events.clone();
                    posts.spawn(async move {
                        let messages = tokio::time::timeout(limits.request_timeout, target.post(wire, limits)).await.map_err(|_| Error::Timeout)??;
                        for bytes in messages {
                            events.try_send(Ok((Direction::Server, bytes))).map_err(|_| Error::Limit)?;
                        }
                        Ok::<(), Error>(())
                    });
                }
                result = posts.join_next(), if !posts.is_empty() => { result.ok_or(Error::Closed)?.map_err(|_| Error::Transport)??; }
            }
        }
    });
    let result = stdio::drive(
        incoming, client_tx, server_tx, &mut tasks, gate, limits, false,
    )
    .await;
    // drive has cancelled/joined network workers before session deletion.
    let cleanup = tokio::time::timeout(limits.request_timeout, target.close(limits))
        .await
        .map_err(|_| Error::Timeout)?;
    result.and(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sse_multiline_and_truncation() -> Result<(), Error> {
        let l = Limits::default();
        assert_eq!(
            parse_sse(
                b":keepalive\r\nevent: message\r\ndata: {\r\ndata: }\r\n\r\n",
                l
            )?,
            vec![b"{\n}".to_vec()]
        );
        assert!(parse_sse(b"data: {}\n", l).is_err());
        assert!(parse_sse(b"event: endpoint\ndata: /evil\n\n", l).is_err());
        Ok(())
    }
    #[test]
    fn metadata_and_mapped_addresses_are_refused() -> Result<(), Box<dyn std::error::Error>> {
        for ip in ["169.254.169.254", "::ffff:127.0.0.1", "fe80::1", "0.0.0.0"] {
            assert!(crate::network::forbidden(ip.parse()?));
        }
        assert!(!crate::network::public("127.0.0.1".parse()?));
        Ok(())
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    #[tokio::test]
    async fn stateful_sse_response_finishes_without_eof_and_session_header_is_scoped() -> Result {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/mcp", listener.local_addr()?);
        let endpoint =
            crate::network::Endpoint::connect(&url, Some("127.0.0.1".parse()?), Limits::default())
                .await?;
        let target = Target::streamable(endpoint);
        let server = tokio::spawn(async move {
            for initialization in [true, false] {
                let (stream, _) = listener.accept().await?;
                let mut reader = BufReader::new(stream);
                let mut length = 0;
                let mut session = None;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).await?;
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((key, value)) = line.split_once(':') {
                        if key.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse::<usize>()?;
                        }
                        if key.eq_ignore_ascii_case("mcp-session-id") {
                            session = Some(value.trim().to_owned());
                        }
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).await?;
                if initialization {
                    assert!(session.is_none());
                    let response = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
                    // No Content-Length, no EOF: completion is the JSON-RPC event.
                    reader.get_mut().write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nMcp-Session-Id: synthetic-session\r\n\r\n{response}").as_bytes()).await?;
                    // Keep the first response open while accepting the next POST.
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        drop(reader);
                    });
                } else {
                    assert_eq!(session.as_deref(), Some("synthetic-session"));
                    reader.get_mut().write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                }
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}});
        let messages = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            target.post(
                Wire {
                    bytes: serde_json::to_vec(&init)?,
                    version: None,
                },
                Limits::default(),
            ),
        )
        .await??;
        assert_eq!(messages.len(), 1);
        target
            .post(
                Wire {
                    bytes: serde_json::to_vec(
                        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                    )?,
                    version: Some("2025-06-18".into()),
                },
                Limits::default(),
            )
            .await?;
        server.await??;
        Ok(())
    }
}

#[cfg(test)]
mod barrier_tests {
    use super::*;
    use serde_json::{Value, json};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
    struct FixtureGate;
    impl Gate for FixtureGate {
        fn inspect(
            &mut self,
            _: Direction,
            message: &Envelope,
        ) -> impl std::future::Future<Output = Result<Envelope, Error>> + Send {
            std::future::ready(Ok(message.clone()))
        }
        fn finish(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send {
            std::future::ready(Ok(()))
        }
    }
    async fn receive(
        listener: &tokio::net::TcpListener,
    ) -> TestResult<(tokio::net::TcpStream, bool)> {
        let (stream, _) = listener.accept().await?;
        let mut read = BufReader::new(stream);
        let mut length = 0;
        let mut get = false;
        loop {
            let mut line = String::new();
            read.read_line(&mut line).await?;
            get |= line.starts_with("GET ");
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':')
                && key.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse()?;
            }
        }
        let mut body = vec![0; length];
        read.read_exact(&mut body).await?;
        Ok((read.into_inner(), get))
    }
    async fn send(stream: &mut tokio::net::TcpStream, status: &str, body: &str) -> TestResult {
        stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
        Ok(())
    }
    #[tokio::test]
    async fn initialized_202_is_a_barrier_and_failure_never_sends_the_next_post() -> TestResult {
        for behavior in ["accepted", "wrong-status", "body", "disconnect", "timeout"] {
            check(behavior).await?;
        }
        Ok(())
    }
    async fn check(behavior: &'static str) -> TestResult {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let limits = Limits {
            request_timeout: std::time::Duration::from_millis(250),
            ..Limits::default()
        };
        let endpoint = crate::network::Endpoint::connect(
            &format!("http://{}/mcp", listener.local_addr()?),
            Some("127.0.0.1".parse()?),
            limits,
        )
        .await?;
        let (client, proxy) = tokio::io::duplex(8192);
        let (read, write) = tokio::io::split(proxy);
        let relay = tokio::spawn(async move {
            relay(
                read,
                write,
                Target::streamable(endpoint),
                &mut FixtureGate,
                limits,
            )
            .await
        });
        let server = tokio::spawn(async move {
            let (mut init, _) = receive(&listener).await?;
            send(&mut init, "200 OK", &json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}).to_string()).await?;
            let (mut initialized, _) = receive(&listener).await?;
            // The next client packet is already queued. No connection is allowed
            // while the initialized acknowledgement is deliberately withheld.
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(40), listener.accept())
                    .await
                    .is_err()
            );
            match behavior {
                "accepted" => send(&mut initialized, "202 Accepted", "").await?,
                "wrong-status" => send(&mut initialized, "200 OK", "").await?,
                "body" => send(&mut initialized, "202 Accepted", "{}").await?,
                "disconnect" => drop(initialized),
                "timeout" => {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    drop(initialized);
                }
                _ => unreachable!(),
            }
            if behavior == "accepted" {
                for _ in 0..2 {
                    let (mut next, get) = receive(&listener).await?;
                    if get {
                        send(&mut next, "405 Method Not Allowed", "").await?;
                    } else {
                        send(
                            &mut next,
                            "200 OK",
                            r#"{"jsonrpc":"2.0","id":2,"result":{}}"#,
                        )
                        .await?;
                    }
                }
            } else {
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(80), listener.accept())
                        .await
                        .is_err()
                );
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (read, mut write) = tokio::io::split(client);
        let mut read = BufReader::new(read);
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}}\n").await?;
        let mut response = String::new();
        read.read_line(&mut response).await?;
        assert_eq!(serde_json::from_str::<Value>(&response)?["id"], 1);
        write.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n").await?;
        response.clear();
        read.read_line(&mut response).await?;
        if behavior == "accepted" {
            assert_eq!(serde_json::from_str::<Value>(&response)?["id"], 2);
        } else {
            assert_eq!(response, "");
        }
        drop(write);
        drop(read);
        server.await??;
        assert!(relay.await?.is_err());
        Ok(())
    }
}

#[cfg(test)]
mod advanced_tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
    async fn receive(
        listener: &tokio::net::TcpListener,
    ) -> TestResult<(tokio::net::TcpStream, Vec<String>, Vec<u8>)> {
        let (stream, _) = listener.accept().await?;
        let mut reader = BufReader::new(stream);
        let mut headers = Vec::new();
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line == "\r\n" {
                break;
            }
            if line.is_empty() {
                return Err("unexpected EOF".into());
            }
            if let Some((k, v)) = line.split_once(':')
                && k.eq_ignore_ascii_case("content-length")
            {
                length = v.trim().parse()?;
            }
            headers.push(line.trim().to_ascii_lowercase());
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).await?;
        Ok((reader.into_inner(), headers, body))
    }
    async fn respond(
        stream: &mut tokio::net::TcpStream,
        status: &str,
        headers: &str,
        body: &str,
    ) -> TestResult {
        stream.write_all(format!("HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await?;
        Ok(())
    }
    async fn target(listener: &tokio::net::TcpListener) -> TestResult<Target> {
        let endpoint = crate::network::Endpoint::connect(
            &format!("http://{}/mcp", listener.local_addr()?),
            Some("127.0.0.1".parse()?),
            Limits::default(),
        )
        .await?;
        let target = Target::streamable(endpoint);
        {
            let mut s = target.session.lock().await;
            s.initialized = true;
            s.id = Some("fixture-session".into());
            s.version = Some("2025-06-18".into());
        }
        Ok(target)
    }
    #[tokio::test]
    async fn interrupted_post_resumes_only_get_and_deletes_exact_session_once() -> TestResult {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let target = target(&listener).await?;
        let server = async {
            let (mut stream, headers, body) = receive(&listener).await?;
            assert!(headers[0].starts_with("post "));
            assert_eq!(serde_json::from_slice::<serde_json::Value>(&body)?["id"], 2);
            respond(
                &mut stream,
                "200 OK",
                "Content-Type: text/event-stream\r\n",
                "id: response-stream-1\n\n",
            )
            .await?;
            drop(stream);
            let (mut stream, headers, body) = receive(&listener).await?;
            assert!(headers[0].starts_with("get "));
            assert!(
                headers
                    .iter()
                    .any(|h| h == "last-event-id: response-stream-1")
            );
            assert!(
                headers
                    .iter()
                    .any(|h| h == "mcp-session-id: fixture-session")
            );
            assert_eq!(body, b"");
            respond(
                &mut stream,
                "200 OK",
                "Content-Type: text/event-stream\r\n",
                "id: response-stream-2\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n",
            )
            .await?;
            let (mut stream, headers, _) = receive(&listener).await?;
            assert!(headers[0].starts_with("delete "));
            assert!(
                headers
                    .iter()
                    .any(|h| h == "mcp-session-id: fixture-session")
            );
            assert!(!headers.iter().any(|h| h.starts_with("last-event-id:")));
            respond(&mut stream, "204 No Content", "", "").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let client = async {
            let messages = target
                .post(
                    Wire {
                        bytes: serde_json::to_vec(
                            &json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
                        )?,
                        version: Some("2025-06-18".into()),
                    },
                    Limits::default(),
                )
                .await?;
            assert_eq!(messages.len(), 1);
            target.close(Limits::default()).await?;
            assert!(target.close(Limits::default()).await.is_err());
            assert!(
                target
                    .post(
                        Wire {
                            bytes: serde_json::to_vec(
                                &json!({"jsonrpc":"2.0","id":3,"method":"ping"})
                            )?,
                            version: None
                        },
                        Limits::default()
                    )
                    .await
                    .is_err()
            );
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (server, client) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(server, client)
        })
        .await?;
        server?;
        client?;
        Ok(())
    }
    #[tokio::test]
    async fn get_stream_resumes_from_last_complete_event_without_disclosing_partial_data()
    -> TestResult {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let target = target(&listener).await?;
        let (events, mut incoming) = mpsc::channel(8);
        let server = async {
            for n in 0..3 {
                let (mut stream, headers, _) = receive(&listener).await?;
                assert!(headers[0].starts_with("get "));
                if n > 0 {
                    assert!(
                        headers
                            .iter()
                            .any(|h| h == &format!("last-event-id: event-{n}"))
                    );
                }
                if n == 2 {
                    respond(&mut stream, "404 Not Found", "", "").await?;
                } else {
                    let event = format!(
                        "id: event-{}\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progressToken\":\"work\",\"progress\":{n}}}}}\n\nid: incomplete\ndata: synthetic-partial",
                        n + 1
                    );
                    respond(
                        &mut stream,
                        "200 OK",
                        "Content-Type: text/event-stream\r\n",
                        &event,
                    )
                    .await?;
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (server, result) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            tokio::join!(server, target.listen(events, Limits::default()))
        })
        .await?;
        server?;
        assert!(result.is_err());
        for _ in 0..2 {
            let (_, bytes) = incoming.recv().await.ok_or("missing event")??;
            assert!(!String::from_utf8(bytes)?.contains("synthetic-partial"));
        }
        assert!(incoming.recv().await.is_none());
        Ok(())
    }
    #[test]
    fn event_ids_are_bounded_session_scoped_and_not_replayed() -> Result<(), Error> {
        let mut cursor = None;
        let mut seen = std::collections::HashSet::new();
        let event = Event {
            data: Some(b"{}".to_vec()),
            id: Some("event-1".into()),
        };
        track_cursor(&event, &mut cursor, &mut seen)?;
        assert!(track_cursor(&event, &mut cursor, &mut seen).is_err());
        track_cursor(
            &Event {
                data: None,
                id: Some(String::new()),
            },
            &mut cursor,
            &mut seen,
        )?;
        assert!(cursor.is_none());
        Ok(())
    }
}
