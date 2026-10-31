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
                response_events(
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
}
// Stop at a complete correlated response event; an SSE connection need not
// close. Buffer all preceding events before the gate inspects/discloses anything.
async fn response_events(
    response: reqwest::Response,
    id: &serde_json::Value,
    limits: Limits,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| Error::Transport)?;
        if bytes.len() + chunk.len() > limits.message_bytes {
            return Err(Error::Limit);
        }
        bytes.extend_from_slice(&chunk);
        // Only parse the complete event prefix; a trailing partial event is not
        // disclosed, interpreted or carried over to another request.
        let end = (0..bytes.len()).rev().find_map(|n| {
            if bytes[..=n].ends_with(b"\n\n")
                || bytes[..=n].ends_with(b"\r\n\r\n")
                || bytes[..=n].ends_with(b"\r\r")
            {
                Some(n + 1)
            } else {
                None
            }
        });
        if let Some(end) = end {
            let messages = parse_sse(&bytes[..end], limits)?;
            for message in &messages {
                let envelope = Envelope::parse(message, Direction::Server, limits.message_bytes)?;
                if envelope.method().is_none() && envelope.id() == Some(id) {
                    return Ok(messages);
                }
            }
        }
    }
    Err(Error::Protocol)
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
            && line.trim_start_matches("event:").trim() != "message"
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
    tasks.spawn(async move {
        let target = std::sync::Arc::new(target);
        let mut posts = JoinSet::new();
        loop {
            tokio::select! {
                wire = server_rx.recv() => {
                    let Some(wire) = wire else { return Ok(()); };
                    if posts.len() >= limits.pending { return Err(Error::Limit); }
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
    stdio::drive(
        incoming, client_tx, server_tx, &mut tasks, gate, limits, false,
    )
    .await
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
