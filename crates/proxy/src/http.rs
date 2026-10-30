//! Stateless Streamable HTTP upstream: one POST per message, JSON or finite SSE.
//! No redirects, ambient proxies, cookies, retries, session IDs or GET replay.
use crate::{
    Direction, Envelope, Error, Gate, Limits,
    stdio::{self, Wire},
};
use futures_util::StreamExt;
use reqwest::{
    Client, Url,
    header::{ACCEPT, CONTENT_TYPE},
};
use std::net::{IpAddr, SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    task::JoinSet,
};

/// Owner-configured endpoint with DNS pinned to checked socket addresses.
/// It intentionally cannot be constructed from server/tool output.
pub struct Target {
    client: Client,
    url: Url,
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
        let limits = limits.validate()?;
        let url = Url::parse(url).map_err(|_| Error::Denied)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::Denied);
        }
        let host = url.host_str().ok_or(Error::Denied)?;
        let port = url.port_or_known_default().ok_or(Error::Denied)?;
        let addresses: Vec<SocketAddr> =
            tokio::time::timeout(limits.timeout, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|_| Error::Transport)?
                .collect();
        if addresses.is_empty() || addresses.len() > 32 {
            return Err(Error::Denied);
        }
        for address in &addresses {
            let ip = address.ip();
            if forbidden(ip)
                || (!public(ip) && private_exception != Some(ip))
                || (url.scheme() != "https"
                    && !(url.scheme() == "http"
                        && ip.is_loopback()
                        && private_exception == Some(ip)))
            {
                return Err(Error::Denied);
            }
        }
        let client = Client::builder()
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .timeout(limits.timeout)
            .connect_timeout(limits.timeout)
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self { client, url })
    }
    async fn post(&self, wire: Wire, limits: Limits) -> Result<Vec<Vec<u8>>, Error> {
        let message = Envelope::parse(&wire.bytes, Direction::Client, limits.message_bytes)?;
        let request_id = if message.method().is_some() {
            message.id().cloned()
        } else {
            None
        };
        let mut request = self
            .client
            .post(self.url.clone())
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .body(wire.bytes);
        if let Some(version) = wire.version {
            request = request.header("MCP-Protocol-Version", version);
        }
        let response = request.send().await.map_err(|_| Error::Transport)?;
        // Stateful upstreams require a different adapter; never drop session identity silently.
        if response.headers().contains_key("mcp-session-id") {
            return Err(Error::Protocol);
        }
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
        let body = bounded_body(response, limits).await?;
        let messages = match content_type.as_str() {
            "application/json" => vec![body],
            "text/event-stream" => parse_sse(&body, limits)?,
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
}
fn forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v == std::net::Ipv4Addr::new(100, 100, 100, 200)
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_broadcast()
        }
        IpAddr::V6(v) => {
            v.to_ipv4_mapped().is_some()
                || v.is_unspecified()
                || v.is_multicast()
                || (v.segments()[0] & 0xffc0 == 0xfe80)
        }
    }
}
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_private()
                || v.is_loopback()
                || v.is_documentation()
                || v.octets()[0] == 0
                || v.octets()[0] >= 224
                || (v.octets()[0] == 192 && v.octets()[1] == 0)
                || (v.octets()[0] == 198 && (18..=19).contains(&v.octets()[1]))
                || (v.octets()[0] == 100 && (64..128).contains(&v.octets()[1])))
        }
        IpAddr::V6(v) => {
            !v.is_loopback()
                && v.segments()[0] & 0xe000 == 0x2000
                && v.segments()[0..2] != [0x2001, 0xdb8]
        }
    }
}
async fn bounded_body(response: reqwest::Response, limits: Limits) -> Result<Vec<u8>, Error> {
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

/// Bridge a client STDIO stream to an owner-approved stateless HTTP endpoint.
/// Every response is buffered and inspected; partial data is never forwarded.
///
/// # Errors
/// Rejects stateful upstreams and reverse requests, denial, overflow and timeouts.
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
                        let messages = tokio::time::timeout(limits.timeout, target.post(wire, limits)).await.map_err(|_| Error::Timeout)??;
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
            assert!(forbidden(ip.parse()?));
        }
        assert!(!public("127.0.0.1".parse()?));
        Ok(())
    }
}
