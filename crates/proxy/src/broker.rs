//! Session-scoped sandbox HTTP capabilities over an inherited connected pipe.
//! Each JSONL request selects an owner-named exact endpoint, never a URL, header
//! or socket destination. No CONNECT, binary transfer, redirects or replay exist.
use crate::{Error, Limits, network::Endpoint};
use clawbell_audit::operations::{OperationStore, Outcome, Reason};
use clawbell_core::policy::{Decision, Policy};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    endpoint: String,
    #[serde(default)]
    body: String,
}
/// Already resolved capabilities, immutable for the complete sandbox session.
pub struct Broker {
    endpoints: HashMap<String, (Endpoint, reqwest::Method)>,
    vault: crate::dlp::SharedVault,
    audit: OperationStore,
    limits: Limits,
}
impl Broker {
    /// Prepare exact owner grants outside the packet path. Denied grants create
    /// no endpoint and perform no DNS lookup. Credentials never enter this API.
    /// # Errors
    /// Refuses invalid grants, DNS/peer policy failures and invalid budgets.
    pub async fn prepare(
        policy: &Policy,
        audit: OperationStore,
        limits: Limits,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        let mut endpoints = HashMap::new();
        for grant in policy.network_grants() {
            if grant.decision != Decision::Allow {
                continue;
            }
            let endpoint = Endpoint::connect(&grant.url, grant.private_ip, limits).await?;
            let method =
                reqwest::Method::from_bytes(grant.method.as_bytes()).map_err(|_| Error::Denied)?;
            endpoints.insert(grant.name.clone(), (endpoint, method));
        }
        Ok(Self {
            endpoints,
            vault: crate::dlp::shared_vault(limits.message_bytes)?,
            audit,
            limits,
        })
    }
    /// Share DLP knowledge with the matching MCP session, never another client.
    #[must_use]
    pub fn with_vault(mut self, vault: crate::dlp::SharedVault) -> Self {
        self.vault = vault;
        self
    }
    async fn request(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if bytes.len() > self.limits.message_bytes {
            return Err(Error::Limit);
        }
        let value = clawbell_core::json::parse(bytes).map_err(|_| Error::InvalidMessage)?;
        let request: Request = serde_json::from_value(value).map_err(|_| Error::InvalidMessage)?;
        let (endpoint, method) = self.endpoints.get(&request.endpoint).ok_or(Error::Denied)?;
        if request.endpoint.len() > 128
            || (*method == reqwest::Method::GET && !request.body.is_empty())
            || inspect_body(&mut *self.vault.lock().await, &request.body, false)? != request.body
        {
            return Err(Error::Denied);
        }
        let intent = self
            .audit
            .record(0, Outcome::Intent)
            .await
            .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
        let result = async {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                reqwest::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            let response = endpoint
                .send(
                    method.clone(),
                    headers,
                    request.body.into_bytes(),
                    self.limits,
                )
                .await?;
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(';').next())
                .map(str::trim)
                .ok_or(Error::Denied)?
                .to_owned();
            if !matches!(content_type.as_str(), "text/plain" | "application/json") {
                return Err(Error::Denied);
            }
            let status = response.status().as_u16();
            let body = crate::http::bounded_body(response, self.limits).await?;
            let text = std::str::from_utf8(&body).map_err(|_| Error::Denied)?;
            let redacted = inspect_body(
                &mut *self.vault.lock().await,
                text,
                content_type == "application/json",
            )?;
            let bytes = serde_json::to_vec(&serde_json::json!({"status":status,"body":redacted}))
                .map_err(|_| Error::InvalidMessage)?;
            if bytes.len() > self.limits.message_bytes {
                return Err(Error::Limit);
            }
            Ok(bytes)
        }
        .await;
        self.audit
            .record_reason(
                intent,
                if result.is_ok() {
                    Outcome::Response
                } else {
                    Outcome::Unknown
                },
                result
                    .as_ref()
                    .err()
                    .map_or(Reason::Unspecified, Error::reason),
            )
            .await
            .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
        result
    }
    /// Serve bounded sequential JSONL operations on a connected session pipe.
    /// A malformed, denied or timed-out request closes the channel. The caller
    /// must cancel/terminate the associated sandbox if this future fails.
    /// # Errors
    /// Refuses oversized/partial frames, failed audit/DLP and network failures.
    pub async fn serve(mut self, stream: tokio::net::UnixStream) -> Result<(), Error> {
        let (read, mut write) = stream.into_split();
        let mut read = BufReader::new(read);
        loop {
            // Silence on an unused capability is not a request timeout. The
            // enclosing MCP session still enforces its idle/absolute deadlines.
            if read
                .fill_buf()
                .await
                .map_err(|_| Error::Transport)?
                .is_empty()
            {
                return Err(Error::Closed);
            }
            let timeout = self.limits.request_timeout;
            let operation = async {
                let mut frame = Vec::new();
                loop {
                    let chunk = read.fill_buf().await.map_err(|_| Error::Transport)?;
                    if chunk.is_empty() {
                        return Err(Error::Closed);
                    }
                    let n = chunk
                        .iter()
                        .position(|b| *b == b'\n')
                        .map_or(chunk.len(), |i| i + 1);
                    if frame.len() + n > self.limits.message_bytes {
                        return Err(Error::Limit);
                    }
                    let complete = chunk[n - 1] == b'\n';
                    frame.extend_from_slice(&chunk[..n]);
                    read.consume(n);
                    if complete {
                        break;
                    }
                }
                let mut response = self.request(&frame).await?;
                response.push(b'\n');
                write
                    .write_all(&response)
                    .await
                    .map_err(|_| Error::Transport)
            };
            let result = tokio::time::timeout(timeout, operation)
                .await
                .map_err(|_| Error::Timeout)
                .and_then(std::convert::identity);
            if let Err(error) = result {
                self.audit
                    .record_reason(0, Outcome::Denied, error.reason())
                    .await
                    .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
                return Err(error);
            }
        }
    }
}

// JSON is inspected structurally even when embedded in text/plain, so escaped
// values and credential field names do not bypass ordinary text inspection.
fn inspect_body(
    vault: &mut clawbell_core::dlp::Vault,
    text: &str,
    json: bool,
) -> Result<String, Error> {
    match clawbell_core::json::parse(text.as_bytes()) {
        Ok(value) => {
            let mut discovered = value.clone();
            crate::dlp::transform(&mut discovered, &mut |s| {
                vault.redact(s).map_err(|_| Error::Denied)
            })?;
            let mut fragments = Vec::new();
            collect_strings(&value, &mut fragments);
            vault
                .inspect_fragments(&fragments)
                .map_err(|_| Error::Denied)?;
            let mut redacted = value.clone();
            crate::dlp::transform(&mut redacted, &mut |s| {
                vault.redact(s).map_err(|_| Error::Denied)
            })?;
            if redacted == value {
                Ok(text.to_owned())
            } else {
                serde_json::to_string(&redacted).map_err(|_| Error::Denied)
            }
        }
        Err(_) if json => Err(Error::Denied),
        Err(_) => {
            vault
                .inspect_fragments(&[text])
                .map_err(|_| Error::Denied)?;
            vault.redact(text).map_err(|_| Error::Denied)
        }
    }
}
fn collect_strings<'a>(value: &'a serde_json::Value, strings: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::String(s) => strings.push(s),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_strings(item, strings);
            }
        }
        serde_json::Value::Object(items) => {
            for item in items.values() {
                collect_strings(item, strings);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    #[test]
    fn structured_broker_bodies_discover_credentials_before_echoes_and_refuse_split_values()
    -> TestResult {
        let mut vault = clawbell_core::dlp::Vault::new(65_536)?;
        let source = r#"{"a_echo":"synthetic-json-secret","password":"synthetic-json-secret"}"#;
        let redacted = inspect_body(&mut vault, source, true)?;
        assert!(!redacted.contains("synthetic-json-secret"));
        assert!(inspect_body(&mut vault, r#"["synthetic-json-","secret"]"#, true).is_err());
        assert!(inspect_body(&mut vault, r#"{"password":12345}"#, true).is_err());
        assert!(inspect_body(&mut vault, "{malformed", true).is_err());
        assert_eq!(inspect_body(&mut vault, "public", false)?, "public");
        Ok(())
    }
    #[tokio::test]
    async fn broker_denies_before_network_and_redacts_complete_split_response() -> TestResult {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::temp_dir().join(format!("clawbell-broker-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let audit = OperationStore::open(&root, "a".repeat(64)).await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let policy = Policy::parse(&format!(
            "version='broker'\ntools=[]\nrules=[]\n[[network]]\nname='public'\nurl='http://{}/public'\nmethod='POST'\nprivate_ip='127.0.0.1'\ndecision='allow'\n",
            listener.local_addr()?
        ))?;
        let shared = crate::dlp::shared_vault(Limits::default().message_bytes)?;
        shared.lock().await.register("synthetic-registered-value")?;
        let mut broker = Broker::prepare(&policy, audit, Limits::default())
            .await?
            .with_vault(shared.clone());
        for request in [
            serde_json::json!({"endpoint":"unknown"}),
            serde_json::json!({"endpoint":"public","url":"http://169.254.169.254"}),
            serde_json::json!({"endpoint":"public","body":"synthetic-registered-value"}),
            serde_json::json!({"endpoint":"public","body":"token=synthetic-labeled-value"}),
        ] {
            assert!(
                broker
                    .request(&serde_json::to_vec(&request)?)
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(10), listener.accept())
                    .await
                    .is_err()
            );
        }
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut bytes = [0; 8192];
            let n = stream.read(&mut bytes).await?;
            assert!(std::str::from_utf8(&bytes[..n])?.starts_with("POST /public "));
            let body = "token=synthetic-response-secret";
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(b"token=synthetic-").await?;
            tokio::task::yield_now().await;
            stream.write_all(b"response-secret").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let bytes = broker
            .request(br#"{"endpoint":"public","body":"public"}"#)
            .await?;
        let result: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(result["status"], 200);
        assert!(!String::from_utf8(bytes)?.contains("synthetic-response-secret"));
        server.await??;
        // Secret learned on the broker boundary is now known to the MCP vault.
        assert!(
            shared
                .lock()
                .await
                .check_request("synthetic-response-secret")
                .is_err()
        );
        drop(broker);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}

#[cfg(test)]
mod latency {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::io::AsyncBufReadExt;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
    #[tokio::test]
    #[ignore = "release-only real broker policy/DLP/durable-audit loopback budget"]
    async fn broker_packet_latency_budget() -> TestResult {
        use std::os::unix::fs::DirBuilderExt;
        let root =
            std::env::temp_dir().join(format!("clawbell-broker-latency-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let audit = OperationStore::open(&root, "b".repeat(64)).await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let policy = Policy::parse(&format!(
            "version='broker-latency'\ntools=[]\nrules=[]\n[[network]]\nname='public'\nurl='http://{}/public'\nprivate_ip='127.0.0.1'\nmethod='GET'\ndecision='allow'\n",
            listener.local_addr()?
        ))?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut read = BufReader::new(stream);
            for _ in 0..2200 {
                loop {
                    let mut line = String::new();
                    if read.read_line(&mut line).await? == 0 {
                        return Err("early EOF".into());
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                read.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\npublic").await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let mut broker = Broker::prepare(&policy, audit, Limits::default()).await?;
        let mut samples = Vec::new();
        for n in 0..2200 {
            let started = Instant::now();
            broker.request(br#"{"endpoint":"public"}"#).await?;
            if n >= 200 {
                samples.push(started.elapsed());
            }
        }
        server.await??;
        samples.sort_unstable();
        println!(
            "Broker policy/DLP/durable audit + loopback: p99 {:?}, max {:?}",
            samples[1979], samples[1999]
        );
        assert!(samples[1979] < Duration::from_millis(40));
        assert!(samples[1999] < Duration::from_secs(1));
        drop(broker);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
