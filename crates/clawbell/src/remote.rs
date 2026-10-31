//! Explicit remote MCP composition. The local process never starts an upstream
//! server or mounts credentials; remote process isolation is outside its boundary.
use crate::{
    errors::Code,
    files::{self, Result},
};
use clawbell_audit::{
    baseline::BaselineStore,
    operations::{OperationStore, Outcome, Reason},
};
use clawbell_core::policy::Policy;
use clawbell_proxy::{
    Limits,
    http::{Target, relay},
    network::Endpoint,
    oauth::{Authorization, Discovery, Persist, TokenSession, Tokens},
};
use sha2::{Digest, Sha256};
use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use zeroize::Zeroizing;

#[derive(clap::Args)]
pub struct Options {
    /// Maximum idle time with no outstanding request (seconds).
    #[arg(long, default_value_t = 600)]
    pub idle_timeout_secs: u64,
    /// Request/inspection/I/O deadline (seconds, at most 300).
    #[arg(long, default_value_t = 30)]
    pub request_timeout_secs: u64,
    /// Absolute session lifetime (seconds, at most 86400).
    #[arg(long, default_value_t = 3600)]
    pub session_lifetime_secs: u64,
    /// Optional owner-private IPC socket; monitor failure closes the session.
    #[arg(long)]
    pub monitor_socket: Option<PathBuf>,
    /// Exact owner-authorized upstream URL (scheme, hostname, port and path).
    #[arg(long)]
    pub url: String,
    /// One exact private IP exception for this endpoint, never a network prefix.
    #[arg(long)]
    pub private_ip: Option<IpAddr>,
    #[arg(long)]
    pub policy: PathBuf,
    /// Private 0700 host state, never exposed to any local sandbox.
    #[arg(long)]
    pub state_dir: PathBuf,
    #[arg(long)]
    pub server: String,
    /// Explicit owner login. Supply endpoint/client flags or a trusted issuer.
    #[arg(long)]
    pub oauth_login: bool,
    #[arg(long)]
    pub oauth_authorization_url: Option<String>,
    #[arg(long)]
    pub oauth_token_url: Option<String>,
    #[arg(long)]
    pub oauth_client_id: Option<String>,
    #[arg(long)]
    pub oauth_scope: Vec<String>,
    /// Trusted HTTPS issuer; discovery may not expand beyond its origin.
    #[arg(long, conflicts_with_all = ["oauth_authorization_url", "oauth_token_url"])]
    pub oauth_issuer: Option<String>,
    /// Explicitly register a public client with the trusted discovered issuer.
    #[arg(long, requires_all = ["oauth_issuer", "oauth_login"], conflicts_with = "oauth_client_id")]
    pub oauth_register: bool,
    /// Persist credentials in a private host store and reuse/refresh on reconnect.
    #[arg(long)]
    pub oauth_persist: bool,
}

impl Options {
    pub(crate) fn limits(&self) -> std::result::Result<Limits, clawbell_proxy::Error> {
        Limits {
            idle_timeout: Duration::from_secs(self.idle_timeout_secs),
            request_timeout: Duration::from_secs(self.request_timeout_secs),
            session_lifetime: Duration::from_secs(self.session_lifetime_secs),
            ..Limits::default()
        }
        .validate()
    }
}

// One local loopback callback, no cookies or token persistence. State+PKCE protect
// against forged callbacks. Unknown/duplicate parameters and HTTP bodies refuse.
async fn callback(listener: TcpListener) -> Result<(Zeroizing<String>, String)> {
    let expected_host = listener.local_addr()?.to_string();
    let (mut stream, peer) = listener.accept().await?;
    if !peer.ip().is_loopback() {
        return Err(Code("oauth_callback_refused").into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = [0; 1024];
    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 || bytes.len() + count > 16_384 {
            return Err(Code("oauth_callback_refused").into());
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.windows(4).any(|s| s == b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&bytes)?;
    let mut lines = text.split("\r\n");
    let line = lines.next().ok_or(Code("oauth_callback_refused"))?;
    let mut parts = line.split(' ');
    if parts.next() != Some("GET") {
        return Err(Code("oauth_callback_refused").into());
    }
    let path = parts.next().ok_or(Code("oauth_callback_refused"))?;
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() || !path.starts_with("/callback?")
    {
        return Err(Code("oauth_callback_refused").into());
    }
    let mut hosts = 0;
    for line in lines.take_while(|s| !s.is_empty()) {
        let (key, value) = line.split_once(':').ok_or(Code("oauth_callback_refused"))?;
        if key.eq_ignore_ascii_case("host") {
            hosts += 1;
            if value.trim() != expected_host {
                return Err(Code("oauth_callback_refused").into());
            }
        }
        if key.eq_ignore_ascii_case("origin")
            || key.eq_ignore_ascii_case("transfer-encoding")
            || (key.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err(Code("oauth_callback_refused").into());
        }
    }
    if hosts != 1 {
        return Err(Code("oauth_callback_refused").into());
    }
    let url = reqwest::Url::parse(&format!("http://{expected_host}{path}"))?;
    let mut code = None;
    let mut state = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" if code.is_none() => code = Some(Zeroizing::new(value.into_owned())),
            "state" if state.is_none() => state = Some(value.into_owned()),
            _ => return Err(Code("oauth_callback_refused").into()),
        }
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 41\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nLogin received. Return to the local CLI.\n").await?;
    Ok((
        code.ok_or(Code("oauth_callback_refused"))?,
        state.ok_or(Code("oauth_callback_refused"))?,
    ))
}
async fn login(
    options: &Options,
    binding: &str,
    audit: OperationStore,
    limits: Limits,
) -> Result<Option<Arc<TokenSession>>> {
    let configured = options.oauth_login
        || options.oauth_persist
        || options.oauth_issuer.is_some()
        || options.oauth_token_url.is_some()
        || options.oauth_authorization_url.is_some()
        || options.oauth_client_id.is_some();
    if !configured {
        return Ok(None);
    }
    let cache = if options.oauth_persist {
        Some(Arc::new(crate::oauth_store::Store::open(
            &options.state_dir,
            binding,
        )?))
    } else {
        None
    };
    let cached = cache.as_ref().map(|c| c.load()).transpose()?.flatten();
    let metadata = if let Some(issuer) = &options.oauth_issuer {
        Some(Discovery::discover(&options.url, issuer, limits).await?)
    } else {
        None
    };
    let authorization_url = metadata
        .as_ref()
        .map(|d| d.authorization_url.as_str())
        .or(options.oauth_authorization_url.as_deref())
        .ok_or(Code("oauth_configuration_required"))?;
    let token_url = metadata
        .as_ref()
        .map(|d| d.token_url.as_str())
        .or(options.oauth_token_url.as_deref())
        .ok_or(Code("oauth_configuration_required"))?;
    let credential_binding = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            binding,
            authorization_url,
            token_url
        ))?)
    );
    let tokens = if let Some(bytes) = cached.filter(|_| !options.oauth_login) {
        let tokens = Tokens::decode(&bytes, &credential_binding, &options.url)?;
        if options
            .oauth_client_id
            .as_deref()
            .is_some_and(|id| id != tokens.client_id())
        {
            return Err(Code("oauth_client_binding_changed").into());
        }
        tokens
    } else {
        if !options.oauth_login {
            return Err(Code("oauth_login_required").into());
        }
        interactive_login(
            options,
            metadata.as_ref(),
            authorization_url,
            token_url,
            &audit,
            limits,
        )
        .await?
    };
    let persist: Option<Persist> = cache.map(|cache| {
        Arc::new(move |bytes: &[u8]| cache.save(bytes).map_err(|_| clawbell_proxy::Error::Denied))
            as Persist
    });
    if let Some(save) = &persist {
        save(&tokens.encode(&credential_binding)?)?;
    }
    let session = Arc::new(
        TokenSession::new(
            tokens,
            token_url,
            credential_binding,
            persist,
            audit,
            limits,
        )
        .await?,
    );
    // Refresh expired cached credentials during initialization, before the DLP
    // gate is composed. The same session handles subsequent rotations.
    session.bearer(limits).await?;
    Ok(Some(session))
}
async fn interactive_login(
    options: &Options,
    metadata: Option<&Discovery>,
    authorization_url: &str,
    token_url: &str,
    audit: &OperationStore,
    limits: Limits,
) -> Result<Tokens> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let redirect = format!("http://{}/callback", listener.local_addr()?);
    let client_id = if options.oauth_register {
        let intent = audit.record(0, Outcome::Intent).await?;
        let result = metadata
            .ok_or(Code("oauth_configuration_required"))?
            .register(&redirect, limits)
            .await;
        audit
            .record_reason(
                intent,
                if result.is_ok() {
                    Outcome::Response
                } else {
                    Outcome::Unknown
                },
                Reason::OAuthInitialization,
            )
            .await?;
        result?
    } else {
        options
            .oauth_client_id
            .clone()
            .ok_or(Code("oauth_configuration_required"))?
    };
    let (flow, url) = Authorization::begin(
        authorization_url,
        token_url,
        &client_id,
        &redirect,
        &options.url,
        &options.oauth_scope,
        limits,
    )
    .await?;
    eprintln!("Open this owner-configured OAuth authorization URL to sign in:\n{url}");
    let (code, state) = tokio::time::timeout(Duration::from_secs(300), callback(listener))
        .await
        .map_err(|_| Code("oauth_login_timeout"))??;
    Ok(flow.complete_tokens(code, &state, limits).await?)
}
pub async fn run(options: Options) -> Result<()> {
    let limits = options.limits()?;
    let endpoint_path = options.monitor_socket.clone();
    if let Some(path) = &endpoint_path {
        files::trusted(path.parent().ok_or(Code("monitor_parent_required"))?)?;
    }
    let monitor = clawbell_proxy::monitor::Monitor::new()?;
    files::trusted(&options.state_dir)?;
    files::trusted(
        options
            .policy
            .parent()
            .ok_or(Code("policy_parent_required"))?,
    )?;
    let policy_bytes = files::read(&options.policy, 1024 * 1024)?;
    let policy = Arc::new(Policy::parse(std::str::from_utf8(&policy_bytes)?)?);
    if options.server.is_empty() || options.server.len() > 128 {
        return Err(Code("invalid_server_identity").into());
    }
    // Preserve existing canonical endpoint pins. Invalid URL input is hashed
    // provisionally; its parse error is returned only after durable launch intent.
    let mut options = options;
    let identity_url = reqwest::Url::parse(&options.url)
        .map_or_else(|_| options.url.clone(), |url| url.to_string());
    let identity = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            &options.server,
            &identity_url,
            &options.oauth_client_id,
            &options.oauth_authorization_url,
            &options.oauth_token_url,
            &options.oauth_issuer,
            &options.oauth_scope
        ))?)
    );
    let store = OperationStore::open_session(
        &options.state_dir,
        format!("{:x}", Sha256::digest(&policy_bytes)),
        identity.clone(),
    )
    .await?;
    let launch = store.record(0, Outcome::Intent).await?;
    let mut stage = Reason::RemoteInitialization;
    let result: Result<()> = async {
        let baseline = BaselineStore::open(&options.state_dir).await?;
        stage = Reason::EndpointInitialization;
        options.url = reqwest::Url::parse(&options.url)?.to_string();
        let endpoint = Endpoint::connect(&options.url, options.private_ip, limits).await?;
        stage = Reason::OAuthInitialization;
        let oauth = login(&options, &identity, store.clone(), limits).await?;
        stage = Reason::RemoteInitialization;
        let mut gate = crate::launch::compose_remote(
            policy,
            baseline,
            store.clone(),
            identity,
            None,
            oauth.as_ref().map(|s| s.credentials()),
            endpoint_path.as_ref().map(|_| monitor.clone()),
        )?;
        stage = Reason::OAuthInitialization;
        let endpoint = match oauth {
            Some(session) => endpoint.with_oauth(session)?,
            None => endpoint,
        };
        stage = Reason::Unspecified;
        let result = monitored_relay(
            endpoint,
            &mut gate,
            limits,
            &monitor,
            endpoint_path.as_deref(),
        )
        .await;
        match result {
            Ok(()) | Err(clawbell_proxy::Error::Closed) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    .await;
    let (outcome, reason) = match &result {
        Ok(()) => (Outcome::Unknown, Reason::Closed),
        Err(error) => (
            if stage == Reason::Unspecified {
                Outcome::Unknown
            } else {
                Outcome::Failure
            },
            if stage == Reason::Unspecified {
                error
                    .downcast_ref::<clawbell_proxy::Error>()
                    .map_or(Reason::Transport, clawbell_proxy::Error::reason)
            } else {
                stage
            },
        ),
    };
    store.record_reason(launch, outcome, reason).await?;
    result
}

async fn monitored_relay(
    endpoint: Endpoint,
    gate: &mut impl clawbell_proxy::Gate,
    limits: Limits,
    monitor: &clawbell_proxy::monitor::Monitor,
    path: Option<&std::path::Path>,
) -> std::result::Result<(), clawbell_proxy::Error> {
    let (result, monitor_failed) = {
        let session = relay(
            tokio::io::stdin(),
            tokio::io::stdout(),
            Target::streamable(endpoint),
            gate,
            limits,
        );
        let server = async {
            if let Some(path) = path {
                monitor.serve(path).await
            } else {
                std::future::pending().await
            }
        };
        tokio::select! {
            biased;
            _ = server => (Err(clawbell_proxy::Error::Denied), true),
            result = session => (result, false),
        }
    };
    if monitor_failed {
        gate.terminated(Reason::InspectionDenied).await?;
        gate.finish().await?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn startup_failures_close_the_launch_intent_without_payloads() -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        for case in ["url", "dns", "endpoint", "oauth", "baseline"] {
            let root = std::env::temp_dir().join(format!(
                "clawbell-remote-terminal-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&root)?;
            let policy = root.join("policy.toml");
            std::fs::write(
                &policy,
                "version = \"remote-terminal\"\ntools = []\nrules = []\n",
            )?;
            let url = match case {
                "url" => "malformed synthetic url",
                "dns" => "https://clawbell-synthetic-nonexistent.invalid/mcp",
                "endpoint" => "http://169.254.169.254/mcp",
                _ => "http://127.0.0.1:1/mcp",
            };
            if case == "baseline" {
                std::fs::create_dir(root.join("tool-baselines.sqlite3"))?;
            }
            let options = Options {
                idle_timeout_secs: 600,
                request_timeout_secs: 30,
                session_lifetime_secs: 3600,
                monitor_socket: None,
                url: url.into(),
                private_ip: Some("127.0.0.1".parse()?),
                policy,
                state_dir: root.clone(),
                server: "synthetic-remote".into(),
                oauth_issuer: None,
                oauth_register: false,
                oauth_persist: false,
                oauth_login: case == "oauth",
                oauth_authorization_url: Some("invalid".into()),
                oauth_token_url: Some("invalid".into()),
                oauth_client_id: Some("synthetic-client".into()),
                oauth_scope: Vec::new(),
            };
            assert!(run(options).await.is_err());
            let db = rusqlite::Connection::open(root.join("operations.sqlite3"))?;
            let events = db
                .prepare("SELECT outcome,reason,correlation FROM events_v1 ORDER BY id")?
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            assert_eq!(events.len(), 2);
            assert_eq!(events[0].0, "allow_intent");
            assert_eq!(events[1].0, "error_response");
            assert!(events[1].2 > 0);
            assert_eq!(
                events[1].1,
                match case {
                    "oauth" => "oauth_initialization_failed",
                    "baseline" => "remote_initialization_failed",
                    _ => "endpoint_initialization_failed",
                }
            );
            drop(db);
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }
    #[tokio::test]
    async fn oauth_callback_accepts_only_bounded_exact_loopback_requests() -> Result<()> {
        for attack in ["valid", "wrong-host", "duplicate-code", "origin", "post"] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let host = if attack == "wrong-host" {
                "untrusted.example".to_owned()
            } else {
                address.to_string()
            };
            let query = if attack == "duplicate-code" {
                "code=synthetic-code&code=other&state=synthetic-state"
            } else {
                "code=synthetic-code&state=synthetic-state"
            };
            let origin = if attack == "origin" {
                "Origin: https://untrusted.example\r\n"
            } else {
                ""
            };
            let method = if attack == "post" { "POST" } else { "GET" };
            let client = async {
                let mut client = tokio::net::TcpStream::connect(address).await?;
                client
                    .write_all(
                        format!(
                            "{method} /callback?{query} HTTP/1.1\r\nHost: {host}\r\n{origin}\r\n"
                        )
                        .as_bytes(),
                    )
                    .await?;
                let mut response = Vec::new();
                client.read_to_end(&mut response).await?;
                Ok::<_, std::io::Error>(response)
            };
            let (result, response) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(callback(listener), client)
            })
            .await?;
            let response = response?;
            assert!(!String::from_utf8_lossy(&response).contains("synthetic-code"));
            if attack == "valid" {
                let (code, state) = result?;
                assert_eq!(code.as_str(), "synthetic-code");
                assert_eq!(state, "synthetic-state");
                assert!(response.starts_with(b"HTTP/1.1 200 OK"));
            } else {
                assert!(result.is_err());
            }
        }
        Ok(())
    }
}
