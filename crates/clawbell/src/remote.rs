//! Explicit remote MCP composition. The local process never starts an upstream
//! server or mounts credentials; remote process isolation is outside its boundary.
use crate::{
    errors::Code,
    files::{self, Result},
};
use clawbell_audit::{
    baseline::BaselineStore,
    operations::{OperationStore, Outcome},
};
use clawbell_core::policy::Policy;
use clawbell_proxy::{
    Limits,
    http::{Target, relay},
    network::{Bearer, Endpoint},
    oauth::Authorization,
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
    /// Initiate an owner OAuth login; requires all three OAuth endpoint/client flags.
    #[arg(long, requires_all = ["oauth_authorization_url", "oauth_token_url", "oauth_client_id"])]
    pub oauth_login: bool,
    #[arg(long, requires = "oauth_login")]
    pub oauth_authorization_url: Option<String>,
    #[arg(long, requires = "oauth_login")]
    pub oauth_token_url: Option<String>,
    #[arg(long, requires = "oauth_login")]
    pub oauth_client_id: Option<String>,
    #[arg(long, requires = "oauth_login")]
    pub oauth_scope: Vec<String>,
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
async fn login(options: &Options, limits: Limits) -> Result<Option<Bearer>> {
    if !options.oauth_login {
        return Ok(None);
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let redirect = format!("http://{}/callback", listener.local_addr()?);
    let (flow, url) = Authorization::begin(
        options
            .oauth_authorization_url
            .as_deref()
            .ok_or(Code("oauth_configuration_required"))?,
        options
            .oauth_token_url
            .as_deref()
            .ok_or(Code("oauth_configuration_required"))?,
        options
            .oauth_client_id
            .as_deref()
            .ok_or(Code("oauth_configuration_required"))?,
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
    Ok(Some(flow.complete(code, &state, limits).await?))
}
pub async fn run(options: Options) -> Result<()> {
    let limits = Limits::default();
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
    // URL is canonicalized before OAuth audience checks and persistent identity.
    let mut options = options;
    options.url = reqwest::Url::parse(&options.url)?.to_string();
    let identity = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            &options.server,
            &options.url,
            &options.oauth_client_id,
            &options.oauth_authorization_url,
            &options.oauth_token_url
        ))?)
    );
    let store = OperationStore::open_session(
        &options.state_dir,
        format!("{:x}", Sha256::digest(&policy_bytes)),
        identity.clone(),
    )
    .await?;
    let baseline = BaselineStore::open(&options.state_dir).await?;
    let launch = store.record(0, Outcome::Intent).await?;
    let endpoint = Endpoint::connect(&options.url, options.private_ip, limits).await?;
    let bearer = login(&options, limits).await?;
    let mut gate =
        crate::launch::compose_remote(policy, baseline, store.clone(), identity, bearer.as_ref())?;
    let endpoint = match bearer {
        Some(bearer) => endpoint.with_bearer(bearer)?,
        None => endpoint,
    };
    let result = relay(
        tokio::io::stdin(),
        tokio::io::stdout(),
        Target::streamable(endpoint),
        &mut gate,
        limits,
    )
    .await;
    store.record(launch, Outcome::Unknown).await?;
    match result {
        Ok(()) | Err(clawbell_proxy::Error::Closed) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
