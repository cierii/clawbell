//! Host-only OAuth refresh, rotation and bounded persistence representation.
//! The storage callback must durably replace a private owner file. No MCP request
//! is replayed after 401; refresh happens before sending the next operation.
use crate::{
    Error, Limits,
    network::{Bearer, Endpoint},
};
use oauth2::{
    ClientId, RefreshToken, TokenResponse, TokenUrl,
    basic::{BasicClient, BasicTokenResponse, BasicTokenType},
};
use secrecy::{ExposeSecret, SecretString};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

/// All credentials learned during a session, including rotated refresh tokens.
/// Shared only with host DLP inspectors; never serialized or debug formatted.
#[derive(Clone, Default)]
pub struct Credentials(Arc<Mutex<Vec<SecretString>>>);
impl Credentials {
    fn add(&self, tokens: &Tokens) -> Result<(), Error> {
        let mut values = self.0.lock().map_err(|_| Error::Denied)?;
        for value in std::iter::once(&tokens.access).chain(tokens.refresh.iter()) {
            if !values
                .iter()
                .any(|v| v.expose_secret() == value.expose_secret())
            {
                if values.len() >= 128 {
                    return Err(Error::Limit);
                }
                values.push(value.clone());
            }
        }
        Ok(())
    }
    /// Register every credential before inspecting any request or response.
    /// # Errors
    /// Refuses lock poisoning or exhausted DLP capacity.
    pub fn register(&self, vault: &mut clawbell_core::dlp::Vault) -> Result<(), Error> {
        for value in self.0.lock().map_err(|_| Error::Denied)?.iter() {
            vault
                .register(value.expose_secret())
                .map_err(|_| Error::Denied)?;
        }
        Ok(())
    }
}
/// Credentials for one exact resource and public client. Values intentionally
/// have no Debug or general Serialize implementation.
pub struct Tokens {
    access: SecretString,
    refresh: Option<SecretString>,
    expires: u64,
    deadline: Instant,
    resource: String,
    client_id: String,
}
fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Denied)
}
impl Tokens {
    pub(crate) fn from_response(
        response: &BasicTokenResponse,
        resource: String,
        client_id: String,
        previous: Option<SecretString>,
    ) -> Result<Self, Error> {
        if response.token_type() != &BasicTokenType::Bearer {
            return Err(Error::Denied);
        }
        let lifetime = response.expires_in().ok_or(Error::Denied)?;
        let access: SecretString = response.access_token().secret().to_owned().into();
        Bearer::new(access.clone(), lifetime)?;
        let refresh = response
            .refresh_token()
            .map(|v| SecretString::from(v.secret().to_owned()))
            .or(previous);
        if refresh.as_ref().is_some_and(|v| {
            v.expose_secret().is_empty()
                || v.expose_secret().len() > 8192
                || v.expose_secret().chars().any(char::is_control)
        }) {
            return Err(Error::Denied);
        }
        Ok(Self {
            access,
            refresh,
            expires: now()?
                .checked_add(lifetime.as_secs())
                .ok_or(Error::Denied)?,
            deadline: Instant::now() + lifetime,
            resource,
            client_id,
        })
    }
    /// Create an exact-resource bearer without disclosing its value to callers.
    /// # Errors
    /// Expired/invalid credentials refuse before network execution.
    pub fn bearer(&self) -> Result<Bearer, Error> {
        Bearer::new(
            self.access.clone(),
            self.deadline.saturating_duration_since(Instant::now()),
        )
        .map(|b| b.with_audience(self.resource.clone()))
    }
    /// Public client identity (never a client secret).
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    /// Encode only for an explicitly authorized private host store. The binding
    /// includes owner configuration/scopes, preventing reuse after settings drift.
    /// # Errors
    /// Refuses encoding failure; returned bytes must never enter logs or Git.
    pub fn encode(&self, binding: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
        #[derive(serde::Serialize)]
        struct Record<'a> {
            version: u8,
            binding: &'a str,
            resource: &'a str,
            client_id: &'a str,
            expires: u64,
            access: &'a str,
            refresh: Option<&'a str>,
        }
        serde_json::to_vec(&Record {
            version: 1,
            binding,
            resource: &self.resource,
            client_id: &self.client_id,
            expires: self.expires,
            access: self.access.expose_secret(),
            refresh: self.refresh.as_ref().map(ExposeSecret::expose_secret),
        })
        .map(Zeroizing::new)
        .map_err(|_| Error::Denied)
    }
    /// Load a bounded owner-store record, enforcing exact configuration/resource.
    /// Expired access tokens can only be used by the refresh adapter.
    /// # Errors
    /// Refuses malformed records, wrong binding or implausible lifetimes.
    pub fn decode(bytes: &[u8], binding: &str, resource: &str) -> Result<Self, Error> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Record {
            version: u8,
            binding: String,
            resource: String,
            client_id: String,
            expires: u64,
            access: String,
            refresh: Option<String>,
        }
        if bytes.len() > 32_768 {
            return Err(Error::Limit);
        }
        let value = clawbell_core::json::parse(bytes).map_err(|_| Error::Denied)?;
        let r: Record = serde_json::from_value(value).map_err(|_| Error::Denied)?;
        if r.version != 1
            || r.binding != binding
            || r.resource != resource
            || r.client_id.is_empty()
            || r.client_id.len() > 1024
            || r.expires > now()? + 86400
        {
            return Err(Error::Denied);
        }
        let access = SecretString::from(r.access);
        Bearer::new(access.clone(), Duration::from_secs(1))?;
        if r.refresh
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 8192 || s.chars().any(char::is_control))
        {
            return Err(Error::Denied);
        }
        Ok(Self {
            access,
            refresh: r.refresh.map(Into::into),
            expires: r.expires,
            deadline: Instant::now() + Duration::from_secs(r.expires.saturating_sub(now()?)),
            resource: r.resource,
            client_id: r.client_id,
        })
    }
}
/// Trusted host storage adapter; implementations synchronize private replacement
/// before returning and must never print the supplied bytes.
pub type Persist = Arc<dyn Fn(&[u8]) -> Result<(), Error> + Send + Sync>;

/// Serialized refresh for one exact endpoint/client. A failed refresh/persistence
/// poisons the session; uncertain refresh grants are never automatically retried.
pub struct TokenSession {
    state: tokio::sync::Mutex<(Tokens, bool)>,
    endpoint: Endpoint,
    token_url: String,
    binding: String,
    credentials: Credentials,
    persist: Option<Persist>,
    audit: clawbell_audit::operations::OperationStore,
}
impl TokenSession {
    /// Prepare a refresh session after durable launch intent and owner trust in
    /// the issuer. Register initial credentials before returning.
    /// # Errors
    /// Refuses unsafe token URLs, DNS policy violations or credential budgets.
    pub async fn new(
        tokens: Tokens,
        token_url: &str,
        binding: String,
        persist: Option<Persist>,
        audit: clawbell_audit::operations::OperationStore,
        limits: Limits,
    ) -> Result<Self, Error> {
        if reqwest::Url::parse(token_url)
            .map_err(|_| Error::Denied)?
            .scheme()
            != "https"
        {
            return Err(Error::Denied);
        }
        let endpoint = Endpoint::connect(token_url, None, limits).await?;
        let credentials = Credentials::default();
        credentials.add(&tokens)?;
        Ok(Self {
            state: tokio::sync::Mutex::new((tokens, false)),
            endpoint,
            token_url: token_url.into(),
            binding,
            credentials,
            persist,
            audit,
        })
    }
    /// Host DLP registration handle, including all future rotations.
    #[must_use]
    pub fn credentials(&self) -> Credentials {
        self.credentials.clone()
    }
    /// Get a valid bearer, refreshing before expiry without replaying MCP.
    /// # Errors
    /// Refuses missing refresh credentials, refresh failure or nondurable storage.
    pub async fn bearer(&self, limits: Limits) -> Result<Bearer, Error> {
        use clawbell_audit::operations::{Outcome, Reason};
        let mut state = self.state.lock().await;
        if state.1 {
            return Err(Error::Denied);
        }
        let remaining = state.0.deadline.saturating_duration_since(Instant::now());
        if remaining > Duration::from_secs(30)
            || (state.0.refresh.is_none() && !remaining.is_zero())
        {
            return state.0.bearer();
        }
        // Poison before dispatch. Cancellation or an unknown token response cannot
        // replay a consumed refresh token on a later call.
        state.1 = true;
        let refresh = state.0.refresh.clone().ok_or(Error::Denied)?;
        let client_id = state.0.client_id.clone();
        let resource = state.0.resource.clone();
        let intent = self
            .audit
            .record(0, Outcome::Intent)
            .await
            .map_err(|_| Error::Denied)?;
        let result = async move {
            // Durable tombstone before a possibly one-use refresh grant. A crash
            // cannot cause a later process to retry an uncertain old credential.
            if let Some(persist) = &self.persist {
                let persist = persist.clone();
                tokio::task::spawn_blocking(move || persist(&[]))
                    .await
                    .map_err(|_| Error::Denied)??;
            }
            let client = BasicClient::new(ClientId::new(client_id.clone()))
                .set_auth_type(oauth2::AuthType::RequestBody)
                .set_token_uri(TokenUrl::new(self.token_url.clone()).map_err(|_| Error::Denied)?);
            let send = TokenHttp {
                endpoint: &self.endpoint,
                url: &self.token_url,
                limits,
            };
            let response = client
                .exchange_refresh_token(&RefreshToken::new(refresh.expose_secret().to_owned()))
                .add_extra_param("resource", &resource)
                .request_async(&send)
                .await
                .map_err(|_| Error::Denied)?;
            let tokens = Tokens::from_response(
                &response,
                resource.clone(),
                client_id.clone(),
                Some(refresh.clone()),
            )?;
            self.credentials.add(&tokens)?;
            if let Some(persist) = &self.persist {
                let bytes = tokens.encode(&self.binding)?;
                let persist = persist.clone();
                tokio::task::spawn_blocking(move || persist(&bytes))
                    .await
                    .map_err(|_| Error::Denied)??;
            }
            Ok::<_, Error>(tokens)
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
                Reason::OAuthInitialization,
            )
            .await
            .map_err(|_| Error::Denied)?;
        state.0 = result?;
        state.1 = false;
        state.0.bearer()
    }
}

struct TokenHttp<'a> {
    endpoint: &'a Endpoint,
    url: &'a str,
    limits: Limits,
}
impl<'c> oauth2::AsyncHttpClient<'c> for TokenHttp<'_> {
    type Error = Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<oauth2::HttpResponse, Error>> + Send + 'c>,
    >;
    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        Box::pin(async move {
            if request.uri() != self.url {
                return Err(Error::Denied);
            }
            let (parts, body) = request.into_parts();
            let response = self
                .endpoint
                .send_raw(parts.method, parts.headers, body, self.limits, None)
                .await?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = crate::http::bounded_body(response, self.limits).await?;
            let mut result = oauth2::HttpResponse::new(body);
            *result.status_mut() = status;
            *result.headers_mut() = headers;
            Ok(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawbell_audit::operations::OperationStore;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    fn tokens() -> Result<Tokens, Error> {
        let response: BasicTokenResponse = serde_json::from_value(serde_json::json!({"access_token":"synthetic-initial-access","token_type":"bearer","expires_in":1,"refresh_token":"synthetic-initial-refresh"})).map_err(|_| Error::Denied)?;
        Tokens::from_response(
            &response,
            "https://resource.example/mcp".into(),
            "public-client".into(),
            None,
        )
    }
    async fn fixture(
        mode: &str,
    ) -> TestResult<(
        TokenSession,
        tokio::net::TcpListener,
        std::path::PathBuf,
        Arc<Mutex<Vec<Vec<u8>>>>,
    )> {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::temp_dir().join(format!(
            "clawbell-oauth-session-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let audit = OperationStore::open(&root, "a".repeat(64)).await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/token", listener.local_addr()?);
        let endpoint =
            Endpoint::connect(&url, Some("127.0.0.1".parse()?), Limits::default()).await?;
        let writes = Arc::new(Mutex::new(Vec::new()));
        let saved = writes.clone();
        let mode = mode.to_owned();
        let persist: Persist = Arc::new(move |bytes| {
            saved
                .lock()
                .map_err(|_| Error::Denied)?
                .push(bytes.to_vec());
            if mode == "before" || (mode == "after" && !bytes.is_empty()) {
                return Err(Error::Denied);
            }
            Ok(())
        });
        let tokens = tokens()?;
        let credentials = Credentials::default();
        credentials.add(&tokens)?;
        Ok((
            TokenSession {
                state: tokio::sync::Mutex::new((tokens, false)),
                endpoint,
                token_url: url,
                binding: "binding".into(),
                credentials,
                persist: Some(persist),
                audit,
            },
            listener,
            root,
            writes,
        ))
    }
    #[test]
    fn persisted_credentials_bind_resource_configuration_and_expiry() -> TestResult {
        let tokens = tokens()?;
        let bytes = tokens.encode("binding")?;
        assert_eq!(
            Tokens::decode(&bytes, "binding", "https://resource.example/mcp")?.client_id(),
            "public-client"
        );
        assert!(Tokens::decode(&bytes, "changed", "https://resource.example/mcp").is_err());
        assert!(Tokens::decode(&bytes, "binding", "https://other.example/mcp").is_err());
        assert!(Tokens::decode(b"", "binding", "https://resource.example/mcp").is_err());
        Ok(())
    }
    #[tokio::test]
    async fn refresh_rotates_once_registers_all_secrets_and_poisoned_sessions_never_retry()
    -> TestResult {
        for mode in ["success", "provider", "before", "after"] {
            let (session, listener, root, writes) = fixture(mode).await?;
            if mode == "before" {
                assert!(session.bearer(Limits::default()).await.is_err());
            } else {
                let provider_failure = mode == "provider";
                let server = async {
                    let (stream, _) = listener.accept().await?;
                    let mut reader = BufReader::new(stream);
                    let mut length = 0;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).await?;
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((key, value)) = line.split_once(':')
                            && key.eq_ignore_ascii_case("content-length")
                        {
                            length = value.trim().parse()?;
                        }
                        assert!(!line.to_ascii_lowercase().starts_with("authorization:"));
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).await?;
                    let body = String::from_utf8(body)?;
                    assert!(body.contains("grant_type=refresh_token"));
                    assert!(body.contains("refresh_token=synthetic-initial-refresh"));
                    assert!(body.contains("client_id=public-client"));
                    assert!(body.contains("resource=https%3A%2F%2Fresource.example%2Fmcp"));
                    let (status, response) = if provider_failure {
                        ("400 Bad Request", r#"{"error":"invalid_grant"}"#)
                    } else {
                        (
                            "200 OK",
                            r#"{"access_token":"synthetic-rotated-access","refresh_token":"synthetic-rotated-refresh","token_type":"bearer","expires_in":3600}"#,
                        )
                    };
                    reader.get_mut().write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).as_bytes()).await?;
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                };
                let requests = async {
                    tokio::join!(
                        session.bearer(Limits::default()),
                        session.bearer(Limits::default())
                    )
                };
                let (server, (first, second)) = tokio::join!(server, requests);
                server?;
                if mode == "success" {
                    assert!(first.is_ok() && second.is_ok());
                    let mut vault = clawbell_core::dlp::Vault::new(65_536)?;
                    session.credentials().register(&mut vault)?;
                    for secret in [
                        "synthetic-initial-access",
                        "synthetic-initial-refresh",
                        "synthetic-rotated-access",
                        "synthetic-rotated-refresh",
                    ] {
                        assert!(vault.check_request(secret).is_err());
                    }
                    let writes = writes.lock().map_err(|_| Error::Denied)?;
                    assert_eq!(writes[0], b"");
                    let restored =
                        Tokens::decode(&writes[1], "binding", "https://resource.example/mcp")?;
                    assert_eq!(restored.access.expose_secret(), "synthetic-rotated-access");
                } else {
                    assert!(first.is_err() && second.is_err());
                }
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
            drop(session);
            std::fs::remove_dir_all(root)?;
        }
        Ok(())
    }
}
