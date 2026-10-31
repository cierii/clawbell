//! OAuth authorization code with S256 PKCE and resource indicators. Discovery
//! narrows an explicit owner issuer grant; registration, refresh and private host
//! persistence never grant authority to server-supplied URLs.
pub use crate::oauth_discovery::Discovery;
pub use crate::oauth_session::{Credentials, Persist, TokenSession, Tokens};
use crate::{
    Error, Limits,
    network::{Bearer, Endpoint},
};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
    basic::{BasicClient, BasicTokenType},
};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

type Client = BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// A one-use OAuth transaction. Never serialize or log this value. The caller
/// must authenticate the callback source and pass the returned state unchanged.
pub struct Authorization {
    client: Client,
    token_endpoint: Endpoint,
    token_url: String,
    resource: String,
    state: CsrfToken,
    verifier: PkceCodeVerifier,
    deadline: Instant,
}
impl Authorization {
    /// Build an authorization URL for an explicitly registered public client.
    /// All endpoints, redirect and scopes are trusted owner configuration. The
    /// caller opens the returned URL only on an explicit owner login action.
    /// # Errors
    /// Refuses non-HTTPS servers, non-loopback HTTP callbacks, query/fragment,
    /// malformed endpoints, oversized scopes and DNS/egress policy violations.
    pub async fn begin(
        authorization_url: &str,
        token_url: &str,
        client_id: &str,
        redirect: &str,
        resource: &str,
        scopes: &[String],
        limits: Limits,
    ) -> Result<(Self, String), Error> {
        for endpoint in [authorization_url, token_url, resource] {
            let url = reqwest::Url::parse(endpoint).map_err(|_| Error::Denied)?;
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.query().is_some()
            {
                return Err(Error::Denied);
            }
        }
        let callback = reqwest::Url::parse(redirect).map_err(|_| Error::Denied)?;
        if !callback.username().is_empty()
            || callback.password().is_some()
            || callback.query().is_some()
            || callback.fragment().is_some()
            || !(callback.scheme() == "https"
                || (callback.scheme() == "http"
                    && matches!(callback.host_str(), Some("127.0.0.1" | "[::1]"))))
            || client_id.is_empty()
            || client_id.len() > 1024
            || scopes.len() > 32
            || scopes
                .iter()
                .any(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control))
        {
            return Err(Error::Denied);
        }
        let token_endpoint = Endpoint::connect(token_url, None, limits).await?;
        let client = BasicClient::new(ClientId::new(client_id.to_owned()))
            .set_auth_uri(AuthUrl::new(authorization_url.to_owned()).map_err(|_| Error::Denied)?)
            .set_token_uri(TokenUrl::new(token_url.to_owned()).map_err(|_| Error::Denied)?)
            .set_auth_type(oauth2::AuthType::RequestBody)
            .set_redirect_uri(RedirectUrl::new(redirect.to_owned()).map_err(|_| Error::Denied)?);
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(challenge)
            .add_extra_param("resource", resource);
        for scope in scopes {
            request = request.add_scope(Scope::new(scope.clone()));
        }
        let (url, state) = request.url();
        Ok((
            Self {
                client,
                token_endpoint,
                token_url: token_url.to_owned(),
                resource: resource.to_owned(),
                state,
                verifier,
                deadline: Instant::now() + Duration::from_secs(300),
            },
            url.to_string(),
        ))
    }
    /// Redeem once; success returns a short-lived bearer for the exact resource.
    /// The caller must durably audit login intent and register the credential in
    /// DLP before attaching it to that resource's endpoint. No automatic refresh,
    /// retry, token persistence or MCP-operation replay occurs.
    /// # Errors
    /// Refuses expired/replayed transactions, CSRF mismatch, invalid token types,
    /// absent/oversized expiry, redirects and unsafe token responses.
    pub async fn complete(
        self,
        code: Zeroizing<String>,
        returned_state: &str,
        limits: Limits,
    ) -> Result<Bearer, Error> {
        self.complete_tokens(code, returned_state, limits)
            .await?
            .bearer()
    }
    /// Redeem once, retaining an optional refresh credential for host-only storage.
    /// # Errors
    /// Applies the same state, PKCE, lifetime and token validation as complete.
    pub async fn complete_tokens(
        self,
        code: Zeroizing<String>,
        returned_state: &str,
        limits: Limits,
    ) -> Result<Tokens, Error> {
        if returned_state.len() > 256
            || Instant::now() >= self.deadline
            || self.state != CsrfToken::new(returned_state.to_owned())
            || code.is_empty()
            || code.len() > 8192
        {
            return Err(Error::Denied);
        }
        let send = |request: oauth2::HttpRequest| async {
            if request.uri().to_string() != self.token_url {
                return Err(Error::Denied);
            }
            let (parts, body) = request.into_parts();
            let response = self
                .token_endpoint
                .send(parts.method, parts.headers, body, limits)
                .await?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = crate::http::bounded_body(response, limits).await?;
            let mut result = oauth2::HttpResponse::new(body);
            *result.status_mut() = status;
            *result.headers_mut() = headers;
            Ok::<_, Error>(result)
        };
        let result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(self.verifier)
            .add_extra_param("resource", &self.resource)
            .request_async(&send)
            .await
            .map_err(|_| Error::Denied)?;
        if result.token_type() != &BasicTokenType::Bearer {
            return Err(Error::Denied);
        }
        Tokens::from_response(
            &result,
            self.resource,
            self.client.client_id().as_str().to_owned(),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    async fn fixture(
        state: &str,
    ) -> Result<(Authorization, tokio::task::JoinHandle<Result<String>>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let token_url = format!("http://{}/token", listener.local_addr()?);
        let token_endpoint =
            Endpoint::connect(&token_url, Some("127.0.0.1".parse()?), Limits::default()).await?;
        let client = BasicClient::new(ClientId::new("synthetic-client".into()))
            .set_auth_uri(AuthUrl::new("https://issuer.example/authorize".into())?)
            .set_token_uri(TokenUrl::new(token_url.clone())?)
            .set_redirect_uri(RedirectUrl::new("http://127.0.0.1:7392/callback".into())?);
        let (_, verifier) = PkceCodeChallenge::new_random_sha256();
        let flow = Authorization {
            client,
            token_endpoint,
            token_url,
            resource: "https://resource.example/mcp".into(),
            state: CsrfToken::new(state.into()),
            verifier,
            deadline: Instant::now() + Duration::from_secs(30),
        };
        let server = tokio::spawn(async move {
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
                    length = value.trim().parse::<usize>()?;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).await?;
            let response = r#"{"access_token":"synthetic-OAuth-access-value","token_type":"bearer","expires_in":60}"#;
            reader.get_mut().write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).as_bytes()).await?;
            Ok(String::from_utf8(body)?)
        });
        Ok((flow, server))
    }
    #[tokio::test]
    async fn pkce_resource_and_state_are_bound_and_consumed() -> Result {
        let (flow, server) = fixture("synthetic-state").await?;
        let token = flow
            .complete(
                Zeroizing::new("synthetic-code".into()),
                "synthetic-state",
                Limits::default(),
            )
            .await?;
        assert_eq!(token.value(), "synthetic-OAuth-access-value");
        let body = server.await??;
        for field in [
            "code_verifier=",
            "resource=https%3A%2F%2Fresource.example%2Fmcp",
            "code=synthetic-code",
            "grant_type=authorization_code",
        ] {
            assert!(body.contains(field));
        }
        let (flow, server) = fixture("synthetic-state").await?;
        assert!(
            flow.complete(
                Zeroizing::new("synthetic-code".into()),
                "forged-state",
                Limits::default()
            )
            .await
            .is_err()
        );
        // No token request was emitted for the forged callback.
        assert!(!server.is_finished());
        server.abort();
        Ok(())
    }
    #[tokio::test]
    async fn expired_flow_and_unsafe_configuration_refuse() -> Result {
        let (mut flow, server) = fixture("state").await?;
        flow.deadline = Instant::now();
        assert!(
            flow.complete(Zeroizing::new("code".into()), "state", Limits::default())
                .await
                .is_err()
        );
        assert!(!server.is_finished());
        server.abort();
        assert!(
            Authorization::begin(
                "http://issuer.example/auth",
                "https://issuer.example/token",
                "client",
                "http://127.0.0.1:7392/callback",
                "https://resource.example/mcp",
                &[],
                Limits::default()
            )
            .await
            .is_err()
        );
        Ok(())
    }
}
