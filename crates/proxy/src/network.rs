//! Owner-configured HTTP egress boundary. Endpoint identity, DNS pins and bearer
//! credentials never enter sandbox configuration or server-controlled requests.
use crate::{Error, Limits};
use reqwest::{
    Client, Method, Response, Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use secrecy::{ExposeSecret, SecretString};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

/// An expiring, exact-endpoint OAuth bearer credential, retained only by the host.
/// No Debug/Serialize implementation can accidentally disclose the value.
pub struct Bearer {
    secret: SecretString,
    expires: Instant,
    audience: Option<String>,
}
impl Bearer {
    /// Accept an owner/OAuth-adapter supplied access token, never MCP arguments.
    /// # Errors
    /// Refuses invalid token syntax or lifetime above 24 hours.
    pub fn new(secret: SecretString, lifetime: Duration) -> Result<Self, Error> {
        let value = secret.expose_secret();
        if value.is_empty()
            || value.len() > 8192
            || lifetime.is_zero()
            || lifetime > Duration::from_hours(24)
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._~+/=".contains(&c))
        {
            return Err(Error::Denied);
        }
        Ok(Self {
            secret,
            expires: Instant::now() + lifetime,
            audience: None,
        })
    }
    pub(crate) fn with_audience(mut self, audience: String) -> Self {
        self.audience = Some(audience);
        self
    }
    pub(crate) fn value(&self) -> &str {
        self.secret.expose_secret()
    }
    fn header(&self) -> Result<HeaderValue, Error> {
        if Instant::now() >= self.expires {
            return Err(Error::Denied);
        }
        let mut value = HeaderValue::from_str(&format!("Bearer {}", self.value()))
            .map_err(|_| Error::Denied)?;
        value.set_sensitive(true);
        Ok(value)
    }
}

/// One exact owner-authorized URL and the only socket addresses it may contact.
/// Creating another endpoint requires another owner grant, including OAuth token
/// endpoints and redirect destinations. No ambient proxies, retries or cookies.
pub struct Endpoint {
    client: Client,
    url: Url,
    addresses: Vec<SocketAddr>,
    bearer: Option<Bearer>,
    oauth: Option<std::sync::Arc<crate::oauth::TokenSession>>,
}
impl Endpoint {
    /// Resolve and pin DNS before any request. TLS retains the URL hostname.
    /// Private access requires one exact IP exception, scoped to this URL/port.
    /// # Errors
    /// Refuses credentials, query/fragment, unsafe IPs, schemes and DNS overflow.
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
            || !matches!(url.scheme(), "http" | "https")
        {
            return Err(Error::Denied);
        }
        let host = url.host_str().ok_or(Error::Denied)?;
        let port = url
            .port_or_known_default()
            .filter(|p| *p != 0)
            .ok_or(Error::Denied)?;
        // URL's host_str includes brackets for IPv6 literals; lookup_host does not.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let addresses: Vec<SocketAddr> = tokio::time::timeout(
            limits.request_timeout,
            tokio::net::lookup_host((host, port)),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Transport)?
        .take(33)
        .collect();
        if addresses.is_empty() || addresses.len() > 32 {
            return Err(Error::Denied);
        }
        for address in &addresses {
            let ip = address.ip();
            if forbidden(ip)
                || (!public(ip) && private_exception != Some(ip))
                || (url.scheme() != "https" && !(ip.is_loopback() && private_exception == Some(ip)))
            {
                return Err(Error::Denied);
            }
        }
        let client = Client::builder()
            .no_proxy()
            .retry(reqwest::retry::never())
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .connect_timeout(limits.request_timeout)
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self {
            client,
            url,
            addresses,
            bearer: None,
            oauth: None,
        })
    }
    /// Bind a credential to this exact HTTPS endpoint, without redirect forwarding.
    /// Register the same value in the session DLP before exposing any responses.
    /// # Errors
    /// Refuses bearer credentials over plaintext, including loopback HTTP.
    pub fn with_bearer(mut self, bearer: Bearer) -> Result<Self, Error> {
        if self.url.scheme() != "https"
            || bearer
                .audience
                .as_ref()
                .is_some_and(|url| url != self.url.as_str())
        {
            return Err(Error::Denied);
        }
        self.bearer = Some(bearer);
        Ok(self)
    }
    /// Attach host-managed OAuth refresh for this exact HTTPS resource.
    /// # Errors
    /// Refuses plaintext; the session validates its bearer audience per request.
    pub fn with_oauth(
        mut self,
        session: std::sync::Arc<crate::oauth::TokenSession>,
    ) -> Result<Self, Error> {
        if self.url.scheme() != "https" || self.bearer.is_some() {
            return Err(Error::Denied);
        }
        self.oauth = Some(session);
        Ok(self)
    }
    /// Execute one already-authorized and inspected request. This is a trusted
    /// adapter API, never a raw sandbox proxy. The caller must durably audit intent
    /// before calling and inspect the complete bounded response before disclosure.
    /// # Errors
    /// Refuses non-MCP verbs, supplied auth/Host/proxy headers, expiry, peer address
    /// mismatch and every redirect. No request is automatically repeated.
    pub async fn send(
        &self,
        method: Method,
        headers: HeaderMap,
        body: Vec<u8>,
        limits: Limits,
    ) -> Result<Response, Error> {
        let bearer = if let Some(session) = &self.oauth {
            let bearer = session.bearer(limits).await?;
            if bearer.audience.as_deref() != Some(self.url.as_str()) {
                return Err(Error::Denied);
            }
            Some(bearer)
        } else {
            None
        };
        let auth = bearer
            .as_ref()
            .or(self.bearer.as_ref())
            .map(Bearer::header)
            .transpose()?;
        self.send_raw(method, headers, body, limits, auth).await
    }
    pub(crate) async fn send_raw(
        &self,
        method: Method,
        headers: HeaderMap,
        body: Vec<u8>,
        limits: Limits,
        auth: Option<HeaderValue>,
    ) -> Result<Response, Error> {
        if !matches!(method, Method::GET | Method::POST | Method::DELETE)
            || body.len() > limits.message_bytes
            || headers.keys().any(|k| {
                matches!(
                    k.as_str(),
                    "authorization" | "host" | "proxy-authorization" | "cookie"
                )
            })
        {
            return Err(Error::Denied);
        }
        let mut request = self
            .client
            .request(method, self.url.clone())
            .headers(headers)
            .body(body);
        if let Some(auth) = auth {
            request = request.header(AUTHORIZATION, auth);
        }
        let response = tokio::time::timeout(limits.request_timeout, request.send())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Transport)?;
        if !response
            .remote_addr()
            .is_some_and(|peer| self.addresses.contains(&peer))
            || response.status().is_redirection()
        {
            return Err(Error::Denied);
        }
        Ok(response)
    }
}
pub(crate) fn forbidden(ip: IpAddr) -> bool {
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
pub(crate) fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_private()
                || v.is_loopback()
                || v.is_documentation()
                || v.octets()[0] == 0
                || v.octets()[0] >= 224
                || (v.octets()[0] == 192 && v.octets()[1] == 0)
                || v.octets()[..3] == [192, 88, 99]
                || (v.octets()[0] == 198 && (18..=19).contains(&v.octets()[1]))
                || (v.octets()[0] == 100 && (64..128).contains(&v.octets()[1])))
        }
        IpAddr::V6(v) => {
            !v.is_loopback()
                && v.segments()[0] & 0xe000 == 0x2000
                && v.segments()[0..2] != [0x2001, 0xdb8]
                && !(v.segments()[0] == 0x2001 && v.segments()[1] < 0x0200)
                && v.segments()[0] != 0x2002
                && !(v.segments()[0] == 0x3fff && v.segments()[1] < 0x1000)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    #[tokio::test]
    async fn egress_rejects_unsafe_destinations_and_plaintext_credentials() -> Result {
        for (url, exception) in [
            ("http://127.0.0.1:7391/mcp", None),
            (
                "https://169.254.169.254/latest",
                Some("169.254.169.254".parse()?),
            ),
            ("https://100.100.100.200/", Some("100.100.100.200".parse()?)),
            ("http://127.0.0.1:0/", Some("127.0.0.1".parse()?)),
            ("https://[::ffff:127.0.0.1]/", None),
            (
                "https://user:synthetic@127.0.0.1/",
                Some("127.0.0.1".parse()?),
            ),
            ("ftp://127.0.0.1/file", Some("127.0.0.1".parse()?)),
        ] {
            assert!(
                Endpoint::connect(url, exception, Limits::default())
                    .await
                    .is_err()
            );
        }
        let endpoint = Endpoint::connect(
            "http://127.0.0.1:7391/mcp",
            Some("127.0.0.1".parse()?),
            Limits::default(),
        )
        .await?;
        assert!(
            endpoint
                .with_bearer(Bearer::new(
                    "synthetic-access-value".into(),
                    Duration::from_secs(30)
                )?)
                .is_err()
        );
        for ip in [
            "2002:7f00:1::",
            "2001::1",
            "3fff::1",
            "192.88.99.1",
            "198.18.0.1",
        ] {
            assert!(!public(ip.parse()?));
        }
        Ok(())
    }
    #[tokio::test]
    async fn expired_bearer_refuses_before_network_and_wrong_audience_refuses() -> Result {
        let mut token = Bearer::new("synthetic-access-value".into(), Duration::from_secs(30))?;
        token.expires = Instant::now();
        assert!(token.header().is_err());
        // Build a pinned endpoint without performing any public DNS lookup.
        let endpoint = Endpoint {
            client: Client::new(),
            url: Url::parse("https://other.example/mcp")?,
            addresses: vec![],
            bearer: None,
            oauth: None,
        };
        assert!(
            endpoint
                .with_bearer(token.with_audience("https://resource.example/mcp".into()))
                .is_err()
        );
        Ok(())
    }
}
