//! OAuth metadata is untrusted data. Discovery can narrow an explicit owner
//! issuer/resource grant, never introduce another origin or private exception.
use crate::{Error, Limits, network::Endpoint};
use reqwest::{
    Method, Url,
    header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue},
};
use serde_json::{Value, json};

fn https(value: &str) -> Result<Url, Error> {
    let url = Url::parse(value).map_err(|_| Error::Denied)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Denied);
    }
    Ok(url)
}
fn endpoint(metadata: &Value, field: &str, issuer: &Url) -> Result<String, Error> {
    let url = https(
        metadata
            .get(field)
            .and_then(Value::as_str)
            .ok_or(Error::Denied)?,
    )?;
    if url.origin() != issuer.origin() {
        return Err(Error::Denied);
    }
    Ok(url.to_string())
}
async fn json_request(
    url: &str,
    method: Method,
    body: Vec<u8>,
    limits: Limits,
) -> Result<Value, Error> {
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let response = Endpoint::connect(url, None, limits)
        .await?
        .send(method, headers, body, limits)
        .await?;
    if !response.status().is_success()
        || response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v.split(';').next().map(str::trim) != Some("application/json"))
    {
        return Err(Error::Denied);
    }
    let bytes = crate::http::bounded_body(response, limits).await?;
    clawbell_core::json::parse(&bytes).map_err(|_| Error::Denied)
}
/// Validated metadata narrowed to one explicitly owner-trusted issuer origin.
pub struct Discovery {
    /// Exact HTTPS authorization endpoint.
    pub authorization_url: String,
    /// Exact HTTPS token endpoint.
    pub token_url: String,
    registration_url: Option<String>,
}
impl Discovery {
    /// Resolve RFC 9728 protected-resource and RFC 8414 authorization-server
    /// metadata. The owner must supply the issuer; WWW-Authenticate never grants
    /// authority. Off-origin endpoint metadata and missing S256 support refuse.
    /// # Errors
    /// Refuses unsafe addresses, redirects, issuer/resource drift and bad metadata.
    pub async fn discover(resource: &str, issuer: &str, limits: Limits) -> Result<Self, Error> {
        let resource = https(resource)?;
        let issuer = https(issuer)?;
        let mut resource_metadata = resource.clone();
        resource_metadata.set_path(&format!(
            "/.well-known/oauth-protected-resource{}",
            resource.path().trim_end_matches('/')
        ));
        let metadata =
            json_request(resource_metadata.as_str(), Method::GET, Vec::new(), limits).await?;
        validate_resource(&metadata, &resource, &issuer)?;
        let mut issuer_metadata = issuer.clone();
        issuer_metadata.set_path(&format!(
            "/.well-known/oauth-authorization-server{}",
            issuer.path().trim_end_matches('/')
        ));
        let metadata =
            json_request(issuer_metadata.as_str(), Method::GET, Vec::new(), limits).await?;
        Self::from_metadata(&metadata, &issuer)
    }
    fn from_metadata(metadata: &Value, issuer: &Url) -> Result<Self, Error> {
        if metadata.get("issuer").and_then(Value::as_str) != Some(issuer.as_str())
            || !metadata
                .get("code_challenge_methods_supported")
                .and_then(Value::as_array)
                .is_some_and(|v| v.iter().any(|s| s == "S256"))
            || !metadata
                .get("response_types_supported")
                .and_then(Value::as_array)
                .is_some_and(|v| v.iter().any(|s| s == "code"))
        {
            return Err(Error::Denied);
        }
        Ok(Self {
            authorization_url: endpoint(metadata, "authorization_endpoint", issuer)?,
            token_url: endpoint(metadata, "token_endpoint", issuer)?,
            registration_url: metadata
                .get("registration_endpoint")
                .map(|_| endpoint(metadata, "registration_endpoint", issuer))
                .transpose()?,
        })
    }
    /// Explicit dynamic registration of a public loopback client (RFC 7591).
    /// Client secrets and registration-management credentials are never accepted.
    /// The caller must durably audit this effectful action and never replay it.
    /// # Errors
    /// Refuses absent registration, callback drift and confidential-client replies.
    pub async fn register(&self, redirect: &str, limits: Limits) -> Result<String, Error> {
        let callback = Url::parse(redirect).map_err(|_| Error::Denied)?;
        if callback.scheme() != "http"
            || callback.host_str() != Some("127.0.0.1")
            || callback.port().is_none()
            || !callback.username().is_empty()
            || callback.password().is_some()
            || callback.query().is_some()
            || callback.fragment().is_some()
        {
            return Err(Error::Denied);
        }
        let body = serde_json::to_vec(&json!({"client_name":"clawbell", "redirect_uris":[redirect], "token_endpoint_auth_method":"none", "grant_types":["authorization_code","refresh_token"], "response_types":["code"]})).map_err(|_| Error::Denied)?;
        let value = json_request(
            self.registration_url.as_deref().ok_or(Error::Denied)?,
            Method::POST,
            body,
            limits,
        )
        .await?;
        validate_registration(&value, redirect)
    }
}
fn validate_resource(metadata: &Value, resource: &Url, issuer: &Url) -> Result<(), Error> {
    if metadata.get("resource").and_then(Value::as_str) != Some(resource.as_str())
        || !metadata
            .get("authorization_servers")
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values.len() <= 32 && values.iter().any(|v| v.as_str() == Some(issuer.as_str()))
            })
    {
        return Err(Error::Denied);
    }
    Ok(())
}
fn validate_registration(value: &Value, redirect: &str) -> Result<String, Error> {
    if value.get("client_secret").is_some()
        || value.get("registration_access_token").is_some()
        || value
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            != Some("none")
        || value.get("redirect_uris") != Some(&json!([redirect]))
    {
        return Err(Error::Denied);
    }
    value
        .get("client_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(Error::Denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_requires_exact_resource_issuer_and_pkce_metadata() -> Result<(), Error> {
        let resource = https("https://resource.example/mcp")?;
        let issuer = https("https://issuer.example/")?;
        let metadata =
            json!({"resource":resource.as_str(),"authorization_servers":[issuer.as_str()]});
        validate_resource(&metadata, &resource, &issuer)?;
        for (key, value) in [
            ("resource", json!("https://other.example/mcp")),
            ("authorization_servers", json!(["https://other.example/"])),
        ] {
            let mut attack = metadata.clone();
            attack[key] = value;
            assert!(validate_resource(&attack, &resource, &issuer).is_err());
        }
        let metadata = json!({
            "issuer":issuer.as_str(), "code_challenge_methods_supported":["S256"],
            "response_types_supported":["code"], "authorization_endpoint":"https://issuer.example/authorize",
            "token_endpoint":"https://issuer.example/token", "registration_endpoint":"https://issuer.example/register"
        });
        assert_eq!(
            Discovery::from_metadata(&metadata, &issuer)?.token_url,
            "https://issuer.example/token"
        );
        for (key, value) in [
            ("issuer", json!("https://other.example/")),
            ("code_challenge_methods_supported", json!(["plain"])),
            ("response_types_supported", json!(["token"])),
            (
                "registration_endpoint",
                json!("https://other.example/register"),
            ),
        ] {
            let mut attack = metadata.clone();
            attack[key] = value;
            assert!(Discovery::from_metadata(&attack, &issuer).is_err());
        }
        Ok(())
    }
    #[test]
    fn metadata_cannot_expand_owner_authority() -> Result<(), Error> {
        let issuer = https("https://issuer.example/")?;
        for url in [
            "https://other.example/token",
            "http://issuer.example/token",
            "https://user@issuer.example/token",
            "https://issuer.example/token?secret=synthetic",
        ] {
            assert!(endpoint(&json!({"token_endpoint":url}), "token_endpoint", &issuer).is_err());
        }
        let redirect = "http://127.0.0.1:7392/callback";
        let valid = json!({"client_id":"public-client","token_endpoint_auth_method":"none","redirect_uris":[redirect]});
        assert_eq!(validate_registration(&valid, redirect)?, "public-client");
        for (key, value) in [
            ("client_secret", json!("synthetic")),
            ("redirect_uris", json!(["http://127.0.0.1:1/other"])),
            ("token_endpoint_auth_method", json!("client_secret_basic")),
        ] {
            let mut attack = valid.clone();
            attack[key] = value;
            assert!(validate_registration(&attack, redirect).is_err());
        }
        Ok(())
    }
}
