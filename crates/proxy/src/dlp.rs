//! DLP decorator for a single local upstream session. The inner gate remains
//! responsible for policy snapshots, pinned schemas, authorization and audit.
use crate::{Direction, Envelope, Error, Gate};
use clawbell_core::dlp::Vault;
use serde_json::Value;

/// Per-session DLP. Owner-supplied tool names authorize token resolution only
/// inside tools/call arguments. Never reuse across upstreams or sessions.
pub struct LocalVaultGate<G> {
    inner: G,
    vault: Option<Vault>,
    tools: Vec<String>,
    limit: usize,
}
impl<G: Gate> LocalVaultGate<G> {
    /// Construct for one local upstream, with an explicit restoration allowlist.
    /// The inner gate must validate schemas against resolved argument semantics
    /// using owner configuration; audit only the tokenized representation.
    /// # Errors
    /// Denies invalid vault configuration or unavailable entropy.
    pub fn new(inner: G, tools: Vec<String>, limit: usize) -> Result<Self, Error> {
        Ok(Self {
            inner,
            vault: Some(Vault::new(limit).map_err(|_| Error::Denied)?),
            tools,
            limit,
        })
    }
}
fn transform(
    value: &mut Value,
    f: &mut impl FnMut(&str) -> Result<String, Error>,
) -> Result<(), Error> {
    match value {
        Value::String(s) => *s = f(s)?,
        Value::Array(items) => {
            for item in items {
                transform(item, f)?;
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                // Changing property names may change schemas or collide: refuse.
                if f(key)? != *key {
                    return Err(Error::Denied);
                }
                if let Value::String(text) = item {
                    let prefix = format!("{key}=");
                    let inspected = f(&format!("{prefix}{text}"))?;
                    inspected
                        .strip_prefix(&prefix)
                        .ok_or(Error::Denied)?
                        .clone_into(text);
                } else {
                    transform(item, f)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
impl<G: Gate> Gate for LocalVaultGate<G> {
    fn permits_remote(&self) -> bool {
        false
    }
    async fn inspect(
        &mut self,
        direction: Direction,
        message: &Envelope,
    ) -> Result<Envelope, Error> {
        let vault = self.vault.as_mut().ok_or(Error::Denied)?;
        if direction == Direction::Server {
            let mut value = message.value().clone();
            transform(&mut value, &mut |s| {
                vault.redact(s).map_err(|_| Error::Denied)
            })?;
            let redacted = Envelope::parse(
                &serde_json::to_vec(&value).map_err(|_| Error::Denied)?,
                direction,
                self.limit,
            )?;
            if redacted.id() != message.id() || redacted.method() != message.method() {
                return Err(Error::Denied);
            }
            return self.inner.inspect(direction, &redacted).await;
        }
        let mut checked = message.value().clone();
        transform(&mut checked, &mut |s| {
            vault.check_request(s).map_err(|_| Error::Denied)?;
            Ok(s.to_owned())
        })?;
        let approved = self.inner.inspect(direction, message).await?;
        let mut value = approved.value().clone();
        let has_tokens = approved.encode()?.windows(10).any(|w| w == b"[clawbell:");
        if has_tokens {
            let tool = value
                .pointer("/params/name")
                .and_then(Value::as_str)
                .ok_or(Error::Denied)?
                .to_owned();
            if approved.method() != Some("tools/call")
                || !self.tools.iter().any(|name| name == &tool)
            {
                return Err(Error::Denied);
            }
            let args = value
                .pointer_mut("/params/arguments")
                .ok_or(Error::Denied)?;
            transform(args, &mut |s| {
                vault
                    .restore(s)
                    .map(|v| v.to_string())
                    .map_err(|_| Error::Denied)
            })?;
            self.inner.validate_local_arguments(&tool, args)?;
        } else {
            // Raw secrets in client requests must not leave this boundary.
            let mut checked = value.clone();
            transform(&mut checked, &mut |s| {
                vault.redact(s).map_err(|_| Error::Denied)
            })?;
            if checked != value {
                return Err(Error::Denied);
            }
        }
        if serde_json::to_vec(&value)
            .map_err(|_| Error::Denied)?
            .windows(10)
            .any(|w| w == b"[clawbell:")
        {
            return Err(Error::Denied);
        }
        Envelope::parse(
            &serde_json::to_vec(&value).map_err(|_| Error::Denied)?,
            direction,
            self.limit,
        )
    }
    async fn finish(&mut self) -> Result<(), Error> {
        self.vault = None;
        self.inner.finish().await
    }
}
