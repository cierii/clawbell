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
/// Non-string scalars cannot hold a marker without changing JSON semantics.
/// Inspect their wire representation (and credential field context), then deny
/// any transformation rather than silently converting the value to a string.
fn inspect_scalar(
    value: &Value,
    key: Option<&str>,
    f: &mut impl FnMut(&str) -> Result<String, Error>,
) -> Result<(), Error> {
    let literal = value.to_string();
    let text = key.map_or_else(|| literal.clone(), |key| format!("{key}={literal}"));
    if f(&text)? != text {
        return Err(Error::Denied);
    }
    Ok(())
}

/// Only formats with a complete UTF-8 inspector may cross the DLP boundary.
/// No Base64 decoder or binary inspector is installed: even a blob claiming a
/// text MIME type must refuse. Unknown fields/types refuse to prevent ambiguous
/// text+binary blocks from being interpreted differently by downstream clients.
fn text_resource(value: &Value) -> Result<(), Error> {
    let map = value.as_object().ok_or(Error::Denied)?;
    if !map.get("uri").is_some_and(Value::is_string)
        || !map.get("text").is_some_and(Value::is_string)
        || map
            .keys()
            .any(|key| !["uri", "text", "mimeType", "_meta"].contains(&key.as_str()))
        || map
            .get("mimeType")
            .is_some_and(|mime| !matches!(mime.as_str(), Some("text/plain" | "text/markdown")))
    {
        return Err(Error::Denied);
    }
    Ok(())
}
fn text_block(value: &Value) -> Result<(), Error> {
    let map = value.as_object().ok_or(Error::Denied)?;
    match map.get("type").and_then(Value::as_str) {
        Some("text")
            if map.get("text").is_some_and(Value::is_string)
                && map.keys().all(|key| {
                    ["type", "text", "annotations", "_meta"].contains(&key.as_str())
                }) =>
        {
            Ok(())
        }
        Some("resource")
            if map.keys().all(|key| {
                ["type", "resource", "annotations", "_meta"].contains(&key.as_str())
            }) =>
        {
            text_resource(map.get("resource").ok_or(Error::Denied)?)
        }
        _ => Err(Error::Denied),
    }
}
fn inspect_result_formats(value: &Value) -> Result<(), Error> {
    let Some(result) = value.get("result") else {
        return Ok(());
    };
    if let Some(content) = result.get("content") {
        for block in content.as_array().ok_or(Error::Denied)? {
            text_block(block)?;
        }
    }
    if let Some(contents) = result.get("contents") {
        for resource in contents.as_array().ok_or(Error::Denied)? {
            text_resource(resource)?;
        }
    }
    if let Some(messages) = result.get("messages") {
        for message in messages.as_array().ok_or(Error::Denied)? {
            text_block(message.get("content").ok_or(Error::Denied)?)?;
        }
    }
    Ok(())
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
                } else if matches!(item, Value::Number(_) | Value::Bool(_) | Value::Null) {
                    inspect_scalar(item, Some(key), f)?;
                } else {
                    transform(item, f)?;
                }
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => inspect_scalar(value, None, f)?,
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
            inspect_result_formats(message.value())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[derive(Default)]
    struct ObservedGate(usize);
    impl Gate for ObservedGate {
        fn inspect(
            &mut self,
            _: Direction,
            message: &Envelope,
        ) -> impl std::future::Future<Output = Result<Envelope, Error>> + Send {
            self.0 += 1;
            std::future::ready(Ok(message.clone()))
        }
        fn finish(&mut self) -> impl std::future::Future<Output = Result<(), Error>> + Send {
            std::future::ready(Ok(()))
        }
    }
    fn packet(value: &Value, direction: Direction) -> Result<Envelope, Error> {
        Envelope::parse(
            &serde_json::to_vec(value).map_err(|_| Error::Denied)?,
            direction,
            65536,
        )
    }
    #[tokio::test]
    async fn secret_scalars_deny_before_inner_gate_in_both_directions() -> TestResult {
        for literal in [
            json!(123_456_789),
            json!(-987_654_321),
            json!(12345.625),
            json!(true),
            json!(false),
            Value::Null,
        ] {
            for field in [json!({"ordinary":literal}), json!([{"nested":[literal]}])] {
                let mut gate = LocalVaultGate::new(ObservedGate::default(), vec![], 65536)?;
                gate.vault
                    .as_mut()
                    .ok_or(Error::Denied)?
                    .register(&literal.to_string())?;
                for (direction, value) in [
                    (
                        Direction::Server,
                        json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":field}}),
                    ),
                    (
                        Direction::Client,
                        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send","arguments":{"value":field}}}),
                    ),
                ] {
                    assert!(matches!(
                        gate.inspect(direction, &packet(&value, direction)?).await,
                        Err(Error::Denied)
                    ));
                    assert_eq!(gate.inner.0, 0);
                }
            }
        }
        Ok(())
    }
    #[tokio::test]
    async fn credential_scalar_fields_deny_and_public_scalars_preserve_types() -> TestResult {
        for direction in [Direction::Server, Direction::Client] {
            for literal in [json!(123_456_789), json!(true), Value::Null] {
                let mut gate = LocalVaultGate::new(ObservedGate::default(), vec![], 65536)?;
                let value = if direction == Direction::Server {
                    json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"PASSWORD":literal}}})
                } else {
                    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"PASSWORD":literal}}})
                };
                assert!(
                    gate.inspect(direction, &packet(&value, direction)?)
                        .await
                        .is_err()
                );
                assert_eq!(gate.inner.0, 0);
            }
        }
        let mut gate = LocalVaultGate::new(ObservedGate::default(), vec![], 65536)?;
        let value = json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"count":42,"nested":[true,false,null,1.25]}}});
        let result = gate
            .inspect(Direction::Server, &packet(&value, Direction::Server)?)
            .await?;
        assert_eq!(result.value(), &value);
        Ok(())
    }
    #[tokio::test]
    async fn unsupported_content_never_reaches_inner_gate() -> TestResult {
        let blob = "VEVTVF9UT0tFTj0xMjM0NTY3ODk="; // Synthetic TEST_TOKEN only.
        for block in [
            json!({"type":"resource","resource":{"uri":"fixture://blob","blob":blob,"mimeType":"application/octet-stream"}}),
            json!({"type":"resource","resource":{"uri":"fixture://blob","blob":blob,"mimeType":"text/plain"}}),
            json!({"type":"resource","resource":{"uri":"fixture://blob","text":"safe","blob":blob}}),
            json!({"type":"resource","resource":{"uri":"fixture://blob","text":"safe","mimeType":"image/svg+xml"}}),
            json!({"type":"image","data":blob,"mimeType":"image/png"}),
            json!({"type":"audio","data":blob,"mimeType":"audio/wav"}),
            json!({"type":"resource_link","uri":"fixture://blob","name":"blob"}),
            json!({"type":"future","data":blob}),
            json!({"type":"text","text":"safe","blob":blob}),
        ] {
            let mut gate = LocalVaultGate::new(ObservedGate::default(), vec![], 65536)?;
            for result in [
                json!({"content":[{"type":"text","text":"safe"},block]}),
                json!({"messages":[{"role":"assistant","content":block}]}),
            ] {
                let value = json!({"jsonrpc":"2.0","id":1,"result":result});
                assert!(
                    gate.inspect(Direction::Server, &packet(&value, Direction::Server)?)
                        .await
                        .is_err()
                );
                assert_eq!(gate.inner.0, 0);
            }
        }
        let mut gate = LocalVaultGate::new(ObservedGate::default(), vec![], 65536)?;
        let value = json!({"jsonrpc":"2.0","id":1,"result":{"contents":[{"uri":"fixture://blob","blob":blob}]}});
        assert!(
            gate.inspect(Direction::Server, &packet(&value, Direction::Server)?)
                .await
                .is_err()
        );
        assert_eq!(gate.inner.0, 0);
        Ok(())
    }
    #[tokio::test]
    async fn text_resources_are_inspected_before_forwarding() -> TestResult {
        for mime in [None, Some("text/plain"), Some("text/markdown")] {
            let mut resource =
                json!({"uri":"fixture://text","text":"TEST_TOKEN=synthetic-resource-secret"});
            if let Some(mime) = mime {
                resource["mimeType"] = json!(mime);
            }
            for result in [
                json!({"content":[{"type":"resource","resource":resource}]}),
                json!({"contents":[resource]}),
            ] {
                let mut gate = LocalVaultGate::new(ObservedGate::default(), vec![], 65536)?;
                let value = json!({"jsonrpc":"2.0","id":1,"result":result});
                let output = gate
                    .inspect(Direction::Server, &packet(&value, Direction::Server)?)
                    .await?;
                assert!(
                    !String::from_utf8(output.encode()?)?.contains("synthetic-resource-secret")
                );
                assert_eq!(gate.inner.0, 1);
            }
        }
        Ok(())
    }
}
