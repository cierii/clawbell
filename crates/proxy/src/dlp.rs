//! DLP decorator for a single local upstream session. The inner gate remains
//! responsible for policy snapshots, pinned schemas, authorization and audit.
use crate::{Direction, Envelope, Error, Gate, Reason};
use clawbell_core::dlp::Vault;
use serde_json::Value;

/// Per-session DLP. Owner-supplied tool names authorize token resolution only
/// inside tools/call arguments. Never reuse across upstreams or sessions.
pub struct LocalVaultGate<G> {
    inner: G,
    vault: Option<Vault>,
    tools: Vec<String>,
    limit: usize,
    remote: bool,
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
            vault: Some(Vault::new(limit).map_err(|_| Error::Refused(Reason::DlpDenied))?),
            tools,
            limit,
            remote: false,
        })
    }
    /// Build a remote DLP boundary with no secret-restoration capability. Register
    /// an adapter-held OAuth credential before inspecting any upstream output.
    /// # Errors
    /// Refuses entropy/registration failures or an inner local-only gate.
    pub fn for_remote(
        inner: G,
        bearer: Option<&crate::network::Bearer>,
        limit: usize,
    ) -> Result<Self, Error> {
        if !inner.permits_remote() {
            return Err(Error::Denied);
        }
        let mut result = Self::new(inner, Vec::new(), limit)?;
        if let Some(bearer) = bearer {
            result
                .vault
                .as_mut()
                .ok_or(Error::Denied)?
                .register(bearer.value())
                .map_err(|_| Error::Refused(Reason::DlpDenied))?;
        }
        result.remote = true;
        Ok(result)
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
        return Err(Error::Refused(Reason::DlpDenied));
    }
    Ok(())
}

/// Only formats with a complete UTF-8 inspector may cross the DLP boundary.
/// No Base64 decoder or binary inspector is installed: even a blob claiming a
/// text MIME type must refuse. Unknown fields/types refuse to prevent ambiguous
/// text+binary blocks from being interpreted differently by downstream clients.
fn text_resource(value: &Value) -> Result<(), Error> {
    let map = value.as_object().ok_or(Error::Refused(Reason::DlpDenied))?;
    if !map.get("uri").is_some_and(Value::is_string)
        || !map.get("text").is_some_and(Value::is_string)
        || map
            .keys()
            .any(|key| !["uri", "text", "mimeType", "_meta"].contains(&key.as_str()))
        || map
            .get("mimeType")
            .is_some_and(|mime| !matches!(mime.as_str(), Some("text/plain" | "text/markdown")))
    {
        return Err(Error::Refused(Reason::DlpDenied));
    }
    Ok(())
}
fn text_block(value: &Value) -> Result<(), Error> {
    let map = value.as_object().ok_or(Error::Refused(Reason::DlpDenied))?;
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
            text_resource(
                map.get("resource")
                    .ok_or(Error::Refused(Reason::DlpDenied))?,
            )
        }
        _ => Err(Error::Refused(Reason::DlpDenied)),
    }
}
fn inspect_result_formats(value: &Value) -> Result<(), Error> {
    let Some(result) = value.get("result") else {
        return Ok(());
    };
    if let Some(content) = result.get("content") {
        for block in content
            .as_array()
            .ok_or(Error::Refused(Reason::DlpDenied))?
        {
            text_block(block)?;
        }
    }
    if let Some(contents) = result.get("contents") {
        for resource in contents
            .as_array()
            .ok_or(Error::Refused(Reason::DlpDenied))?
        {
            text_resource(resource)?;
        }
    }
    if let Some(messages) = result.get("messages") {
        for message in messages
            .as_array()
            .ok_or(Error::Refused(Reason::DlpDenied))?
        {
            text_block(
                message
                    .get("content")
                    .ok_or(Error::Refused(Reason::DlpDenied))?,
            )?;
        }
    }
    Ok(())
}

/// Content blocks are ordered display fragments. Resource-read entries remain
/// separate documents; prompt messages are separate role-bearing units. We never
/// concatenate arbitrary JSON properties, schemas, arguments or metadata.
fn inspect_text_units(vault: &mut Vault, value: &Value) -> Result<(), Error> {
    let inspect = |vault: &mut Vault, blocks: &[Value]| {
        let fragments: Vec<&str> = blocks
            .iter()
            .filter_map(|block| {
                block
                    .get("text")
                    .or_else(|| block.pointer("/resource/text"))
                    .and_then(Value::as_str)
            })
            .collect();
        vault
            .inspect_fragments(&fragments)
            .map_err(|_| Error::Refused(Reason::DlpDenied))
    };
    if let Some(blocks) = value.pointer("/result/content").and_then(Value::as_array) {
        inspect(vault, blocks)?;
    }
    if let Some(resources) = value.pointer("/result/contents").and_then(Value::as_array) {
        for resource in resources {
            inspect(vault, std::slice::from_ref(resource))?;
        }
    }
    if let Some(messages) = value.pointer("/result/messages").and_then(Value::as_array) {
        for message in messages {
            if let Some(content) = message.get("content") {
                inspect(vault, std::slice::from_ref(content))?;
            }
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
                    return Err(Error::Refused(Reason::DlpDenied));
                }
                if let Value::String(text) = item {
                    let prefix = format!("{key}=");
                    let inspected = f(&format!("{prefix}{text}"))?;
                    inspected
                        .strip_prefix(&prefix)
                        .ok_or(Error::Refused(Reason::DlpDenied))?
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
/// Inspect a complete private server response before any associated effects are
/// published. Shares the production DLP rules and caller's session vault; it does
/// not authorize execution, write audit or disclose the returned packet.
/// # Errors
/// Refuses unsupported formats, fragmented/scalar secrets and secret catalogs.
pub fn inspect_server_message(
    vault: &mut Vault,
    message: &Envelope,
    limit: usize,
) -> Result<Envelope, Error> {
    inspect_result_formats(message.value())?;
    let mut value = message.value().clone();
    transform(&mut value, &mut |s| {
        vault
            .redact(s)
            .map_err(|_| Error::Refused(Reason::DlpDenied))
    })?;
    // Discover all individual credentials first, then inspect semantic
    // text units against the complete vault before releasing any output.
    inspect_text_units(vault, message.value())?;
    // A later field/unit may register a value seen earlier. Redact from
    // the original only after discovery, so JSON field order cannot leak.
    value = message.value().clone();
    transform(&mut value, &mut |s| {
        vault
            .redact(s)
            .map_err(|_| Error::Refused(Reason::DlpDenied))
    })?;
    // Session-random markers cannot participate in a persistent pin.
    // Refuse secret-bearing catalogs before the first baseline write.
    if ["tools", "resources", "resourceTemplates", "prompts"]
        .iter()
        .any(|key| message.value().pointer(&format!("/result/{key}")).is_some())
        && value != *message.value()
    {
        return Err(Error::Refused(Reason::CatalogDenied));
    }
    let redacted = Envelope::parse(
        &serde_json::to_vec(&value).map_err(|_| Error::Refused(Reason::DlpDenied))?,
        Direction::Server,
        limit,
    )?;
    if redacted.id() != message.id() || redacted.method() != message.method() {
        return Err(Error::Refused(Reason::DlpDenied));
    }
    Ok(redacted)
}

impl<G: Gate> Gate for LocalVaultGate<G> {
    fn permits_remote(&self) -> bool {
        self.remote && self.inner.permits_remote()
    }
    async fn inspect(
        &mut self,
        direction: Direction,
        message: &Envelope,
    ) -> Result<Envelope, Error> {
        let vault = self
            .vault
            .as_mut()
            .ok_or(Error::Refused(Reason::DlpDenied))?;
        if direction == Direction::Server {
            let redacted = inspect_server_message(vault, message, self.limit)?;
            return self.inner.inspect(direction, &redacted).await;
        }
        let mut checked = message.value().clone();
        transform(&mut checked, &mut |s| {
            vault
                .check_request(s)
                .map_err(|_| Error::Refused(Reason::DlpDenied))?;
            Ok(s.to_owned())
        })?;
        let approved = self.inner.inspect(direction, message).await?;
        let mut value = approved.value().clone();
        let has_tokens = approved.encode()?.windows(10).any(|w| w == b"[clawbell:");
        if has_tokens {
            let tool = value
                .pointer("/params/name")
                .and_then(Value::as_str)
                .ok_or(Error::Refused(Reason::DlpDenied))?
                .to_owned();
            if approved.method() != Some("tools/call")
                || !self.tools.iter().any(|name| name == &tool)
            {
                return Err(Error::Refused(Reason::DlpDenied));
            }
            let args = value
                .pointer_mut("/params/arguments")
                .ok_or(Error::Refused(Reason::DlpDenied))?;
            transform(args, &mut |s| {
                vault
                    .restore(s)
                    .map(|v| v.to_string())
                    .map_err(|_| Error::Refused(Reason::DlpDenied))
            })?;
            self.inner.validate_local_arguments(&tool, args)?;
        } else {
            // Raw secrets in client requests must not leave this boundary.
            let mut checked = value.clone();
            transform(&mut checked, &mut |s| {
                vault
                    .redact(s)
                    .map_err(|_| Error::Refused(Reason::DlpDenied))
            })?;
            if checked != value {
                return Err(Error::Refused(Reason::DlpDenied));
            }
        }
        if serde_json::to_vec(&value)
            .map_err(|_| Error::Refused(Reason::DlpDenied))?
            .windows(10)
            .any(|w| w == b"[clawbell:")
        {
            return Err(Error::Refused(Reason::DlpDenied));
        }
        Envelope::parse(
            &serde_json::to_vec(&value).map_err(|_| Error::Refused(Reason::DlpDenied))?,
            direction,
            self.limit,
        )
    }
    async fn terminated(&mut self, reason: Reason) -> Result<(), Error> {
        self.inner.terminated(reason).await
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
            &serde_json::to_vec(value).map_err(|_| Error::Refused(Reason::DlpDenied))?,
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
                    .ok_or(Error::Refused(Reason::DlpDenied))?
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
                        Err(Error::Refused(Reason::DlpDenied))
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
    async fn semantic_units_deny_split_secrets_before_inner_gate_without_joining_json_fields()
    -> TestResult {
        for content in [
            json!([{"type":"text","text":"1234"},{"type":"text","text":"56789"}]),
            json!([{"type":"text","text":"1234"},{"type":"resource","resource":{"uri":"fixture://text","text":"56789"}}]),
            json!([{"type":"text","text":"1234"}]),
        ] {
            let mut gate = LocalVaultGate::new(ObservedGate::default(), vec![], 65536)?;
            gate.vault
                .as_mut()
                .ok_or(Error::Denied)?
                .register("123456789")?;
            let value = json!({"jsonrpc":"2.0","id":1,"result":{"content":content}});
            assert!(
                gate.inspect(Direction::Server, &packet(&value, Direction::Server)?)
                    .await
                    .is_err()
            );
            assert_eq!(gate.inner.0, 0);
        }
        let mut gate = LocalVaultGate::new(ObservedGate::default(), vec![], 65536)?;
        gate.vault
            .as_mut()
            .ok_or(Error::Denied)?
            .register("123456789")?;
        let value = json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"separate-a":"1234","separate-b":"56789"}}});
        assert_eq!(
            gate.inspect(Direction::Server, &packet(&value, Direction::Server)?)
                .await?
                .value(),
            &value
        );
        Ok(())
    }
    #[tokio::test]
    async fn discovery_precedes_redaction_regardless_of_field_order() -> TestResult {
        let mut gate = LocalVaultGate::new(ObservedGate::default(), vec![], 65536)?;
        let value = json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"123456789"}],"structuredContent":{"TEST_TOKEN":"123456789"}}});
        let output = gate
            .inspect(Direction::Server, &packet(&value, Direction::Server)?)
            .await?;
        assert!(!String::from_utf8(output.encode()?)?.contains("123456789"));
        assert_eq!(gate.inner.0, 1);
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
