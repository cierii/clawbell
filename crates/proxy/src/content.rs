//! Resource/prompt authorization and pinned metadata. This boundary never treats
//! a listed URI, template, prompt instruction or annotation as a permission.
use crate::{Direction, Envelope, Error, Reason};
use clawbell_audit::baseline::BaselineStore;
use clawbell_core::{
    policy::{Decision, Policy},
    signatures::{catalog_digest, tool_digests},
};
use serde_json::{Value, json};
use std::collections::HashMap;

#[derive(Default)]
pub(crate) struct ContentPolicy {
    pending: HashMap<String, (String, Option<String>)>,
    prompts: HashMap<String, Vec<(String, bool)>>,
}
impl ContentPolicy {
    // True means this validated immutable request still needs owner consent.
    // The caller must not invoke its execution/audit-intent adapter before consent.
    pub(crate) async fn check(
        &mut self,
        policy: &Policy,
        store: &BaselineStore,
        server: &str,
        direction: Direction,
        message: &Envelope,
    ) -> Result<bool, Error> {
        if direction == Direction::Client {
            let Some(method) = message
                .method()
                .filter(|m| m.starts_with("resources/") || m.starts_with("prompts/"))
            else {
                return Ok(false);
            };
            return self.request(policy, message, method);
        } else if message.method().is_some_and(|m| {
            m.starts_with("notifications/resources/") || m.starts_with("notifications/prompts/")
        }) {
            return Err(Error::Refused(Reason::CatalogDenied));
        } else if message.method().is_none() {
            let id = message.id().ok_or(Error::Protocol)?.to_string();
            let Some((method, target)) = self.pending.remove(&id) else {
                return Ok(false);
            };
            if message.value().get("error").is_some() {
                return Ok(false);
            }
            let result = message.value().get("result").ok_or(Error::Protocol)?;
            let (field, key) = match method.as_str() {
                "resources/list" => ("resources", "uri"),
                "resources/templates/list" => ("resourceTemplates", "uriTemplate"),
                "prompts/list" => ("prompts", "name"),
                "resources/read" => {
                    let typed =
                        serde_json::from_value::<rmcp::model::ReadResourceResult>(result.clone())
                            .map_err(|_| Error::Protocol)?;
                    if typed.contents.is_empty()
                        || result
                            .get("contents")
                            .and_then(Value::as_array)
                            .ok_or(Error::Protocol)?
                            .iter()
                            .any(|v| v.get("uri").and_then(Value::as_str) != target.as_deref())
                    {
                        return Err(Error::Protocol);
                    }
                    return Ok(false);
                }
                "prompts/get" => {
                    serde_json::from_value::<rmcp::model::GetPromptResult>(result.clone())
                        .map_err(|_| Error::Protocol)?;
                    return Ok(false);
                }
                _ => return Err(Error::Denied),
            };
            validate_list(&method, result)?;
            if result.get("nextCursor").is_some() {
                return Err(Error::Refused(Reason::CatalogDenied));
            }
            let entries = result
                .get(field)
                .and_then(Value::as_array)
                .ok_or(Error::Protocol)?;
            if entries.len() > 4096 {
                return Err(Error::Limit);
            }
            let mut pins = Vec::new();
            let mut prompts = HashMap::new();
            for entry in entries {
                let name = entry
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty() && s.len() <= 4096)
                    .ok_or(Error::Protocol)?;
                // Keep complete untrusted metadata under an opaque signed field.
                // URI keys can exceed the tool-name bound; hash them canonically.
                let name_digest = clawbell_core::signatures::argument_digest(&json!({"key":name}))
                    .map_err(|_| Error::Protocol)?;
                pins.push(json!({"name":name_digest,"inputSchema":{},"metadata":entry}));
                if method == "prompts/list" {
                    let arguments = prompt_arguments(entry)?;
                    prompts.insert(name.to_owned(), arguments);
                }
            }
            store
                .check(
                    &clawbell_core::signatures::scoped_catalog_identity(server, &method, 0)
                        .map_err(|_| Error::Denied)?,
                    catalog_digest(&pins).map_err(|_| Error::Protocol)?,
                    tool_digests(&pins).map_err(|_| Error::Protocol)?,
                )
                .await
                .map_err(|_| Error::Refused(Reason::CatalogDenied))?;
            if method == "prompts/list" {
                self.prompts = prompts;
            }
        }
        Ok(false)
    }
    fn request(
        &mut self,
        policy: &Policy,
        message: &Envelope,
        method: &str,
    ) -> Result<bool, Error> {
        let target = match method {
            "resources/read" => Some(
                message
                    .value()
                    .pointer("/params/uri")
                    .and_then(Value::as_str)
                    .ok_or(Error::Denied)?,
            ),
            "prompts/get" => Some(
                message
                    .value()
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .ok_or(Error::Denied)?,
            ),
            _ => None,
        };
        let decision = policy.evaluate_protocol(method, target).decision;
        if decision == Decision::Deny {
            return Err(Error::Refused(Reason::MethodDenied));
        }
        if message.value().pointer("/params/cursor").is_some() {
            // No silent truncation or cursor forwarding without a pin contract.
            return Err(Error::Refused(Reason::CatalogDenied));
        }
        if method == "prompts/get" {
            let definition = self
                .prompts
                .get(target.ok_or(Error::Denied)?)
                .ok_or(Error::Refused(Reason::CatalogDenied))?;
            let empty = serde_json::Map::new();
            let args = message
                .value()
                .pointer("/params/arguments")
                .map(|v| v.as_object().ok_or(Error::Denied))
                .transpose()?
                .unwrap_or(&empty);
            if args
                .iter()
                .any(|(k, v)| !v.is_string() || !definition.iter().any(|(name, _)| name == k))
                || definition
                    .iter()
                    .any(|(name, required)| *required && !args.contains_key(name))
            {
                return Err(Error::Refused(Reason::SchemaDenied));
            }
        }
        if self.pending.len() >= 32 {
            return Err(Error::Limit);
        }
        let id = message.id().ok_or(Error::Protocol)?.to_string();
        if self
            .pending
            .insert(id, (method.to_owned(), target.map(str::to_owned)))
            .is_some()
        {
            return Err(Error::Protocol);
        }
        Ok(decision == Decision::RequireApproval)
    }
}

fn prompt_arguments(entry: &Value) -> Result<Vec<(String, bool)>, Error> {
    let mut arguments = Vec::new();
    if let Some(args) = entry.get("arguments") {
        for arg in args.as_array().ok_or(Error::Protocol)? {
            let name = arg
                .get("name")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= 256)
                .ok_or(Error::Protocol)?;
            let required = arg
                .get("required")
                .map(|v| v.as_bool().ok_or(Error::Protocol))
                .transpose()?
                .unwrap_or(false);
            if arguments.iter().any(|(existing, _)| existing == name) {
                return Err(Error::Protocol);
            }
            arguments.push((name.to_owned(), required));
            if arguments.len() > 256 {
                return Err(Error::Limit);
            }
        }
    }
    Ok(arguments)
}

fn validate_list(method: &str, result: &Value) -> Result<(), Error> {
    match method {
        "resources/list" => {
            serde_json::from_value::<rmcp::model::ListResourcesResult>(result.clone())
                .map_err(|_| Error::Protocol)?;
        }
        "resources/templates/list" => {
            serde_json::from_value::<rmcp::model::ListResourceTemplatesResult>(result.clone())
                .map_err(|_| Error::Protocol)?;
        }
        "prompts/list" => {
            serde_json::from_value::<rmcp::model::ListPromptsResult>(result.clone())
                .map_err(|_| Error::Protocol)?;
        }
        _ => return Err(Error::Denied),
    }
    Ok(())
}
