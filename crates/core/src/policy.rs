//! Fail-closed, precompiled owner policy. Tool effects are trusted configuration,
//! never inferred from server annotations. This module performs no filesystem I/O.
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

/// Maximum serialized arguments and policy source size.
pub const MAX_BYTES: usize = 1024 * 1024;
/// Authorization outcome; approvals are requests, never execution permission.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Explicit permission, subject to independent security controls.
    Allow,
    /// Terminal refusal.
    Deny,
    /// Ask the owner; execution remains blocked until separately authorized.
    RequireApproval,
}
/// Stable, payload-free policy outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// Authorization outcome.
    pub decision: Decision,
    /// Machine-readable reason, never interpolated from arguments.
    pub reason: &'static str,
}
impl Evaluation {
    fn deny(reason: &'static str) -> Self {
        Self {
            decision: Decision::Deny,
            reason,
        }
    }
}
/// Invalid owner policy; diagnostics deliberately omit its contents.
#[derive(Debug, thiserror::Error)]
#[error("invalid_policy")]
pub struct PolicyError;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    version: String,
    tools: Vec<Tool>,
    rules: Vec<Rule>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tool {
    name: String,
    effect: Effect,
    #[serde(default)]
    paths: Vec<String>,
}
#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Effect {
    Read,
    Write,
    Opaque,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    tool: String,
    decision: Decision,
    path_prefix: Option<String>,
    arguments_regex: Option<String>,
}
struct CompiledRule {
    rule: Rule,
    regex: Option<Regex>,
}
/// Immutable snapshot. Compile once outside the packet path; replace atomically
/// only after successful parsing. Existing sessions keep their old snapshot.
pub struct Policy {
    version: String,
    fingerprint: [u8; 32],
    tools: Vec<Tool>,
    rules: Vec<CompiledRule>,
}
/// Normalize an owner-relative POSIX path without resolving untrusted symlinks.
/// Absolute paths, parent traversal and platform-dependent separators are refused.
#[must_use]
pub fn normalized_path(value: &str) -> Option<String> {
    if value.is_empty() || value.contains(['\\', '\0', ':']) || value.len() > 4096 {
        return None;
    }
    let mut parts = Vec::new();
    for part in Path::new(value).components() {
        match part {
            Component::Normal(v) => parts.push(v.to_str()?),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}
/// Reserved agent memory names and skill directory components, case-insensitive.
/// Applied to every path component, including non-existing files and directories.
#[must_use]
pub fn protected_path(path: &str) -> bool {
    path.split('/').any(|part| {
        matches!(
            part.to_ascii_lowercase().as_str(),
            "soul.md"
                | "claude.md"
                | "agents.md"
                | ".cursorrules"
                | "skills"
                | ".skills"
                | "skillks"
        )
    })
}
impl Policy {
    /// Owner-configured effect and affected paths for the approval display.
    /// This describes declared effects; it cannot attest to remote server code.
    #[must_use]
    pub fn approval_scope(&self, name: &str, arguments: &Value) -> Value {
        self.tools.iter().find(|tool| tool.name == name).map_or(Value::Null, |tool| {
            serde_json::json!({
                "effect": match tool.effect { Effect::Read => "read", Effect::Write => "write", Effect::Opaque => "opaque" },
                "paths": tool.paths.iter().filter_map(|pointer| arguments.pointer(pointer)).collect::<Vec<_>>()
            })
        })
    }
    /// Parse strict TOML and compile bounded regexes before installing a snapshot.
    /// # Errors
    /// Rejects unknown fields/effects, duplicate tools, invalid selectors or limits.
    pub fn parse(source: &str) -> Result<Self, PolicyError> {
        if source.len() > MAX_BYTES {
            return Err(PolicyError);
        }
        let config: Config = toml::from_str(source).map_err(|_| PolicyError)?;
        if config.version.is_empty()
            || config.version.len() > 128
            || config.tools.len() > 256
            || config.rules.len() > 256
        {
            return Err(PolicyError);
        }
        let mut names = std::collections::HashSet::new();
        for tool in &config.tools {
            if tool.name.is_empty()
                || tool.name.len() > 256
                || !names.insert(&tool.name)
                || tool.paths.len() > 16
                || tool
                    .paths
                    .iter()
                    .any(|p| !p.starts_with('/') || p.len() > 256)
                || (tool.effect == Effect::Write && tool.paths.is_empty())
            {
                return Err(PolicyError);
            }
        }
        let mut rules = Vec::new();
        for rule in config.rules {
            if rule.tool != "*" && !names.contains(&rule.tool) {
                return Err(PolicyError);
            }
            if let Some(path) = &rule.path_prefix
                && normalized_path(path).as_ref() != Some(path)
            {
                return Err(PolicyError);
            }
            let regex = rule
                .arguments_regex
                .as_ref()
                .map(|r| {
                    if r.len() > 4096 {
                        return Err(PolicyError);
                    }
                    RegexBuilder::new(r)
                        .size_limit(MAX_BYTES)
                        .dfa_size_limit(MAX_BYTES)
                        .build()
                        .map_err(|_| PolicyError)
                })
                .transpose()?;
            rules.push(CompiledRule { rule, regex });
        }
        Ok(Self {
            fingerprint: Sha256::digest(source.as_bytes()).into(),
            version: config.version,
            tools: config.tools,
            rules,
        })
    }
    /// Digest of the exact immutable owner configuration, including same-version edits.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    /// Policy revision used to bind audit records and approval requests.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
    /// Evaluate a bounded tools/call. Deny overrides approval, which overrides
    /// allow. Opaque operations (shells, rename/delete trees, unknown semantics)
    /// cannot be made safe by argument regexes and are always refused.
    #[must_use]
    pub fn evaluate(&self, name: &str, arguments: &Value) -> Evaluation {
        let Some(tool) = self.tools.iter().find(|t| t.name == name) else {
            return Evaluation::deny("unknown_tool");
        };
        if tool.effect == Effect::Opaque {
            return Evaluation::deny("opaque_effect");
        }
        let Ok(encoded) = serde_json::to_string(arguments) else {
            return Evaluation::deny("invalid_arguments");
        };
        if encoded.len() > MAX_BYTES || !arguments.is_object() {
            return Evaluation::deny("argument_limit");
        }
        let mut paths = Vec::new();
        for pointer in &tool.paths {
            let Some(path) = arguments
                .pointer(pointer)
                .and_then(Value::as_str)
                .and_then(normalized_path)
            else {
                return Evaluation::deny("invalid_path");
            };
            if tool.effect == Effect::Write && protected_path(&path) {
                return Evaluation::deny("memory_write_denied");
            }
            paths.push(path);
        }
        let mut result = Evaluation::deny("default_deny");
        for compiled in &self.rules {
            let rule = &compiled.rule;
            if rule.tool != "*" && rule.tool != name {
                continue;
            }
            if rule.path_prefix.as_ref().is_some_and(|prefix| {
                paths.is_empty()
                    || !paths.iter().all(|p| {
                        p == prefix || p.strip_prefix(prefix).is_some_and(|s| s.starts_with('/'))
                    })
            }) {
                continue;
            }
            if compiled
                .regex
                .as_ref()
                .is_some_and(|r| !r.is_match(&encoded))
            {
                continue;
            }
            match rule.decision {
                Decision::Deny => return Evaluation::deny("rule_deny"),
                Decision::RequireApproval => {
                    result = Evaluation {
                        decision: Decision::RequireApproval,
                        reason: "owner_approval_required",
                    }
                }
                Decision::Allow if result.decision != Decision::RequireApproval => {
                    result = Evaluation {
                        decision: Decision::Allow,
                        reason: "rule_allow",
                    }
                }
                Decision::Allow => {}
            }
        }
        result
    }
}
