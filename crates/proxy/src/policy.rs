//! Mandatory policy and rug-pull checks layered over the existing audit/DLP gate.
//! Catalog checks run before forwarding metadata; tool calls require a complete
//! catalog and compiled offline schemas. A list change closes the session.
use crate::{Direction, Envelope, Error, Gate, Reason};
use clawbell_audit::baseline::BaselineStore;
use clawbell_core::{
    policy::{Decision, Policy},
    signatures::{catalog_digest, tool_digests},
};
use serde_json::Value;
static SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
use std::{collections::HashMap, sync::Arc};

/// A session-local security decorator. Inner Gate still supplies durable intent /
/// outcome audit and DLP. Construct a fresh instance for every upstream session.
pub struct PolicyGate<G> {
    inner: G,
    policy: Arc<Policy>,
    store: BaselineStore,
    server: String,
    list_id: Option<Value>,
    schemas: HashMap<String, jsonschema::Validator>,
    pinned: bool,
    closed: bool,
    monitor: Option<crate::monitor::Monitor>,
    session: u64,
}
impl<G: Gate> PolicyGate<G> {
    /// Bind owner-configured server identity, immutable policy and private store.
    /// # Errors
    /// Refuses an absent or oversized identity.
    pub fn new(
        inner: G,
        policy: Arc<Policy>,
        store: BaselineStore,
        server: String,
    ) -> Result<Self, Error> {
        if server.is_empty() || server.len() > 512 {
            return Err(Error::Denied);
        }
        Ok(Self {
            inner,
            policy,
            store,
            server,
            list_id: None,
            schemas: HashMap::new(),
            pinned: false,
            closed: false,
            monitor: None,
            session: SESSION.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        })
    }
    /// Attach the owner-private interactive approval channel to this session.
    /// Use a fresh gate for each session; no approval survives a reconnect.
    #[must_use]
    pub fn with_monitor(mut self, monitor: crate::monitor::Monitor) -> Self {
        let _ = monitor.publish(&serde_json::json!({"server": self.server, "active": true, "sandbox": "not attested by policy gate"}));
        self.monitor = Some(monitor);
        self
    }
    fn schema(&self, tool: &str, arguments: &Value) -> Result<(), Error> {
        if self.closed || !self.pinned {
            return Err(Error::Refused(Reason::CatalogDenied));
        }
        if !self
            .schemas
            .get(tool)
            .is_some_and(|v| v.is_valid(arguments))
        {
            return Err(Error::Refused(Reason::SchemaDenied));
        }
        Ok(())
    }
    fn policy_reason(reason: &str) -> Reason {
        match reason {
            "unknown_tool" => Reason::UnknownTool,
            "opaque_effect" => Reason::OpaqueEffect,
            "invalid_arguments" => Reason::InvalidArguments,
            "argument_limit" => Reason::ArgumentLimit,
            "invalid_path" => Reason::InvalidPath,
            "memory_write_denied" => Reason::MemoryWriteDenied,
            "rule_deny" => Reason::RuleDeny,
            "owner_approval_required" => Reason::ApprovalRequired,
            _ => Reason::DefaultDeny,
        }
    }
    fn arguments(&self, tool: &str, arguments: &Value) -> Result<(), Error> {
        self.schema(tool, arguments)?;
        let evaluation = self.policy.evaluate(tool, arguments);
        if evaluation.decision != Decision::Allow {
            return Err(Error::Refused(Self::policy_reason(evaluation.reason)));
        }
        Ok(())
    }
    async fn authorize(&mut self, tool: &str, arguments: &Value) -> Result<(), Error> {
        let decision = self.policy.evaluate(tool, arguments).decision;
        if decision != Decision::RequireApproval {
            return self.arguments(tool, arguments);
        }
        self.schema(tool, arguments)?;
        // The future owns this exact call's rendezvous. It cannot redeem approval
        // for a different argument, policy snapshot, server or catalog.
        self.monitor
            .as_ref()
            .ok_or(Error::Refused(Reason::ApprovalRequired))?
            .approve(serde_json::json!({
                "session": self.session, "server": self.server, "tool": tool, "arguments": arguments,
                "policy": self.policy.version(), "arguments_sha256": clawbell_core::signatures::argument_digest(arguments).map_err(|_| Error::Denied)?, "expires_in_seconds": 25, "scope": self.policy.approval_scope(tool, arguments)
            }))
            .await
    }
    async fn check(&mut self, direction: Direction, message: &Envelope) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Refused(Reason::CatalogDenied));
        }
        if direction == Direction::Server
            && message.method() == Some("notifications/tools/list_changed")
        {
            // No stale window and no silent re-baselining. Reconnect and fetch a
            // full catalog; the persistent pin will reject changed metadata.
            return Err(Error::Refused(Reason::CatalogDenied));
        }
        if direction == Direction::Client {
            match message.method() {
                Some("tools/list") => {
                    if self.list_id.is_some() || message.value().pointer("/params/cursor").is_some()
                    {
                        return Err(Error::Refused(Reason::CatalogDenied));
                    }
                    self.list_id = Some(
                        message
                            .id()
                            .ok_or(Error::Refused(Reason::CatalogDenied))?
                            .clone(),
                    );
                    self.pinned = false;
                }
                Some("tools/call") => {
                    let params = message
                        .value()
                        .get("params")
                        .ok_or(Error::Refused(Reason::CatalogDenied))?;
                    self.authorize(
                        params
                            .get("name")
                            .and_then(Value::as_str)
                            .ok_or(Error::Refused(Reason::CatalogDenied))?,
                        params
                            .get("arguments")
                            .unwrap_or(&Value::Object(serde_json::Map::new())),
                    )
                    .await?;
                }
                _ => {}
            }
        } else if self
            .list_id
            .as_ref()
            .is_some_and(|id| Some(id) == message.id())
        {
            let result = message
                .value()
                .get("result")
                .ok_or(Error::Refused(Reason::CatalogDenied))?;
            if result.get("nextCursor").is_some() {
                return Err(Error::Refused(Reason::CatalogDenied));
            }
            let tools = result
                .get("tools")
                .and_then(Value::as_array)
                .ok_or(Error::Refused(Reason::CatalogDenied))?;
            let digest =
                catalog_digest(tools).map_err(|_| Error::Refused(Reason::CatalogDenied))?;
            let signatures =
                tool_digests(tools).map_err(|_| Error::Refused(Reason::CatalogDenied))?;
            let mut schemas = HashMap::new();
            for tool in tools {
                let name = tool
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(Error::Refused(Reason::CatalogDenied))?;
                let schema = tool
                    .get("inputSchema")
                    .ok_or(Error::Refused(Reason::CatalogDenied))?;
                let compiled = jsonschema::options()
                    .offline()
                    .with_pattern_options(
                        jsonschema::PatternOptions::regex().size_limit(1024 * 1024),
                    )
                    .build(schema)
                    .map_err(|_| Error::Refused(Reason::SchemaDenied))?;
                schemas.insert(name.into(), compiled);
            }
            self.store
                .check(&self.server, digest, signatures)
                .await
                .map_err(|_| Error::Refused(Reason::CatalogDenied))?;
            self.schemas = schemas;
            self.pinned = true;
            self.list_id = None;
        }
        Ok(())
    }
}
impl<G: Gate> Gate for PolicyGate<G> {
    fn permits_remote(&self) -> bool {
        self.inner.permits_remote()
    }
    fn validate_local_arguments(&self, tool: &str, arguments: &Value) -> Result<(), Error> {
        self.arguments(tool, arguments)?;
        self.inner.validate_local_arguments(tool, arguments)
    }
    async fn inspect(
        &mut self,
        direction: Direction,
        message: &Envelope,
    ) -> Result<Envelope, Error> {
        let immutable = message.method() == Some("tools/call")
            || (direction == Direction::Server
                && self
                    .list_id
                    .as_ref()
                    .is_some_and(|id| Some(id) == message.id()));
        let result = self.check(direction, message).await;
        if let Err(error) = result {
            self.closed = true;
            return Err(error);
        }
        let result = self.inner.inspect(direction, message).await;
        if let Err(error) = result {
            self.closed = true;
            return Err(error);
        }
        if immutable
            && result
                .as_ref()
                .is_ok_and(|approved| approved.value() != message.value())
        {
            self.closed = true;
            return Err(Error::Refused(Reason::SchemaDenied));
        }
        if let (Some(monitor), Ok(packet)) = (&self.monitor, &result) {
            let _ = monitor.publish(packet.value());
        }
        result
    }
    async fn terminated(&mut self, reason: Reason) -> Result<(), Error> {
        self.inner.terminated(reason).await
    }
    async fn finish(&mut self) -> Result<(), Error> {
        self.closed = true;
        if let Some(monitor) = &self.monitor {
            let _ = monitor.publish(&serde_json::json!({"server": self.server, "active": false}));
        }
        self.schemas.clear();
        self.inner.finish().await
    }
}
