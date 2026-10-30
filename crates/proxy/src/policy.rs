//! Mandatory policy and rug-pull checks layered over the existing audit/DLP gate.
//! Catalog checks run before forwarding metadata; tool calls require a complete
//! catalog and compiled offline schemas. A list change closes the session.
use crate::{Direction, Envelope, Error, Gate};
use clawbell_audit::baseline::BaselineStore;
use clawbell_core::{
    policy::{Decision, Policy},
    signatures::{catalog_digest, tool_digests},
};
use serde_json::Value;
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
        })
    }
    fn arguments(&self, tool: &str, arguments: &Value) -> Result<(), Error> {
        if self.closed
            || !self.pinned
            || !self
                .schemas
                .get(tool)
                .is_some_and(|v| v.is_valid(arguments))
            || self.policy.evaluate(tool, arguments).decision != Decision::Allow
        {
            return Err(Error::Denied);
        }
        Ok(())
    }
    async fn check(&mut self, direction: Direction, message: &Envelope) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Denied);
        }
        if direction == Direction::Server
            && message.method() == Some("notifications/tools/list_changed")
        {
            // No stale window and no silent re-baselining. Reconnect and fetch a
            // full catalog; the persistent pin will reject changed metadata.
            return Err(Error::Denied);
        }
        if direction == Direction::Client {
            match message.method() {
                Some("tools/list") => {
                    if self.list_id.is_some() || message.value().pointer("/params/cursor").is_some()
                    {
                        return Err(Error::Denied);
                    }
                    self.list_id = Some(message.id().ok_or(Error::Denied)?.clone());
                    self.pinned = false;
                }
                Some("tools/call") => {
                    let params = message.value().get("params").ok_or(Error::Denied)?;
                    self.arguments(
                        params
                            .get("name")
                            .and_then(Value::as_str)
                            .ok_or(Error::Denied)?,
                        params
                            .get("arguments")
                            .unwrap_or(&Value::Object(serde_json::Map::new())),
                    )?;
                }
                _ => {}
            }
        } else if self
            .list_id
            .as_ref()
            .is_some_and(|id| Some(id) == message.id())
        {
            let result = message.value().get("result").ok_or(Error::Denied)?;
            if result.get("nextCursor").is_some() {
                return Err(Error::Denied);
            }
            let tools = result
                .get("tools")
                .and_then(Value::as_array)
                .ok_or(Error::Denied)?;
            let digest = catalog_digest(tools).map_err(|_| Error::Denied)?;
            let signatures = tool_digests(tools).map_err(|_| Error::Denied)?;
            let mut schemas = HashMap::new();
            for tool in tools {
                let name = tool
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or(Error::Denied)?;
                let schema = tool.get("inputSchema").ok_or(Error::Denied)?;
                let compiled = jsonschema::options()
                    .offline()
                    .with_pattern_options(
                        jsonschema::PatternOptions::regex().size_limit(1024 * 1024),
                    )
                    .build(schema)
                    .map_err(|_| Error::Denied)?;
                schemas.insert(name.into(), compiled);
            }
            self.store
                .check(&self.server, digest, signatures)
                .await
                .map_err(|_| Error::Denied)?;
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
        if result.is_err() {
            self.closed = true;
            return Err(Error::Denied);
        }
        let result = self.inner.inspect(direction, message).await;
        if result.is_err()
            || (immutable
                && result
                    .as_ref()
                    .is_ok_and(|approved| approved.value() != message.value()))
        {
            self.closed = true;
            return Err(Error::Denied);
        }
        result
    }
    async fn finish(&mut self) -> Result<(), Error> {
        self.closed = true;
        self.schemas.clear();
        self.inner.finish().await
    }
}
