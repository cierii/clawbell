//! Strict JSON-RPC framing and bidirectional MCP lifecycle/correlation adapter.
use crate::{Error, Limits};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tokio::time::Instant;

/// Message origin; request ID namespaces are isolated by direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Originating MCP client.
    Client,
    /// Target MCP server.
    Server,
}
/// A transport session is never implicitly initialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// No initialization request has been accepted.
    New,
    /// Waiting for the initialize response.
    Initializing,
    /// Waiting for the client initialized notification.
    AwaitingInitialized,
    /// Bidirectional operation is permitted subject to the gate.
    Ready,
    /// Terminal state; no replay or reconnect is attempted.
    Closed,
}
/// Validated wire envelope. Payloads intentionally do not implement `Debug`.
#[derive(Clone)]
pub struct Envelope(Value);
impl Envelope {
    /// Parse one message, enforcing size, depth (serde's recursion bound),
    /// JSON-RPC shape and the official SDK's direction-specific MCP schemas.
    ///
    /// # Errors
    /// Rejects batches, null/fractional IDs, extra envelope fields and unknown MCP methods.
    pub fn parse(bytes: &[u8], direction: Direction, max: usize) -> Result<Self, Error> {
        if bytes.len() > max {
            return Err(Error::Limit);
        }
        let value: Value = clawbell_core::json::parse(bytes).map_err(|_| Error::InvalidMessage)?;
        let obj = value.as_object().ok_or(Error::InvalidMessage)?;
        if obj.get("jsonrpc") != Some(&Value::String("2.0".into())) {
            return Err(Error::InvalidMessage);
        }
        if let Some(id) = obj.get("id")
            && !(id.as_str().is_some_and(|s| s.len() <= 256) || id.as_i64().is_some())
        {
            return Err(Error::InvalidMessage);
        }
        if let Some(method) = obj.get("method") {
            if !method.as_str().is_some_and(|m| {
                known_method(direction, m)
                    && m.starts_with("notifications/") != obj.contains_key("id")
            }) || obj.contains_key("result")
                || obj.contains_key("error")
                || obj
                    .keys()
                    .any(|k| !["jsonrpc", "id", "method", "params"].contains(&k.as_str()))
            {
                return Err(Error::InvalidMessage);
            }
            if obj.get("params").is_some_and(|p| !p.is_object()) {
                return Err(Error::InvalidMessage);
            }
        } else if !obj.contains_key("id")
            || obj.contains_key("result") == obj.contains_key("error")
            || obj
                .keys()
                .any(|k| !["jsonrpc", "id", "result", "error"].contains(&k.as_str()))
        {
            return Err(Error::InvalidMessage);
        }
        // SDK schemas live only here; transport code does not depend on SDK internals.
        match direction {
            Direction::Client => {
                use rmcp::model::{
                    ClientJsonRpcMessage, ClientNotification, ClientRequest, JsonRpcMessage,
                };
                let typed: ClientJsonRpcMessage =
                    serde_json::from_value(value.clone()).map_err(|_| Error::InvalidMessage)?;
                match typed {
                    JsonRpcMessage::Request(r)
                        if matches!(r.request, ClientRequest::CustomRequest(_)) =>
                    {
                        return Err(Error::InvalidMessage);
                    }
                    JsonRpcMessage::Notification(n)
                        if matches!(n.notification, ClientNotification::CustomNotification(_)) =>
                    {
                        return Err(Error::InvalidMessage);
                    }
                    _ => {}
                }
            }
            Direction::Server => {
                use rmcp::model::{
                    JsonRpcMessage, ServerJsonRpcMessage, ServerNotification, ServerRequest,
                };
                let typed: ServerJsonRpcMessage =
                    serde_json::from_value(value.clone()).map_err(|_| Error::InvalidMessage)?;
                match typed {
                    JsonRpcMessage::Request(r)
                        if matches!(r.request, ServerRequest::CustomRequest(_)) =>
                    {
                        return Err(Error::InvalidMessage);
                    }
                    JsonRpcMessage::Notification(n)
                        if matches!(n.notification, ServerNotification::CustomNotification(_)) =>
                    {
                        return Err(Error::InvalidMessage);
                    }
                    _ => {}
                }
            }
        }
        Ok(Self(value))
    }
    /// Read validated contents for policy/schema inspection. Do not log them.
    #[must_use]
    pub fn value(&self) -> &Value {
        &self.0
    }
    /// Encode a single compact message, without the STDIO newline delimiter.
    /// # Errors
    /// Returns `InvalidMessage` on serialization failure.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.0).map_err(|_| Error::InvalidMessage)
    }
    /// Request/response correlation identifier.
    #[must_use]
    pub fn id(&self) -> Option<&Value> {
        self.0.get("id")
    }
    /// Method for requests and notifications.
    #[must_use]
    pub fn method(&self) -> Option<&str> {
        self.0.get("method").and_then(Value::as_str)
    }
    pub(crate) fn kind(&self) -> u8 {
        if self.method().is_some() {
            u8::from(self.id().is_some())
        } else {
            2
        }
    }
}
struct Pending {
    method: String,
    deadline: Instant,
}
/// State belongs to a single client/upstream pair. No global routing tables.
pub struct Session {
    phase: Phase,
    client: HashMap<String, Pending>,
    server: HashMap<String, Pending>,
    client_ids: HashSet<String>,
    server_ids: HashSet<String>,
    limits: Limits,
    version: Option<String>,
}
impl Session {
    /// Create an uninitialized session with validated bounds.
    /// # Errors
    /// Rejects invalid limits.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            phase: Phase::New,
            client: HashMap::new(),
            client_ids: HashSet::new(),
            server_ids: HashSet::new(),
            server: HashMap::new(),
            limits: limits.validate()?,
            version: None,
        })
    }
    /// Current lifecycle phase.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// Negotiated protocol version, available after the initialize response.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    /// Earliest request deadline, including reverse requests.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.client
            .values()
            .chain(self.server.values())
            .map(|p| p.deadline)
            .min()
    }
    /// Mark termination; requests are never replayed.
    pub fn close(&mut self) {
        self.phase = Phase::Closed;
    }
    /// Validate and commit one transition, BEFORE forwarding. A failure terminates
    /// the session; callers must never reuse partially failed sessions.
    /// # Errors
    /// Rejects out-of-order initialization, duplicate/unknown IDs and overload. IDs cannot be reused even after a response;
    /// each direction is limited to 65,536 requests per session.
    pub fn accept(&mut self, direction: Direction, message: &Envelope) -> Result<(), Error> {
        if self.phase == Phase::Closed {
            return Err(Error::Protocol);
        }
        let method = message.method();
        if let Some(method) = method {
            match (self.phase, direction, method) {
                (Phase::New, Direction::Client, "initialize") if message.id().is_some() => {
                    let v = message
                        .value()
                        .pointer("/params/protocolVersion")
                        .and_then(Value::as_str)
                        .ok_or(Error::Protocol)?;
                    if !supported(v) {
                        return Err(Error::Protocol);
                    }
                    self.phase = Phase::Initializing;
                }
                (Phase::AwaitingInitialized, Direction::Client, "notifications/initialized")
                    if message.id().is_none() =>
                {
                    self.phase = Phase::Ready;
                }
                (Phase::Ready, _, "initialize" | "notifications/initialized") => {
                    return Err(Error::Protocol);
                }
                (Phase::Ready, _, _) => {}
                (Phase::Initializing | Phase::AwaitingInitialized, _, "ping")
                    if message.id().is_some() => {}
                _ => return Err(Error::Protocol),
            }
            if let Some(id) = message.id() {
                let key = serde_json::to_string(id).map_err(|_| Error::InvalidMessage)?;
                let pending = if direction == Direction::Client {
                    &mut self.client
                } else {
                    &mut self.server
                };
                if pending.len() >= self.limits.pending {
                    return Err(Error::Limit);
                }
                let seen = if direction == Direction::Client {
                    &mut self.client_ids
                } else {
                    &mut self.server_ids
                };
                if seen.len() >= 65_536 {
                    return Err(Error::Limit);
                }
                if !seen.insert(key.clone()) {
                    return Err(Error::Protocol);
                }
                pending.insert(
                    key,
                    Pending {
                        method: method.into(),
                        deadline: Instant::now() + self.limits.request_timeout,
                    },
                );
            }
        } else {
            let id = message.id().ok_or(Error::Protocol)?;
            let key = serde_json::to_string(id).map_err(|_| Error::InvalidMessage)?;
            let pending = if direction == Direction::Server {
                &mut self.client
            } else {
                &mut self.server
            };
            let request = pending.remove(&key).ok_or(Error::Protocol)?;
            if request.deadline <= Instant::now() {
                return Err(Error::Timeout);
            }
            if request.method == "initialize" {
                if message.value().get("error").is_some() {
                    return Err(Error::Protocol);
                }
                let v = message
                    .value()
                    .pointer("/result/protocolVersion")
                    .and_then(Value::as_str)
                    .ok_or(Error::Protocol)?;
                if !supported(v) {
                    return Err(Error::Protocol);
                }
                // Validate initialization result beyond the generic JSON-RPC response.
                serde_json::from_value::<rmcp::model::InitializeResult>(
                    message.value()["result"].clone(),
                )
                .map_err(|_| Error::Protocol)?;
                self.version = Some(v.into());
                self.phase = Phase::AwaitingInitialized;
            }
        }
        Ok(())
    }
}
fn supported(version: &str) -> bool {
    matches!(
        version,
        "2024-11-05" | "2025-03-26" | "2025-06-18" | "2025-11-25"
    )
}

// SDK custom-method extensions are deliberately not a bypass around policy.
fn known_method(direction: Direction, method: &str) -> bool {
    if matches!(
        method,
        "ping" | "notifications/progress" | "notifications/cancelled"
    ) {
        return true;
    }
    match direction {
        Direction::Client => matches!(
            method,
            "initialize"
                | "notifications/initialized"
                | "notifications/roots/list_changed"
                | "tools/list"
                | "tools/call"
                | "resources/list"
                | "resources/templates/list"
                | "resources/read"
                | "resources/subscribe"
                | "resources/unsubscribe"
                | "prompts/list"
                | "prompts/get"
                | "logging/setLevel"
                | "completion/complete"
        ),
        Direction::Server => matches!(
            method,
            "sampling/createMessage"
                | "roots/list"
                | "elicitation/create"
                | "notifications/tools/list_changed"
                | "notifications/resources/list_changed"
                | "notifications/resources/updated"
                | "notifications/prompts/list_changed"
                | "notifications/message"
        ),
    }
}
