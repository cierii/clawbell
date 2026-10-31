#![deny(missing_docs)]
//! Bounded, policy-gated MCP transport core.
//!
//! No permissive gate or unisolated process launcher is supplied. The composition
//! root must provide durable audit, policy, redaction and isolation adapters.
//! Composition example: security adapters are mandatory caller dependencies.
//!
//! ```no_run
//! use clawbell_proxy::{Gate, Limits, stdio};
//! use clawbell_sandbox::Runner;
//! async fn serve<G: Gate, R: Runner>(gate: &mut G, runner: &mut R)
//!     -> Result<(), clawbell_proxy::Error>
//! {
//!     stdio::run(tokio::io::stdin(), tokio::io::stdout(), gate, runner, Limits::default()).await
//! }
//! ```

#[cfg(unix)]
pub mod broker;
#[cfg(unix)]
mod content;
pub mod dlp;
pub mod http;
#[cfg(unix)]
pub mod monitor;
pub mod network;
pub mod oauth;
mod oauth_discovery;
mod oauth_session;
#[cfg(unix)]
pub mod policy;
pub mod protocol;
#[cfg(target_os = "linux")]
pub mod skill;
pub mod stdio;

use std::{future::Future, time::Duration};

pub use clawbell_audit::operations::Reason;
pub use protocol::{Direction, Envelope, Phase, Session};

/// Transport limits are enforced before inspection and before forwarding.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete JSON message or HTTP/SSE body in bytes.
    pub message_bytes: usize,
    /// Maximum outstanding requests in each direction.
    pub pending: usize,
    /// Maximum buffered messages per queue.
    pub queue: usize,
    /// Deadline for requests and individual I/O operations.
    pub request_timeout: Duration,
    /// Maximum silence between complete messages when no request is pending.
    pub idle_timeout: Duration,
    /// Absolute lifetime, never extended by traffic.
    pub session_lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            message_bytes: 1024 * 1024,
            pending: 32,
            queue: 32,
            request_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            session_lifetime: Duration::from_secs(3600),
        }
    }
}
impl Limits {
    /// Reject zero or unreasonable bounds before allocating queues.
    ///
    /// # Errors
    /// Returns `Limit` for invalid configuration.
    pub fn validate(self) -> Result<Self, Error> {
        if self.message_bytes == 0
            || self.message_bytes > 16 * 1024 * 1024
            || self.pending == 0
            || self.pending > 1024
            || self.queue == 0
            || self.queue > 1024
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(300)
            || self.idle_timeout.is_zero()
            || self.idle_timeout > Duration::from_hours(24)
            || self.session_lifetime.is_zero()
            || self.session_lifetime > Duration::from_hours(24)
        {
            return Err(Error::Limit);
        }
        Ok(self)
    }
}

/// Static reason codes deliberately exclude untrusted payloads and diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Fixed local isolation failure, retained for owner diagnostics.
    #[error("{0}")]
    Host(clawbell_sandbox::LaunchError),
    /// Framing, JSON-RPC or MCP schema violation.
    #[error("invalid_message")]
    InvalidMessage,
    /// Invalid lifecycle transition, response ID, or negotiated version.
    #[error("invalid_protocol_state")]
    Protocol,
    /// Message, queue or concurrent-operation bound exceeded.
    #[error("limit_exceeded")]
    Limit,
    /// Deadline elapsed; remote side effects may have happened.
    #[error("operation_timeout_outcome_unknown")]
    Timeout,
    /// Policy or durable audit refused the operation.
    #[error("inspection_denied")]
    Denied,
    /// A security boundary refused with a fixed, payload-free reason.
    #[error("{0:?}")]
    Refused(Reason),
    /// Transport failed; raw I/O details are intentionally not exposed.
    #[error("transport_failed_outcome_unknown")]
    Transport,
    /// Local cancellation requests teardown of the entire containment group.
    #[error("operation_cancelled_outcome_unknown")]
    Cancelled,
    /// Peer closed its transport.
    #[error("transport_closed")]
    Closed,
}

impl Error {
    /// Fixed audit reason, without formatting any transport or peer data.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        match self {
            Self::Host(_) => Reason::IsolationUnavailable,
            Self::InvalidMessage => Reason::InvalidMessage,
            Self::Protocol => Reason::Protocol,
            Self::Limit => Reason::Limit,
            Self::Timeout => Reason::Timeout,
            Self::Denied => Reason::InspectionDenied,
            Self::Refused(reason) => *reason,
            Self::Transport => Reason::Transport,
            Self::Cancelled => Reason::Cancelled,
            Self::Closed => Reason::Closed,
        }
    }
}

/// Trusted security boundary, one instance per session with an immutable policy
/// snapshot. Implementations MUST inspect both directions, validate pinned tool
/// schemas and server identity, redact complete messages, reject semantic changes
/// to arguments, and durably audit intent BEFORE returning success. Responses
/// must durably record results; interrupted requests must become outcome unknown.
///
/// A returned message may redact content, but cannot change IDs, method or kind.
/// Errors, approval requirements and audit failures MUST return a refusal. Override
/// `terminated` to persist pre-inspection failures; `finish` must close pending work
/// even if terminal auditing fails.
/// No default implementation exists, so missing security adapters fail closed.
pub trait Gate: Send {
    /// Validate resolved local arguments against pinned schemas and destination
    /// policy without logging or auditing plaintext. Default denies restoration.
    /// # Errors
    /// Denies unless the adapter explicitly validates the resolved arguments.
    fn validate_local_arguments(
        &self,
        _tool: &str,
        _arguments: &serde_json::Value,
    ) -> Result<(), Error> {
        Err(Error::Denied)
    }
    /// Whether this adapter may be attached to a remote transport.
    fn permits_remote(&self) -> bool {
        true
    }
    /// Inspect one complete, validated message. Never log its raw contents.
    fn inspect(
        &mut self,
        direction: Direction,
        message: &Envelope,
    ) -> impl Future<Output = Result<Envelope, Error>> + Send;
    /// Audit a terminal transport error, including failures before inspection.
    /// The callback receives only a fixed reason, never an invalid payload.
    /// # Errors
    /// A durable audit failure must remain a failure; no forwarding may resume.
    fn terminated(&mut self, _reason: Reason) -> impl Future<Output = Result<(), Error>> + Send {
        std::future::ready(Ok(()))
    }
    /// Record session termination and outstanding operations as unknown.
    fn finish(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
}

pub(crate) async fn inspect<G: Gate>(
    gate: &mut G,
    direction: Direction,
    message: &Envelope,
    limits: Limits,
) -> Result<Envelope, Error> {
    let inspected = tokio::time::timeout(limits.request_timeout, gate.inspect(direction, message))
        .await
        .map_err(|_| Error::Timeout)??;
    let checked = Envelope::parse(&inspected.encode()?, direction, limits.message_bytes)?;
    if checked.id() != message.id()
        || checked.method() != message.method()
        || checked.kind() != message.kind()
    {
        return Err(Error::Denied);
    }
    Ok(checked)
}
