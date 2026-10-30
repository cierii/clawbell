#![deny(missing_docs)]
//! Mandatory isolated process-launch boundary for local MCP servers.
//!
//! A concrete Linux runner must enforce bubblewrap, seccomp and cgroups v2
//! before returning a child. This transport-focused crate supplies no direct
//! `Command::spawn` fallback, so missing host isolation cannot silently downgrade.
use std::future::Future;
use tokio::process::Child;

/// Trusted process supervisor owned by the composition root. Implementations must
/// clear the environment, apply explicit mounts/network/resource policy, drain or
/// discard stderr, and kill/reap the entire process tree on cancellation or drop.
/// The returned child must have piped stdin/stdout and `kill_on_drop(true)`.
///
/// Implementations must not interpret tool or skill text as launch authorization.
pub trait Runner: Send {
    /// Start an owner-configured, isolated MCP server. Missing isolation is an error.
    fn spawn(&mut self) -> impl Future<Output = Result<Child, LaunchError>> + Send;
    /// Kill and reap the complete containment group, including detached descendants.
    /// Must be idempotent; a remote cancellation cannot undo completed side effects.
    fn terminate(&mut self) -> impl Future<Output = Result<(), LaunchError>> + Send;
}
/// Static launch errors do not reveal environment variables or filesystem contents.
#[derive(Debug, thiserror::Error)]
#[error("required_process_isolation_unavailable")]
pub struct LaunchError;

#[cfg(unix)]
pub mod memory;
