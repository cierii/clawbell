#![deny(missing_docs)]
//! Mandatory isolated process-launch boundary for local MCP servers.
//!
//! `native::NativeRunner` supplies Linux bubblewrap, seccomp and cgroups v2
//! containment. macOS currently supplies only a Seatbelt profile component;
//! native launch refuses there until complete resource supervision is available.
//! No unsupported platform receives an unisolated `Command::spawn` fallback.
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

#[cfg(target_os = "linux")]
pub mod linux;
pub mod macos;
pub mod native;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod sys;
