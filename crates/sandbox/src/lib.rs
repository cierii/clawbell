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
/// Fixed host failures never contain paths, arguments, environment or child stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LaunchError {
    /// Required isolation could not be established.
    #[error("required_process_isolation_unavailable")]
    IsolationUnavailable,
    /// Owner resource limits are outside supported bounds.
    #[error("host_invalid_resource_limits")]
    InvalidLimits,
    /// The selected executable is missing or outside the supported location.
    #[error("host_executable_refused")]
    ExecutableRefused,
    /// Startup arguments exceed the bounded budget.
    #[error("host_argument_limit")]
    ArgumentLimit,
    /// Native enforcement is unavailable on this platform.
    #[error("host_unsupported_platform")]
    UnsupportedPlatform,
    /// The runner must execute as an unprivileged owner.
    #[error("host_root_refused")]
    RootRefused,
    /// The selected workspace cannot be safely mounted.
    #[error("host_workspace_refused")]
    WorkspaceRefused,
    /// A writable delegated cgroups v2 subtree is required.
    #[error("host_cgroup_unavailable")]
    CgroupUnavailable,
    /// Mandatory cpu, memory, pids or kill controls are unavailable.
    #[error("host_resource_controls_unavailable")]
    ResourceControlsUnavailable,
    /// The mandatory syscall filter could not be prepared.
    #[error("host_seccomp_unavailable")]
    SeccompUnavailable,
    /// Pinned isolation descriptors could not be prepared.
    #[error("host_descriptor_setup_failed")]
    DescriptorUnavailable,
    /// The fixed bubblewrap executable is missing.
    #[error("host_bubblewrap_unavailable")]
    BubblewrapUnavailable,
    /// The isolated process could not start.
    #[error("host_isolated_spawn_failed")]
    SpawnFailed,
    /// The fixed trusted isolation probe timed out.
    #[error("host_isolation_probe_timeout")]
    ProbeTimeout,
    /// The fixed trusted probe exited unsuccessfully; namespaces or bubblewrap capabilities may be unavailable.
    #[error("host_isolation_probe_failed")]
    ProbeFailed,
    /// Complete containment cleanup could not be confirmed.
    #[error("host_process_cleanup_failed")]
    CleanupFailed,
    /// A runner instance cannot be reused.
    #[error("host_runner_already_started")]
    AlreadyStarted,
}

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
