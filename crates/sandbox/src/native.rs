//! Native backend selection. Configuration is trusted owner input, never MCP data.
use crate::{LaunchError, Runner};
use std::{path::PathBuf, time::Duration};
use tokio::process::Child;

/// Hard limits for a complete Linux containment group.
#[derive(Clone, Copy)]
pub struct ResourceLimits {
    /// Aggregate resident memory and charged kernel memory; swap is disabled.
    pub memory_bytes: u64,
    /// Maximum number of tasks, including bubblewrap's supervisor.
    pub tasks: u32,
    /// CPU microseconds available in each 100 ms period.
    pub cpu_quota: u32,
    /// Absolute session lifetime, independent of transport activity.
    pub lifetime: Duration,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 256 * 1024 * 1024,
            tasks: 32,
            cpu_quota: 100_000,
            lifetime: Duration::from_secs(300),
        }
    }
}
impl ResourceLimits {
    pub(crate) fn validate(self) -> Result<Self, LaunchError> {
        if self.memory_bytes < 16 * 1024 * 1024
            || self.tasks < 4
            || self.cpu_quota == 0
            || self.cpu_quota > 100_000
            || self.lifetime.is_zero()
            || self.lifetime > Duration::from_hours(24)
        {
            return Err(LaunchError);
        }
        Ok(self)
    }
}
/// Launch configuration supplied only after owner authorization and durable audit.
/// Only a credential-free, read-only workspace is exposed; no host write or network
/// exceptions are supported. Interpreters are authorized by choosing the executable.
pub struct NativeConfig {
    /// Trusted directory containing code/data, never a home or credentials directory.
    pub workspace: PathBuf,
    /// Absolute executable under /usr/bin (Linux); no PATH lookup or shell expansion.
    pub executable: String,
    /// Literal argument vector. This type intentionally has no Debug implementation.
    pub arguments: Vec<String>,
    /// Owner-delegated cgroups v2 directory with cpu, memory and pids enabled.
    pub cgroup_parent: PathBuf,
    /// Whole-session resource budget.
    pub limits: ResourceLimits,
}
/// Platform-selected runner. Unsupported/missing enforcement always refuses launch.
/// Linux supports x86-64 and `AArch64`. macOS profile construction is available in
/// `macos`, but production launch refuses until aggregate resource enforcement exists.
pub struct NativeRunner {
    #[cfg(target_os = "linux")]
    inner: crate::linux::LinuxRunner,
}
impl NativeRunner {
    /// Prepare containment before starting any untrusted code.
    /// # Errors
    /// Missing isolation, invalid configuration and unsupported platforms refuse.
    pub fn new(config: NativeConfig) -> Result<Self, LaunchError> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                inner: crate::linux::LinuxRunner::new(config)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            config.limits.validate()?;
            Err(LaunchError)
        }
    }
}
impl Runner for NativeRunner {
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unused_async_trait_impl))]
    async fn spawn(&mut self) -> Result<Child, LaunchError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.spawn().await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(LaunchError)
        }
    }
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unused_async_trait_impl))]
    async fn terminate(&mut self) -> Result<(), LaunchError> {
        #[cfg(target_os = "linux")]
        {
            self.inner.terminate().await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }
}
