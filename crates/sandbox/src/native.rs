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
            return Err(LaunchError::InvalidLimits);
        }
        Ok(self)
    }
}
/// Launch configuration supplied only after owner authorization and durable audit.
/// Only a credential-free, read-only workspace is exposed. Direct network access
/// and host writes remain denied; an explicit host broker can supply a connected
/// capability without enabling sockets. Interpreters require owner selection.
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
    /// Attach a connected, session-scoped broker channel without enabling sockets
    /// or sharing the host network namespace.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn with_broker(mut self, stream: std::os::unix::net::UnixStream) -> Self {
        self.inner = self.inner.with_broker(stream);
        self
    }
    /// Exercise the actual containment profile using only trusted `/usr/bin/true`.
    /// The configured upstream is never executed. Temporary cgroups are reclaimed;
    /// client files, workspace contents and persistent host settings are untouched.
    /// # Errors
    /// Refuses unavailable namespaces, bubblewrap flags, seccomp, descriptor setup,
    /// controllers, resource limits, probe timeout or unsuccessful cleanup.
    pub async fn preflight(mut config: NativeConfig) -> Result<(), LaunchError> {
        // Validate the configured program without executing it or resolving PATH.
        let executable = std::path::Path::new(&config.executable);
        if !executable.starts_with("/usr/bin")
            || executable
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || !executable.is_file()
        {
            return Err(LaunchError::ExecutableRefused);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if executable
                .metadata()
                .map_err(|_| LaunchError::ExecutableRefused)?
                .permissions()
                .mode()
                & 0o111
                == 0
            {
                return Err(LaunchError::ExecutableRefused);
            }
        }
        if config.arguments.len() > 256
            || config.arguments.iter().map(String::len).sum::<usize>() > 131_072
        {
            return Err(LaunchError::ArgumentLimit);
        }
        config.executable = "/usr/bin/true".into();
        config.arguments.clear();
        let mut runner = Self::new(config)?;
        let probe = async {
            let mut child = runner.spawn().await?;
            child.wait().await.map_err(|_| LaunchError::ProbeFailed)
        };
        let status = tokio::time::timeout(Duration::from_secs(10), probe).await;
        let cleanup = runner.terminate().await;
        cleanup?;
        if !status.map_err(|_| LaunchError::ProbeTimeout)??.success() {
            return Err(LaunchError::ProbeFailed);
        }
        Ok(())
    }
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
            Err(LaunchError::UnsupportedPlatform)
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
            Err(LaunchError::UnsupportedPlatform)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preflight_reports_invalid_executable_without_executing_or_creating_cgroups() {
        let result = NativeRunner::preflight(NativeConfig {
            workspace: "/nonexistent-synthetic-workspace".into(),
            executable: "/nonexistent-synthetic-executable".into(),
            arguments: Vec::new(),
            cgroup_parent: "/nonexistent-synthetic-cgroup".into(),
            limits: ResourceLimits::default(),
        })
        .await;
        assert_eq!(result, Err(LaunchError::ExecutableRefused));
    }

    #[test]
    fn invalid_limits_have_a_specific_code() {
        let limits = ResourceLimits {
            tasks: 0,
            ..ResourceLimits::default()
        };
        assert!(matches!(limits.validate(), Err(LaunchError::InvalidLimits)));
    }
}
