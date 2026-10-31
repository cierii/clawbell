//! Filesystem containment component for the trusted Linux Runner. All persistent
//! mounts are read-only, so aliases, hardlinks, rename/unlink and not-yet-created
//! memory files cannot bypass the guard. There are deliberately no writable host
//! mounts. This component alone is NOT a complete Runner (seccomp/cgroups remain
//! mandatory); it prepares a command but never launches it.
use crate::LaunchError;
use std::{
    fs::File,
    path::Path,
    process::{Command, Stdio},
};
/// Pins a workspace directory by an open handle for the lifetime of setup.
/// The workspace must not contain credentials; descendants receive read access.
pub struct MemoryGuard {
    workspace: File,
}
impl MemoryGuard {
    /// Open the owner-selected workspace directory, retaining its identity across
    /// renames. Never mount an entire home directory or credential directory.
    /// # Errors
    /// Returns a static refusal if the directory is unavailable or not a directory.
    pub fn open(workspace: &Path) -> Result<Self, LaunchError> {
        let workspace = File::open(workspace).map_err(|_| LaunchError::IsolationUnavailable)?;
        if !workspace
            .metadata()
            .map_err(|_| LaunchError::IsolationUnavailable)?
            .is_dir()
        {
            return Err(LaunchError::IsolationUnavailable);
        }
        Ok(Self { workspace })
    }
    /// Prepare a bubblewrap filesystem profile for an owner-authorized command.
    /// A fixed exec shim replaces the setup directory stdin with /dev/null. No
    /// untrusted argument is interpolated into shell code. stdin carries a
    /// cloned directory handle consumed during mount setup, not
    /// MCP input. Suitable for skills with no stdin; an MCP runner must transport
    /// its directory handle on a separately inherited fd. Add seccomp and cgroup
    /// containment BEFORE spawning; never add writable host mounts or reuse this
    /// as an unisolated fallback. Shell permission must be checked separately.
    /// # Errors
    /// Refuses unsupported hosts or failure to clone the pinned directory handle.
    pub fn prepare(&self, executable: &str, arguments: &[String]) -> Result<Command, LaunchError> {
        if !cfg!(target_os = "linux") || !executable.starts_with("/usr/bin/") {
            return Err(LaunchError::IsolationUnavailable);
        }
        let mut command = Command::new("/usr/bin/bwrap");
        command.env_clear().stdin(Stdio::from(
            self.workspace
                .try_clone()
                .map_err(|_| LaunchError::IsolationUnavailable)?,
        ));
        command.args([
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--ro-bind",
            "/usr",
            "/usr",
        ]);
        // Runtime library directories differ between x86-64 and AArch64.
        // Match the native runner: expose existing directories read-only only.
        for path in ["/lib", "/lib64"] {
            if Path::new(path).exists() {
                command.args(["--ro-bind", path, path]);
            }
        }
        command
            .args([
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                "/proc/self/fd/0",
                "/workspace",
                "--chdir",
                "/workspace",
                "--",
                "/usr/bin/sh",
                "-c",
                "exec \"$@\" </dev/null",
                "clawbell-memory",
                executable,
            ])
            .args(arguments);
        Ok(command)
    }
}
