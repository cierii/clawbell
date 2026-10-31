//! Linux isolation is applied before exec; children cannot race cgroup enrollment.
use crate::{LaunchError, Runner, native::NativeConfig, seccomp, sys};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    process::{Child, Command},
    task::JoinHandle,
};
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Group {
    directory: PathBuf,
    kill: File,
}
impl Group {
    fn kill(&self) -> Result<(), LaunchError> {
        (&self.kill)
            .write_all(b"1")
            .map_err(|_| LaunchError::CleanupFailed)
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        let _ = self.kill();
        if fs::remove_dir(&self.directory).is_err() {
            // SIGKILL completion is asynchronous. Reclaim the empty cgroup without
            // blocking Tokio; no live process is ever moved out of containment.
            let directory = self.directory.clone();
            let _ = std::thread::Builder::new()
                .name("clawbell-reap-group".into())
                .spawn(move || {
                    for _ in 0..200 {
                        if fs::remove_dir(&directory).is_ok() || !directory.exists() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                });
        }
    }
}
/// Linux runner; use `NativeRunner` for platform selection.
pub struct LinuxRunner {
    config: NativeConfig,
    workspace: File,
    staging: Option<File>,
    broker: Option<File>,
    group: Arc<Group>,
    watchdog: Option<JoinHandle<()>>,
    started: bool,
}
impl LinuxRunner {
    /// Create a fresh limited cgroup in a trusted delegated subtree. No process runs.
    /// The delegation and all ancestors must be inaccessible to untrusted writers.
    /// # Errors
    /// Refuses invalid budgets, root, missing controllers or inaccessible isolation.
    pub fn new(config: NativeConfig) -> Result<Self, LaunchError> {
        config.limits.validate()?;
        if !sys::non_root() {
            return Err(LaunchError::RootRefused);
        }
        if !config.executable.starts_with("/usr/bin/")
            || Path::new(&config.executable)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(LaunchError::ExecutableRefused);
        }
        if config.arguments.len() > 256
            || config.arguments.iter().map(String::len).sum::<usize>() > 131_072
        {
            return Err(LaunchError::ArgumentLimit);
        }
        let workspace = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&config.workspace)
            .map_err(|_| LaunchError::WorkspaceRefused)?;
        let canonical = fs::canonicalize(format!("/proc/self/fd/{}", workspace.as_raw_fd()))
            .map_err(|_| LaunchError::WorkspaceRefused)?;
        if canonical == Path::new("/")
            || canonical == Path::new("/home")
            || canonical == Path::new("/root")
            || canonical == Path::new("/tmp")
            || std::env::var_os("HOME").is_some_and(|home| canonical.as_os_str() == home)
            || canonical
                .components()
                .any(|c| matches!(c.as_os_str().to_str(), Some(".ssh" | ".aws" | ".gnupg")))
        {
            return Err(LaunchError::WorkspaceRefused);
        }
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&config.cgroup_parent)
            .map_err(|_| LaunchError::CgroupUnavailable)?;
        if !sys::cgroup_fs(&parent).map_err(|_| LaunchError::CgroupUnavailable)? {
            return Err(LaunchError::CgroupUnavailable);
        }
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()));
        let name = format!(
            "clawbell-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let setup = pinned.join(&name);
        fs::create_dir(&setup).map_err(|_| LaunchError::CgroupUnavailable)?;
        // Keep a stable directory handle through construction and later cleanup.
        let result = (|| {
            for (file, value) in [
                ("memory.max", config.limits.memory_bytes.to_string()),
                ("memory.swap.max", "0".into()),
                ("memory.oom.group", "1".into()),
                ("pids.max", config.limits.tasks.to_string()),
                ("cpu.max", format!("{} 100000", config.limits.cpu_quota)),
            ] {
                fs::write(setup.join(file), value)
                    .map_err(|_| LaunchError::ResourceControlsUnavailable)?;
            }
            let directory =
                fs::canonicalize(&setup).map_err(|_| LaunchError::ResourceControlsUnavailable)?;
            let kill = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(setup.join("cgroup.kill"))
                .map_err(|_| LaunchError::ResourceControlsUnavailable)?;
            Ok(Self {
                config,
                workspace,
                staging: None,
                broker: None,
                group: Arc::new(Group { directory, kill }),
                watchdog: None,
                started: false,
            })
        })();
        if result.is_err() {
            let _ = fs::remove_dir(setup);
        }
        result
    }
}
impl LinuxRunner {
    /// Attach one connected host broker capability as fd 3. The runner never
    /// receives a listener, network socket constructor or host credentials.
    #[must_use]
    pub fn with_broker(mut self, stream: std::os::unix::net::UnixStream) -> Self {
        self.broker = Some(std::os::fd::OwnedFd::from(stream).into());
        self
    }
    fn command(&self) -> std::process::Command {
        let mut command = std::process::Command::new("/usr/bin/bwrap");
        command
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args([
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
        for path in ["/lib", "/lib64"] {
            if Path::new(path).exists() {
                command.args(["--ro-bind", path, path]);
            }
        }
        if self.broker.is_some() {
            command.args(["--setenv", "CLAWBELL_BROKER_FD", "3"]);
        }
        command.args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            "16777216",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/home/sandbox",
            "--setenv",
            "HOME",
            "/home/sandbox",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--ro-bind-fd",
            if self.broker.is_some() { "4" } else { "3" },
            if self.staging.is_some() {
                "/original"
            } else {
                "/workspace"
            },
        ]);
        if self.staging.is_some() {
            command.args([
                "--bind-fd",
                if self.broker.is_some() { "6" } else { "5" },
                "/workspace",
            ]);
        }
        command
            .args([
                "--chdir",
                "/workspace",
                "--seccomp",
                if self.broker.is_some() { "5" } else { "4" },
                "--",
            ])
            .arg(&self.config.executable)
            .args(&self.config.arguments);
        command
    }
    pub(crate) fn workspace_handle(&self) -> Result<File, LaunchError> {
        self.workspace
            .try_clone()
            .map_err(|_| LaunchError::DescriptorUnavailable)
    }
    pub(crate) fn with_staging(mut self, staging: File) -> Self {
        self.staging = Some(staging);
        self
    }
}
impl Runner for LinuxRunner {
    #[allow(clippy::unused_async_trait_impl)] // Spawn must execute only when the future is polled.
    async fn spawn(&mut self) -> Result<Child, LaunchError> {
        if self.started {
            return Err(LaunchError::AlreadyStarted);
        }
        self.started = true;
        let membership = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.group.directory.join("cgroup.procs"))
            .map_err(|_| LaunchError::ResourceControlsUnavailable)?;
        let filter = seccomp::filter()?;
        let mut command = self.command();
        sys::setup(
            &mut command,
            sys::high_fd(&self.workspace).map_err(|_| LaunchError::DescriptorUnavailable)?,
            sys::high_fd(&filter).map_err(|_| LaunchError::DescriptorUnavailable)?,
            sys::high_fd(&membership).map_err(|_| LaunchError::DescriptorUnavailable)?,
            self.staging
                .as_ref()
                .map(sys::high_fd)
                .transpose()
                .map_err(|_| LaunchError::DescriptorUnavailable)?,
            self.broker
                .as_ref()
                .map(sys::high_fd)
                .transpose()
                .map_err(|_| LaunchError::DescriptorUnavailable)?,
        );
        let child = Command::from(command)
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    LaunchError::BubblewrapUnavailable
                } else {
                    LaunchError::SpawnFailed
                }
            })?;
        self.broker = None;
        let group = Arc::clone(&self.group);
        let lifetime = self.config.limits.lifetime;
        self.watchdog = Some(tokio::spawn(async move {
            tokio::time::sleep(lifetime).await;
            let _ = group.kill();
        }));
        Ok(child)
    }
    async fn terminate(&mut self) -> Result<(), LaunchError> {
        self.group.kill()?;
        if let Some(task) = self.watchdog.take() {
            task.abort();
        }
        for _ in 0..200 {
            let events = fs::read_to_string(self.group.directory.join("cgroup.events"))
                .map_err(|_| LaunchError::CleanupFailed)?;
            if events.lines().any(|line| line == "populated 0") {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(LaunchError::CleanupFailed)
    }
}
impl Drop for LinuxRunner {
    fn drop(&mut self) {
        let _ = self.group.kill();
        if let Some(task) = self.watchdog.take() {
            task.abort();
        }
    }
}
