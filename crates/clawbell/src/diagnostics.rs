//! Fixed trusted host probes. No downloaded code, owner data or client config is used.
use crate::errors::Code;
use crate::files::Result;
use clawbell_audit::operations::{OperationStore, Outcome};
use clawbell_sandbox::{
    Runner,
    native::{NativeConfig, NativeRunner, ResourceLimits},
};
use std::{os::unix::fs::DirBuilderExt, path::PathBuf, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(clap::Args)]
pub struct Options {
    /// Existing delegated cpu/memory/pids cgroups v2 subtree.
    #[arg(long)]
    pub cgroup_parent: PathBuf,
    /// Exercise read/write/socket refusal, descendant cleanup and audit loss.
    #[arg(long)]
    pub self_test: bool,
}
#[derive(clap::Args)]
pub struct DemoOptions {
    #[arg(long)]
    pub cgroup_parent: PathBuf,
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn temporary() -> Result<Temporary> {
    for index in 0..128 {
        let path =
            std::env::temp_dir().join(format!("clawbell-doctor-{}-{index}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(Temporary(path)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(Code("probe_directory_unavailable").into())
}
/// A failed prerequisite or probe is an error, never a skipped/pass result.
pub async fn run(options: Options) -> Result<()> {
    let root = temporary()?;
    let workspace = root.0.join("workspace");
    std::fs::create_dir(&workspace)?;
    let config = |arguments| NativeConfig {
        workspace: workspace.clone(),
        cgroup_parent: options.cgroup_parent.clone(),
        executable: "/usr/bin/python3".into(),
        arguments,
        limits: ResourceLimits::default(),
    };
    NativeRunner::preflight(config(Vec::new())).await?;
    println!("native_prerequisites: passed");
    if !options.self_test {
        return Ok(());
    }
    let outside = root.0.join("outside");
    std::fs::write(&outside, b"SYNTHETIC-DOCTOR-CANARY")?;
    std::os::unix::fs::symlink(&outside, workspace.join("alias"))?;
    let script = r"import os,socket,errno,sys,time
for path in [sys.argv[1], '/workspace/alias']:
    try: fd=os.open(path,os.O_RDONLY)
    except OSError as e: assert e.errno in (errno.ENOENT,errno.EACCES,errno.EPERM)
    else: os.close(fd); raise RuntimeError('read escaped')
try: os.open('/workspace/forbidden',os.O_CREAT|os.O_WRONLY,0o600)
except OSError as e: assert e.errno in (errno.EROFS,errno.EACCES,errno.EPERM)
else: raise RuntimeError('write escaped')
for family in (socket.AF_INET,socket.AF_UNIX):
    try: socket.socket(family)
    except OSError as e: assert e.errno == errno.EPERM
    else: raise RuntimeError('socket escaped')
pid=os.fork()
if pid == 0: os.setsid()
print('contained',flush=True)
time.sleep(60)
";
    let mut runner = NativeRunner::new(config(vec![
        "-B".into(),
        "-c".into(),
        script.into(),
        outside.to_string_lossy().into_owned(),
    ]))?;
    let mut child = runner.spawn().await?;
    let mut lines =
        BufReader::new(child.stdout.take().ok_or(Code("probe_stdout_missing"))?).lines();
    for _ in 0..2 {
        if tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await??
            .as_deref()
            != Some("contained")
        {
            return Err(Code("containment_probe_failed").into());
        }
    }
    // terminate waits for cgroup populated=0, covering detached descendants too.
    runner.terminate().await?;
    tokio::time::timeout(Duration::from_secs(10), child.wait()).await??;
    if std::fs::read(&outside)? != b"SYNTHETIC-DOCTOR-CANARY"
        || workspace.join("forbidden").exists()
    {
        return Err(Code("host_fixture_changed").into());
    }
    println!(
        "outside_read: blocked\nworkspace_write: blocked\nsockets: blocked\ndescendants_after_cancel: absent"
    );
    let audit = root.0.join("audit");
    std::fs::DirBuilder::new().mode(0o700).create(&audit)?;
    let store = OperationStore::open(&audit, "0".repeat(64)).await?;
    store.record(0, Outcome::Intent).await?;
    let connection = rusqlite::Connection::open(audit.join("operations.sqlite3"))?;
    connection.execute_batch("CREATE TRIGGER doctor_loss BEFORE INSERT ON events_v1 BEGIN SELECT RAISE(ABORT,'synthetic'); END;")?;
    crate::launch::verify_audit_refusal(store).await?;
    println!("audit_loss: forwarding_blocked\ndemo: passed");
    Ok(())
}
