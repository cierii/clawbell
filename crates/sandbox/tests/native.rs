#![cfg(target_os = "linux")]
use clawbell_sandbox::{
    Runner,
    native::{NativeConfig, NativeRunner, ResourceLimits},
};
use std::{fs, path::PathBuf, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn config(workspace: PathBuf, cgroup_parent: PathBuf, arguments: Vec<String>) -> NativeConfig {
    NativeConfig {
        workspace,
        cgroup_parent,
        executable: "/usr/bin/python3".into(),
        arguments,
        limits: ResourceLimits::default(),
    }
}
#[test]
fn refuses_fake_cgroup_before_launch() -> Result {
    let root = std::env::temp_dir().join(format!("clawbell-refusal-{}", std::process::id()));
    fs::create_dir(&root)?;
    assert!(NativeRunner::new(config(root.clone(), root.clone(), vec![])).is_err());
    assert_eq!(fs::read_dir(&root)?.count(), 0);
    fs::remove_dir(root)?;
    Ok(())
}
/// This test must fail, not silently skip, on hosts without delegated cgroup v2.
/// Supply `CLAWBELL_TEST_CGROUP` pointing to a trusted delegated cpu/memory/pids subtree.
#[tokio::test]
#[ignore = "requires real Linux namespace and cgroup v2 delegation"]
async fn malicious_mcp_cannot_read_ssh_key() -> Result {
    let parent = PathBuf::from(std::env::var("CLAWBELL_TEST_CGROUP")?);
    let root = std::env::temp_dir().join(format!("clawbell-native-{}", std::process::id()));
    fs::create_dir(&root)?;
    fs::create_dir(root.join("workspace"))?;
    fs::create_dir_all(root.join("home/.ssh"))?;
    let key = root.join("home/.ssh/id_rsa");
    fs::write(&key, "SYNTHETIC-NOT-A-REAL-PRIVATE-KEY")?;
    std::os::unix::fs::symlink(&key, root.join("workspace/alias"))?;
    let script = include_str!("../../../tests/fixtures/malicious_mcp.py");
    fs::write(root.join("workspace/server.py"), script)?;
    // Exercise the real preflight without running the configured Python source.
    NativeRunner::preflight(config(
        root.join("workspace"),
        parent.clone(),
        vec![
            "-c".into(),
            "raise SystemExit('untrusted upstream must not run during preflight')".into(),
        ],
    ))
    .await?;
    let mut runner = NativeRunner::new(config(
        root.join("workspace"),
        parent,
        vec![
            "-B".into(),
            "/workspace/server.py".into(),
            key.to_string_lossy().into_owned(),
        ],
    ))?;
    let mut child = runner.spawn().await?;
    let mut stdin = child.stdin.take().ok_or("missing stdin")?;
    let stdout = child.stdout.take().ok_or("missing stdout")?;
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
        .await?;
    let mut lines = BufReader::new(stdout).lines();
    let response = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await??
        .ok_or("server failed before response")?;
    assert!(response.contains("blocked"), "unexpected MCP response");
    assert!(!response.contains("SYNTHETIC"));
    assert!(child.wait().await?.success());
    runner.terminate().await?;
    assert_eq!(fs::read_to_string(key)?, "SYNTHETIC-NOT-A-REAL-PRIVATE-KEY");
    drop(runner);
    // Detached grandchildren must die on explicit cancellation, runner drop and
    // the absolute deadline, even while the server keeps the transport alive.
    for mode in ["terminate", "drop", "deadline"] {
        let parent = PathBuf::from(std::env::var("CLAWBELL_TEST_CGROUP")?);
        let before: std::collections::HashSet<_> = fs::read_dir(&parent)?
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<_>>()?;
        let mut settings = config(root.join("workspace"), parent.clone(), vec![
            "-c".into(), "import os,time; pid=os.fork(); os.setsid() if pid == 0 else None; print('ready',flush=True); time.sleep(60)".into()
        ]);
        settings.limits.lifetime = Duration::from_secs(1);
        let mut runner = NativeRunner::new(settings)?;
        let group = fs::read_dir(&parent)?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .find(|path| !before.contains(path))
            .ok_or("missing group")?;
        assert_eq!(
            fs::read_to_string(group.join("memory.max"))?.trim(),
            "268435456"
        );
        assert_eq!(
            fs::read_to_string(group.join("memory.swap.max"))?.trim(),
            "0"
        );
        assert_eq!(fs::read_to_string(group.join("pids.max"))?.trim(), "32");
        let mut child = runner.spawn().await?;
        let stdout = child.stdout.take().ok_or("missing stdout")?;
        let mut lines = BufReader::new(stdout).lines();
        for _ in 0..2 {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                    .await??
                    .as_deref(),
                Some("ready")
            );
        }
        if mode == "terminate" {
            runner.terminate().await?;
        }
        if mode == "drop" {
            drop(runner);
        } else {
            tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
            runner.terminate().await?;
            drop(runner);
        }
        tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        if group.exists() {
            match fs::read_to_string(group.join("cgroup.events")) {
                Ok(events) => assert!(events.contains("populated 0")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            // Cleanup may finish concurrently on the runner's reaper thread.
        }
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

/// Transactional staging is exercised on the same mandatory native release host.
#[tokio::test]
#[ignore = "requires real Linux namespace and cgroup v2 delegation"]
async fn transaction_stops_descendants_and_refuses_hidden_writes() -> Result {
    use clawbell_sandbox::transaction::{
        ChangeKind, Effect, Transaction, TransactionError, TreeLimits,
    };
    let parent = PathBuf::from(std::env::var("CLAWBELL_TEST_CGROUP")?);
    let root = std::env::temp_dir().join(format!(
        "clawbell-transaction-native-{}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    fs::write(root.join("canary"), b"SYNTHETIC-TRANSACTION-CANARY")?;
    for (effect, mutate) in [
        (Effect::ReadOnly, false),
        (Effect::ReadOnly, true),
        (Effect::Write, true),
    ] {
        let script = r"import os,socket,time,sys
assert open('/workspace/canary').read() == 'SYNTHETIC-TRANSACTION-CANARY'
try: open('/original/canary','w')
except OSError: pass
else: raise RuntimeError('original writable')
for family in (socket.AF_INET,socket.AF_UNIX):
    try: socket.socket(family)
    except OSError: pass
    else: raise RuntimeError('network enabled')
if sys.argv[1] == 'write':
    open('/workspace/canary','w').write('changed')
    open('/workspace/created','w').write('new')
pid=os.fork()
if pid == 0:
    os.setsid()
    print('ready',flush=True)
    while True: time.sleep(1)
print('ready',flush=True)
time.sleep(60)
";
        let settings = config(
            root.clone(),
            parent.clone(),
            vec![
                "-B".into(),
                "-c".into(),
                script.into(),
                if mutate {
                    "write".into()
                } else {
                    "read".into()
                },
            ],
        );
        let mut transaction = Transaction::prepare(settings, effect, TreeLimits::default()).await?;
        let mut child = transaction.spawn().await?;
        let mut lines = BufReader::new(child.stdout.take().ok_or("missing stdout")?).lines();
        for _ in 0..2 {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(10), lines.next_line())
                    .await??
                    .as_deref(),
                Some("ready")
            );
        }
        let inspected = transaction.inspect().await;
        tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        if effect == Effect::ReadOnly && mutate {
            assert!(matches!(inspected, Err(TransactionError::HiddenWrite)));
        } else {
            let changes = inspected?;
            if mutate {
                assert!(
                    changes
                        .iter()
                        .any(|c| c.path == std::path::Path::new("canary")
                            && c.kind == ChangeKind::Modified)
                );
                assert!(
                    changes
                        .iter()
                        .any(|c| c.path == std::path::Path::new("created")
                            && c.kind == ChangeKind::Created)
                );
            } else {
                assert!(changes.is_empty());
            }
        }
        assert_eq!(
            fs::read(root.join("canary"))?,
            b"SYNTHETIC-TRANSACTION-CANARY"
        );
        assert!(!root.join("created").exists());
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
