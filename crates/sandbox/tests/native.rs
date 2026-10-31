#![cfg(target_os = "linux")]
use clawbell_sandbox::{
    Runner,
    native::{NativeConfig, NativeRunner, ResourceLimits},
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
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
        let mut settings = config(root.join("workspace"), parent.clone(), vec![
            "-c".into(), "import os,time; pid=os.fork(); os.setsid() if pid == 0 else None; print('ready',flush=True); time.sleep(60)".into()
        ]);
        settings.limits.lifetime = Duration::from_secs(1);
        let mut runner = NativeRunner::new(settings)?;
        let mut child = runner.spawn().await?;
        // Other native tests create cgroups concurrently. Identify this child's
        // actual membership instead of selecting an unrelated newly seen group.
        let pid = child.id().ok_or("missing child pid")?;
        let membership = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let relative = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or("missing unified cgroup membership")?;
        let group = PathBuf::from(format!("/sys/fs/cgroup{relative}"));
        assert_eq!(group.parent(), Some(fs::canonicalize(&parent)?.as_path()));
        assert_eq!(
            fs::read_to_string(group.join("memory.max"))?.trim(),
            "268435456"
        );
        assert_eq!(
            fs::read_to_string(group.join("memory.swap.max"))?.trim(),
            "0"
        );
        assert_eq!(fs::read_to_string(group.join("pids.max"))?.trim(), "32");
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
        // Reaping the direct child does not wait for detached descendants.
        // Drop kills synchronously, but kernel exit and cgroup reclamation are
        // asynchronous. Require actual emptiness/removal within a fixed deadline.
        wait_for_empty_group(&group).await?;
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

/// cgroup.kill and direct-child wait do not synchronize descendant exit.
async fn wait_for_empty_group(group: &Path) -> Result {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match fs::read_to_string(group.join("cgroup.events")) {
                Ok(events) if events.lines().any(|line| line == "populated 0") => break,
                Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => return Err(error),
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn cleanup_observation_waits_for_descendants_and_accepts_reclaimed_group() -> Result {
    let group = std::env::temp_dir().join(format!("clawbell-cleanup-{}", std::process::id()));
    fs::create_dir(&group)?;
    let events = group.join("cgroup.events");
    fs::write(&events, "populated 1\nfrozen 0\n")?;
    let wait = wait_for_empty_group(&group);
    tokio::pin!(wait);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut wait)
            .await
            .is_err()
    );
    fs::write(&events, "populated 0\nfrozen 0\n")?;
    wait.await?;
    fs::remove_file(events)?;
    fs::remove_dir(&group)?;
    wait_for_empty_group(&group).await?;
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

#[tokio::test]
#[ignore = "requires real Linux namespace and cgroup v2 delegation"]
async fn approved_commit_and_soul_symlink_conflict_attacks() -> Result {
    use clawbell_core::{dlp::Vault, policy::Policy};
    use clawbell_sandbox::transaction::{
        Effect, Transaction, TreeLimits,
        commit::{CommitError, RecoveryState, recovery},
    };
    use std::fs::File;
    let parent = PathBuf::from(std::env::var("CLAWBELL_TEST_CGROUP")?);
    let policy = Policy::parse(
        "version = 'native'\n[[tools]]\nname = 'clawbell.commit'\neffect = 'write'\npaths = ['/path']\n[[rules]]\ntool = 'clawbell.commit'\ndecision = 'require_approval'\n",
    )?;
    let binding = commit_binding();
    for attack in ["safe", "soul", "symlink", "host_edit"] {
        let root = commit_fixture(attack)?;
        let workspace = root.join("workspace");
        let mut transaction = Transaction::prepare(
            config(
                workspace.clone(),
                parent.clone(),
                vec![
                    "-B".into(),
                    "-c".into(),
                    COMMIT_ATTACK_SCRIPT.into(),
                    attack.into(),
                ],
            ),
            Effect::Write,
            TreeLimits::default(),
        )
        .await?;
        let mut child = transaction.spawn().await?;
        let mut lines = BufReader::new(child.stdout.take().ok_or("missing stdout")?).lines();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(10), lines.next_line())
                .await??
                .as_deref(),
            Some("done")
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await??
                .success()
        );
        let candidate = transaction.inspect_for_commit().await;
        if attack == "symlink" {
            assert!(candidate.is_err());
        } else {
            let reviewed = candidate?.review(
                binding.clone(),
                &policy,
                &mut Vault::new(1024)?,
                Duration::from_secs(60),
            );
            if attack == "soul" {
                assert!(matches!(reviewed, Err(CommitError::Policy)));
            } else {
                let review = reviewed?;
                assert!(review.preview().contains("approved"));
                let approval = review.approve(review.digest())?;
                if attack == "host_edit" {
                    fs::write(workspace.join("file.txt"), "external")?;
                }
                let outcome = review.commit(
                    approval,
                    &binding,
                    &policy,
                    &File::open(root.join("journal"))?,
                );
                if attack == "host_edit" {
                    assert_eq!(outcome, Err(CommitError::Conflict));
                } else {
                    outcome?;
                    assert_eq!(fs::read(workspace.join("file.txt"))?, b"approved");
                    assert_eq!(
                        recovery(&File::open(root.join("journal/publication.journal"))?)?,
                        RecoveryState::Complete
                    );
                }
            }
        }
        assert_eq!(
            fs::read(workspace.join("SOUL.md"))?,
            b"SYNTHETIC-MEMORY-CANARY"
        );
        if attack != "safe" {
            assert!(!root.join("journal/publication.journal").exists());
            assert_eq!(
                fs::read(workspace.join("file.txt"))?,
                if attack == "host_edit" {
                    b"external".as_slice()
                } else {
                    b"old".as_slice()
                }
            );
        }
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

fn commit_fixture(attack: &str) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!(
            "clawbell-native-commit-{}-{attack}",
            std::process::id()
        ));
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let workspace = root.join("workspace");
    fs::DirBuilder::new().mode(0o700).create(&workspace)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("journal"))?;
    fs::write(workspace.join("file.txt"), "old")?;
    fs::write(workspace.join("SOUL.md"), "SYNTHETIC-MEMORY-CANARY")?;
    Ok(root)
}

const COMMIT_ATTACK_SCRIPT: &str = r"import os,sys
open('/workspace/file.txt','w').write('approved')
if sys.argv[1] == 'soul': open('/workspace/SOUL.md','w').write('unauthorized instructions')
if sys.argv[1] == 'symlink':
    os.unlink('/workspace/file.txt')
    os.symlink('/original/SOUL.md','/workspace/file.txt')
print('done',flush=True)
";

fn commit_binding() -> clawbell_sandbox::transaction::commit::Binding {
    clawbell_sandbox::transaction::commit::Binding {
        session: [1; 32],
        server: [2; 32],
        schema: [3; 32],
        arguments: [4; 32],
    }
}

#[tokio::test]
#[ignore = "requires real Linux namespace and cgroup v2 delegation"]
async fn skill_snapshot_binds_code_policy_command_and_instructions() -> Result {
    use clawbell_sandbox::transaction::skill::{ScannedSkill, SkillSpec};
    let root = std::env::temp_dir().join(format!("clawbell-skill-native-{}", std::process::id()));
    fs::create_dir(&root)?;
    fs::write(
        root.join("entry.py"),
        "from pathlib import Path\ntry:\n Path('/workspace/entry.py').write_text('changed')\n raise SystemExit(9)\nexcept OSError:\n print('scanned-original', flush=True)\n",
    )?;
    let spec = || -> std::result::Result<SkillSpec, clawbell_core::policy::PolicyError> {
        Ok(SkillSpec {
        workspace: root.clone(),
        executable: "/usr/bin/python3".into(),
        arguments: vec!["-B".into(), "/workspace/entry.py".into()],
        instructions: "Summarize public notes".into(),
        policy: clawbell_core::policy::Policy::parse("version='skill'\ntools=[]\nrules=[]\n[skills]\nallow_execution=true\nallow_shell=true\n")?.skill_permission(),
    })
    };
    let scan = ScannedSkill::prepare(spec()?).await?;
    let digest = scan.digest().to_owned();
    let binding = scan.instruction_binding();
    assert!(binding.matches(Some("Summarize public notes")));
    assert!(!binding.matches(Some("changed instructions")));
    assert!(!binding.matches(None));
    for field in ["policy", "command", "instructions"] {
        let mut changed = spec()?;
        match field {
            "policy" => changed.policy = clawbell_core::policy::Policy::parse("version='skill'\ntools=[]\nrules=[]\n[skills]\nallow_execution=true\nallow_shell=true\n# changed\n")?.skill_permission(),
            "command" => changed.arguments.push("changed".into()),
            _ => changed.instructions.push('!'),
        }
        let changed = ScannedSkill::prepare(changed).await?;
        assert_ne!(changed.digest(), digest);
        assert!(
            changed
                .into_runner(
                    &digest,
                    PathBuf::from("/nonexistent"),
                    ResourceLimits::default()
                )
                .is_err()
        );
    }
    // The source pathname is no longer the executed code after a complete scan.
    fs::write(
        root.join("entry.py"),
        "raise SystemExit('source changed after scan')",
    )?;
    let changed = ScannedSkill::prepare(spec()?).await?;
    assert_ne!(changed.digest(), digest);
    let parent = PathBuf::from(std::env::var("CLAWBELL_TEST_CGROUP")?);
    let mut runner = scan.into_runner(&digest, parent, ResourceLimits::default())?;
    let mut child = runner.spawn().await?;
    let stdout = child.stdout.take().ok_or("missing stdout")?;
    let mut lines = BufReader::new(stdout).lines();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await??
            .as_deref(),
        Some("scanned-original")
    );
    assert!(child.wait().await?.success());
    runner.terminate().await?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real Linux namespace and cgroup v2 delegation"]
async fn native_memory_and_task_exhaustion_stay_in_the_containment_group() -> Result {
    let root =
        std::env::temp_dir().join(format!("clawbell-resource-native-{}", std::process::id()));
    fs::create_dir(&root)?;
    let parent = PathBuf::from(std::env::var("CLAWBELL_TEST_CGROUP")?);
    for attack in ["memory", "tasks"] {
        let code = if attack == "memory" {
            "a=[]\nwhile True: a.append(bytearray(1024*1024))"
        } else {
            "import os,time\nchildren=[]\ntry:\n while True:\n  pid=os.fork()\n  if pid==0: time.sleep(30); os._exit(0)\n  children.append(pid)\nexcept OSError:\n print('task-limit-refused',flush=True)\ntime.sleep(30)"
        };
        let mut cfg = config(root.clone(), parent.clone(), vec!["-c".into(), code.into()]);
        cfg.limits.memory_bytes = 32 * 1024 * 1024;
        cfg.limits.tasks = 8;
        cfg.limits.cpu_quota = 10_000;
        cfg.limits.lifetime = Duration::from_secs(5);
        let mut runner = NativeRunner::new(cfg)?;
        let mut child = runner.spawn().await?;
        if attack == "tasks" {
            let mut lines = BufReader::new(child.stdout.take().ok_or("missing stdout")?).lines();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                    .await??
                    .as_deref(),
                Some("task-limit-refused")
            );
        } else {
            let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
            assert!(!status.success());
        }
        runner.terminate().await?;
        tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires real Linux namespace and cgroup v2 delegation"]
async fn inherited_broker_channel_does_not_enable_network_socket_creation() -> Result {
    let parent = PathBuf::from(std::env::var("CLAWBELL_TEST_CGROUP")?);
    let root = std::env::temp_dir().join(format!("clawbell-native-broker-{}", std::process::id()));
    fs::create_dir(&root)?;
    let script = r"
import os,socket
fd=int(os.environ['CLAWBELL_BROKER_FD'])
assert fd == 3
for family in [socket.AF_INET,socket.AF_INET6,socket.AF_UNIX]:
 try:
  socket.socket(family,socket.SOCK_STREAM)
  raise RuntimeError('socket constructor escaped seccomp')
 except PermissionError:
  pass
os.write(fd,b'broker-ready\n')
assert os.read(fd,128) == b'public-response\n'
print('broker-only',flush=True)
";
    let (host, child) = std::os::unix::net::UnixStream::pair()?;
    host.set_nonblocking(true)?;
    let mut host = BufReader::new(tokio::net::UnixStream::from_std(host)?);
    let mut runner = NativeRunner::new(config(
        root.clone(),
        parent,
        vec!["-c".into(), script.into()],
    ))?
    .with_broker(child);
    let mut child = runner.spawn().await?;
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), host.read_line(&mut line)).await??;
    if line.is_empty() {
        use tokio::io::AsyncReadExt;
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .ok_or("missing stderr")?
            .read_to_string(&mut stderr)
            .await?;
        return Err(format!("synthetic broker fixture startup failed: {stderr}").into());
    }
    assert_eq!(line, "broker-ready\n");
    host.get_mut().write_all(b"public-response\n").await?;
    let stdout = child.stdout.take().ok_or("missing stdout")?;
    let mut stdout = BufReader::new(stdout);
    line.clear();
    stdout.read_line(&mut line).await?;
    assert_eq!(line, "broker-only\n");
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await??
            .success()
    );
    runner.terminate().await?;
    drop(runner);
    fs::remove_dir(root)?;
    Ok(())
}
