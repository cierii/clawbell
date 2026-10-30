//! Synthetic, owner-private configuration round trips and refusal paths.
use super::bind::{self, Settings};
use super::files;
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> files::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "clawbell-bind-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
    fn settings(&self) -> Settings {
        Settings {
            binary: "/usr/bin/clawbell".into(),
            policy: self.0.join("policy.toml"),
            workspace: self.0.join("workspace"),
            state_dir: self.0.join("state"),
            cgroup_parent: "/sys/fs/cgroup/owner".into(),
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
const ORIGINAL: &[u8] = br#"{ "mcpServers": { "fixture": { "command": "/usr/bin/python3", "args": ["/workspace/test.py", "literal; $(touch nope)"], "env": {} } }, "other": true }"#;
#[test]
fn exact_roundtrip_idempotence_private_backup_and_literal_arguments() -> files::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("mcp.json");
    files::create(&path, ORIGINAL)?;
    assert!(bind::init(&path, &dir.settings())?);
    assert!(!bind::init(&path, &dir.settings())?);
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    assert_eq!(
        value["mcpServers"]["fixture"]["command"],
        "/usr/bin/clawbell"
    );
    assert_eq!(
        value["mcpServers"]["fixture"]["args"]
            .as_array()
            .ok_or("args")?
            .last(),
        Some(&serde_json::json!("literal; $(touch nope)"))
    );
    assert_eq!(std::fs::read(dir.0.join("mcp.json.bak"))?, ORIGINAL);
    assert_eq!(
        std::fs::metadata(dir.0.join("mcp.json.bak"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(bind::unbind(&path)?);
    assert!(!bind::unbind(&path)?);
    assert_eq!(std::fs::read(&path)?, ORIGINAL);
    assert!(bind::init(&path, &dir.settings()).is_err()); // Never clobber retained backup.
    Ok(())
}
#[test]
fn refuses_user_edits_backup_collision_links_and_unsafe_formats() -> files::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("mcp.json");
    files::create(&path, ORIGINAL)?;
    bind::init(&path, &dir.settings())?;
    std::fs::write(&path, b"owner later edit")?;
    assert!(bind::unbind(&path).is_err());
    assert_eq!(std::fs::read(&path)?, b"owner later edit");
    let link = dir.0.join("link.json");
    symlink(&path, &link)?;
    assert!(bind::init(&link, &dir.settings()).is_err());
    for (i, bytes) in [
        br#"{"mcpServers":{"x":{"command":"echo"}}}"#.as_slice(),
        br#"{"mcpServers":{"x":{"command":"/usr/bin/python3","env":{"TEST":"synthetic"}}}}"#,
        br#"{"servers":{"x":{"url":"https://fixture.invalid"}}}"#,
        br#"{"servers":{},"servers":{}}"#,
        b"not json",
    ]
    .iter()
    .enumerate()
    {
        let candidate = dir.0.join(format!("invalid-{i}.json"));
        files::create(&candidate, bytes)?;
        assert!(bind::init(&candidate, &dir.settings()).is_err());
        assert_eq!(std::fs::read(candidate)?, *bytes);
    }
    Ok(())
}
#[test]
fn vscode_map_and_bounded_discovery() -> files::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("mcp.json");
    files::create(
        &path,
        br#"{"servers":{"x":{"type":"stdio","command":"/usr/bin/true"}}}"#,
    )?;
    bind::init(&path, &dir.settings())?;
    bind::unbind(&path)?;
    assert_eq!(bind::discover(&dir.0, &dir.0), Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn tampered_backup_receipt_and_interrupted_rename_preserve_live_config() -> files::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("mcp.json");
    files::create(&path, ORIGINAL)?;
    bind::init(&path, &dir.settings())?;
    let bound = std::fs::read(&path)?;
    // Simulate a crash after writing the receipt but before atomic replacement.
    std::fs::write(&path, ORIGINAL)?;
    assert!(bind::unbind(&path)?);
    assert_eq!(std::fs::read(&path)?, ORIGINAL);
    std::fs::remove_file(dir.0.join("mcp.json.bak"))?;
    bind::init(&path, &dir.settings())?;
    std::fs::write(dir.0.join("mcp.json.bak"), b"synthetic corrupt backup")?;
    assert!(bind::unbind(&path).is_err());
    assert_eq!(std::fs::read(&path)?, bound);
    Ok(())
}
#[test]
fn hardlinks_and_untrusted_parent_are_refused() -> files::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("mcp.json");
    files::create(&path, ORIGINAL)?;
    std::fs::hard_link(&path, dir.0.join("alias.json"))?;
    assert!(bind::init(&path, &dir.settings()).is_err());
    std::fs::remove_file(dir.0.join("alias.json"))?;
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777))?;
    assert!(bind::init(&path, &dir.settings()).is_err());
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}
