//! Private point-in-time containment evidence. Hashes bind bytes and profiles;
//! they never grant execution permission or attest against a malicious owner.
use crate::{
    errors::Code,
    files::{self, Result},
};
use clawbell_sandbox::native::ResourceLimits;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::Path,
};

fn hash_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
/// Capture exact compiled profile identity and host prerequisites once, off the
/// packet path. The binary digest also binds seccomp BPF and namespace/mount code.
pub(crate) fn profile(cgroup: &Path, limits: ResourceLimits) -> Result<Value> {
    let cgroup = std::fs::canonicalize(cgroup)
        .map_err(|_| clawbell_sandbox::LaunchError::CgroupUnavailable)?;
    let meta = std::fs::metadata(&cgroup)?;
    Ok(json!({
        "binary_version": env!("CARGO_PKG_VERSION"),
        "binary_sha256": hash_file(Path::new("/proc/self/exe"))?,
        "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
        "kernel_release": std::fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
        "boot_id": std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "bubblewrap_sha256": hash_file(Path::new("/usr/bin/bwrap"))?,
        "mode": "native-read-only-v1",
        "namespaces": "unshare-all,unshare-user,disable-userns",
        "capabilities": "none", "network": "disconnected-seccomp-sockets-denied",
        "environment": {"HOME":"/home/sandbox","PATH":"/usr/bin"},
        "mounts": {"/usr":"read-only","/lib":"read-only-if-present","/lib64":"read-only-if-present","/workspace":"read-only-fd","/proc":"private-proc","/dev":"private-dev","/tmp":"tmpfs-16777216"},
        "cgroup": {"path":cgroup,"device":meta.dev(),"inode":meta.ino(),
            "controllers":std::fs::read_to_string(cgroup.join("cgroup.controllers"))?.trim(),
            "subtree_control":std::fs::read_to_string(cgroup.join("cgroup.subtree_control"))?.trim()},
        "limits": {"memory_bytes":limits.memory_bytes,"swap_bytes":0,"tasks":limits.tasks,
            "cpu_quota_us":limits.cpu_quota,"cpu_period_us":100_000,"lifetime_secs":limits.lifetime.as_secs()}
    }))
}
fn private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        let parent = path.parent().ok_or(Code("report_parent_required"))?;
        private_directory(parent)?;
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
        files::sync_parent(path)?;
    }
    files::trusted(path)
}
/// Retain an exclusive, synchronized report, including failures. No raw error or
/// probe output is stored. Identical reports are safe to reuse after byte checking.
pub(crate) fn persist(directory: &Path, profile: &Value, passed: bool) -> Result<[u8; 32]> {
    let directory = std::path::absolute(directory)?;
    private_directory(&directory)?;
    if std::fs::metadata(&directory)?.mode() & 0o777 != 0o700 {
        return Err(Code("private_report_directory_required").into());
    }
    let report = json!({"format":"clawbell-doctor-v1","utc_unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        "profile":profile,"self_test_passed":passed,
        "checks":["native_prerequisites","outside_read","workspace_write","sockets","descendants_after_cancel","audit_loss"],
        "scope":"Point-in-time synthetic probes; no execution authorization or remote isolation"});
    let bytes = serde_json::to_vec(&report)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let path = directory.join(format!("doctor-{:x}.json", Sha256::digest(&bytes)));
    if path.exists() {
        if files::read(&path, 65536)? != bytes {
            return Err(Code("report_collision").into());
        }
    } else {
        files::create(&path, &bytes)?;
    }
    println!(
        "{}",
        json!({"doctor_report":path,"sha256":format!("{:x}", Sha256::digest(&bytes)),"report_status":if passed { "passed" } else { "failed" }})
    );
    Ok(digest)
}
/// Verify local evidence against the running binary, current boot/delegation and
/// exact ordinary runner budget. Read once before starting a session, never per packet.
pub(crate) fn validate(path: &Path, expected: &Value) -> Result<[u8; 32]> {
    let parent = path.parent().ok_or(Code("report_parent_required"))?;
    files::trusted(parent)?;
    let meta = std::fs::symlink_metadata(path)?;
    let directory_meta = std::fs::metadata(parent)?;
    if meta.mode() & 0o777 != 0o600
        || directory_meta.mode() & 0o777 != 0o700
        || meta.uid() != directory_meta.uid()
    {
        return Err(Code("private_report_required").into());
    }
    let bytes = files::read(path, 65536)?;
    let report = clawbell_core::json::parse(&bytes)?;
    let digest = Sha256::digest(&bytes);
    let name = format!("doctor-{digest:x}.json");
    if path.file_name() != Some(std::ffi::OsStr::new(&name))
        || report["format"] != "clawbell-doctor-v1"
        || report["self_test_passed"] != true
        || &report["profile"] != expected
    {
        return Err(Code("doctor_evidence_mismatch").into());
    }
    Ok(digest.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn retained_evidence_refuses_failure_profile_drift_tampering_and_unsafe_files() -> Result<()> {
        let directory =
            std::env::temp_dir().join(format!("clawbell-evidence-{}", std::process::id()));
        let profile = json!({"binary_sha256":"synthetic-binary","limits":{"tasks":32}});
        let digest = persist(&directory, &profile, true)?;
        let path = std::fs::read_dir(&directory)?
            .next()
            .ok_or(Code("report_missing"))??
            .path();
        assert_eq!(validate(&path, &profile)?, digest);
        assert!(validate(&path, &json!({"binary_sha256":"changed"})).is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
        assert!(validate(&path, &profile).is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(validate(&path, &profile).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let original = std::fs::read(&path)?;
        std::fs::write(&path, b"{}")?;
        assert!(validate(&path, &profile).is_err());
        std::fs::write(&path, original)?;
        let alias = directory.join("alias.json");
        std::os::unix::fs::symlink(&path, &alias)?;
        assert!(validate(&alias, &profile).is_err());
        persist(&directory, &profile, false)?;
        for entry in std::fs::read_dir(&directory)? {
            let failed = entry?.path();
            if failed != path && failed != alias {
                assert!(validate(&failed, &profile).is_err());
            }
        }
        assert_eq!(validate(&path, &profile)?, digest);
        std::fs::remove_dir_all(directory)?;
        Ok(())
    }
}
