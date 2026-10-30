//! Explicit owner review and narrow, handle-based publication of existing UTF-8
//! regular files. Call on a blocking worker, never in the proxy packet path.
//! No deserializable approval or raw diff is exposed. See ADR 0012 for recovery
//! and the requirement to quiesce independent host writers during publication.
use super::{
    File, Node, OpenOptions, Path, PathBuf, Tree, TreeLimits, directory, fs_error, metadata,
    pinned, scan,
};
use clawbell_core::{
    dlp::Vault,
    policy::{Decision, Policy, normalized_path, protected_path},
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, CommitError>;
/// Fixed publication errors, with no file contents, names or OS diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CommitError {
    /// Unsupported changes, paths, metadata or content.
    #[error("commit_candidate_refused")]
    Candidate,
    /// Policy denial cannot be overridden by owner approval.
    #[error("commit_policy_denied")]
    Policy,
    /// Review, context or expiry no longer matches.
    #[error("commit_approval_invalid")]
    Approval,
    /// Original identity, content or metadata changed since snapshot.
    #[error("commit_baseline_changed")]
    Conflict,
    /// Private durable intent could not be established; no target writes started.
    #[error("commit_journal_unavailable")]
    Journal,
    /// Writes may have occurred. Inspect the persistent journal and host manually.
    #[error("commit_recovery_required")]
    RecoveryRequired,
}
/// Owner-derived invocation binding. Digests must come from trusted adapters,
/// never server annotations. Policy fingerprint is added independently.
#[derive(Clone, PartialEq, Eq)]
pub struct Binding {
    /// Session identity digest.
    pub session: [u8; 32],
    /// Pinned upstream identity digest.
    pub server: [u8; 32],
    /// Complete pinned tool-definition digest, including its name, schema and
    /// metadata (use core `signatures::tool_digests`, never a schema-only hash).
    pub schema: [u8; 32],
    /// Canonical original tool arguments digest.
    pub arguments: [u8; 32],
}
/// Frozen, private candidate. No public constructor accepts arbitrary paths/data.
pub struct Candidate {
    original: File,
    before: Tree,
    after: Tree,
    staged_before: Tree,
    limits: TreeLimits,
}
/// Owner-visible, redacted before/after replacement preview and exact digest.
/// Render `preview` as untrusted text, never HTML or terminal escape sequences.
pub struct Review {
    candidate: Candidate,
    binding: Binding,
    policy: [u8; 32],
    expires: SystemTime,
    deadline: Instant,
    digest: [u8; 32],
    paths: Vec<PathBuf>,
    /// Complete redacted changes. JSON quoting escapes control characters.
    preview: String,
}
/// In-process one-use owner capability, neither cloneable nor deserializable.
/// Only the authenticated owner adapter may call `Review::approve`.
pub struct Approval([u8; 32]);
/// Persistent journal outcome. Partial/torn records always require recovery.
#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryState {
    /// No new publication can start until the owner inspects this journal.
    Required,
    /// All file writes and the final completion record were synchronized.
    Complete,
}
fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}
fn tree_hash(hash: &mut Sha256, tree: &Tree) {
    hash.update((tree.len() as u64).to_le_bytes());
    for (path, n) in tree {
        field(hash, path.as_os_str().as_encoded_bytes());
        for value in [
            u64::from(n.mode),
            n.object.0,
            n.object.1,
            u64::from(n.identity.0),
            u64::from(n.identity.1),
        ] {
            hash.update(value.to_le_bytes());
        }
        for value in [
            n.timestamps.0,
            n.timestamps.1,
            n.timestamps.2,
            n.timestamps.3,
        ] {
            hash.update(value.to_le_bytes());
        }
        field(hash, &n.attributes);
        hash.update([u8::from(n.data.is_some())]);
        field(hash, n.data.as_deref().unwrap_or_default());
    }
}
fn policy_check(policy: &Policy, path: &str) -> Result<()> {
    let arguments = serde_json::json!({"path": path});
    let scope = policy.approval_scope("clawbell.commit", &arguments);
    if scope.get("effect").and_then(serde_json::Value::as_str) != Some("write")
        || protected_path(path)
        || policy.evaluate("clawbell.commit", &arguments).decision == Decision::Deny
    {
        return Err(CommitError::Policy);
    }
    Ok(())
}
fn text(node: &Node) -> Result<&str> {
    std::str::from_utf8(node.data.as_deref().ok_or(CommitError::Candidate)?)
        .map_err(|_| CommitError::Candidate)
}
impl Candidate {
    pub(super) fn new(
        original: File,
        before: Tree,
        after: Tree,
        staged_before: Tree,
        limits: TreeLimits,
    ) -> Self {
        Self {
            original,
            before,
            after,
            staged_before,
            limits,
        }
    }
    /// Build a bounded complete preview using the session vault. Each actual
    /// changed path is evaluated as `clawbell.commit` with `{"path": relative}`.
    /// Metadata changes, creation/deletion and binary replacements refuse.
    /// # Errors
    /// Refuses denied/protected paths, unsupported changes, DLP or invalid expiry.
    pub fn review(
        self,
        binding: Binding,
        policy: &Policy,
        vault: &mut Vault,
        ttl: Duration,
    ) -> Result<Review> {
        if ttl.is_zero()
            || ttl > Duration::from_secs(300)
            || self.before.keys().ne(self.after.keys())
        {
            return Err(CommitError::Candidate);
        }
        let mut preview = String::new();
        let mut paths = Vec::new();
        // Discover secrets in all changed units before redacting the preview.
        for (path, before) in &self.before {
            let after = self.after.get(path).ok_or(CommitError::Candidate)?;
            let staged = self.staged_before.get(path).ok_or(CommitError::Candidate)?;
            if staged.identity != after.identity
                || staged.attributes != after.attributes
                || staged.mode != after.mode
                || before.data.is_some() != after.data.is_some()
            {
                return Err(CommitError::Candidate);
            }
            if before.data != after.data {
                let name = path.to_str().ok_or(CommitError::Candidate)?;
                if normalized_path(name).as_deref() != Some(name) {
                    return Err(CommitError::Candidate);
                }
                policy_check(policy, name)?;
                for unit in [name, text(before)?, text(after)?] {
                    vault.redact(unit).map_err(|_| CommitError::Candidate)?;
                }
                paths.push(path.clone());
            }
        }
        if paths.is_empty() {
            return Err(CommitError::Candidate);
        }
        for path in &paths {
            let before = self.before.get(path).ok_or(CommitError::Candidate)?;
            let after = self.after.get(path).ok_or(CommitError::Candidate)?;
            let units = [
                path.to_str().ok_or(CommitError::Candidate)?,
                text(before)?,
                text(after)?,
            ];
            let redacted = units
                .into_iter()
                .map(|s| vault.redact(s).map_err(|_| CommitError::Candidate))
                .collect::<Result<Vec<_>>>()?;
            preview
                .push_str(&serde_json::to_string(&redacted).map_err(|_| CommitError::Candidate)?);
            preview.push('\n');
            if preview.len() > 128 * 1024 * 1024 {
                return Err(CommitError::Candidate);
            }
        }
        let deadline = Instant::now() + ttl;
        let expires = SystemTime::now()
            .checked_add(ttl)
            .ok_or(CommitError::Approval)?;
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| CommitError::Approval)?;
        let mut hash = Sha256::new();
        hash.update(b"clawbell/file-approval/v1\0");
        for bytes in [
            &nonce,
            &binding.session,
            &binding.server,
            &binding.schema,
            &binding.arguments,
            &policy.fingerprint(),
        ] {
            field(&mut hash, bytes);
        }
        hash.update(
            expires
                .duration_since(UNIX_EPOCH)
                .map_err(|_| CommitError::Approval)?
                .as_nanos()
                .to_le_bytes(),
        );
        tree_hash(&mut hash, &self.before);
        tree_hash(&mut hash, &self.after);
        field(&mut hash, preview.as_bytes());
        Ok(Review {
            candidate: self,
            binding,
            policy: policy.fingerprint(),
            expires,
            deadline,
            digest: hash.finalize().into(),
            paths,
            preview,
        })
    }
}
impl Review {
    /// Complete redacted replacement preview, for display as untrusted text.
    #[must_use]
    pub fn preview(&self) -> &str {
        &self.preview
    }
    /// Digest the owner adapter must display and return unchanged on acceptance.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    /// Absolute UTC expiry included in the digest; monotonic time also enforced.
    #[must_use]
    pub fn expires(&self) -> SystemTime {
        self.expires
    }
    /// Issue a capability only after authenticated owner acceptance of this digest.
    /// # Errors
    /// A different preview digest or expired review refuses.
    pub fn approve(&self, displayed_digest: [u8; 32]) -> Result<Approval> {
        if displayed_digest != self.digest || self.expired() {
            return Err(CommitError::Approval);
        }
        Ok(Approval(self.digest))
    }
    fn expired(&self) -> bool {
        SystemTime::now() >= self.expires || Instant::now() >= self.deadline
    }
    /// Consume both candidate and approval. `journal_directory` must be a pinned,
    /// owner-only durable directory outside the workspace, with no old journal.
    /// The caller must quiesce independent host writers through completion.
    /// # Errors
    /// All preflight conflicts refuse without target writes. Once durable intent
    /// exists, any error is recovery-required; never automatically retry it.
    pub fn commit(
        self,
        approval: Approval,
        binding: &Binding,
        policy: &Policy,
        journal_directory: &File,
    ) -> Result<()> {
        self.publish(approval, binding, policy, journal_directory, |_| Ok(()))
    }
    #[allow(clippy::needless_pass_by_value)] // Consuming the capability is intentional.
    fn publish(
        self,
        approval: Approval,
        binding: &Binding,
        policy: &Policy,
        journal_directory: &File,
        mut fault: impl FnMut(usize) -> std::io::Result<()>,
    ) -> Result<()> {
        if approval.0 != self.digest
            || *binding != self.binding
            || policy.fingerprint() != self.policy
            || self.expired()
        {
            return Err(CommitError::Approval);
        }
        if scan(&self.candidate.original, self.candidate.limits)
            .map_err(|_| CommitError::Conflict)?
            != self.candidate.before
        {
            return Err(CommitError::Conflict);
        }
        let mut handles = Vec::new();
        for path in &self.paths {
            policy_check(policy, path.to_str().ok_or(CommitError::Candidate)?)?;
            let file = open_file(&self.candidate.original, path)?;
            verify(
                &file,
                self.candidate
                    .before
                    .get(path)
                    .ok_or(CommitError::Candidate)?,
            )?;
            handles.push(file);
        }
        let journal_path =
            std::fs::canonicalize(pinned(journal_directory)).map_err(|_| CommitError::Journal)?;
        let root_path = std::fs::canonicalize(pinned(&self.candidate.original))
            .map_err(|_| CommitError::Journal)?;
        if journal_path.starts_with(root_path) {
            return Err(CommitError::Journal);
        }
        let mut journal = journal(journal_directory)?;
        let intent = (|| -> std::io::Result<()> {
            record(&mut journal, b'I', &self.digest)?;
            let utc = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| std::io::Error::other("invalid_clock"))?;
            record(&mut journal, b'T', &utc.as_nanos().to_le_bytes())?;
            record(&mut journal, b'P', &self.policy)?;
            record(&mut journal, b'S', &self.binding.session)?;
            record(&mut journal, b'N', &(self.paths.len() as u64).to_le_bytes())?;
            for path in &self.paths {
                record(
                    &mut journal,
                    b'R',
                    &Sha256::digest(path.as_os_str().as_encoded_bytes()),
                )?;
                for (kind, tree) in [
                    (b'B', &self.candidate.before),
                    (b'A', &self.candidate.after),
                ] {
                    let data = tree
                        .get(path)
                        .and_then(|n| n.data.as_deref())
                        .ok_or_else(|| std::io::Error::other("missing_candidate"))?;
                    record(&mut journal, kind, &Sha256::digest(data))?;
                }
            }
            journal_directory.sync_all()
        })();
        intent.map_err(|_| CommitError::Journal)?;
        // Any failure after this point may follow an interrupted side effect.
        let writes = (|| -> Result<()> {
            for (index, (path, file)) in self.paths.iter().zip(handles.iter_mut()).enumerate() {
                if self.expired() {
                    return Err(CommitError::RecoveryRequired);
                }
                let current = open_file(&self.candidate.original, path)?;
                let before = self
                    .candidate
                    .before
                    .get(path)
                    .ok_or(CommitError::Candidate)?;
                verify(&current, before)?;
                verify(file, before)?;
                fault(index).map_err(|_| CommitError::RecoveryRequired)?;
                record(&mut journal, b'W', &(index as u64).to_le_bytes())
                    .map_err(|_| CommitError::RecoveryRequired)?;
                let data = self
                    .candidate
                    .after
                    .get(path)
                    .and_then(|n| n.data.as_deref())
                    .ok_or(CommitError::Candidate)?;
                // No pathname replacement: a swapped symlink cannot redirect this write.
                file.write_all(data)
                    .and_then(|()| file.set_len(data.len() as u64))
                    .and_then(|()| file.sync_all())
                    .map_err(|_| CommitError::RecoveryRequired)?;
                record(&mut journal, b'F', &(index as u64).to_le_bytes())
                    .map_err(|_| CommitError::RecoveryRequired)?;
            }
            record(&mut journal, b'C', &self.digest).map_err(|_| CommitError::RecoveryRequired)
        })();
        writes.map_err(|_| CommitError::RecoveryRequired)
    }
}
fn open_file(root: &File, path: &Path) -> Result<File> {
    let mut parent = root.try_clone().map_err(|_| CommitError::Conflict)?;
    let mut parts = path.components().peekable();
    while let Some(part) = parts.next() {
        if !matches!(part, std::path::Component::Normal(_)) {
            return Err(CommitError::Conflict);
        }
        let next = pinned(&parent).join(part);
        if parts.peek().is_none() {
            let handle = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                .open(next)
                .map_err(|_| CommitError::Conflict)?;
            let m = handle.metadata().map_err(|_| CommitError::Conflict)?;
            if !m.is_file() {
                return Err(CommitError::Conflict);
            }
            return OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(pinned(&handle))
                .map_err(|_| CommitError::Conflict);
        }
        parent = directory(&next).map_err(|_| CommitError::Conflict)?;
    }
    Err(CommitError::Conflict)
}
fn verify(file: &File, before: &Node) -> Result<()> {
    use std::os::unix::fs::FileExt;
    let m = metadata(file).map_err(|_| CommitError::Conflict)?;
    if (m.dev(), m.ino()) != before.object
        || (m.uid(), m.gid()) != before.identity
        || m.mode() & 0o777 != before.mode
        || (m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()) != before.timestamps
        || super::sys::staging_metadata(file)
            .map_err(|_| CommitError::Conflict)?
            .as_ref()
            != Some(&before.attributes)
    {
        return Err(CommitError::Conflict);
    }
    let expected = before.data.as_deref().ok_or(CommitError::Conflict)?;
    if m.len() != expected.len() as u64 {
        return Err(CommitError::Conflict);
    }
    let mut data = zeroize::Zeroizing::new(vec![0; expected.len()]);
    file.read_exact_at(&mut data, 0)
        .map_err(|_| CommitError::Conflict)?;
    if data.as_slice() != expected {
        return Err(CommitError::Conflict);
    }
    Ok(())
}
fn journal(parent: &File) -> Result<File> {
    let m = parent.metadata().map_err(|_| CommitError::Journal)?;
    if !m.is_dir()
        || m.mode() & 0o7777 != 0o700
        || m.uid() != super::sys::owner_uid()
        || super::sys::tmpfs(parent).map_err(|_| CommitError::Journal)?
    {
        return Err(CommitError::Journal);
    }
    let path = pinned(parent).join("publication.journal");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| CommitError::Journal)?;
    if file.metadata().map_err(|_| CommitError::Journal)?.uid() != m.uid() {
        return Err(CommitError::Journal);
    }
    Ok(file)
}
fn record(file: &mut File, kind: u8, data: &[u8]) -> std::io::Result<()> {
    let mut frame = [0; 65];
    frame[0] = kind;
    frame[1..=data.len()].copy_from_slice(data);
    let sum = Sha256::digest(&frame[..33]);
    frame[33..].copy_from_slice(&sum);
    file.write_all(&frame)?;
    file.sync_all()
}
/// Inspect an owner-opened journal after restart. No payload is ever replayed.
/// # Errors
/// Unreadable/oversized journals refuse; empty, malformed or torn journals require recovery.
pub fn recovery(file: &File) -> Result<RecoveryState> {
    let mut data = Vec::new();
    fs_error(file.take(2 * 1024 * 1024).read_to_end(&mut data))
        .map_err(|_| CommitError::Journal)?;
    if data.is_empty() || data.len() % 65 != 0 || data.len() >= 2 * 1024 * 1024 {
        return Ok(RecoveryState::Required);
    }
    let frames = data.as_chunks::<65>().0;
    if frames.len() < 5 || frames[..5].iter().map(|f| f[0]).ne(*b"ITPSN") {
        return Ok(RecoveryState::Required);
    }
    if frames
        .iter()
        .any(|f| Sha256::digest(&f[..33]).as_slice() != &f[33..])
    {
        return Ok(RecoveryState::Required);
    }
    let mut count = [0; 8];
    count.copy_from_slice(&frames[4][1..9]);
    let count = usize::try_from(u64::from_le_bytes(count)).map_err(|_| CommitError::Journal)?;
    if count == 0 || count > 4096 || frames.len() != 6 + 5 * count {
        return Ok(RecoveryState::Required);
    }
    for index in 0..count {
        let start = 5 + 3 * index;
        if frames[start..start + 3].iter().map(|f| f[0]).ne(*b"RBA") {
            return Ok(RecoveryState::Required);
        }
        let start = 5 + 3 * count + 2 * index;
        if frames[start][0] != b'W'
            || frames[start + 1][0] != b'F'
            || frames[start][1..9] != (index as u64).to_le_bytes()
            || frames[start + 1][1..9] != (index as u64).to_le_bytes()
        {
            return Ok(RecoveryState::Required);
        }
    }
    if let Some(last) = frames.last()
        && last[0] == b'C'
        && last[1..33] == frames[0][1..33]
    {
        return Ok(RecoveryState::Complete);
    }

    Ok(RecoveryState::Required)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
    };
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> std::io::Result<Self> {
            let path = std::env::current_dir()?.join("../../target").join(format!(
                "clawbell-commit-{}-{}",
                std::process::id(),
                super::super::NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path)?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join("journal"))?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join("workspace"))?;
            fs::write(path.join("workspace/a.txt"), "old a")?;
            fs::write(path.join("workspace/b.txt"), "old b")?;
            Ok(Self(path))
        }
        fn root(&self) -> PathBuf {
            self.0.join("workspace")
        }
        fn candidate(&self) -> super::super::Result<Candidate> {
            let root = directory(&self.root())?;
            let before = scan(&root, TreeLimits::default())?;
            let mut after = scan(&root, TreeLimits::default())?;
            for n in after.values_mut() {
                if let Some(data) = &mut n.data {
                    *data = b"approved text".to_vec();
                }
            }
            Ok(Candidate::new(
                root,
                before,
                after,
                scan(&directory(&self.root())?, TreeLimits::default())?,
                TreeLimits::default(),
            ))
        }
        fn journal(&self) -> super::super::Result<File> {
            directory(&self.0.join("journal"))
        }
        fn review(&self) -> std::result::Result<Review, Box<dyn std::error::Error>> {
            Ok(self.candidate()?.review(
                binding(),
                &policy("require_approval")?,
                &mut Vault::new(16 * 1024 * 1024)?,
                Duration::from_secs(60),
            )?)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn binding() -> Binding {
        Binding {
            session: [1; 32],
            server: [2; 32],
            schema: [3; 32],
            arguments: [4; 32],
        }
    }
    fn policy(decision: &str) -> std::result::Result<Policy, clawbell_core::policy::PolicyError> {
        Policy::parse(&format!(
            "version = 'test'\n[[tools]]\nname = 'clawbell.commit'\neffect = 'write'\npaths = ['/path']\n[[rules]]\ntool = 'clawbell.commit'\ndecision = '{decision}'\n"
        ))
    }
    #[test]
    fn commits_reviewed_files_and_persists_hash_only_completion() -> TestResult {
        let f = Fixture::new()?;
        let review = f.review()?;
        assert!(review.preview().contains("old a"));
        assert!(review.preview().contains("approved text"));
        let approval = review.approve(review.digest())?;
        review.commit(
            approval,
            &binding(),
            &policy("require_approval")?,
            &f.journal()?,
        )?;
        assert_eq!(fs::read_to_string(f.root().join("a.txt"))?, "approved text");
        assert_eq!(fs::read_to_string(f.root().join("b.txt"))?, "approved text");
        let path = f.0.join("journal/publication.journal");
        assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o600);
        assert_eq!(recovery(&File::open(&path)?)?, RecoveryState::Complete);
        assert!(!fs::read(&path)?.windows(13).any(|s| s == b"approved text"));
        assert!(matches!(journal(&f.journal()?), Err(CommitError::Journal)));
        Ok(())
    }
    #[test]
    fn changed_baselines_invalidate_approval_without_writes() -> TestResult {
        for mutation in [
            "edit",
            "same_bytes_new_inode",
            "symlink",
            "parent_symlink",
            "hardlink",
            "mode",
        ] {
            let f = Fixture::new()?;
            let r = f.review()?;
            let approval = r.approve(r.digest())?;
            let path = f.root().join("a.txt");
            match mutation {
                "edit" => fs::write(&path, "external edit")?,
                "same_bytes_new_inode" => {
                    fs::rename(&path, f.root().join("saved"))?;
                    fs::write(&path, "old a")?;
                    fs::remove_file(f.root().join("saved"))?;
                }
                "symlink" => {
                    fs::remove_file(&path)?;
                    std::os::unix::fs::symlink("b.txt", &path)?;
                }
                "parent_symlink" => {
                    fs::rename(f.root(), f.0.join("moved"))?;
                    std::os::unix::fs::symlink(f.0.join("moved"), f.root())?;
                    fs::write(f.0.join("moved/a.txt"), "changed")?;
                }
                "hardlink" => fs::hard_link(&path, f.root().join("link"))?,
                _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?,
            }
            assert_eq!(
                r.commit(
                    approval,
                    &binding(),
                    &policy("require_approval")?,
                    &f.journal()?
                ),
                Err(CommitError::Conflict)
            );
            let b = if mutation == "parent_symlink" {
                f.0.join("moved/b.txt")
            } else {
                f.root().join("b.txt")
            };
            assert_eq!(fs::read(b)?, b"old b");
            assert!(!f.0.join("journal/publication.journal").exists());
        }
        Ok(())
    }
    #[test]
    fn approval_binds_every_context_field_exact_policy_and_expiry() -> TestResult {
        for mutation in [
            "session",
            "server",
            "schema",
            "arguments",
            "policy",
            "expiry",
            "digest",
            "other_review",
        ] {
            let f = Fixture::new()?;
            let mut r = f.review()?;
            let approval = r.approve(r.digest())?;
            let mut context = binding();
            let mut p = policy("require_approval")?;
            match mutation {
                "session" => context.session[0] ^= 1,
                "server" => context.server[0] ^= 1,
                "schema" => context.schema[0] ^= 1,
                "arguments" => context.arguments[0] ^= 1,
                "policy" => p = policy("allow")?,
                "expiry" => r.deadline = Instant::now(),
                "digest" => r.digest[0] ^= 1,
                _ => r = f.review()?,
            }
            assert_eq!(
                r.commit(approval, &context, &p, &f.journal()?),
                Err(CommitError::Approval)
            );
            assert_eq!(fs::read(f.root().join("a.txt"))?, b"old a");
        }
        Ok(())
    }
    #[test]
    fn soul_and_policy_denial_cannot_be_approved() -> TestResult {
        let f = Fixture::new()?;
        assert!(matches!(
            f.candidate()?.review(
                binding(),
                &policy("deny")?,
                &mut Vault::new(1024)?,
                Duration::from_secs(60)
            ),
            Err(CommitError::Policy)
        ));
        fs::rename(f.root().join("a.txt"), f.root().join("SOUL.md"))?;
        assert!(matches!(
            f.candidate()?.review(
                binding(),
                &policy("allow")?,
                &mut Vault::new(1024)?,
                Duration::from_secs(60)
            ),
            Err(CommitError::Policy)
        ));
        assert_eq!(fs::read(f.root().join("SOUL.md"))?, b"old a");
        Ok(())
    }
    #[test]
    fn partial_multi_file_failure_and_restart_require_manual_recovery() -> TestResult {
        for failed_at in [0, 1] {
            let f = Fixture::new()?;
            let r = f.review()?;
            let approval = r.approve(r.digest())?;
            assert_eq!(
                r.publish(
                    approval,
                    &binding(),
                    &policy("require_approval")?,
                    &f.journal()?,
                    |i| if i == failed_at {
                        Err(std::io::Error::other("synthetic"))
                    } else {
                        Ok(())
                    }
                ),
                Err(CommitError::RecoveryRequired)
            );
            let expected = if failed_at == 0 {
                "old a"
            } else {
                "approved text"
            };
            assert_eq!(fs::read_to_string(f.root().join("a.txt"))?, expected);
            assert_eq!(fs::read(f.root().join("b.txt"))?, b"old b");
            assert_eq!(
                recovery(&File::open(f.0.join("journal/publication.journal"))?)?,
                RecoveryState::Required
            );
            assert!(matches!(journal(&f.journal()?), Err(CommitError::Journal)));
        }
        Ok(())
    }
    #[test]
    fn torn_journal_never_reports_success() -> TestResult {
        let f = Fixture::new()?;
        let r = f.review()?;
        let approval = r.approve(r.digest())?;
        r.commit(
            approval,
            &binding(),
            &policy("require_approval")?,
            &f.journal()?,
        )?;
        let path = f.0.join("journal/publication.journal");
        let data = fs::read(&path)?;
        for length in 0..data.len() {
            fs::write(&path, &data[..length])?;
            assert_eq!(recovery(&File::open(&path)?)?, RecoveryState::Required);
        }
        Ok(())
    }
    #[test]
    fn preview_redacts_known_secret_and_escapes_control_text() -> TestResult {
        let f = Fixture::new()?;
        fs::write(
            f.root().join("a.txt"),
            "SYNTHETIC-PRIVATE-VALUE\n\u{1b}[31m",
        )?;
        let mut vault = Vault::new(1024)?;
        vault.register("SYNTHETIC-PRIVATE-VALUE")?;
        let r = f.candidate()?.review(
            binding(),
            &policy("allow")?,
            &mut vault,
            Duration::from_secs(60),
        )?;
        assert!(!r.preview().contains("SYNTHETIC-PRIVATE-VALUE"));
        assert!(!r.preview().contains('\u{1b}'));
        assert!(r.preview().contains("[clawbell:"));
        assert!(matches!(r.approve([0; 32]), Err(CommitError::Approval)));
        Ok(())
    }
    #[test]
    fn unsupported_changes_and_unsafe_journals_refuse() -> TestResult {
        for mutation in ["create", "delete", "mode", "binary", "owner", "xattr"] {
            let f = Fixture::new()?;
            let mut candidate = f.candidate()?;
            match mutation {
                "create" => {
                    let n = candidate
                        .after
                        .remove(Path::new("a.txt"))
                        .ok_or("missing node")?;
                    candidate.after.insert("created".into(), n);
                }
                "delete" => {
                    candidate.after.remove(Path::new("a.txt"));
                }
                other => {
                    let node = candidate
                        .after
                        .get_mut(Path::new("a.txt"))
                        .ok_or("missing node")?;
                    match other {
                        "mode" => node.mode = 0o400,
                        "binary" => node.data = Some(vec![0xff]),
                        "owner" => node.identity.0 ^= 1,
                        _ => node.attributes.push(1),
                    }
                }
            }
            assert!(matches!(
                candidate.review(
                    binding(),
                    &policy("allow")?,
                    &mut Vault::new(1024)?,
                    Duration::from_secs(60)
                ),
                Err(CommitError::Candidate)
            ));
            assert_eq!(fs::read(f.root().join("a.txt"))?, b"old a");
        }
        let f = Fixture::new()?;
        let r = f.review()?;
        let approval = r.approve(r.digest())?;
        fs::set_permissions(f.0.join("journal"), fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            r.commit(
                approval,
                &binding(),
                &policy("require_approval")?,
                &f.journal()?
            ),
            Err(CommitError::Journal)
        );
        assert_eq!(fs::read(f.root().join("a.txt"))?, b"old a");
        Ok(())
    }
    #[test]
    fn mid_file_failure_remains_unknown_without_replay() -> TestResult {
        let f = Fixture::new()?;
        let r = f.review()?;
        let approval = r.approve(r.digest())?;
        assert_eq!(
            r.publish(
                approval,
                &binding(),
                &policy("require_approval")?,
                &f.journal()?,
                |_| {
                    fs::write(f.root().join("a.txt"), "partial")?;
                    Err(std::io::Error::other("synthetic interrupted write"))
                }
            ),
            Err(CommitError::RecoveryRequired)
        );
        assert_eq!(
            recovery(&File::open(f.0.join("journal/publication.journal"))?)?,
            RecoveryState::Required
        );
        assert_eq!(fs::read(f.root().join("a.txt"))?, b"partial");
        assert_eq!(fs::read(f.root().join("b.txt"))?, b"old b");
        Ok(())
    }
    #[test]
    fn write_effect_is_mandatory_and_private_root_mode_is_not_published() -> TestResult {
        let f = Fixture::new()?;
        let read_policy = Policy::parse(
            "version = 'read'\n[[tools]]\nname = 'clawbell.commit'\neffect = 'read'\npaths = ['/path']\n[[rules]]\ntool = '*'\ndecision = 'allow'\n",
        )?;
        assert!(matches!(
            f.candidate()?.review(
                binding(),
                &read_policy,
                &mut Vault::new(1024)?,
                Duration::from_secs(60)
            ),
            Err(CommitError::Policy)
        ));
        fs::set_permissions(f.root(), fs::Permissions::from_mode(0o755))?;
        let mut candidate = f.candidate()?;
        candidate
            .staged_before
            .get_mut(Path::new(""))
            .ok_or("missing root")?
            .mode = 0o700;
        candidate
            .after
            .get_mut(Path::new(""))
            .ok_or("missing root")?
            .mode = 0o700;
        let review = candidate.review(
            binding(),
            &policy("require_approval")?,
            &mut Vault::new(1024)?,
            Duration::from_secs(60),
        )?;
        let approval = review.approve(review.digest())?;
        review.commit(
            approval,
            &binding(),
            &policy("require_approval")?,
            &f.journal()?,
        )?;
        assert_eq!(fs::metadata(f.root())?.mode() & 0o777, 0o755);
        assert_eq!(fs::read(f.root().join("a.txt"))?, b"approved text");
        Ok(())
    }
    #[test]
    fn unavailable_journal_blocks_all_target_writes() -> TestResult {
        let f = Fixture::new()?;
        let r = f.review()?;
        let approval = r.approve(r.digest())?;
        fs::write(f.0.join("journal/publication.journal"), "existing")?;
        assert_eq!(
            r.commit(
                approval,
                &binding(),
                &policy("require_approval")?,
                &f.journal()?
            ),
            Err(CommitError::Journal)
        );
        assert_eq!(fs::read(f.root().join("a.txt"))?, b"old a");
        Ok(())
    }
}
