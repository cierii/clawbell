//! One-shot staging supervisor with a separate explicitly approved committer.

//!
//! The trusted caller must authorize and durably audit before spawn, enforce pipe
//! budgets, and withhold results until `Transaction::inspect` succeeds. Reports
//! contain untrusted private paths; do not log or serialize them without redaction.
pub mod commit;

use crate::{LaunchError, Runner, linux::LinuxRunner, native::NativeConfig, sys};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::process::Child;

static NEXT: AtomicU64 = AtomicU64::new(0);
type Result<T> = std::result::Result<T, TransactionError>;

/// Owner-supplied effect, never inferred from upstream annotations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Any surviving workspace change is a refusal.
    ReadOnly,
    /// Changes may be inspected; this grants no publication permission.
    Write,
}
/// Fixed errors deliberately omit filenames, contents and operating-system text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransactionError {
    /// Native containment failed.
    #[error(transparent)]
    Isolation(#[from] LaunchError),
    /// A filesystem operation failed or the tree changed during inspection.
    #[error("transaction_filesystem_refused")]
    Filesystem,
    /// Only regular files and directories with ordinary metadata are supported.
    #[error("transaction_node_refused")]
    UnsupportedNode,
    /// The bounded tree budget was exceeded.
    #[error("transaction_tree_limit")]
    Limit,
    /// A private tmpfs could not be established.
    #[error("transaction_staging_unavailable")]
    StagingUnavailable,
    /// A read-only declaration concealed a surviving workspace change.
    #[error("transaction_hidden_write")]
    HiddenWrite,
    /// Inspection requires a started, one-shot transaction.
    #[error("transaction_not_started")]
    NotStarted,
    /// Snapshot or inspection exceeded its ten-second supervisor deadline.
    #[error("transaction_inspection_timeout")]
    Timeout,
}
/// Hard ceilings for snapshot and diff; these do not bound filesystem latency.
#[derive(Clone, Copy)]
pub struct TreeLimits {
    /// Total regular-file bytes, at most 8 MiB.
    pub bytes: u64,
    /// Total entries including root, at most 4096.
    pub entries: usize,
    /// Maximum nesting depth, at most 32.
    pub depth: usize,
}
impl Default for TreeLimits {
    fn default() -> Self {
        Self {
            bytes: 8 * 1024 * 1024,
            entries: 4096,
            depth: 32,
        }
    }
}
impl TreeLimits {
    fn validate(self) -> Result<Self> {
        let max = Self::default();
        if self.bytes == 0
            || self.bytes > max.bytes
            || self.entries == 0
            || self.entries > max.entries
            || self.depth == 0
            || self.depth > max.depth
        {
            return Err(TransactionError::Limit);
        }
        Ok(self)
    }
}
/// Structural change, without file contents. A rename appears as delete/create.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// A new regular file or directory.
    Created,
    /// A removed regular file or directory.
    Deleted,
    /// Contents, node type or inspected metadata changed.
    Modified,
}
/// Private untrusted relative path, for trusted review after redaction only.
pub struct Change {
    /// Empty path denotes the staging root.
    pub path: PathBuf,
    /// Structural classification; no raw content is included.
    pub kind: ChangeKind,
}
#[derive(PartialEq, Eq)]
struct Node {
    mode: u32,
    object: (u64, u64),
    data: Option<Vec<u8>>,
    attributes: Vec<u8>,
    identity: (u32, u32),
    timestamps: (i64, i64, i64, i64),
}
impl Drop for Node {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(data) = &mut self.data {
            data.zeroize();
        }
    }
}
type Tree = BTreeMap<PathBuf, Node>;
struct Stage {
    path: PathBuf,
    directory: File,
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn directory(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| TransactionError::Filesystem)
}
fn pinned(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}
impl Stage {
    fn new(original: &File) -> Result<Self> {
        let parent = directory(Path::new("/dev/shm"))?;
        let parent_metadata = fs_error(parent.metadata())?;
        if parent_metadata.uid() != 0
            || parent_metadata.mode() & 0o1000 == 0
            || !sys::tmpfs(&parent).map_err(|_| TransactionError::StagingUnavailable)?
        {
            return Err(TransactionError::StagingUnavailable);
        }
        let source =
            fs::canonicalize(pinned(original)).map_err(|_| TransactionError::Filesystem)?;
        if Path::new("/dev/shm").starts_with(&source) || source.starts_with("/dev/shm") {
            return Err(TransactionError::StagingUnavailable);
        }
        for _ in 0..128 {
            let path = pinned(&parent).join(format!(
                "clawbell-stage-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    let directory = directory(&path)?;
                    let path = fs::canonicalize(pinned(&directory))
                        .map_err(|_| TransactionError::Filesystem)?;
                    return Ok(Self { path, directory });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(_) => return Err(TransactionError::StagingUnavailable),
            }
        }
        Err(TransactionError::StagingUnavailable)
    }
}
fn fs_error<T>(value: std::io::Result<T>) -> Result<T> {
    value.map_err(|_| TransactionError::Filesystem)
}
fn metadata(file: &File) -> Result<std::fs::Metadata> {
    let m = fs_error(file.metadata())?;
    if (!m.is_dir() && !m.is_file())
        || (m.is_file() && m.nlink() != 1)
        || m.mode() & 0o7000 != 0
        || fs_error(sys::staging_metadata(file))?.is_none()
    {
        return Err(TransactionError::UnsupportedNode);
    }
    Ok(m)
}
fn unchanged(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    (
        a.dev(),
        a.ino(),
        a.mode(),
        a.uid(),
        a.gid(),
        a.nlink(),
        a.len(),
        a.mtime(),
        a.mtime_nsec(),
        a.ctime(),
        a.ctime_nsec(),
    ) == (
        b.dev(),
        b.ino(),
        b.mode(),
        b.uid(),
        b.gid(),
        b.nlink(),
        b.len(),
        b.mtime(),
        b.mtime_nsec(),
        b.ctime(),
        b.ctime_nsec(),
    )
}
fn scan(root: &File, limits: TreeLimits) -> Result<Tree> {
    let mut tree = Tree::new();
    let mut remaining = limits.bytes;
    walk(root, Path::new(""), 0, limits, &mut remaining, &mut tree)?;
    Ok(tree)
}
fn walk(
    file: &File,
    relative: &Path,
    depth: usize,
    limits: TreeLimits,
    remaining: &mut u64,
    tree: &mut Tree,
) -> Result<()> {
    if depth > limits.depth || tree.len() >= limits.entries {
        return Err(TransactionError::Limit);
    }
    let before = metadata(file)?;
    let data = if before.is_file() {
        if before.len() > *remaining {
            return Err(TransactionError::Limit);
        }
        let mut data = Vec::new();
        fs_error(file.take(*remaining + 1).read_to_end(&mut data))?;
        *remaining = remaining
            .checked_sub(data.len() as u64)
            .ok_or(TransactionError::Limit)?;
        Some(data)
    } else {
        None
    };
    tree.insert(
        relative.to_path_buf(),
        Node {
            mode: before.mode() & 0o777,
            object: (before.dev(), before.ino()),
            attributes: fs_error(sys::staging_metadata(file))?
                .ok_or(TransactionError::UnsupportedNode)?,
            identity: (before.uid(), before.gid()),
            timestamps: (
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ),
            data,
        },
    );
    if before.is_dir() {
        // Do not collect unbounded names or trust directory-entry type hints.
        for entry in fs_error(fs::read_dir(pinned(file)))? {
            let name = fs_error(entry)?.file_name();
            // Pin with O_PATH before opening: a malicious special node must never
            // be opened for I/O (not even briefly before a metadata check).
            let handle = fs_error(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
                    .open(pinned(file).join(&name)),
            )?;
            let m = fs_error(handle.metadata())?;
            if !m.is_file() && !m.is_dir() {
                return Err(TransactionError::UnsupportedNode);
            }
            let child = fs_error(
                OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(pinned(&handle)),
            )?;
            walk(
                &child,
                &relative.join(name),
                depth + 1,
                limits,
                remaining,
                tree,
            )?;
        }
    }
    if !unchanged(&before, &fs_error(file.metadata())?) {
        return Err(TransactionError::Filesystem);
    }
    Ok(())
}
fn copy(tree: &Tree, stage: &Stage) -> Result<()> {
    // Destinations are exclusively supervisor-owned and contain no links. Parents
    // precede descendants in BTree order; no untrusted process exists during copy.
    for (relative, node) in tree {
        if relative.as_os_str().is_empty() {
            continue;
        }
        let path = pinned(&stage.directory).join(relative);
        if let Some(data) = &node.data {
            let mut file = fs_error(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path),
            )?;
            fs_error(file.write_all(data))?;
            fs_error(file.set_permissions(fs::Permissions::from_mode(node.mode)))?;
        } else {
            fs_error(fs::DirBuilder::new().mode(0o700).create(path))?;
        }
    }
    // Apply directory modes after copying, so read-only source directories work.
    for (relative, node) in tree.iter().rev() {
        if node.data.is_none() && !relative.as_os_str().is_empty() {
            fs_error(fs::set_permissions(
                pinned(&stage.directory).join(relative),
                fs::Permissions::from_mode(node.mode),
            ))?;
        }
    }
    Ok(())
}
fn changes(before: &Tree, after: &Tree, effect: Effect) -> Result<Vec<Change>> {
    let mut result = BTreeMap::new();
    for (path, node) in before {
        let kind = match after.get(path) {
            None => Some(ChangeKind::Deleted),
            Some(other) if node != other => Some(ChangeKind::Modified),
            _ => None,
        };
        if let Some(kind) = kind {
            result.insert(path.clone(), kind);
        }
    }
    for path in after.keys().filter(|p| !before.contains_key(*p)) {
        result.insert(path.clone(), ChangeKind::Created);
    }
    if effect == Effect::ReadOnly && !result.is_empty() {
        return Err(TransactionError::HiddenWrite);
    }
    Ok(result
        .into_iter()
        .map(|(path, kind)| Change { path, kind })
        .collect())
}
// A timeout never releases a late result or launches untrusted code. Blocking
// filesystem syscalls cannot be force-cancelled; a late worker only drops its
// private candidate. Native execution has its separate whole-group watchdog.
async fn worker<T: Send + 'static>(job: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::task::spawn_blocking(job),
    )
    .await
    .map_err(|_| TransactionError::Timeout)?
    .map_err(|_| TransactionError::Filesystem)?
}

/// One operation with no host publisher. Not a `Runner`: inspection cannot be
/// accidentally bypassed by passing this to a persistent proxy relay.
pub struct Transaction {
    runner: LinuxRunner,
    stage: Stage,
    baseline: Tree,
    original: File,
    original_baseline: Tree,
    limits: TreeLimits,
    effect: Effect,
    started: bool,
}
impl Transaction {
    /// Prepare a bounded private copy on a blocking worker before untrusted exec.
    /// # Errors
    /// Refuses unsupported nodes, oversized trees or unavailable native isolation.
    pub async fn prepare(config: NativeConfig, effect: Effect, limits: TreeLimits) -> Result<Self> {
        worker(move || {
            let limits = limits.validate()?;
            let runner = LinuxRunner::new(config)?;
            let original = runner.workspace_handle()?;
            let stage = Stage::new(&original)?;
            let original_baseline = scan(&original, limits)?;
            copy(&original_baseline, &stage)?;
            let baseline = scan(&stage.directory, limits)?;
            let runner = runner.with_staging(fs_error(stage.directory.try_clone())?);
            Ok(Self {
                runner,
                stage,
                baseline,
                original,
                original_baseline,
                limits,
                effect,
                started: false,
            })
        })
        .await
    }
    /// Start once, after the caller's authorization and durable intent audit.
    /// The caller must bound/drain all three pipes and reap the returned child.
    /// # Errors
    /// Missing containment refuses before untrusted execution.
    pub async fn spawn(&mut self) -> Result<Child> {
        let child = self.runner.spawn().await?;
        self.started = true;
        Ok(child)
    }
    /// Stop execution and freeze a candidate for trusted owner review and publication.
    /// The caller must keep tool results private until review/commit succeeds.
    /// # Errors
    /// Refuses unfinished cleanup, hidden writes, unsupported nodes and tree limits.
    pub async fn inspect_for_commit(mut self) -> Result<commit::Candidate> {
        self.runner.terminate().await?;
        if !self.started {
            return Err(TransactionError::NotStarted);
        }
        worker(move || {
            let after = scan(&self.stage.directory, self.limits)?;
            changes(&self.baseline, &after, self.effect)?;
            Ok(commit::Candidate::new(
                self.original,
                self.original_baseline,
                after,
                self.baseline,
                self.limits,
            ))
        })
        .await
    }
    /// Consume execution, kill all descendants, confirm empty cgroup, then diff.
    /// No candidate is ever written back, even for `Effect::Write`.
    /// # Errors
    /// Cleanup, unsupported nodes, limits and hidden read-only writes fail closed.
    pub async fn inspect(mut self) -> Result<Vec<Change>> {
        self.runner.terminate().await?;
        if !self.started {
            return Err(TransactionError::NotStarted);
        }
        worker(move || {
            changes(
                &self.baseline,
                &scan(&self.stage.directory, self.limits)?,
                self.effect,
            )
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> std::io::Result<Fixture> {
        let path = std::env::temp_dir().join(format!(
            "clawbell-tree-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Fixture(path))
    }
    #[test]
    fn isolated_copy_diff_and_hidden_write_refusal() -> TestResult {
        let root = fixture()?;
        fs::write(root.0.join("canary"), b"SYNTHETIC-STAGING-CANARY")?;
        fs::create_dir(root.0.join("nested"))?;
        fs::write(root.0.join("nested/deleted"), b"old")?;
        let source = directory(&root.0)?;
        let stage = Stage::new(&source)?;
        assert_eq!(stage.directory.metadata()?.mode() & 0o777, 0o700);
        copy(&scan(&source, TreeLimits::default())?, &stage)?;
        let before = scan(&stage.directory, TreeLimits::default())?;
        assert!(changes(&before, &before, Effect::ReadOnly)?.is_empty());
        fs::write(stage.path.join("canary"), b"modified")?;
        fs::remove_file(stage.path.join("nested/deleted"))?;
        fs::write(stage.path.join("created"), b"new")?;
        fs::set_permissions(stage.path.join("nested"), fs::Permissions::from_mode(0o700))?;
        let after = scan(&stage.directory, TreeLimits::default())?;
        assert!(matches!(
            changes(&before, &after, Effect::ReadOnly),
            Err(TransactionError::HiddenWrite)
        ));
        let diff = changes(&before, &after, Effect::Write)?;
        let actual: Vec<_> = diff
            .iter()
            .map(|c| (c.path.to_string_lossy().into_owned(), c.kind))
            .collect();
        assert_eq!(
            actual,
            vec![
                (String::new(), ChangeKind::Modified),
                ("canary".into(), ChangeKind::Modified),
                ("created".into(), ChangeKind::Created),
                ("nested".into(), ChangeKind::Modified),
                ("nested/deleted".into(), ChangeKind::Deleted)
            ]
        );
        assert_eq!(
            fs::read(root.0.join("canary"))?,
            b"SYNTHETIC-STAGING-CANARY"
        );
        assert!(root.0.join("nested/deleted").exists());
        assert!(!root.0.join("created").exists());
        let path = stage.path.clone();
        drop(stage);
        assert!(!path.exists());
        Ok(())
    }
    #[test]
    fn read_only_refuses_each_content_and_metadata_change() -> TestResult {
        for mutation in ["content", "mode", "timestamp", "delete", "create", "type"] {
            let root = fixture()?;
            fs::write(root.0.join("file"), b"unchanged")?;
            let dir = directory(&root.0)?;
            let before = scan(&dir, TreeLimits::default())?;
            match mutation {
                "content" => fs::write(root.0.join("file"), b"changed")?,
                "mode" => {
                    fs::set_permissions(root.0.join("file"), fs::Permissions::from_mode(0o400))?;
                }
                "timestamp" => File::open(root.0.join("file"))?
                    .set_modified(std::time::SystemTime::UNIX_EPOCH)?,
                "delete" => fs::remove_file(root.0.join("file"))?,
                "create" => fs::write(root.0.join("new"), b"new")?,
                _ => {
                    fs::remove_file(root.0.join("file"))?;
                    fs::create_dir(root.0.join("file"))?;
                }
            }
            let after = scan(&dir, TreeLimits::default())?;
            assert!(matches!(
                changes(&before, &after, Effect::ReadOnly),
                Err(TransactionError::HiddenWrite)
            ));
        }
        Ok(())
    }
    #[test]
    fn refuses_links_special_nodes_and_privileged_modes() -> TestResult {
        let root = fixture()?;
        let dir = directory(&root.0)?;
        fs::write(root.0.join("regular"), b"public")?;
        std::os::unix::fs::symlink("regular", root.0.join("alias"))?;
        assert!(matches!(
            scan(&dir, TreeLimits::default()),
            Err(TransactionError::UnsupportedNode)
        ));
        fs::remove_file(root.0.join("alias"))?;
        fs::hard_link(root.0.join("regular"), root.0.join("alias"))?;
        assert!(matches!(
            scan(&dir, TreeLimits::default()),
            Err(TransactionError::UnsupportedNode)
        ));
        fs::remove_file(root.0.join("alias"))?;
        let socket = std::os::unix::net::UnixListener::bind(root.0.join("socket"))?;
        assert!(matches!(
            scan(&dir, TreeLimits::default()),
            Err(TransactionError::UnsupportedNode)
        ));
        drop(socket);
        fs::remove_file(root.0.join("socket"))?;
        fs::set_permissions(root.0.join("regular"), fs::Permissions::from_mode(0o4600))?;
        assert!(matches!(
            scan(&dir, TreeLimits::default()),
            Err(TransactionError::UnsupportedNode)
        ));
        Ok(())
    }
    #[test]
    fn enforces_byte_count_depth_and_sparse_file_limits() -> TestResult {
        let root = fixture()?;
        fs::write(root.0.join("file"), b"abcd")?;
        let dir = directory(&root.0)?;
        for limits in [
            TreeLimits {
                bytes: 3,
                ..TreeLimits::default()
            },
            TreeLimits {
                entries: 1,
                ..TreeLimits::default()
            },
        ] {
            assert!(matches!(scan(&dir, limits), Err(TransactionError::Limit)));
        }
        fs::create_dir_all(root.0.join("a/b"))?;
        assert!(matches!(
            scan(
                &dir,
                TreeLimits {
                    depth: 1,
                    ..TreeLimits::default()
                }
            ),
            Err(TransactionError::Limit)
        ));
        File::create(root.0.join("sparse"))?.set_len(1 << 30)?;
        assert!(matches!(
            scan(&dir, TreeLimits::default()),
            Err(TransactionError::Limit)
        ));
        assert!(
            TreeLimits {
                bytes: u64::MAX,
                ..TreeLimits::default()
            }
            .validate()
            .is_err()
        );
        Ok(())
    }
}
