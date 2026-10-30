//! Owner-controlled filesystem adapter. Ancestors cannot be symlinks or writable
//! by other users (a sticky system temporary directory is allowed). Same-UID
//! malicious processes remain outside the project's owner trust boundary.
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub fn trusted(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err("absolute_path_required".into());
    }
    let mut cursor = std::path::PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            return Err("unsafe_path".into());
        }
        cursor.push(component);
        let meta = std::fs::symlink_metadata(&cursor)?;
        if !meta.is_dir() || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0) {
            return Err("untrusted_directory".into());
        }
    }
    Ok(())
}
pub fn read(path: &Path, max: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > u64::try_from(max)? {
        return Err("unsafe_file".into());
    }
    let mut bytes = Vec::new();
    file.take(u64::try_from(max)? + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err("file_limit".into());
    }
    Ok(bytes)
}
pub fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_parent(path)
}
pub fn sync_parent(path: &Path) -> Result<()> {
    File::open(path.parent().ok_or("parent_required")?)?.sync_all()?;
    Ok(())
}
/// Replacement occurs only in a trusted directory, using an exclusive temporary
/// file and an exact comparison immediately before rename. Backup remains intact
/// on interruption. No raw configuration data is ever returned in diagnostics.
pub fn replace(path: &Path, expected: &[u8], bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!("clawbell-{}.tmp", std::process::id()));
    create(&temp, bytes)?;
    let result = (|| {
        if read(path, 1024 * 1024)? != expected {
            return Err("configuration_changed".into());
        }
        std::fs::rename(&temp, path)?;
        sync_parent(path)
    })();
    if temp.exists() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
