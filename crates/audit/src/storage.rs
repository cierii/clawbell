//! Cooperative owner maintenance locks and private files. Never mounted in runners.
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(crate) fn private(directory: &Path, name: &str, create: bool) -> std::io::Result<File> {
    let meta = std::fs::symlink_metadata(directory)?;
    if !meta.is_dir() || meta.mode() & 0o777 != 0o700 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let path = directory.join(name);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(file)
}
pub(crate) fn lock(directory: &Path, name: &str, exclusive: bool) -> std::io::Result<File> {
    let file = private(directory, name, true)?;
    if exclusive {
        file.try_lock()?;
    } else {
        file.try_lock_shared()?;
    }
    Ok(file)
}
