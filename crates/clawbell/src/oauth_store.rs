//! Private host token files, excluded from client backups and sandbox mounts.
//! A session-long exclusive lease prevents parallel refresh-token consumption.
//! Crash leases require explicit owner cleanup; recovery never guesses/replays.
use crate::{
    errors::Code,
    files::{self, Result},
};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub struct Store {
    path: PathBuf,
    lease: PathBuf,
    owner: u32,
}
impl Store {
    pub fn open(directory: &Path, binding: &str) -> Result<Self> {
        files::trusted(directory)?;
        let meta = std::fs::metadata(directory)?;
        if meta.permissions().mode() & 0o777 != 0o700
            || binding.len() != 64
            || !binding.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Code("oauth_private_store_required").into());
        }
        let path = directory.join(format!("oauth-{binding}.json"));
        let lease = directory.join(format!("oauth-{binding}.lease"));
        files::create(&lease, b"clawbell OAuth session lease v1\n")?;
        Ok(Self {
            path,
            lease,
            owner: meta.uid(),
        })
    }
    pub fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let meta = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !meta.is_file()
            || meta.mode() & 0o777 != 0o600
            || meta.uid() != self.owner
            || meta.nlink() != 1
        {
            return Err(Code("oauth_private_store_required").into());
        }
        Ok(Some(Zeroizing::new(files::read(&self.path, 32_768)?)))
    }
    pub fn save(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 32_768 {
            return Err(Code("oauth_store_limit").into());
        }
        match self.load()? {
            Some(previous) => files::replace(&self.path, &previous, bytes),
            None => files::create(&self.path, bytes),
        }
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lease);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_atomic_storage_leases_and_unsafe_files() -> Result<()> {
        use std::os::unix::fs::{DirBuilderExt, symlink};
        let root =
            std::env::temp_dir().join(format!("clawbell-oauth-store-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let binding = "a".repeat(64);
        let store = Store::open(&root, &binding)?;
        assert!(Store::open(&root, &binding).is_err());
        assert!(store.load()?.is_none());
        store.save(b"synthetic-first")?;
        store.save(b"synthetic-rotated")?;
        assert_eq!(
            store.load()?.ok_or("missing cache")?.as_slice(),
            b"synthetic-rotated"
        );
        assert_eq!(std::fs::metadata(&store.path)?.mode() & 0o777, 0o600);
        std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o644))?;
        assert!(store.load().is_err());
        assert!(store.save(b"must-not-write").is_err());
        std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o600))?;
        std::fs::hard_link(&store.path, root.join("alias"))?;
        assert!(store.load().is_err());
        std::fs::remove_file(root.join("alias"))?;
        std::fs::remove_file(&store.path)?;
        symlink(root.join("outside"), &store.path)?;
        assert!(store.load().is_err());
        assert!(store.save(b"must-not-write").is_err());
        assert!(!root.join("outside").exists());
        drop(store);
        let reopened = Store::open(&root, &binding)?;
        drop(reopened);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
