//! Reviewed syscall boundary: no allocation/locks in the post-fork callback.
//! All descriptors are owned and live until spawn completes. Sources are duplicated
//! above fd 9 to avoid collisions with stdio and destination descriptors 3, 4 and optional staging 5.
#![allow(unsafe_code)]
use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::process::CommandExt,
    process::Command,
};

pub(crate) fn high_fd(file: &File) -> io::Result<File> {
    // SAFETY: fcntl duplicates a live descriptor; ownership transfers only on success.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(crate) fn owner_uid() -> u32 {
    // SAFETY: geteuid has no pointer arguments or preconditions.
    unsafe { libc::geteuid() }
}
pub(crate) fn non_root() -> bool {
    // SAFETY: getuid/geteuid have no pointer arguments or preconditions.
    unsafe { libc::getuid() != 0 && libc::geteuid() != 0 }
}
pub(crate) fn cgroup_fs(file: &File) -> io::Result<bool> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: valid descriptor and correctly sized output storage; read only on success.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() }.f_type == libc::CGROUP2_SUPER_MAGIC)
}
pub(crate) fn setup(
    command: &mut Command,
    workspace: File,
    filter: File,
    membership: File,
    staging: Option<File>,
) {
    // SAFETY: callback uses only async-signal-safe syscalls, no heap allocation or
    // Rust locks. Captured descriptors cannot alias destinations (all >= 10).
    unsafe {
        command.pre_exec(move || {
            // CLOEXEC preserves Rust's exec-error pipe while ensuring arbitrary
            // caller-owned descriptors cannot leak across the sandbox boundary.
            if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) != 0
                || libc::write(membership.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1
                || libc::dup2(workspace.as_raw_fd(), 3) < 0
                || libc::dup2(filter.as_raw_fd(), 4) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if let Some(ref staging) = staging
                && libc::dup2(staging.as_raw_fd(), 5) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// No paths or untrusted output cross this syscall boundary.
pub(crate) fn staging_metadata(file: &File) -> io::Result<Option<Vec<u8>>> {
    let mut names = [0_u8; 4096];
    // SAFETY: a live fd and a bounded writable buffer, no borrowed syscall output.
    let count =
        unsafe { libc::flistxattr(file.as_raw_fd(), names.as_mut_ptr().cast(), names.len()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = usize::try_from(count).map_err(|_| io::Error::other("attribute_limit"))?;
    if count == 0 {
        return Ok(Some(Vec::new()));
    }
    // SELinux attaches its own label even to fresh files on enforcing hosts. It
    // is compared in the baseline, never copied from untrusted source metadata.
    if &names[..count] != b"security.selinux\0" {
        return Ok(None);
    }
    let mut label = [0_u8; 4096];
    // SAFETY: fixed NUL-terminated name, live descriptor, bounded output buffer.
    let count = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.selinux".as_ptr(),
            label.as_mut_ptr().cast(),
            label.len(),
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = usize::try_from(count).map_err(|_| io::Error::other("attribute_limit"))?;
    Ok(Some(label[..count].to_vec()))
}
pub(crate) fn tmpfs(file: &File) -> io::Result<bool> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: valid fd and correctly sized output; initialized only on success.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() }.f_type == libc::TMPFS_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_user_extended_attributes() -> io::Result<()> {
        let path = std::env::temp_dir().join(format!("clawbell-xattr-test-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        // Unlink immediately so even a failing assertion leaves no host fixture.
        std::fs::remove_file(path)?;
        assert!(staging_metadata(&file)?.is_some());
        // SAFETY: live fd, fixed NUL-terminated name and correctly sized literal.
        let result = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c"user.clawbell".as_ptr(),
                b"synthetic".as_ptr().cast(),
                9,
                0,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        assert!(staging_metadata(&file)?.is_none());
        Ok(())
    }
}
