//! Reviewed syscall boundary: no allocation/locks in the post-fork callback.
//! All descriptors are owned and live until spawn completes. Sources are duplicated
//! above fd 9 to avoid collisions with stdio and destination descriptors 3 and 4.
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
pub(crate) fn setup(command: &mut Command, workspace: File, filter: File, membership: File) {
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
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
