//! Classic BPF defense in depth, layered with user/PID/network/mount namespaces.
//! Reject foreign ABIs and x32; deny kernel-control and alternate I/O escape paths.
use crate::LaunchError;
use std::{
    fs::File,
    io::{Seek, Write},
    os::fd::FromRawFd,
};

pub(crate) fn filter() -> Result<File, LaunchError> {
    #[cfg(target_arch = "x86_64")]
    let arch = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    let arch = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(LaunchError::SeccompUnavailable);
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let mut bytes = Vec::new();
        let mut emit = |code: u16, jt: u8, jf: u8, k: u32| {
            bytes.extend_from_slice(&code.to_ne_bytes());
            bytes.extend_from_slice(&[jt, jf]);
            bytes.extend_from_slice(&k.to_ne_bytes());
        };
        emit(0x20, 0, 0, 4); // seccomp_data.arch
        emit(0x15, 1, 0, arch);
        emit(0x06, 0, 0, 0x8000_0000); // KILL_PROCESS
        emit(0x20, 0, 0, 0); // syscall number
        emit(0x35, 0, 1, 0x4000_0000); // x32 / invalid syscall range
        emit(0x06, 0, 0, 0x8000_0000);
        for nr in [
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_open_by_handle_at,
            libc::SYS_io_uring_setup,
            libc::SYS_userfaultfd,
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_kexec_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_reboot,
        ] {
            emit(
                0x15,
                0,
                1,
                u32::try_from(nr).map_err(|_| LaunchError::SeccompUnavailable)?,
            );
            emit(0x06, 0, 0, 0x0005_0001); // ERRNO EPERM
        }
        emit(0x06, 0, 0, 0x7fff_0000); // ALLOW (filesystem still kernel-confined)
        let mut file = anonymous_file()?;
        file.write_all(&bytes)
            .map_err(|_| LaunchError::SeccompUnavailable)?;
        file.rewind().map_err(|_| LaunchError::SeccompUnavailable)?;
        Ok(file)
    }
}
#[allow(unsafe_code)]
fn anonymous_file() -> Result<File, LaunchError> {
    // SAFETY: static NUL-terminated name; successful fresh fd transferred once.
    let fd = unsafe { libc::memfd_create(c"clawbell-seccomp".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(LaunchError::SeccompUnavailable);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
