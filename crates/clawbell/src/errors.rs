//! The owner-facing error boundary emits only static codes and trusted hints.
//! Never format an unknown error: JSON, I/O and upstream errors may embed secrets.
use std::{error::Error, fmt, io};

/// Internal owner-validation code, constructed exclusively from source literals.
#[derive(Debug)]
pub(crate) struct Code(pub(crate) &'static str);
impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl Error for Code {}

/// Classify without printing payloads, paths, child stderr or arbitrary Display.
pub(crate) fn diagnostic(error: &(dyn Error + 'static)) -> String {
    if let Some(clawbell_proxy::Error::Host(host)) = error.downcast_ref::<clawbell_proxy::Error>() {
        return diagnostic(host);
    }
    let (code, hint) = if let Some(error) = error.downcast_ref::<clawbell_sandbox::LaunchError>() {
        use clawbell_sandbox::LaunchError as Host;
        let hint = match error {
            Host::CgroupUnavailable | Host::ResourceControlsUnavailable => {
                "provide an owner-delegated cgroups v2 subtree with cpu, memory, pids and cgroup.kill; run clawbell doctor"
            }
            Host::BubblewrapUnavailable => {
                "install bubblewrap at /usr/bin/bwrap with --ro-bind-fd and --disable-userns support"
            }
            Host::ProbeFailed | Host::ProbeTimeout | Host::SpawnFailed => {
                "check unprivileged namespaces, bubblewrap capabilities, seccomp and close_range; run clawbell doctor"
            }
            Host::WorkspaceRefused => {
                "select a readable credential-free directory outside home and credential trees"
            }
            Host::RootRefused => "run as the unprivileged workspace owner",
            Host::ExecutableRefused => "select an executable file under /usr/bin",
            Host::CleanupFailed => {
                "stop clients and inspect the delegated process group before restarting"
            }
            _ => {
                "check owner settings and supported Linux isolation prerequisites; run clawbell doctor"
            }
        };
        return format!("{error}: {hint}"); // LaunchError contains only unit variants.
    } else if let Some(code) = error.downcast_ref::<Code>() {
        (
            code.0,
            "review the selected command settings; client configuration and credentials are never printed",
        )
    } else if let Some(error) = error.downcast_ref::<io::Error>() {
        let code = match error.raw_os_error() {
            Some(libc::ELOOP) => "host_symlink_refused",
            Some(libc::ENOSPC | libc::EDQUOT) => "host_storage_full",
            Some(libc::EROFS) => "host_filesystem_read_only",
            _ => match error.kind() {
                io::ErrorKind::NotFound => "host_path_not_found",
                io::ErrorKind::PermissionDenied => "host_permission_denied",
                io::ErrorKind::AlreadyExists => "host_path_already_exists",
                io::ErrorKind::TimedOut => "host_io_timeout",
                io::ErrorKind::BrokenPipe => "host_pipe_closed",
                _ => "host_io_failed",
            },
        };
        (
            code,
            "check selected paths, ownership, permissions and available storage; existing backups are never overwritten",
        )
    } else if error.is::<clawbell_core::policy::PolicyError>() {
        (
            "policy_invalid",
            "validate the owner policy with clawbell policy check",
        )
    } else if error.is::<serde_json::Error>() || error.is::<std::str::Utf8Error>() {
        (
            "configuration_encoding_invalid",
            "use bounded UTF-8 strict JSON without duplicate keys",
        )
    } else if error.is::<clawbell_audit::operations::AuditError>() {
        (
            "audit_unavailable",
            "check private state permissions and storage; execution remains blocked",
        )
    } else if error.is::<clawbell_audit::baseline::BaselineError>() {
        (
            "baseline_unavailable",
            "stop sessions and inspect private state with clawbell pins review",
        )
    } else if let Some(error) = error.downcast_ref::<clawbell_proxy::Error>() {
        (
            error.reason().code(),
            "review owner policy, pins and audit; no operation is automatically retried",
        )
    } else if error.is::<clawbell_core::skills::ScanError>() {
        (
            "skill_inspection_refused",
            "check supported input formats and inspection limits",
        )
    } else if error.is::<tokio::time::error::Elapsed>() {
        (
            "host_probe_timeout",
            "run clawbell doctor and inspect host isolation prerequisites",
        )
    } else if error.is::<tokio::task::JoinError>() {
        (
            "host_worker_failed",
            "stop clients and inspect host resource availability",
        )
    } else {
        (
            "host_unclassified_failure",
            "operation refused; no raw diagnostics are printed",
        )
    };
    format!("{code}: {hint}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug)]
    struct Untrusted;
    impl fmt::Display for Untrusted {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            unreachable!("untrusted Display must never run")
        }
    }
    impl Error for Untrusted {}
    #[test]
    fn only_static_diagnostics_cross_the_boundary() {
        assert!(diagnostic(&Untrusted).starts_with("host_unclassified_failure:"));
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "SYNTHETIC-SECRET\x1b[31m");
        let output = diagnostic(&error);
        assert!(output.starts_with("host_permission_denied:"));
        assert!(!output.contains("SYNTHETIC"));
        assert!(!output.contains('\x1b'));
        assert!(diagnostic(&Code("configuration_changed")).starts_with("configuration_changed:"));
        assert!(
            diagnostic(&clawbell_sandbox::LaunchError::CgroupUnavailable)
                .starts_with("host_cgroup_unavailable:")
        );
        assert!(
            diagnostic(&io::Error::from_raw_os_error(libc::ELOOP))
                .starts_with("host_symlink_refused:")
        );
        assert!(
            diagnostic(&io::Error::from_raw_os_error(libc::ENOSPC))
                .starts_with("host_storage_full:")
        );
    }
}
