//! macOS Seatbelt filesystem/network backend. This profile is deliberately NOT a
//! production Runner: Seatbelt alone cannot enforce aggregate memory/CPU budgets
//! or reliably supervise detached descendants. `NativeRunner` refuses macOS launch.
use crate::LaunchError;
use std::path::Path;

/// Build a deny-by-default Seatbelt profile for a trusted, immutable code directory.
/// No network, IPC, fork, host writes, home reads or user-selected profile syntax.
/// System executable/library reads are narrowly allowed; only exec is permitted.
/// A future supervisor must pin/copy the workspace before using this profile.
/// # Errors
/// Refuses non-absolute paths and characters unsafe in SBPL literals. This function
/// does not grant authorization, pin a directory, or start a process.
pub fn profile(workspace: &Path) -> Result<String, LaunchError> {
    let path = workspace
        .to_str()
        .ok_or(LaunchError::IsolationUnavailable)?;
    if !workspace.is_absolute()
        || path == "/"
        || path.len() > 4096
        || path
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\'))
        || workspace
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(LaunchError::IsolationUnavailable);
    }
    Ok(format!(
        r#"(version 1)
(deny default)
(allow process-exec)
(allow file-read* (subpath "/usr/bin") (subpath "/usr/lib")
    (subpath "/System/Library") (subpath "{path}"))
(allow file-read-metadata (literal "/") (literal "/usr") (literal "/System"))
(allow file-read* file-write-data (literal "/dev/null"))
(allow sysctl-read)
"#
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_rejects_injection() {
        for path in [
            "/",
            "relative",
            "/safe/../secret",
            "/tmp/\" ) (allow default)",
            "/tmp/\n",
        ] {
            assert!(profile(Path::new(path)).is_err());
        }
        let profile = profile(Path::new("/private/tmp/clawbell-code"));
        assert!(profile.is_ok());
    }
}
