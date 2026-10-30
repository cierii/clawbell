//! Bounded package walk. No symlinks, archives, executables or network activity.
use crate::files::{self, Result};
use clawbell_core::skills::{self, MAX_BYTES};
use serde_json::json;
use std::path::{Path, PathBuf};
fn collect(path: &Path, depth: usize, paths: &mut Vec<PathBuf>, visited: &mut usize) -> Result<()> {
    *visited += 1;
    if *visited > 1024 {
        return Err("package_entry_limit".into());
    }
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || depth > 16 {
        return Err("unsupported_package_entry".into());
    }
    if meta.is_dir() {
        // Bound before collecting/sorting: huge directories cannot exhaust memory.
        let entries = std::fs::read_dir(path)?
            .take(257)
            .collect::<std::io::Result<Vec<_>>>()?;
        if entries.len() > 256 {
            return Err("package_entry_limit".into());
        }
        for entry in entries {
            collect(&entry.path(), depth + 1, paths, visited)?;
        }
    } else if meta.is_file() && paths.len() < 256 {
        paths.push(path.to_owned());
    } else {
        return Err("package_entry_limit_or_type".into());
    }
    Ok(())
}
pub fn run(path: &Path) -> Result<bool> {
    let mut paths = Vec::new();
    collect(path, 0, &mut paths, &mut 0)?;
    paths.sort();
    if paths.is_empty() {
        return Err("empty_package".into());
    }
    let mut reports = Vec::new();
    let mut total = 0;
    let mut findings = false;
    for (index, path) in paths.iter().enumerate() {
        let bytes = files::read(path, MAX_BYTES)?;
        total += bytes.len();
        if total > 8 * MAX_BYTES {
            return Err("package_byte_limit".into());
        }
        let report = skills::inspect(&bytes)?;
        findings |= !report.findings.is_empty();
        reports.push(json!({"file_index": index, "findings": report.findings}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"format": "clawbell.skill-scan.v1", "files": paths.len(), "reports": reports, "status": if findings {"review_required"} else {"no_indicators_detected"}, "warning": "Static heuristics do not authorize execution or prove safety. File indices follow sorted paths; payloads are never printed."})
        )?
    );
    Ok(findings)
}
