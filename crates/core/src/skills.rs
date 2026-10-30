//! Bounded, offline heuristics for untrusted skill text. Findings are evidence for
//! review, never an authorization or proof that a package is safe. No input text
//! or decoded payload is included in reports.
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::Serialize;

/// Maximum UTF-8 unit accepted by the static inspector.
pub const MAX_BYTES: usize = 1024 * 1024;
const MAX_FINDINGS: usize = 256;
/// A stable reason and source location; decoded locations point at the carrier.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    /// One-based line in the original file.
    pub line: usize,
    /// Stable machine-readable reason.
    pub code: &'static str,
    /// True if observed inside a Base64-decoded unit.
    pub decoded: bool,
}
/// A complete bounded report. No findings does not establish safety.
#[derive(Debug, Serialize)]
pub struct Report {
    /// Findings, capped at 256; further evidence causes an error.
    pub findings: Vec<Finding>,
}
/// Unsupported encoding, excessive input, or exhausted inspection budget.
#[derive(Debug, thiserror::Error)]
#[error("skill_inspection_incomplete")]
pub struct ScanError;

/// Inspect one complete UTF-8 file without executing or fetching anything.
/// Base64 is decoded with standard/URL-safe alphabets, optional padding and up to
/// three nesting levels. Total decoded bytes cannot exceed four input budgets.
/// # Errors
/// Refuses oversized/non-UTF-8 files and exhausted budgets rather than returning
/// an apparently clean partial report. Archives and binary files are unsupported.
pub fn inspect(bytes: &[u8]) -> Result<Report, ScanError> {
    if bytes.len() > MAX_BYTES {
        return Err(ScanError);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ScanError)?;
    let mut report = Report {
        findings: Vec::new(),
    };
    let mut budget = MAX_BYTES * 4;
    visit(text, 0, 0, &mut budget, &mut report)?;
    Ok(report)
}
fn finding(
    report: &mut Report,
    line: usize,
    code: &'static str,
    decoded: bool,
) -> Result<(), ScanError> {
    let item = Finding {
        line,
        code,
        decoded,
    };
    if !report.findings.contains(&item) {
        if report.findings.len() == MAX_FINDINGS {
            return Err(ScanError);
        }
        report.findings.push(item);
    }
    Ok(())
}
fn visit(
    text: &str,
    depth: usize,
    carrier: usize,
    budget: &mut usize,
    report: &mut Report,
) -> Result<(), ScanError> {
    for (index, line) in text.lines().enumerate() {
        let location = if depth == 0 { index + 1 } else { carrier };
        let decoded = depth != 0;
        if line.chars().any(hidden) {
            finding(report, location, "hidden_unicode", decoded)?;
        }
        let lower = line.to_ascii_lowercase();
        // Report indicators, not a claim to understand arbitrary shell/program semantics.
        for (code, patterns) in [
            (
                "network_indicator",
                &[
                    "http://",
                    "https://",
                    "curl ",
                    "wget ",
                    "fetch(",
                    "requests.",
                    "urllib",
                    "socket",
                    "/dev/tcp",
                    "invoke-webrequest",
                    "nc ",
                    "netcat ",
                ][..],
            ),
            (
                "credential_access",
                &[
                    ".env",
                    ".ssh",
                    "id_rsa",
                    "id_ed25519",
                    "/credentials",
                    "aws_secret",
                ][..],
            ),
            (
                "agent_memory_mutation",
                &["soul.md", "agents.md", "claude.md", ".cursorrules"][..],
            ),
            (
                "instruction_override",
                &[
                    "ignore previous",
                    "ignore all previous",
                    "system prompt",
                    "disable_guard",
                    "disable security",
                    "highest priority",
                    "exfiltrate",
                ][..],
            ),
        ] {
            if patterns.iter().any(|pattern| lower.contains(pattern)) {
                finding(report, location, code, decoded)?;
            }
        }
        for token in line.split(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-".contains(c))) {
            if token.len() < 16 {
                continue;
            }
            let data = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
                .iter()
                .find_map(|engine| engine.decode(token).ok());
            if let Some(data) = data {
                finding(report, location, "base64_payload", decoded)?;
                if depth == 3 || data.len() > *budget {
                    return Err(ScanError);
                }
                *budget -= data.len();
                if let Ok(payload) = std::str::from_utf8(&data) {
                    visit(payload, depth + 1, location, budget, report)?;
                }
            }
        }
    }
    Ok(())
}
fn hidden(c: char) -> bool {
    matches!(u32::from(c), 0x00ad | 0x034f | 0x061c | 0x115f..=0x1160 | 0x17b4..=0x17b5 | 0x180b..=0x180f | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f | 0x3164 | 0xfe00..=0xfe0f | 0xfeff | 0xffa0 | 0xfff9..=0xfffb | 0xe0000..=0xe0fff)
        || (c.is_control() && !matches!(c, '\t' | '\r' | '\n'))
}
