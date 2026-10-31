//! Scan-bound, read-only skill execution. Static findings require owner review;
//! even an empty report grants no execution permission. Snapshots are private
//! tmpfs trees and never depend on source pathnames after scanning.
use super::{Stage, TransactionError, TreeLimits, copy, directory, metadata, scan, worker};
use crate::{
    LaunchError, Runner,
    linux::LinuxRunner,
    native::{NativeConfig, ResourceLimits},
};
use clawbell_core::skills::{Finding, inspect};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use tokio::process::Child;

/// Owner-configured invocation to bind into a complete scan digest.
pub struct SkillSpec {
    /// Credential-free package directory; links and binary files are refused.
    pub workspace: PathBuf,
    /// Trusted system interpreter, validated again by the native runner.
    pub executable: String,
    /// Exact argument vector, including the /workspace entrypoint.
    pub arguments: Vec<String>,
    /// Exact initialize.instructions text expected from this package.
    pub instructions: String,
    /// Fingerprint of the exact immutable policy snapshot, not its version label.
    pub policy: clawbell_core::policy::SkillPermission,
}
/// A scanned file's findings. Paths and content stay private; sorted file indices
/// identify files in the reviewed package. Instructions have their own report.
pub struct FileReport {
    /// Stable index in the sorted package tree.
    pub index: usize,
    /// Bounded static indicators requiring owner review.
    pub findings: Vec<Finding>,
}
/// Unforgeable binding produced only by a complete package/instructions scan.
#[derive(Clone)]
pub struct InstructionBinding([u8; 32]);
impl InstructionBinding {
    /// Check the complete initialization field, including absence versus empty.
    #[must_use]
    pub fn matches(&self, instructions: Option<&str>) -> bool {
        instructions.is_some_and(|s| <[u8; 32]>::from(Sha256::digest(s.as_bytes())) == self.0)
    }
}
/// Immutable reviewed bytes and the scan's invocation/policy binding. This value
/// owns the snapshot and cannot be reconstructed from an untrusted receipt.
pub struct ScannedSkill {
    stage: Stage,
    spec: SkillSpec,
    digest: String,
    reports: Vec<FileReport>,
    instruction_findings: Vec<Finding>,
    argument_reports: Vec<FileReport>,
}
impl ScannedSkill {
    /// Freeze and scan complete UTF-8 code plus initialization instructions on a
    /// blocking worker. Ten-second preparation deadline; late results are dropped.
    /// # Errors
    /// Refuses links/special nodes, invalid encoding, exhausted budgets or races.
    pub async fn prepare(spec: SkillSpec) -> Result<Self, TransactionError> {
        worker(move || {
            if spec.arguments.len() > 256
                || spec.arguments.iter().map(String::len).sum::<usize>() > 131_072
            {
                return Err(TransactionError::Limit);
            }
            let source = directory(&spec.workspace)?;
            metadata(&source)?;
            let tree = scan(&source, TreeLimits::default())?;
            let stage = Stage::new(&source)?;
            copy(&tree, &stage)?;
            let mut hash = Sha256::new();
            hash.update(b"clawbell/skill-scan/v1\0");
            let mut reports = Vec::new();
            for (path, node) in &tree {
                let name = path.to_str().ok_or(TransactionError::UnsupportedNode)?;
                hash.update((name.len() as u64).to_be_bytes());
                hash.update(name.as_bytes());
                hash.update(node.mode.to_be_bytes());
                if let Some(data) = &node.data {
                    hash.update([1]);
                    hash.update((data.len() as u64).to_be_bytes());
                    hash.update(data);
                    let report = inspect(data).map_err(|_| TransactionError::UnsupportedNode)?;
                    reports.push(FileReport {
                        index: reports.len(),
                        findings: report.findings,
                    });
                } else {
                    hash.update([0]);
                }
            }
            if reports.is_empty() {
                return Err(TransactionError::UnsupportedNode);
            }
            let mut argument_reports = Vec::new();
            for (index, argument) in spec.arguments.iter().enumerate() {
                argument_reports.push(FileReport {
                    index,
                    findings: inspect(argument.as_bytes())
                        .map_err(|_| TransactionError::UnsupportedNode)?
                        .findings,
                });
            }
            let instruction_findings = inspect(spec.instructions.as_bytes())
                .map_err(|_| TransactionError::UnsupportedNode)?
                .findings;
            let invocation = serde_json::to_vec(&(
                &spec.executable,
                &spec.arguments,
                &spec.instructions,
                spec.policy.fingerprint(),
            ))
            .map_err(|_| TransactionError::Limit)?;
            hash.update((invocation.len() as u64).to_be_bytes());
            hash.update(invocation);
            let digest = format!("{:x}", hash.finalize());
            Ok(Self {
                stage,
                spec,
                digest,
                reports,
                instruction_findings,
                argument_reports,
            })
        })
        .await
    }
    /// Hash-only scan receipt. The owner must review findings before using it as
    /// a launch argument. Knowledge of this hash is not sandbox/policy permission.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
    /// Bounded scan findings without payload text or host paths.
    #[must_use]
    pub fn reports(&self) -> &[FileReport] {
        &self.reports
    }
    /// Indicators in the initialization field included in the same scan digest.
    #[must_use]
    pub fn instruction_findings(&self) -> &[Finding] {
        &self.instruction_findings
    }
    /// Findings in every literal argument, including any inline interpreter code.
    #[must_use]
    pub fn argument_reports(&self) -> &[FileReport] {
        &self.argument_reports
    }
    /// Obtain the protocol binding for these exact scanned instruction bytes.
    #[must_use]
    pub fn instruction_binding(&self) -> InstructionBinding {
        InstructionBinding(Sha256::digest(self.spec.instructions.as_bytes()).into())
    }
    /// Prepare mandatory native containment of the frozen snapshot after owner
    /// authorization and durable audit. The source package is never mounted.
    /// # Errors
    /// Refuses mismatched prior scan, cgroup/namespace/resource setup failures.
    pub fn into_runner(
        self,
        approved_digest: &str,
        cgroup_parent: PathBuf,
        limits: ResourceLimits,
    ) -> Result<SkillRunner, TransactionError> {
        if approved_digest != self.digest {
            return Err(TransactionError::ScanBinding);
        }
        if !self.spec.policy.permits_execution() {
            return Err(TransactionError::SkillExecutionDenied);
        }
        let runner = LinuxRunner::new(NativeConfig {
            workspace: fs::canonicalize(super::pinned(&self.stage.directory))
                .map_err(|_| TransactionError::Filesystem)?,
            executable: self.spec.executable,
            arguments: self.spec.arguments,
            cgroup_parent,
            limits,
        })?;
        Ok(SkillRunner {
            runner,
            _stage: self.stage,
        })
    }
}
/// One-shot native runner retaining the read-only scanned snapshot for the full
/// process lifetime. Use the bounded stdio supervisor and an instruction gate;
/// callers must never expose raw pipes or bypass durable launch auditing.
pub struct SkillRunner {
    runner: LinuxRunner,
    _stage: Stage,
}
impl Runner for SkillRunner {
    async fn spawn(&mut self) -> Result<Child, LaunchError> {
        self.runner.spawn().await
    }
    async fn terminate(&mut self) -> Result<(), LaunchError> {
        self.runner.terminate().await
    }
}
