//! Owner-facing hash-only review for the native read-only skill runner.
use crate::{
    errors::Code,
    files::{self, Result},
};
use clawbell_core::policy::Policy;
use clawbell_sandbox::transaction::skill::{ScannedSkill, SkillSpec};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Options {
    /// Credential-free UTF-8 package directory, never a home or credentials tree.
    #[arg(long)]
    pub workspace: PathBuf,
    /// Exact owner policy that will apply at execution.
    #[arg(long)]
    pub policy: PathBuf,
    /// Complete expected initialize.instructions as a UTF-8 file.
    #[arg(long)]
    pub instructions_file: PathBuf,
    /// Exact trusted /usr/bin interpreter and literal /workspace arguments.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}
pub async fn prepare(
    workspace: PathBuf,
    policy: &Policy,
    instructions_file: PathBuf,
    command: &[String],
) -> Result<ScannedSkill> {
    let instructions = String::from_utf8(files::read(&instructions_file, 1024 * 1024)?)?;
    Ok(ScannedSkill::prepare(SkillSpec {
        workspace,
        executable: command.first().ok_or(Code("command_required"))?.clone(),
        arguments: command.iter().skip(1).cloned().collect(),
        instructions,
        policy: policy.skill_permission(),
    })
    .await?)
}
pub async fn run(options: Options) -> Result<()> {
    let policy = Policy::parse(std::str::from_utf8(&files::read(
        &options.policy,
        1024 * 1024,
    )?)?)?;
    let scan = prepare(
        options.workspace,
        &policy,
        options.instructions_file,
        &options.command,
    )
    .await?;
    let files: Vec<_> = scan
        .reports()
        .iter()
        .map(|r| serde_json::json!({"file_index":r.index,"findings":r.findings}))
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "format":"clawbell.skill-scan.v2", "digest":scan.digest(), "reports": files,
            "instruction_findings":scan.instruction_findings(),
        "argument_reports":scan.argument_reports().iter().map(|r| serde_json::json!({"argument_index":r.index,"findings":r.findings})).collect::<Vec<_>>(),
            "warning":"Review findings and the exact package before supplying this digest to proxy. Static inspection does not establish safety or grant execution permission."
        }))?
    );
    Ok(())
}
