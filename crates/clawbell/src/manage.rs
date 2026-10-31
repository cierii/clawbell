//! Explicit owner control plane; never reachable through MCP.
use crate::errors::Code;
use crate::files::{self, Result};
use clawbell_audit::{baseline::BaselineStore, maintenance};
use std::{io::Write, path::PathBuf};

#[derive(clap::Args)]
pub struct Pins {
    #[arg(long)]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: PinCommand,
}
#[derive(clap::Subcommand)]
enum PinCommand {
    /// Show pending catalog/tool hash differences. No metadata is printed.
    Review,
    /// Show the latest 256 immutable proposals and acceptance timestamps.
    History,
    /// Accept one reviewed candidate while all proxy sessions are stopped.
    Accept {
        #[arg(long)]
        review_id: i64,
        /// Explicit owner decision; never supplied by an upstream tool.
        #[arg(long, required = true)]
        accept: bool,
    },
}
pub async fn pins(options: Pins) -> Result<()> {
    files::trusted(&options.state_dir)?;
    let store = BaselineStore::open(&options.state_dir).await?;
    match options.command {
        PinCommand::History => {
            println!("{}", serde_json::to_string_pretty(&store.history().await?)?);
        }
        PinCommand::Review => println!("{}", serde_json::to_string_pretty(&store.review().await?)?),
        PinCommand::Accept {
            review_id,
            accept: true,
        } => {
            store.accept(review_id).await?;
            println!("baseline_accepted_reconnect_required");
        }
        PinCommand::Accept { .. } => {
            return Err(Code("explicit_acceptance_required").into());
        }
    }
    Ok(())
}
#[derive(clap::Args)]
pub struct Audit {
    #[arg(long)]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: AuditCommand,
}
#[derive(clap::Subcommand)]
enum AuditCommand {
    /// Show page capacity and warning severity without starting a session.
    Status,
    /// Print a bounded page of payload-free JSONL events.
    View {
        /// Continuously print new events until interrupted; prevents offline rotation.
        #[arg(long)]
        follow: bool,
        #[arg(long, default_value_t = 0)]
        after: i64,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Export a bounded page to a new private JSONL file (never overwrite).
    Export {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 0)]
        after: i64,
        #[arg(long, default_value_t = 100_000)]
        limit: u32,
    },
    /// Archive all events and reclaim active pages; stop every proxy first.
    Rotate {
        #[arg(long, required = true)]
        accept: bool,
    },
}
pub fn audit(options: Audit) -> Result<()> {
    files::trusted(&options.state_dir)?;
    match options.command {
        AuditCommand::Status => {
            let status = maintenance::status(&options.state_dir)?;
            if status.warning_level > 0 {
                eprintln!("audit_capacity_warning: rotate before the intent reserve is exhausted");
            }
            println!("{}", serde_json::to_string(&status)?);
        }
        AuditCommand::View {
            after,
            limit,
            follow: true,
        } => {
            let mut follower = maintenance::Follower::new(&options.state_dir, after, limit)?;
            let mut output = std::io::stdout().lock();
            loop {
                follower.poll(&mut output)?;
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
        AuditCommand::View {
            after,
            limit,
            follow: false,
        } => maintenance::export(
            &options.state_dir,
            after,
            limit,
            &mut std::io::stdout().lock(),
        )?,
        AuditCommand::Export {
            output,
            after,
            limit,
        } => {
            use std::os::unix::fs::OpenOptionsExt;
            files::trusted(output.parent().ok_or(Code("output_parent_required"))?)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&output)?;
            maintenance::export(&options.state_dir, after, limit, &mut file)?;
            file.flush()?;
            file.sync_all()?;
            files::sync_parent(&output)?;
            println!("audit_exported");
        }
        AuditCommand::Rotate { accept: true } => {
            let (archive, sha256) = maintenance::rotate(&options.state_dir)?;
            println!(
                "{}",
                serde_json::json!({"status":"audit_rotated","archive":archive,"sha256":sha256})
            );
        }
        AuditCommand::Rotate { .. } => {
            return Err(Code("explicit_acceptance_required").into());
        }
    }
    Ok(())
}
