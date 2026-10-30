//! Conservative production composition: local stdio only, no network, no host
//! writes, no reverse capabilities/resources/prompts and no secret restoration.
use crate::files::{self, Result};
use clawbell_audit::{
    baseline::BaselineStore,
    operations::{OperationStore, Outcome, Reason},
};
use clawbell_core::policy::Policy;
use clawbell_proxy::{
    Direction, Envelope, Error, Gate, Limits, dlp::LocalVaultGate, policy::PolicyGate,
};
use clawbell_sandbox::native::{NativeConfig, NativeRunner, ResourceLimits};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, path::PathBuf, sync::Arc};

#[derive(clap::Args)]
pub struct Options {
    /// Absolute owner policy path, not supplied by an MCP server.
    #[arg(long)]
    pub policy: PathBuf,
    /// Credential-free read-only directory. Never a home or credential tree.
    #[arg(long)]
    pub workspace: PathBuf,
    /// Existing delegated cgroups v2 subtree with cpu/memory/pids controllers.
    #[arg(long)]
    pub cgroup_parent: PathBuf,
    /// Existing private (0700) directory, outside workspace and runtime mounts.
    #[arg(long)]
    pub state_dir: PathBuf,
    /// Owner-assigned upstream identity, bound also to executable and arguments.
    #[arg(long)]
    pub server: String,
    /// Absolute /usr/bin executable followed by literal arguments; no shell parsing.
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}
/// Only these control methods have explicit launcher permission. Everything else
/// requires a future owner policy contract and is denied at this boundary.
fn permitted(direction: Direction, method: Option<&str>) -> bool {
    match direction {
        Direction::Client => matches!(
            method,
            None | Some(
                "initialize"
                    | "notifications/initialized"
                    | "ping"
                    | "tools/list"
                    | "tools/call"
                    | "notifications/cancelled"
            )
        ),
        Direction::Server => method.is_none() || method == Some("ping"),
    }
}
struct AuditGate {
    store: OperationStore,
    pending: HashMap<String, i64>,
}
impl Gate for AuditGate {
    fn permits_remote(&self) -> bool {
        false
    }
    async fn inspect(
        &mut self,
        direction: Direction,
        message: &Envelope,
    ) -> std::result::Result<Envelope, Error> {
        if !permitted(direction, message.method()) {
            return Err(Error::Refused(Reason::MethodDenied));
        }
        if let Some(id) = message.id() {
            // Response uses the opposite direction's ID namespace.
            let origin = if message.method().is_some() {
                direction
            } else {
                match direction {
                    Direction::Client => Direction::Server,
                    Direction::Server => Direction::Client,
                }
            };
            let key = format!(
                "{origin:?}:{}",
                serde_json::to_string(id).map_err(|_| Error::Denied)?
            );
            if message.method().is_some() {
                if self.pending.len() >= 64 || self.pending.contains_key(&key) {
                    return Err(Error::Denied);
                }
                let correlation = self
                    .store
                    .record(0, Outcome::Intent)
                    .await
                    .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
                self.pending.insert(key, correlation);
            } else {
                let correlation = *self.pending.get(&key).ok_or(Error::Denied)?;
                self.store
                    .record(
                        correlation,
                        if message.value().get("error").is_some() {
                            Outcome::Failure
                        } else {
                            Outcome::Response
                        },
                    )
                    .await
                    .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
                self.pending.remove(&key);
            }
        } else {
            self.store
                .record(0, Outcome::Intent)
                .await
                .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
        }
        Ok(message.clone())
    }
    async fn finish(&mut self) -> std::result::Result<(), Error> {
        for (_, correlation) in self.pending.drain() {
            self.store
                .record(correlation, Outcome::Unknown)
                .await
                .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
        }
        Ok(())
    }
}
/// Validate owner input and audit launch before constructing any runner. Native
/// preflight remains mandatory; missing delegation/isolation cannot spawn directly.
pub async fn run(options: Options) -> Result<()> {
    files::trusted(&options.state_dir)?;
    files::trusted(options.policy.parent().ok_or("policy_parent_required")?)?;
    files::trusted(&options.workspace)?;
    let workspace = std::fs::canonicalize(&options.workspace)?;
    let state = std::fs::canonicalize(&options.state_dir)?;
    if state.starts_with(&workspace)
        || state.starts_with("/usr")
        || state.starts_with("/etc")
        || state.starts_with("/var")
    {
        return Err("state_exposed_to_runner".into());
    }
    if options.server.is_empty() || options.server.len() > 128 {
        return Err("invalid_server_identity".into());
    }
    let policy_bytes = files::read(&options.policy, 1024 * 1024)?;
    let policy = Arc::new(Policy::parse(std::str::from_utf8(&policy_bytes)?)?);
    let digest = format!("{:x}", Sha256::digest(&policy_bytes));
    let identity = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            options.server,
            &workspace,
            &options.command
        ))?)
    );
    let store = OperationStore::open_session(&state, digest, identity.clone()).await?;
    let baseline = BaselineStore::open(&state).await?;
    let launch = store.record(0, Outcome::Intent).await?;
    let config = NativeConfig {
        workspace,
        executable: options.command.first().ok_or("command_required")?.clone(),
        arguments: options.command.iter().skip(1).cloned().collect(),
        cgroup_parent: options.cgroup_parent,
        limits: ResourceLimits::default(),
    };
    let mut runner = match NativeRunner::new(config) {
        Ok(r) => r,
        Err(e) => {
            store
                .record_reason(launch, Outcome::Denied, Reason::IsolationUnavailable)
                .await?;
            return Err(e.into());
        }
    };
    let mut gate = compose(policy, baseline, store.clone(), identity)?;
    let result = clawbell_proxy::stdio::run(
        tokio::io::stdin(),
        tokio::io::stdout(),
        &mut gate,
        &mut runner,
        Limits::default(),
    )
    .await;
    // A session/launch is not a successful operation just because pipes closed.
    store.record(launch, Outcome::Unknown).await?;
    match result {
        Ok(()) | Err(Error::Closed) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

// Outer boundary records refusals from policy, pinned schemas and DLP as well as
// method permissions. The store accepts only fixed codes, never packet contents.
struct SessionGate<G> {
    inner: G,
    store: OperationStore,
}
impl<G: Gate> Gate for SessionGate<G> {
    fn permits_remote(&self) -> bool {
        false
    }
    async fn inspect(
        &mut self,
        direction: Direction,
        message: &Envelope,
    ) -> std::result::Result<Envelope, Error> {
        let result = self.inner.inspect(direction, message).await;
        if let Err(error) = &result {
            self.store
                .record_reason(0, Outcome::Denied, error.reason())
                .await
                .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
        }
        result
    }
    async fn terminated(&mut self, reason: Reason) -> std::result::Result<(), Error> {
        let outcome = if matches!(
            reason,
            Reason::Timeout | Reason::Transport | Reason::Cancelled | Reason::Closed
        ) {
            Outcome::Unknown
        } else {
            Outcome::Denied
        };
        self.store
            .record_reason(0, outcome, reason)
            .await
            .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
        Ok(())
    }
    async fn finish(&mut self) -> std::result::Result<(), Error> {
        self.inner.finish().await
    }
}
fn compose(
    policy: Arc<Policy>,
    baseline: BaselineStore,
    store: OperationStore,
    identity: String,
) -> Result<impl Gate> {
    let audit = AuditGate {
        store: store.clone(),
        pending: HashMap::new(),
    };
    let gate = PolicyGate::new(audit, policy, baseline, identity)?;
    Ok(SessionGate {
        inner: LocalVaultGate::new(gate, Vec::new(), Limits::default().message_bytes)?,
        store,
    })
}
#[cfg(test)]
#[path = "attack_tests.rs"]
mod tests;
