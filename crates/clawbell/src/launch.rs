//! Conservative production composition: local stdio only, no network, no host
//! writes, no reverse capabilities and no secret restoration.
use crate::errors::Code;
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
    /// Digest from the owner-reviewed skill-scan of this exact invocation/policy.
    #[cfg(target_os = "linux")]
    #[arg(long, requires = "skill_instructions_file")]
    pub skill_scan_digest: Option<String>,
    /// UTF-8 initialize.instructions file used by the reviewed skill-scan.
    #[cfg(target_os = "linux")]
    #[arg(long, requires = "skill_scan_digest")]
    pub skill_instructions_file: Option<PathBuf>,
    /// Maximum idle time with no outstanding request (seconds).
    #[arg(long, default_value_t = 600)]
    pub idle_timeout_secs: u64,
    /// Request/inspection/I/O deadline (seconds, at most 300).
    #[arg(long, default_value_t = 30)]
    pub request_timeout_secs: u64,
    /// Absolute transport and containment lifetime (seconds, at most 86400).
    #[arg(long, default_value_t = 3600)]
    pub session_lifetime_secs: u64,
    /// Optional private owner IPC socket, outside all runner mounts.
    #[arg(long)]
    pub monitor_socket: Option<PathBuf>,
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
impl Options {
    pub(crate) fn limits(&self) -> std::result::Result<Limits, Error> {
        Limits {
            idle_timeout: std::time::Duration::from_secs(self.idle_timeout_secs),
            request_timeout: std::time::Duration::from_secs(self.request_timeout_secs),
            session_lifetime: std::time::Duration::from_secs(self.session_lifetime_secs),
            ..Limits::default()
        }
        .validate()
    }
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
                    | "resources/list"
                    | "resources/templates/list"
                    | "resources/read"
                    | "prompts/list"
                    | "prompts/get"
                    | "notifications/cancelled"
            )
        ),
        Direction::Server => method.is_none() || method == Some("ping"),
    }
}
struct AuditGate {
    remote: bool,
    store: OperationStore,
    pending: HashMap<String, i64>,
}
impl Gate for AuditGate {
    fn permits_remote(&self) -> bool {
        self.remote
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
/// Validate the optional owner endpoint without exposing it to the runner.
fn monitor_endpoint(
    socket: Option<PathBuf>,
    workspace: &std::path::Path,
) -> Result<Option<PathBuf>> {
    let endpoint = if let Some(path) = socket {
        files::trusted(path.parent().ok_or(Code("monitor_parent_required"))?)?;
        let parent = std::fs::canonicalize(path.parent().ok_or(Code("monitor_parent_required"))?)?;
        if parent.starts_with(workspace)
            || ["/usr", "/etc", "/var"]
                .iter()
                .any(|p| parent.starts_with(p))
        {
            return Err(Code("monitor_exposed_to_runner").into());
        }
        Some(path)
    } else {
        None
    };
    Ok(endpoint)
}
/// Validate owner input and audit launch before constructing any runner. Native
/// preflight remains mandatory; missing delegation/isolation cannot spawn directly.
pub async fn run(options: Options) -> Result<()> {
    let limits = options.limits()?;
    validate_owner_paths(&options)?;
    let workspace = std::fs::canonicalize(&options.workspace)?;
    let state = std::fs::canonicalize(&options.state_dir)?;
    validate_state(&state, &workspace, &options.server)?;
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
        workspace: workspace.clone(),
        executable: options
            .command
            .first()
            .ok_or(Code("command_required"))?
            .clone(),
        arguments: options.command.iter().skip(1).cloned().collect(),
        cgroup_parent: options.cgroup_parent,
        limits: ResourceLimits {
            lifetime: limits.session_lifetime,
            ..ResourceLimits::default()
        },
    };
    #[cfg(target_os = "linux")]
    let prepared = prepare_runner(
        config,
        &policy,
        options.skill_instructions_file,
        options.skill_scan_digest,
    )
    .await;
    #[cfg(not(target_os = "linux"))]
    let prepared = NativeRunner::new(config)
        .map(|r| (r, ()))
        .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) });
    let (mut runner, binding) = match prepared {
        Ok(value) => value,
        Err(error) => {
            store
                .record_reason(launch, Outcome::Denied, Reason::IsolationUnavailable)
                .await?;
            return Err(error);
        }
    };
    let monitor = clawbell_proxy::monitor::Monitor::new()?;
    let endpoint = monitor_endpoint(options.monitor_socket, &workspace)?;
    #[allow(unused_mut)] // Non-Linux builds do not add the scan-bound wrapper.
    let mut gate = compose_monitor(
        policy,
        baseline,
        store.clone(),
        identity,
        endpoint.as_ref().map(|_| monitor.clone()),
    )?;
    #[cfg(target_os = "linux")]
    let mut gate = match binding {
        Some(binding) => LaunchGate::Skill(clawbell_proxy::skill::SkillGate::new(gate, binding)),
        None => LaunchGate::Ordinary(gate),
    };
    let server = async {
        if let Some(path) = &endpoint {
            monitor.serve(path).await
        } else {
            std::future::pending().await
        }
    };
    let result = {
        let session = clawbell_proxy::stdio::run(
            tokio::io::stdin(),
            tokio::io::stdout(),
            &mut gate,
            &mut runner,
            limits,
        );
        tokio::pin!(session);
        tokio::select! {
            biased;
            _ = server => Err(Error::Denied),
            result = &mut session => result,
        }
    };
    clawbell_sandbox::Runner::terminate(&mut runner).await?;
    // A session/launch is not a successful operation just because pipes closed.
    store.record(launch, Outcome::Unknown).await?;
    session_result(result)
}

fn validate_owner_paths(options: &Options) -> Result<()> {
    files::trusted(&options.state_dir)?;
    files::trusted(
        options
            .policy
            .parent()
            .ok_or(Code("policy_parent_required"))?,
    )?;
    files::trusted(&options.workspace)?;
    Ok(())
}

fn session_result(result: std::result::Result<(), Error>) -> Result<()> {
    match result {
        Ok(()) | Err(Error::Closed) => Ok(()),
        Err(e) => {
            if e.reason() == Reason::CatalogDenied {
                eprintln!(
                    "catalog_review_required: stop sessions, run clawbell pins --state-dir <private-state> review, verify upstream changes, then accept the reviewed ID and reconnect"
                );
            }
            Err(e.into())
        }
    }
}

fn validate_state(
    state: &std::path::Path,
    workspace: &std::path::Path,
    server: &str,
) -> Result<()> {
    if state.starts_with(workspace)
        || ["/usr", "/etc", "/var"]
            .iter()
            .any(|p| state.starts_with(p))
    {
        return Err(Code("state_exposed_to_runner").into());
    }
    if server.is_empty() || server.len() > 128 {
        return Err(Code("invalid_server_identity").into());
    }
    Ok(())
}

// Outer boundary records refusals from policy, pinned schemas and DLP as well as
// method permissions. The store accepts only fixed codes, never packet contents.
struct SessionGate<G> {
    inner: G,
    store: OperationStore,
}
impl<G: Gate> Gate for SessionGate<G> {
    fn permits_remote(&self) -> bool {
        self.inner.permits_remote()
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
#[cfg(test)]
fn compose(
    policy: Arc<Policy>,
    baseline: BaselineStore,
    store: OperationStore,
    identity: String,
) -> Result<impl Gate> {
    compose_monitor(policy, baseline, store, identity, None)
}
fn compose_monitor(
    policy: Arc<Policy>,
    baseline: BaselineStore,
    store: OperationStore,
    identity: String,
    monitor: Option<clawbell_proxy::monitor::Monitor>,
) -> Result<impl Gate> {
    let audit = AuditGate {
        remote: false,
        store: store.clone(),
        pending: HashMap::new(),
    };
    let gate = PolicyGate::new(audit, policy, baseline, identity)?;
    let gate = if let Some(monitor) = monitor {
        gate.with_monitor(monitor)
    } else {
        gate
    };
    Ok(SessionGate {
        inner: LocalVaultGate::new(gate, Vec::new(), Limits::default().message_bytes)?,
        store,
    })
}
#[cfg(test)]
#[path = "attack_tests.rs"]
mod tests;

/// Exercise the actual forwarding gate against an intentionally unavailable writer.
pub(crate) async fn verify_audit_refusal(store: OperationStore) -> Result<()> {
    let mut gate = AuditGate {
        remote: false,
        store,
        pending: HashMap::new(),
    };
    let message = Envelope::parse(
        br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
        Direction::Client,
        Limits::default().message_bytes,
    )?;
    if !matches!(
        gate.inspect(Direction::Client, &message).await,
        Err(Error::Refused(Reason::AuditUnavailable))
    ) {
        return Err(Code("audit_loss_probe_failed").into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
enum LaunchRunner {
    Native(NativeRunner),
    Skill(clawbell_sandbox::transaction::skill::SkillRunner),
}
#[cfg(target_os = "linux")]
impl clawbell_sandbox::Runner for LaunchRunner {
    async fn spawn(
        &mut self,
    ) -> std::result::Result<tokio::process::Child, clawbell_sandbox::LaunchError> {
        match self {
            Self::Native(r) => r.spawn().await,
            Self::Skill(r) => r.spawn().await,
        }
    }
    async fn terminate(&mut self) -> std::result::Result<(), clawbell_sandbox::LaunchError> {
        match self {
            Self::Native(r) => r.terminate().await,
            Self::Skill(r) => r.terminate().await,
        }
    }
}
#[cfg(target_os = "linux")]
enum LaunchGate<G> {
    Ordinary(G),
    Skill(clawbell_proxy::skill::SkillGate<G>),
}
#[cfg(target_os = "linux")]
impl<G: Gate> Gate for LaunchGate<G> {
    fn permits_remote(&self) -> bool {
        false
    }
    async fn inspect(
        &mut self,
        direction: Direction,
        message: &Envelope,
    ) -> std::result::Result<Envelope, Error> {
        match self {
            Self::Ordinary(g) => g.inspect(direction, message).await,
            Self::Skill(g) => g.inspect(direction, message).await,
        }
    }
    async fn terminated(&mut self, reason: Reason) -> std::result::Result<(), Error> {
        match self {
            Self::Ordinary(g) => g.terminated(reason).await,
            Self::Skill(g) => g.terminated(reason).await,
        }
    }
    async fn finish(&mut self) -> std::result::Result<(), Error> {
        match self {
            Self::Ordinary(g) => g.finish().await,
            Self::Skill(g) => g.finish().await,
        }
    }
}

/// Compose the same policy/audit/DLP boundary for an explicitly remote endpoint.
/// Credentials are learned by DLP before the first upstream response is exposed.
pub(crate) fn compose_remote(
    policy: Arc<Policy>,
    baseline: BaselineStore,
    store: OperationStore,
    identity: String,
    bearer: Option<&clawbell_proxy::network::Bearer>,
) -> Result<impl Gate + use<>> {
    let audit = AuditGate {
        remote: true,
        store: store.clone(),
        pending: HashMap::new(),
    };
    let policy_gate = PolicyGate::new(audit, policy, baseline, identity)?;
    Ok(SessionGate {
        inner: LocalVaultGate::for_remote(policy_gate, bearer, Limits::default().message_bytes)?,
        store,
    })
}

#[cfg(target_os = "linux")]
async fn prepare_runner(
    config: NativeConfig,
    policy: &Policy,
    instructions: Option<PathBuf>,
    digest: Option<String>,
) -> Result<(
    LaunchRunner,
    Option<clawbell_sandbox::transaction::skill::InstructionBinding>,
)> {
    if let Some(path) = instructions {
        let command: Vec<_> = std::iter::once(config.executable.clone())
            .chain(config.arguments.iter().cloned())
            .collect();
        let scan = crate::skill_scan::prepare(config.workspace, policy, path, &command).await?;
        let binding = scan.instruction_binding();
        let runner = scan.into_runner(
            digest.as_deref().ok_or(Code("skill_scan_required"))?,
            config.cgroup_parent,
            config.limits,
        )?;
        Ok((LaunchRunner::Skill(runner), Some(binding)))
    } else {
        Ok((LaunchRunner::Native(NativeRunner::new(config)?), None))
    }
}
