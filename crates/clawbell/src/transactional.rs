//! Production one-operation MCP supervisor. Only initialization and catalog reads
//! are replayed, never prior tool calls. Every process has a private filesystem;
//! results remain private until containment cleanup, inspection and publication.
use crate::{errors::Code, files, launch};
use clawbell_audit::{
    baseline::BaselineStore,
    operations::{OperationStore, Outcome, Reason},
};
use clawbell_core::{dlp::Vault, policy::Policy, signatures};
use clawbell_proxy::{Direction, Envelope, Error, Limits, Session, monitor::Monitor};
use clawbell_sandbox::{
    native::{NativeConfig, ResourceLimits},
    transaction::{Effect, Transaction, TreeLimits, commit::Binding},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::Arc,
    time::{Duration, UNIX_EPOCH},
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

#[derive(clap::Args)]
pub struct Options {
    #[command(flatten)]
    pub proxy: launch::Options,
    /// Existing private durable directory outside runner mounts. An existing
    /// publication journal blocks new writes until explicit owner recovery.
    #[arg(long)]
    pub journal_dir: PathBuf,
}

pub async fn run(options: Options) -> files::Result<()> {
    let owner = options.proxy;
    let limits = Limits {
        pending: 1,
        ..owner.limits()?
    };
    launch::validate_owner_paths(&owner)?;
    if owner.skill_scan_digest.is_some() || owner.skill_instructions_file.is_some() {
        return Err(Code("transaction_skill_mode_unsupported").into());
    }
    let workspace = std::fs::canonicalize(&owner.workspace)?;
    let state = std::fs::canonicalize(&owner.state_dir)?;
    launch::validate_state(&state, &workspace, &owner.server)?;
    files::trusted(&options.journal_dir)?;
    let journal_path = std::fs::canonicalize(&options.journal_dir)?;
    launch::validate_state(&journal_path, &workspace, &owner.server)?;
    let journal = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&journal_path)?;
    let socket = launch::monitor_endpoint(owner.monitor_socket.clone(), &workspace)?
        .ok_or(Code("transaction_owner_monitor_required"))?;
    let policy_bytes = files::read(&owner.policy, 1024 * 1024)?;
    let policy = Arc::new(Policy::parse(std::str::from_utf8(&policy_bytes)?)?);
    let identity = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            &owner.server,
            &workspace,
            &owner.command,
            "transaction-v1"
        ))?)
    );
    let store = OperationStore::open_session(
        &state,
        format!("{:x}", Sha256::digest(&policy_bytes)),
        identity.clone(),
    )
    .await?;
    let baseline = BaselineStore::open(&state).await?;
    let monitor = Monitor::new()?;
    let mut gate = launch::compose_monitor(
        policy.clone(),
        baseline,
        store.clone(),
        identity.clone(),
        Some(monitor.clone()),
    )?;
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let supervisor = Supervisor {
        cancelled: cancel_rx,
        owner,
        policy,
        store,
        monitor: monitor.clone(),
        journal,
        identity,
        transcript: Vec::new(),
        transcript_bytes: 0,
        vault: Vault::new(limits.message_bytes)?,
    };
    let (relay_side, worker_side) = tokio::io::duplex(limits.message_bytes);
    let (read, write) = tokio::io::split(relay_side);
    // Keep the supervisor future alive after client cancellation. In particular,
    // never detach or abort a running publication worker and lose its audit result.
    let relay = async {
        let result = tokio::select! {
            result = clawbell_proxy::stdio::relay(tokio::io::stdin(), tokio::io::stdout(), read, write, &mut gate, limits) => result,
            _ = monitor.serve(&socket) => Err(Error::Denied),
        };
        let _ = cancel_tx.send(true);
        result
    };
    let (relay, worker) = tokio::join!(relay, supervisor.serve(worker_side, limits));
    worker?;
    match relay {
        Ok(()) | Err(Error::Closed) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

struct Exchange {
    request: Envelope,
    response: Option<Envelope>,
}
struct Supervisor {
    cancelled: tokio::sync::watch::Receiver<bool>,
    owner: launch::Options,
    policy: Arc<Policy>,
    store: OperationStore,
    monitor: Monitor,
    journal: File,
    identity: String,
    transcript: Vec<Exchange>,
    transcript_bytes: usize,
    vault: Vault,
}
impl Supervisor {
    fn config(&self, limits: Limits) -> Result<NativeConfig, Error> {
        Ok(NativeConfig {
            workspace: self.owner.workspace.clone(),
            executable: self.owner.command.first().ok_or(Error::Denied)?.clone(),
            arguments: self.owner.command.iter().skip(1).cloned().collect(),
            cgroup_parent: self.owner.cgroup_parent.clone(),
            limits: ResourceLimits {
                lifetime: limits.request_timeout,
                ..ResourceLimits::default()
            },
        })
    }
    async fn serve(mut self, stream: tokio::io::DuplexStream, limits: Limits) -> Result<(), Error> {
        let (read, mut write) = tokio::io::split(stream);
        let mut read = BufReader::new(read);
        loop {
            let Some(bytes) = packet(&mut read, limits).await? else {
                return Ok(());
            };
            let request = Envelope::parse(&bytes, Direction::Client, limits.message_bytes)?;
            let fingerprint: [u8; 32] = Sha256::digest(request.encode()?).into();
            let correlation = self
                .store
                .record_digest(0, Outcome::Intent, Reason::Unspecified, Some(fingerprint))
                .await
                .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
            let result = self.operation(&request, correlation, limits).await;
            if let Err(error) = &result {
                self.store
                    .record_reason(
                        correlation,
                        if matches!(
                            error,
                            Error::Transport
                                | Error::Timeout
                                | Error::Refused(Reason::PublicationRecovery)
                        ) {
                            Outcome::Unknown
                        } else {
                            Outcome::Denied
                        },
                        error.reason(),
                    )
                    .await
                    .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
            }
            let response = result?;
            if let Some(response) = response {
                write
                    .write_all(&response.encode()?)
                    .await
                    .map_err(|_| Error::Transport)?;
                write.write_all(b"\n").await.map_err(|_| Error::Transport)?;
                write.flush().await.map_err(|_| Error::Transport)?;
            }
        }
    }
    async fn operation(
        &mut self,
        request: &Envelope,
        correlation: i64,
        limits: Limits,
    ) -> Result<Option<Envelope>, Error> {
        let tool = request.method() == Some("tools/call");
        if !matches!(
            request.method(),
            Some("initialize" | "notifications/initialized" | "tools/list" | "tools/call" | "ping")
        ) {
            return Err(Error::Refused(Reason::MethodDenied));
        }
        let name = request
            .value()
            .pointer("/params/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let arguments = request
            .value()
            .pointer("/params/arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let effect = if tool {
            match self
                .policy
                .approval_scope(name, &arguments)
                .get("effect")
                .and_then(Value::as_str)
            {
                Some("read") => Effect::ReadOnly,
                Some("write") => Effect::Write,
                _ => return Err(Error::Refused(Reason::OpaqueEffect)),
            }
        } else {
            Effect::ReadOnly
        };
        let mut transaction =
            Transaction::prepare(self.config(limits)?, effect, TreeLimits::default())
                .await
                .map_err(transaction_error)?;
        let mut child = transaction.spawn().await.map_err(transaction_error)?;
        let mut cancelled = self.cancelled.clone();
        let result = tokio::select! {
            result = tokio::time::timeout(limits.request_timeout, self.execute(&mut child, request, limits)) => result,
            _ = cancelled.changed() => Ok(Err(Error::Cancelled)),
        };
        let reaped = reap(&mut child).await;
        if let Err(error) = reaped {
            transaction.inspect().await.map_err(transaction_error)?;
            return Err(error);
        }
        // On every error explicitly stop and inspect; drop is a last-resort kill,
        // never proof that descendants stopped or that an operation was undone.
        let response = match result {
            Ok(Ok(response)) => response,
            other => {
                transaction.inspect().await.map_err(transaction_error)?;
                return Err(match other {
                    Ok(Err(e)) => e,
                    _ => Error::Timeout,
                });
            }
        };
        if effect == Effect::ReadOnly {
            transaction.inspect().await.map_err(transaction_error)?;
            self.record(correlation, Outcome::Inspected).await?;
        } else {
            // An upstream error or isError response can never publish a partial effect.
            if response.as_ref().is_none_or(|r| {
                r.value().get("error").is_some()
                    || r.value().pointer("/result/isError") == Some(&Value::Bool(true))
            }) {
                transaction.inspect().await.map_err(transaction_error)?;
                return Err(Error::Denied);
            }
            let binding = self.binding(name, &arguments, correlation)?;
            let candidate = transaction
                .inspect_for_commit()
                .await
                .map_err(transaction_error)?;
            self.record(correlation, Outcome::Inspected).await?;
            self.publish(candidate, binding, correlation, limits, request)
                .await?;
        }
        if !tool && request.method() != Some("ping") {
            self.transcript_bytes += request.encode()?.len()
                + response
                    .as_ref()
                    .map(Envelope::encode)
                    .transpose()?
                    .map_or(0, |b| b.len());
            if self.transcript.len() >= 66 || self.transcript_bytes > 8 * 1024 * 1024 {
                return Err(Error::Limit);
            }
            self.transcript.push(Exchange {
                request: request.clone(),
                response: response.clone(),
            });
        }
        self.record(correlation, Outcome::Response).await?;
        Ok(response)
    }
    async fn publish(
        &mut self,
        candidate: clawbell_sandbox::transaction::commit::Candidate,
        binding: Binding,
        correlation: i64,
        limits: Limits,
        request: &Envelope,
    ) -> Result<(), Error> {
        let policy = self.policy.clone();
        let mut vault = std::mem::replace(
            &mut self.vault,
            Vault::new(limits.message_bytes).map_err(|_| Error::Denied)?,
        );
        let review_binding = binding.clone();
        let (review, vault) = tokio::task::spawn_blocking(move || {
            let review =
                candidate.review(review_binding, &policy, &mut vault, Duration::from_secs(25));
            (review, vault)
        })
        .await
        .map_err(|_| Error::Denied)?;
        self.vault = vault;
        let review = review.map_err(|_| Error::Denied)?;
        self.store
            .record_digest(
                correlation,
                Outcome::Review,
                Reason::Unspecified,
                Some(review.digest()),
            )
            .await
            .map_err(|_| Error::Refused(Reason::AuditUnavailable))?;
        let digest = review.digest();
        let display_digest = digest.iter().fold(String::new(), |mut output, byte| {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
            output
        });
        if *self.cancelled.borrow() {
            return Err(Error::Cancelled);
        }
        tokio::select! {
            result = self.monitor.approve(json!({"kind":"file_publication", "invocation":request.value().get("params"), "effect":"replace_existing_files", "digest":display_digest, "expires_utc_seconds":review.expires().duration_since(UNIX_EPOCH).map_err(|_| Error::Denied)?.as_secs(), "preview":review.preview()})) => result?,
            _ = self.cancelled.changed() => return Err(Error::Cancelled),
        }
        if *self.cancelled.borrow() {
            return Err(Error::Cancelled);
        }
        let approval = review.approve(digest).map_err(|_| Error::Denied)?;
        self.record(correlation, Outcome::Approved).await?;
        if *self.cancelled.borrow() {
            return Err(Error::Cancelled);
        }
        let journal = self.journal.try_clone().map_err(|_| Error::Denied)?;
        let policy = self.policy.clone();
        // This worker is always joined, including when the client disconnects.
        let result = tokio::task::spawn_blocking(move || {
            review.commit(approval, &binding, &policy, &journal)
        })
        .await
        .map_err(|_| Error::Transport)?;
        result.map_err(|error| {
            use clawbell_sandbox::transaction::commit::CommitError;
            Error::Refused(match error {
                CommitError::RecoveryRequired => Reason::PublicationRecovery,
                CommitError::Conflict => Reason::PublicationConflict,
                CommitError::Journal => Reason::PublicationJournal,
                _ => Reason::InspectionDenied,
            })
        })?;
        self.record(correlation, Outcome::Published).await?;
        Ok(())
    }
    async fn record(&self, correlation: i64, outcome: Outcome) -> Result<(), Error> {
        self.store
            .record(correlation, outcome)
            .await
            .map(|_| ())
            .map_err(|_| Error::Refused(Reason::AuditUnavailable))
    }
    fn binding(&self, name: &str, arguments: &Value, correlation: i64) -> Result<Binding, Error> {
        let definition = self
            .transcript
            .iter()
            .filter_map(|e| e.response.as_ref())
            .filter_map(|e| e.value().pointer("/result/tools").and_then(Value::as_array))
            .flatten()
            .find(|t| t.get("name").and_then(Value::as_str) == Some(name))
            .ok_or(Error::Denied)?;
        let schema = signatures::tool_digests(std::slice::from_ref(definition))
            .map_err(|_| Error::Denied)?
            .first()
            .copied()
            .ok_or(Error::Denied)?;
        Ok(Binding {
            session: Sha256::digest(
                serde_json::to_vec(&(self.store.session_id(), &self.identity, correlation))
                    .map_err(|_| Error::Denied)?,
            )
            .into(),
            server: Sha256::digest(self.identity.as_bytes()).into(),
            schema,
            arguments: Sha256::digest(
                signatures::argument_digest(arguments)
                    .map_err(|_| Error::Denied)?
                    .as_bytes(),
            )
            .into(),
        })
    }
    async fn execute(
        &mut self,
        child: &mut tokio::process::Child,
        request: &Envelope,
        limits: Limits,
    ) -> Result<Option<Envelope>, Error> {
        let mut write = child.stdin.take().ok_or(Error::Transport)?;
        let mut read = BufReader::new(child.stdout.take().ok_or(Error::Transport)?);
        let mut stderr = child.stderr.take().ok_or(Error::Transport)?;
        // Drain, but never disclose stderr. Total output is bounded independently.
        let exchange = async {
            let mut session = Session::new(limits)?;
            for prior in &self.transcript {
                let actual =
                    exchange(&mut read, &mut write, &mut session, &prior.request, limits).await?;
                if actual.as_ref().map(Envelope::value)
                    != prior.response.as_ref().map(Envelope::value)
                {
                    return Err(Error::Refused(Reason::CatalogDenied));
                }
            }
            exchange(&mut read, &mut write, &mut session, request, limits).await
        };
        let drain = async {
            use tokio::io::AsyncReadExt;
            let mut bytes = [0; 4096];
            let mut total = 0;
            loop {
                let n = stderr
                    .read(&mut bytes)
                    .await
                    .map_err(|_| Error::Transport)?;
                if n == 0 {
                    return Err(Error::Closed);
                }
                total += n;
                if total > limits.message_bytes {
                    return Err(Error::Limit);
                }
            }
        };
        let response = tokio::select! { result = exchange => result, error = drain => error }?;
        if let Some(response) = &response {
            clawbell_proxy::dlp::inspect_server_message(
                &mut self.vault,
                response,
                limits.message_bytes,
            )?;
        }
        Ok(response)
    }
}
/// Reap the direct child explicitly. Transaction inspection separately kills
/// and confirms cleanup of every descendant, including detached processes.
async fn reap(child: &mut tokio::process::Child) -> Result<(), Error> {
    let _ = child.start_kill();
    tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .map_err(|_| Error::Host(clawbell_sandbox::LaunchError::CleanupFailed))?
        .map_err(|_| Error::Host(clawbell_sandbox::LaunchError::CleanupFailed))?;
    Ok(())
}
fn transaction_error(error: clawbell_sandbox::transaction::TransactionError) -> Error {
    match error {
        clawbell_sandbox::transaction::TransactionError::Isolation(error) => Error::Host(error),
        _ => Error::Denied,
    }
}
async fn packet<R: AsyncBufRead + Unpin>(
    read: &mut R,
    limits: Limits,
) -> Result<Option<Vec<u8>>, Error> {
    let mut bytes = Vec::new();
    loop {
        let buf = read.fill_buf().await.map_err(|_| Error::Transport)?;
        if buf.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(Error::InvalidMessage)
            };
        }
        let n = buf
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buf.len(), |n| n + 1);
        if bytes.len() + n > limits.message_bytes + 1 {
            return Err(Error::Limit);
        }
        let done = buf[n - 1] == b'\n';
        bytes.extend_from_slice(&buf[..n]);
        read.consume(n);
        if done {
            bytes.pop();
            return Ok(Some(bytes));
        }
    }
}
async fn exchange<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    session: &mut Session,
    request: &Envelope,
    limits: Limits,
) -> Result<Option<Envelope>, Error> {
    session.accept(Direction::Client, request)?;
    write
        .write_all(&request.encode()?)
        .await
        .map_err(|_| Error::Transport)?;
    write.write_all(b"\n").await.map_err(|_| Error::Transport)?;
    write.flush().await.map_err(|_| Error::Transport)?;
    if request.id().is_none() {
        return Ok(None);
    }
    let bytes = packet(read, limits).await?.ok_or(Error::Closed)?;
    let response = Envelope::parse(&bytes, Direction::Server, limits.message_bytes)?;
    if response.method().is_some() || response.id() != request.id() {
        return Err(Error::Protocol);
    }
    session.accept(Direction::Server, &response)?;
    Ok(Some(response))
}
