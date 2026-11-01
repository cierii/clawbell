//! Owner-private IPC and bounded, one-use human approval rendezvous.
//!
//! Keep the socket directory outside all child mounts. The caller must supply
//! durable audit and independent method authorization through the inner Gate.
use crate::Error;
use clawbell_core::dlp::Vault;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{broadcast, oneshot},
};

const MAX: usize = 65536;
/// A redacted monitor event. Never contains executable approval credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic rendezvous identifier; zero denotes a telemetry event.
    pub id: u64,
    /// Human-readable JSON, sanitized again by the terminal renderer.
    pub display: String,
}
struct Pending {
    event: Event,
    reply: oneshot::Sender<bool>,
}
struct State {
    next: u64,
    pending: BTreeMap<u64, Pending>,
    vault: Vault,
    recent: std::collections::VecDeque<Event>,
}
/// Cloneable owner-side monitor. Telemetry is lossy; approval is fail-closed.
#[derive(Clone)]
pub struct Monitor {
    state: Arc<Mutex<State>>,
    events: broadcast::Sender<Event>,
}
// Remove only the socket inode created by this service, including cancellation.
// A pre-existing endpoint is never adopted; crash leftovers require owner cleanup.
struct SocketGuard {
    path: std::path::PathBuf,
    device: u64,
    inode: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if let Ok(meta) = std::fs::symlink_metadata(&self.path)
            && meta.file_type().is_socket()
            && meta.dev() == self.device
            && meta.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
impl Monitor {
    /// Create bounded state with a dedicated session-scoped display redactor.
    /// # Errors
    /// Refuses unavailable entropy.
    pub fn new() -> Result<Self, Error> {
        let (events, _) = broadcast::channel(128);
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                next: 1,
                recent: std::collections::VecDeque::new(),
                pending: BTreeMap::new(),
                vault: Vault::new(MAX).map_err(|_| Error::Denied)?,
            })),
            events,
        })
    }
    /// Register an owner-known secret before publishing any associated metadata.
    /// # Errors
    /// Refuses invalid secrets or exhausted vault capacity.
    pub fn register_secret(&self, secret: &str) -> Result<(), Error> {
        self.state
            .lock()
            .map_err(|_| Error::Denied)?
            .vault
            .register(secret)
            .map_err(|_| Error::Denied)?;
        Ok(())
    }
    /// Publish a bounded complete JSON packet or owner-configured server status.
    /// Slow/disconnected monitors cannot block proxy execution.
    /// # Errors
    /// Refuses oversized or unredactable data.
    pub fn publish(&self, value: &Value) -> Result<(), Error> {
        let display = self.display(value)?;
        let event = Event { id: 0, display };
        let mut state = self.state.lock().map_err(|_| Error::Denied)?;
        if state.recent.len() == 128 {
            state.recent.pop_front();
        }
        state.recent.push_back(event.clone());
        let _ = self.events.send(event);
        Ok(())
    }
    fn display(&self, value: &Value) -> Result<String, Error> {
        let text = serde_json::to_string(value).map_err(|_| Error::Denied)?;
        if text.len() > MAX {
            return Err(Error::Limit);
        }
        self.state
            .lock()
            .map_err(|_| Error::Denied)?
            .vault
            .redact(&text)
            .map_err(|_| Error::Denied)
    }
    /// Suspend exactly this immutable call, never issuing a reusable token.
    /// Cancellation removes the sender on the next request/snapshot; stale replies
    /// cannot authorize another call. Human wait is excluded from packet latency.
    /// # Errors
    /// Denies timeout, cancellation, overload, missing owner or explicit rejection.
    pub async fn approve(&self, context: Value) -> Result<(), Error> {
        let display = self.display(&context)?;
        if display.chars().count() > 1800 {
            return Err(Error::Limit);
        }
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut state = self.state.lock().map_err(|_| Error::Denied)?;
            state.pending.retain(|_, p| !p.reply.is_closed());
            if state.pending.len() >= 32 || self.events.receiver_count() == 0 {
                return Err(Error::Denied);
            }
            let id = state.next;
            state.next = id.checked_add(1).ok_or(Error::Denied)?;
            let event = Event { id, display };
            state.pending.insert(
                id,
                Pending {
                    event: event.clone(),
                    reply: tx,
                },
            );
            let _ = self.events.send(event);
            id
        };
        let result = tokio::time::timeout(Duration::from_secs(25), rx).await;
        self.state
            .lock()
            .map_err(|_| Error::Denied)?
            .pending
            .remove(&id);
        if matches!(result, Ok(Ok(true))) {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
    /// Serve one owner connection at a time in an existing private 0700 directory.
    /// Existing sockets are never removed or replaced. Normal shutdown removes
    /// this service's socket; crash leftovers require explicit owner cleanup.
    /// Peer UID and filesystem ownership must both match.
    /// # Errors
    /// Returns sanitized I/O errors for unsafe paths, disconnects or framing faults.
    pub async fn serve(&self, path: &Path) -> Result<(), Error> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let parent = path.parent().ok_or(Error::Denied)?;
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| Error::Denied)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(Error::Denied);
        }
        let listener = UnixListener::bind(path).map_err(|_| Error::Denied)?;
        let socket_meta = std::fs::symlink_metadata(path).map_err(|_| Error::Denied)?;
        let _cleanup = SocketGuard {
            path: path.to_owned(),
            device: socket_meta.dev(),
            inode: socket_meta.ino(),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::Denied)?;
        loop {
            let (stream, _) = listener.accept().await.map_err(|_| Error::Transport)?;
            if stream.peer_cred().map_err(|_| Error::Denied)?.uid() != metadata.uid() {
                continue;
            }
            let _ = self.connection(stream).await;
            // Disconnect invalidates every rendezvous before accepting another owner.
            self.state
                .lock()
                .map_err(|_| Error::Denied)?
                .pending
                .clear();
        }
    }
    async fn connection(&self, stream: UnixStream) -> Result<(), Error> {
        let mut events = self.events.subscribe();
        let snapshot = {
            let mut state = self.state.lock().map_err(|_| Error::Denied)?;
            state.pending.retain(|_, p| !p.reply.is_closed());
            state
                .pending
                .values()
                .map(|p| p.event.clone())
                .chain(state.recent.iter().cloned())
                .collect::<Vec<_>>()
        };
        let (read, mut write) = stream.into_split();
        for event in snapshot {
            send(&mut write, &event).await?;
        }
        let mut reader = BufReader::new(read);
        let mut buffer = Vec::new();
        loop {
            tokio::select! {
                event = events.recv() => send(&mut write, &event.map_err(|_| Error::Denied)?).await?,
                command = frame(&mut reader, &mut buffer) => {
                    let command: Command = serde_json::from_slice(&command?).map_err(|_| Error::Denied)?;
                    let pending = self.state.lock().map_err(|_| Error::Denied)?.pending.remove(&command.id);
                    if let Some(pending) = pending { let _ = pending.reply.send(command.allow); }
                }
            }
        }
    }
}
/// Owner decision for a single live rendezvous. Unknown fields are refused.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    /// Identifier displayed in the pending queue.
    pub id: u64,
    /// Explicit approval or rejection.
    pub allow: bool,
}
/// Read bounded newline framing without allocating an unbounded line.
/// # Errors
/// Refuses oversized frames, EOF and I/O failure.
pub async fn frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    bytes: &mut Vec<u8>,
) -> Result<Vec<u8>, Error> {
    loop {
        let chunk = reader.fill_buf().await.map_err(|_| Error::Transport)?;
        if chunk.is_empty() {
            return Err(Error::Closed);
        }
        let count = chunk
            .iter()
            .position(|b| *b == b'\n')
            .map_or(chunk.len(), |i| i + 1);
        if bytes.len() + count > MAX * 2 {
            return Err(Error::Limit);
        }
        bytes.extend_from_slice(&chunk[..count]);
        reader.consume(count);
        if bytes.last() == Some(&b'\n') {
            return Ok(std::mem::take(bytes));
        }
    }
}
async fn send<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    event: &Event,
) -> Result<(), Error> {
    let mut bytes = serde_json::to_vec(event).map_err(|_| Error::Denied)?;
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(2), writer.write_all(&bytes))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Transport)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;
    #[tokio::test]
    async fn one_use_bound_rendezvous_and_redaction() {
        let monitor = Monitor::new().unwrap();
        monitor
            .register_secret("synthetic-private-value-987654")
            .unwrap();
        let mut events = monitor.events.subscribe();
        let task_monitor = monitor.clone();
        let task = tokio::spawn(async move {
            task_monitor
                .approve(json!({"arguments": "synthetic-private-value-987654"}))
                .await
        });
        let event = events.recv().await.unwrap();
        assert!(!event.display.contains("synthetic-private-value-987654"));
        let pending = monitor
            .state
            .lock()
            .unwrap()
            .pending
            .remove(&event.id)
            .unwrap();
        pending.reply.send(true).unwrap();
        assert!(task.await.unwrap().is_ok());
        assert!(
            monitor
                .state
                .lock()
                .unwrap()
                .pending
                .remove(&event.id)
                .is_none()
        );
    }
    #[tokio::test]
    async fn absent_owner_and_rejection_deny() {
        let monitor = Monitor::new().unwrap();
        assert!(monitor.approve(json!({})).await.is_err());
        let mut events = monitor.events.subscribe();
        let other = monitor.clone();
        let task = tokio::spawn(async move { other.approve(json!({})).await });
        let event = events.recv().await.unwrap();
        monitor
            .state
            .lock()
            .unwrap()
            .pending
            .remove(&event.id)
            .unwrap()
            .reply
            .send(false)
            .unwrap();
        assert!(task.await.unwrap().is_err());
    }
    #[tokio::test]
    async fn disconnect_denies_pending_and_reconnect_cannot_reuse() {
        use std::os::unix::fs::PermissionsExt;
        let monitor = Monitor::new().unwrap();
        let root = std::env::temp_dir().join(format!("clawbell-disconnect-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("monitor.sock");
        let other = monitor.clone();
        let endpoint = path.clone();
        let server = tokio::spawn(async move { other.serve(&endpoint).await });
        let stream = loop {
            if let Ok(stream) = UnixStream::connect(&path).await {
                break stream;
            }
            tokio::task::yield_now().await;
        };
        let mut reader = BufReader::new(stream);
        // Observe an event to synchronize subscription before requesting approval.
        loop {
            if monitor.events.receiver_count() > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        let other = monitor.clone();
        let call = tokio::spawn(async move { other.approve(json!({"tool":"synthetic"})).await });
        let mut buffer = Vec::new();
        let bytes = frame(&mut reader, &mut buffer).await.unwrap();
        let event: Event = serde_json::from_slice(&bytes).unwrap();
        drop(reader);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), call)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(
            !monitor
                .state
                .lock()
                .unwrap()
                .pending
                .contains_key(&event.id)
        );
        server.abort();
        let _ = server.await;
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn approval_deadline_denies_and_removes_sender() {
        let monitor = Monitor::new().unwrap();
        let _owner = monitor.events.subscribe();
        assert!(monitor.approve(json!({"tool":"synthetic"})).await.is_err());
        assert!(monitor.state.lock().unwrap().pending.is_empty());
    }
    #[tokio::test]
    async fn frame_limits_and_eof() {
        let mut bytes = Vec::new();
        let mut input = &b"{}\n"[..];
        assert_eq!(frame(&mut input, &mut bytes).await.unwrap(), b"{}\n");
        assert!(frame(&mut input, &mut bytes).await.is_err());
        let oversized = vec![b'x'; MAX * 2 + 1];
        assert!(frame(&mut oversized.as_slice(), &mut bytes).await.is_err());
    }
    #[test]
    #[ignore = "release latency experiment"]
    fn monitor_packet_under_ten_ms() {
        let monitor = Monitor::new().unwrap();
        let _subscriber = monitor.events.subscribe();
        let packet = json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"synthetic packet"}]}});
        for _ in 0..200 {
            monitor.publish(&packet).unwrap();
        }
        let mut maximum = Duration::ZERO;
        for _ in 0..2000 {
            let start = std::time::Instant::now();
            monitor.publish(&packet).unwrap();
            maximum = maximum.max(start.elapsed());
        }
        eprintln!("monitor maximum: {maximum:?}");
        assert!(maximum < Duration::from_millis(10));
    }
}
