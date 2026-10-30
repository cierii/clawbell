//! Append-only, payload-free operation audit on a dedicated bounded SQLite writer.
//! Full durability is acknowledged before callers may forward operations. A hard
//! database size/event limit stops new operations; no silent deletion/retention.
use rusqlite::{Connection, params};
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use tokio::sync::{mpsc, oneshot};
/// Static storage failure; never exposes SQL, paths or request data.
#[derive(Debug, thiserror::Error)]
#[error("operation_audit_unavailable")]
pub struct AuditError;
/// Fixed audit vocabulary. `Unknown` never means success or a replay request.
#[derive(Clone, Copy)]
pub enum Outcome {
    /// Durable permission/intention preceding an operation.
    Intent,
    /// A response was inspected (not proof of the remote operation's semantics).
    Response,
    /// A protocol-level error response was received.
    Failure,
    /// Execution or forwarding may have happened without a known result.
    Unknown,
    /// Explicit policy/protocol refusal.
    Denied,
}
impl Outcome {
    fn code(self) -> &'static str {
        match self {
            Self::Intent => "allow_intent",
            Self::Response => "response_received",
            Self::Failure => "error_response",
            Self::Unknown => "outcome_unknown",
            Self::Denied => "deny",
        }
    }
}
struct Write {
    correlation: i64,
    outcome: Outcome,
    answer: oneshot::Sender<Result<i64, AuditError>>,
}
/// Session-local handle. The database generates globally unique correlation IDs;
/// only fixed codes and a policy digest are persisted, never raw arguments/IDs.
#[derive(Clone)]
pub struct OperationStore {
    sender: mpsc::Sender<Write>,
}
impl OperationStore {
    /// Open in an existing trusted 0700 directory outside all sandbox mounts.
    /// Policy digest must be exactly 64 hex digits. Startup does not reinterpret
    /// unfinished intents: readers must treat intents without results as unknown.
    /// # Errors
    /// Refuses unsafe paths, exhausted storage and initialization failures.
    pub async fn open(directory: &Path, policy_digest: String) -> Result<Self, AuditError> {
        if policy_digest.len() != 64 || !policy_digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AuditError);
        }
        let directory = directory.to_owned();
        let (sender, mut receiver) = mpsc::channel::<Write>(32);
        let (ready, result) = oneshot::channel();
        std::thread::Builder::new()
            .name("clawbell-audit".into())
            .spawn(move || {
                let Ok(connection) = open(&directory) else {
                    let _ = ready.send(Err(AuditError));
                    return;
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Some(write) = receiver.blocking_recv() {
                    let result = append(
                        &connection,
                        &policy_digest,
                        write.correlation,
                        write.outcome,
                    );
                    let _ = write.answer.send(result);
                }
            })
            .map_err(|_| AuditError)?;
        result.await.map_err(|_| AuditError)??;
        Ok(Self { sender })
    }
    /// Durably append a fixed event. Pass zero for a new correlation ID and the
    /// returned row ID for its response. Queue saturation refuses immediately.
    /// # Errors
    /// Storage, quota or writer failure prevents execution; no fallback exists.
    pub async fn record(&self, correlation: i64, outcome: Outcome) -> Result<i64, AuditError> {
        if correlation < 0 {
            return Err(AuditError);
        }
        let (answer, result) = oneshot::channel();
        self.sender
            .try_send(Write {
                correlation,
                outcome,
                answer,
            })
            .map_err(|_| AuditError)?;
        result.await.map_err(|_| AuditError)?
    }
}
fn open(directory: &Path) -> Result<Connection, AuditError> {
    let meta = std::fs::symlink_metadata(directory).map_err(|_| AuditError)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        return Err(AuditError);
    }
    let path = directory.join("operations.sqlite3");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(AuditError),
    }
    let meta = std::fs::symlink_metadata(&path).map_err(|_| AuditError)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(AuditError);
    }
    let connection = Connection::open(path).map_err(|_| AuditError)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(100))
        .map_err(|_| AuditError)?;
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=16384;
        CREATE TABLE IF NOT EXISTS events_v1 (
            id INTEGER PRIMARY KEY, correlation INTEGER NOT NULL,
            utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            policy_sha256 TEXT NOT NULL, outcome TEXT NOT NULL
        ) STRICT;
        CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;") .map_err(|_| AuditError)?;
    Ok(connection)
}
fn append(
    connection: &Connection,
    policy: &str,
    correlation: i64,
    outcome: Outcome,
) -> Result<i64, AuditError> {
    connection
        .execute(
            "INSERT INTO events_v1(correlation,policy_sha256,outcome) VALUES(?1,?2,?3)",
            params![correlation, policy, outcome.code()],
        )
        .map_err(|_| AuditError)?;
    Ok(connection.last_insert_rowid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> std::io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "clawbell-audit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
            Ok(Self(path))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[tokio::test]
    async fn durable_correlations_payload_free_append_only_and_reopen() -> Result {
        let dir = Directory::new()?;
        let store = OperationStore::open(&dir.0, "a".repeat(64)).await?;
        let first = store.record(0, Outcome::Intent).await?;
        store.record(first, Outcome::Response).await?;
        let unknown = store.record(0, Outcome::Intent).await?;
        drop(store);
        let reader = open(&dir.0)?;
        let outcome: String = reader.query_row(
            "SELECT outcome FROM events_v1 WHERE correlation=?1",
            [first],
            |row| row.get(0),
        )?;
        assert_eq!(outcome, "response_received");
        // Crash-like unfinished intent is retained; reopening never replays it or
        // fabricates a success, even when no Unknown event could be written.
        let pending: i64 = reader.query_row(
            "SELECT COUNT(*) FROM events_v1 WHERE id=?1 AND outcome='allow_intent'",
            [unknown],
            |row| row.get(0),
        )?;
        assert_eq!(pending, 1);
        assert!(reader.execute("DELETE FROM events_v1", []).is_err());
        assert!(
            reader
                .execute("UPDATE events_v1 SET outcome='response_received'", [])
                .is_err()
        );
        let mode = std::fs::metadata(dir.0.join("operations.sqlite3"))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        Ok(())
    }
    #[tokio::test]
    async fn unsafe_storage_and_write_failure_refuse_acknowledgement() -> Result {
        let dir = Directory::new()?;
        assert!(
            OperationStore::open(&dir.0, "raw secret".into())
                .await
                .is_err()
        );
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755))?;
        assert!(OperationStore::open(&dir.0, "a".repeat(64)).await.is_err());
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700))?;
        let store = OperationStore::open(&dir.0, "b".repeat(64)).await?;
        let connection = open(&dir.0)?;
        connection.execute_batch("CREATE TRIGGER synthetic_disk_failure BEFORE INSERT ON events_v1 BEGIN SELECT RAISE(ABORT,'synthetic'); END;")?;
        assert!(store.record(0, Outcome::Intent).await.is_err());
        assert!(store.record(-1, Outcome::Intent).await.is_err());
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM events_v1", [], |row| row.get(0))?;
        assert_eq!(count, 0);
        Ok(())
    }
}
