//! Append-only, payload-free operation audit on a dedicated bounded SQLite writer.
//! Full durability is acknowledged before callers may forward operations. A hard
//! database size/event limit stops new operations; no silent deletion/retention.
use rusqlite::{Connection, params};
use std::path::Path;
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
/// Payload-free reason shared by policy, inspection and transport boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Stable `unspecified` reason.
    Unspecified,
    /// Stable `invalid_message` reason.
    InvalidMessage,
    /// Stable `invalid_protocol_state` reason.
    Protocol,
    /// Stable `limit_exceeded` reason.
    Limit,
    /// Stable `operation_timeout` reason.
    Timeout,
    /// Stable `transport_failed` reason.
    Transport,
    /// Stable `operation_cancelled` reason.
    Cancelled,
    /// Stable `transport_closed` reason.
    Closed,
    /// Stable `inspection_denied` reason.
    InspectionDenied,
    /// Stable `dlp_denied` reason.
    DlpDenied,
    /// Stable `schema_denied` reason.
    SchemaDenied,
    /// Stable `catalog_denied` reason.
    CatalogDenied,
    /// Stable `method_denied` reason.
    MethodDenied,
    /// Stable `audit_unavailable` reason.
    AuditUnavailable,
    /// Stable `isolation_unavailable` reason.
    IsolationUnavailable,
    /// Stable `unknown_tool` reason.
    UnknownTool,
    /// Stable `opaque_effect` reason.
    OpaqueEffect,
    /// Stable `invalid_arguments` reason.
    InvalidArguments,
    /// Stable `argument_limit` reason.
    ArgumentLimit,
    /// Stable `invalid_path` reason.
    InvalidPath,
    /// Stable `memory_write_denied` reason.
    MemoryWriteDenied,
    /// Stable `default_deny` reason.
    DefaultDeny,
    /// Stable `rule_deny` reason.
    RuleDeny,
    /// Stable `owner_approval_required` reason.
    ApprovalRequired,
}
impl Reason {
    /// Stable storage code containing no peer-supplied data.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::InvalidMessage => "invalid_message",
            Self::Protocol => "invalid_protocol_state",
            Self::Limit => "limit_exceeded",
            Self::Timeout => "operation_timeout",
            Self::Transport => "transport_failed",
            Self::Cancelled => "operation_cancelled",
            Self::Closed => "transport_closed",
            Self::InspectionDenied => "inspection_denied",
            Self::DlpDenied => "dlp_denied",
            Self::SchemaDenied => "schema_denied",
            Self::CatalogDenied => "catalog_denied",
            Self::MethodDenied => "method_denied",
            Self::AuditUnavailable => "audit_unavailable",
            Self::IsolationUnavailable => "isolation_unavailable",
            Self::UnknownTool => "unknown_tool",
            Self::OpaqueEffect => "opaque_effect",
            Self::InvalidArguments => "invalid_arguments",
            Self::ArgumentLimit => "argument_limit",
            Self::InvalidPath => "invalid_path",
            Self::MemoryWriteDenied => "memory_write_denied",
            Self::DefaultDeny => "default_deny",
            Self::RuleDeny => "rule_deny",
            Self::ApprovalRequired => "owner_approval_required",
        }
    }
}
struct Write {
    correlation: i64,
    outcome: Outcome,
    reason: Reason,
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
        Self::open_session(directory, policy_digest, "0".repeat(64)).await
    }
    /// Create a globally distinct session with an owner-derived upstream digest.
    /// Existing records remain append-only; legacy rows keep explicit legacy IDs.
    /// # Errors
    /// Refuses invalid digests, unsafe storage or a failed durable session insert.
    pub async fn open_session(
        directory: &Path,
        policy_digest: String,
        upstream_digest: String,
    ) -> Result<Self, AuditError> {
        if [&policy_digest, &upstream_digest]
            .iter()
            .any(|digest| digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(AuditError);
        }
        let directory = directory.to_owned();
        let (sender, mut receiver) = mpsc::channel::<Write>(32);
        let (ready, result) = oneshot::channel();
        std::thread::Builder::new()
            .name("clawbell-audit".into())
            .spawn(move || {
                let Ok(_lock) = crate::storage::lock(&directory, "operations.lock", false) else {
                    let _ = ready.send(Err(AuditError)); return;
                };
                let Ok(connection) = open(&directory) else {
                    let _ = ready.send(Err(AuditError));
                    return;
                };
                let session = connection.query_row(
                    "INSERT INTO sessions_v1(policy_sha256,upstream_sha256) VALUES(?1,?2) RETURNING id",
                    params![policy_digest, upstream_digest], |row| row.get::<_, String>(0));
                let Ok(session) = session else {
                    let _ = ready.send(Err(AuditError));
                    return;
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                let mut warned = 0;
                while let Some(write) = receiver.blocking_recv() {
                    warn_capacity(&connection, &mut warned);
                    let result = append(
                        &connection,
                        &policy_digest,
                        write.correlation,
                        write.outcome,
                        write.reason,
                        &session,
                        &upstream_digest,
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
        self.record_reason(correlation, outcome, Reason::Unspecified)
            .await
    }
    /// Durably append an event with its fixed reason and this handle's session.
    /// # Errors
    /// Storage/queue failure denies execution, including terminal-event failure.
    pub async fn record_reason(
        &self,
        correlation: i64,
        outcome: Outcome,
        reason: Reason,
    ) -> Result<i64, AuditError> {
        if correlation < 0 {
            return Err(AuditError);
        }
        let (answer, result) = oneshot::channel();
        self.sender
            .try_send(Write {
                correlation,
                outcome,
                reason,
                answer,
            })
            .map_err(|_| AuditError)?;
        result.await.map_err(|_| AuditError)?
    }
}
fn open(directory: &Path) -> Result<Connection, AuditError> {
    let _file =
        crate::storage::private(directory, "operations.sqlite3", true).map_err(|_| AuditError)?;
    let path = directory.join("operations.sqlite3");
    let mut connection = Connection::open(path).map_err(|_| AuditError)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(100))
        .map_err(|_| AuditError)?;
    warn_capacity(&connection, &mut 0);
    connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=16384;
        CREATE TABLE IF NOT EXISTS events_v1 (
            id INTEGER PRIMARY KEY, correlation INTEGER NOT NULL,
            utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            policy_sha256 TEXT NOT NULL, outcome TEXT NOT NULL
        ) STRICT;
        CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;") .map_err(|_| AuditError)?;
    // Serialize additive migration across concurrent sessions. Never rewrite old
    // records or invent identities/reasons for historical events.
    let tx = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| AuditError)?;
    let columns = {
        let mut query = tx
            .prepare("PRAGMA table_info(events_v1)")
            .map_err(|_| AuditError)?;
        query
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|_| AuditError)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AuditError)?
    };
    for (name, sql) in [
        (
            "session_id",
            "ALTER TABLE events_v1 ADD COLUMN session_id TEXT NOT NULL DEFAULT 'legacy'",
        ),
        (
            "upstream_sha256",
            "ALTER TABLE events_v1 ADD COLUMN upstream_sha256 TEXT NOT NULL DEFAULT 'legacy'",
        ),
        (
            "reason",
            "ALTER TABLE events_v1 ADD COLUMN reason TEXT NOT NULL DEFAULT 'legacy_unspecified'",
        ),
    ] {
        if !columns.iter().any(|column| column == name) {
            tx.execute_batch(sql).map_err(|_| AuditError)?;
        }
    }
    tx.execute_batch("CREATE TABLE IF NOT EXISTS sessions_v1 (
        id TEXT PRIMARY KEY NOT NULL DEFAULT (lower(hex(randomblob(16)))),
        utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
        policy_sha256 TEXT NOT NULL, upstream_sha256 TEXT NOT NULL
    ) STRICT;
    CREATE TRIGGER IF NOT EXISTS sessions_no_update BEFORE UPDATE ON sessions_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
    CREATE TRIGGER IF NOT EXISTS sessions_no_delete BEFORE DELETE ON sessions_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
    CREATE TABLE IF NOT EXISTS operation_migrations_v1 (
        version INTEGER PRIMARY KEY, utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    ) STRICT;
    INSERT OR IGNORE INTO operation_migrations_v1(version) VALUES(2);
    CREATE TRIGGER IF NOT EXISTS migrations_no_update BEFORE UPDATE ON operation_migrations_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
    CREATE TRIGGER IF NOT EXISTS migrations_no_delete BEFORE DELETE ON operation_migrations_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;").map_err(|_| AuditError)?;
    tx.commit().map_err(|_| AuditError)?;
    Ok(connection)
}
fn append(
    connection: &Connection,
    policy: &str,
    correlation: i64,
    outcome: Outcome,
    reason: Reason,
    session: &str,
    upstream: &str,
) -> Result<i64, AuditError> {
    let pages: u32 = connection
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .map_err(|_| AuditError)?;
    if matches!(outcome, Outcome::Intent) && pages >= crate::maintenance::PAGE_LIMIT - 32 {
        return Err(AuditError);
    }
    let inserted = connection
        .execute(
            "INSERT INTO events_v1(correlation,policy_sha256,outcome,reason,session_id,upstream_sha256)
             SELECT ?1,?2,?3,?4,?5,?6 WHERE ?1=0 OR EXISTS (
                SELECT 1 FROM events_v1 WHERE id=?1 AND session_id=?5 AND outcome='allow_intent'
             )",
            params![correlation, policy, outcome.code(), reason.code(), session, upstream],
        )
        .map_err(|_| AuditError)?;
    if inserted != 1 {
        return Err(AuditError);
    }
    Ok(connection.last_insert_rowid())
}

fn warn_capacity(connection: &Connection, warned: &mut u8) {
    if let Ok(status) = crate::maintenance::capacity(connection) {
        let level = status.warning_level;
        if level > *warned {
            eprintln!(
                "audit_capacity_warning: level={level} pages={} limit={}; stop sessions and run clawbell audit rotate --accept",
                status.pages, status.page_limit
            );
            *warned = level;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
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
    async fn additive_migration_sessions_reasons_and_cross_session_refusal() -> Result {
        let dir = Directory::new()?;
        let path = dir.0.join("operations.sqlite3");
        // Create an actual old-schema database, preserving its immutable row.
        let legacy = Connection::open(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        legacy.execute_batch("CREATE TABLE events_v1 (
            id INTEGER PRIMARY KEY, correlation INTEGER NOT NULL,
            utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
            policy_sha256 TEXT NOT NULL, outcome TEXT NOT NULL
        ) STRICT;
        INSERT INTO events_v1(correlation,policy_sha256,outcome) VALUES(0,'legacy-policy','allow_intent');")?;
        drop(legacy);
        let (one, two) = tokio::join!(
            OperationStore::open_session(&dir.0, "a".repeat(64), "b".repeat(64)),
            OperationStore::open_session(&dir.0, "a".repeat(64), "c".repeat(64))
        );
        let (one, two) = (one?, two?);
        let first = one.record(0, Outcome::Intent).await?;
        let second = two.record(0, Outcome::Intent).await?;
        one.record_reason(first, Outcome::Denied, Reason::DlpDenied)
            .await?;
        two.record_reason(second, Outcome::Denied, Reason::MemoryWriteDenied)
            .await?;
        assert!(two.record(first, Outcome::Response).await.is_err());
        assert!(one.record(999_999, Outcome::Response).await.is_err());
        let reader = open(&dir.0)?;
        let mut query = reader
            .prepare("SELECT session_id,upstream_sha256,reason FROM events_v1 ORDER BY id")?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(rows.len(), 5);
        assert_eq!(
            rows[0],
            (
                "legacy".into(),
                "legacy".into(),
                "legacy_unspecified".into()
            )
        );
        assert_ne!(rows[1].0, rows[2].0);
        assert_eq!(rows[1].0.len(), 32);
        assert_eq!(rows[1].0, rows[3].0);
        assert_eq!(rows[2].0, rows[4].0);
        assert_eq!(rows[3].1, "b".repeat(64));
        assert_eq!(rows[3].2, "dlp_denied");
        assert_eq!(rows[4].2, "memory_write_denied");
        assert_eq!(
            reader.query_row(
                "SELECT count(*) FROM operation_migrations_v1 WHERE version=2",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );
        assert!(
            reader
                .execute("UPDATE sessions_v1 SET upstream_sha256='changed'", [])
                .is_err()
        );
        assert!(reader.execute("DELETE FROM sessions_v1", []).is_err());
        assert!(reader.execute("DELETE FROM events_v1", []).is_err());
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
