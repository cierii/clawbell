//! Owner-only audit inspection, bounded JSONL export and lossless offline rotation.
//! Maintenance never replays intents; archives preserve their unknown outcomes.
use crate::{operations::AuditError, storage};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

/// Hard quota used by every writer (normally 64 MiB with 4096-byte pages).
pub const PAGE_LIMIT: u32 = 16384;
/// Visible storage capacity. Levels: 0 normal, 1 >=80%, 2 >=95%, 3 intent reserve.
#[derive(Debug, Serialize)]
pub struct Status {
    /// Currently allocated pages.
    pub pages: u32,
    /// SQLite page size in bytes.
    pub page_size: u32,
    /// Configured maximum pages.
    pub page_limit: u32,
    /// Capacity warning severity, independent of database contents.
    pub warning_level: u8,
}
pub(crate) fn capacity(connection: &Connection) -> Result<Status, AuditError> {
    let pages = connection
        .query_row("PRAGMA page_count", [], |r| r.get(0))
        .map_err(|_| AuditError)?;
    let page_size = connection
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .map_err(|_| AuditError)?;
    let warning_level = if pages >= PAGE_LIMIT - 32 {
        3
    } else if pages * 100 >= PAGE_LIMIT * 95 {
        2
    } else {
        u8::from(pages * 100 >= PAGE_LIMIT * 80)
    };
    Ok(Status {
        pages,
        page_size,
        page_limit: PAGE_LIMIT,
        warning_level,
    })
}
fn reader(directory: &Path) -> Result<Connection, AuditError> {
    let _file = storage::private(directory, "operations.sqlite3", false).map_err(|_| AuditError)?;
    let connection = Connection::open_with_flags(
        directory.join("operations.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| AuditError)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(100))
        .map_err(|_| AuditError)?;
    Ok(connection)
}
/// Inspect capacity without creating a database/session or migrating rows.
/// # Errors
/// Refuses missing, unsafe or unreadable storage.
pub fn status(directory: &Path) -> Result<Status, AuditError> {
    capacity(&reader(directory)?)
}

/// Stream a bounded page of payload-free events as JSONL, ordered by row ID.
/// `after` is exclusive; repeat with the last returned ID to export large logs.
/// # Errors
/// Refuses unsafe storage, invalid bounds, unsupported schemas and failed output.
pub fn export(
    directory: &Path,
    after: i64,
    limit: u32,
    output: &mut dyn Write,
) -> Result<(), AuditError> {
    export_page(directory, after, limit, output).map(|_| ())
}

fn export_page(
    directory: &Path,
    after: i64,
    limit: u32,
    output: &mut dyn Write,
) -> Result<i64, AuditError> {
    if after < 0 || limit == 0 || limit > 100_000 {
        return Err(AuditError);
    }
    let connection = reader(directory)?;
    let has_binding = connection
        .prepare("PRAGMA table_info(events_v1)")
        .map_err(|_| AuditError)?
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| AuditError)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AuditError)?
        .iter()
        .any(|name| name == "binding_sha256");
    // Export older v2 logs without requiring a writer or silently migrating them.
    let sql = if has_binding {
        "SELECT id,correlation,utc,policy_sha256,outcome,reason,session_id,upstream_sha256,lower(hex(binding_sha256)) FROM events_v1 WHERE id>?1 ORDER BY id LIMIT ?2"
    } else {
        "SELECT id,correlation,utc,policy_sha256,outcome,reason,session_id,upstream_sha256,'' FROM events_v1 WHERE id>?1 ORDER BY id LIMIT ?2"
    };
    let mut stmt = connection.prepare(sql).map_err(|_| AuditError)?;
    let rows = stmt
        .query_map(rusqlite::params![after, limit], |row| {
            Ok(Event {
                id: row.get(0)?,
                correlation: row.get(1)?,
                utc: row.get(2)?,
                policy_sha256: row.get(3)?,
                outcome: row.get(4)?,
                reason: row.get(5)?,
                session_id: row.get(6)?,
                upstream_sha256: row.get(7)?,
                binding_sha256: row.get(8)?,
            })
        })
        .map_err(|_| AuditError)?;
    let events = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AuditError)?;
    // Release the read transaction before potentially slow output can block writers.
    drop(stmt);
    drop(connection);
    let mut cursor = after;
    for event in events {
        serde_json::to_writer(&mut *output, &event).map_err(|_| AuditError)?;
        output.write_all(b"\n").map_err(|_| AuditError)?;
        cursor = event.id;
    }
    Ok(cursor)
}
/// Bounded live reader. Its shared maintenance lease prevents offline rotation
/// from changing the cursor generation; concurrent operation writers remain allowed.
pub struct Follower {
    _lease: File,
    directory: std::path::PathBuf,
    cursor: i64,
    limit: u32,
}
impl Follower {
    /// Start after an exclusive row cursor, without creating a database/session.
    /// # Errors
    /// Refuses invalid bounds, missing storage or active exclusive maintenance.
    pub fn new(directory: &Path, after: i64, limit: u32) -> Result<Self, AuditError> {
        if after < 0 || limit == 0 || limit > 1000 {
            return Err(AuditError);
        }
        let lease = storage::lock(directory, "operations.lock", false).map_err(|_| AuditError)?;
        reader(directory)?;
        Ok(Self {
            _lease: lease,
            directory: directory.to_owned(),
            cursor: after,
            limit,
        })
    }
    /// Write at most one page and flush it before advancing the cursor.
    /// # Errors
    /// Storage/output failure ends the follow session; no events are replayed.
    pub fn poll(&mut self, output: &mut dyn Write) -> Result<(), AuditError> {
        let next = export_page(&self.directory, self.cursor, self.limit, output)?;
        output.flush().map_err(|_| AuditError)?;
        self.cursor = next;
        Ok(())
    }
}

// Only the fixed payload-free audit schema is exportable; no SQL or dynamic
// column selection comes from the owner CLI or an upstream message.
#[derive(Serialize)]
struct Event {
    id: i64,
    correlation: i64,
    utc: String,
    policy_sha256: String,
    outcome: String,
    reason: String,
    session_id: String,
    upstream_sha256: String,
    binding_sha256: String,
}
/// Archive every event/session, then reclaim active event pages. Requires all
/// sessions stopped and explicit owner authorization. The archive is durable
/// before transactional retention; interruptions may leave a harmless extra copy.
/// Returns a fixed safe archive filename and its SHA-256, never raw event data.
/// # Errors
/// Refuses active writers, unsafe storage, collisions, copy or retention failure.
pub fn rotate(directory: &Path) -> Result<(String, String), AuditError> {
    let _lock = storage::lock(directory, "operations.lock", true).map_err(|_| AuditError)?;
    let source =
        storage::private(directory, "operations.sqlite3", false).map_err(|_| AuditError)?;
    let mut connection =
        Connection::open(directory.join("operations.sqlite3")).map_err(|_| AuditError)?;
    connection
        .execute_batch("PRAGMA synchronous=FULL; PRAGMA max_page_count=16384;")
        .map_err(|_| AuditError)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .map_err(|_| AuditError)?;
    if mode == "wal" {
        // Cooperative writers/followers are stopped by the exclusive lease.
        // Copying only the main file is safe after all WAL frames are durable
        // there and SQLite itself has switched back to rollback journaling.
        let (busy, _, _): (u32, i32, i32) = connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|_| AuditError)?;
        if busy != 0 {
            return Err(AuditError);
        }
        let switched: String = connection
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
            .map_err(|_| AuditError)?;
        if switched != "delete" {
            return Err(AuditError);
        }
    } else if mode != "delete" {
        return Err(AuditError);
    }
    let tx = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
        .map_err(|_| AuditError)?;
    let nonce: String = tx
        .query_row("SELECT lower(hex(randomblob(16)))", [], |r| r.get(0))
        .map_err(|_| AuditError)?;
    let name = format!("operations-{nonce}.sqlite3");
    let path = directory.join(&name);
    let mut archive = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| AuditError)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    let mut source = source;
    loop {
        let n = source.read(&mut buffer).map_err(|_| AuditError)?;
        if n == 0 {
            break;
        }
        archive.write_all(&buffer[..n]).map_err(|_| AuditError)?;
        hash.update(&buffer[..n]);
    }
    archive.sync_all().map_err(|_| AuditError)?;
    File::open(directory)
        .and_then(|f| f.sync_all())
        .map_err(|_| AuditError)?;
    let digest = format!("{:x}", hash.finalize());
    // Only this explicit offline transaction may remove active events; their full
    // append-only copy stays in the private archive. Receipt history is retained.
    tx.execute_batch("DROP TRIGGER events_no_delete; DROP TRIGGER sessions_no_delete;
        DELETE FROM events_v1; DELETE FROM sessions_v1;
        CREATE TABLE IF NOT EXISTS audit_rotations_v1 (archive TEXT PRIMARY KEY, sha256 TEXT NOT NULL, utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))) STRICT;
        CREATE TRIGGER IF NOT EXISTS rotations_no_update BEFORE UPDATE ON audit_rotations_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS rotations_no_delete BEFORE DELETE ON audit_rotations_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER events_no_delete BEFORE DELETE ON events_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER sessions_no_delete BEFORE DELETE ON sessions_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;").map_err(|_| AuditError)?;
    tx.execute(
        "INSERT INTO audit_rotations_v1(archive,sha256) VALUES(?1,?2)",
        rusqlite::params![name, digest],
    )
    .map_err(|_| AuditError)?;
    tx.commit().map_err(|_| AuditError)?;
    connection.execute_batch("VACUUM").map_err(|_| AuditError)?;
    Ok((name, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operations::{OperationStore, Outcome};
    use std::os::unix::fs::PermissionsExt;
    #[tokio::test]
    async fn live_follow_pages_without_duplicates_and_blocks_rotation()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("clawbell-follow-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        assert!(Follower::new(&dir, 0, 1).is_err());
        let store = OperationStore::open(&dir, "a".repeat(64)).await?;
        let first = store.record(0, Outcome::Intent).await?;
        let mut follower = Follower::new(&dir, first, 1)?;
        let mut output = Vec::new();
        follower.poll(&mut output)?;
        assert_eq!(output, [] as [u8; 0]);
        let second = store.record(first, Outcome::Response).await?;
        store.record(0, Outcome::Intent).await?;
        follower.poll(&mut output)?;
        let event: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(event["id"], second);
        output.clear();
        follower.poll(&mut output)?;
        assert_ne!(output, [] as [u8; 0]);
        output.clear();
        follower.poll(&mut output)?;
        assert_eq!(output, [] as [u8; 0]);
        drop(store);
        assert!(rotate(&dir).is_err());
        assert!(Follower::new(&dir, -1, 1).is_err());
        assert!(Follower::new(&dir, 0, 1001).is_err());
        drop(follower);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    #[test]
    fn v2_export_stays_read_only_without_a_binding_column() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = std::env::temp_dir().join(format!("clawbell-export-v2-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let _file = storage::private(&dir, "operations.sqlite3", true)?;
        let db = Connection::open(dir.join("operations.sqlite3"))?;
        db.execute_batch("CREATE TABLE events_v1 (id INTEGER PRIMARY KEY,correlation INTEGER,utc TEXT,policy_sha256 TEXT,outcome TEXT,reason TEXT,session_id TEXT,upstream_sha256 TEXT);
            INSERT INTO events_v1 VALUES(1,0,'synthetic-time','synthetic-policy','allow_intent','unspecified','synthetic-session','synthetic-upstream');")?;
        let mut output = Vec::new();
        export(&dir, 0, 10, &mut output)?;
        let event: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(event["binding_sha256"], "");
        assert_eq!(event["outcome"], "allow_intent");
        assert!(db.prepare("SELECT binding_sha256 FROM events_v1").is_err());
        drop(db);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    #[tokio::test]
    async fn failed_retention_rolls_back_and_wal_rotation_refuses()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir =
            std::env::temp_dir().join(format!("clawbell-rotate-failure-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let store = OperationStore::open(&dir, "b".repeat(64)).await?;
        store.record(0, Outcome::Intent).await?;
        drop(store);
        let mut stopped = false;
        for _ in 0..100 {
            if crate::storage::lock(&dir, "operations.lock", true).is_ok() {
                stopped = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert!(stopped);
        let db = Connection::open(dir.join("operations.sqlite3"))?;
        db.execute_batch("CREATE TRIGGER synthetic_retention_failure BEFORE DELETE ON events_v1 BEGIN SELECT RAISE(ABORT,'synthetic'); END;")?;
        assert!(rotate(&dir).is_err());
        assert_eq!(
            db.query_row("SELECT count(*) FROM events_v1", [], |r| r.get::<_, i64>(0))?,
            1
        );
        assert!(db.execute("DELETE FROM events_v1", []).is_err());
        db.execute_batch("DROP TRIGGER synthetic_retention_failure; PRAGMA journal_mode=WAL;")?;
        assert!(rotate(&dir).is_err());
        assert_eq!(
            db.query_row("SELECT count(*) FROM events_v1", [], |r| r.get::<_, i64>(0))?,
            1
        );
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    #[tokio::test]
    async fn private_export_offline_rotation_preserves_unknown_and_append_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("clawbell-rotate-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        assert!(status(&dir).is_err());
        let store = OperationStore::open(&dir, "a".repeat(64)).await?;
        let intent = store.record(0, Outcome::Intent).await?;
        assert!(rotate(&dir).is_err());
        let mut output = Vec::new();
        export(&dir, 0, 10, &mut output)?;
        assert!(String::from_utf8(output)?.contains("allow_intent"));
        assert!(export(&dir, -1, 10, &mut Vec::new()).is_err());
        // Exercise all warning levels without writing gigabytes of event data.
        let connection = Connection::open(dir.join("operations.sqlite3"))?;
        connection.execute_batch("CREATE TABLE synthetic_fill(data BLOB); INSERT INTO synthetic_fill VALUES(zeroblob(55000000));")?;
        assert_eq!(status(&dir)?.warning_level, 1);
        connection.execute_batch("INSERT INTO synthetic_fill VALUES(zeroblob(9000000));")?;
        assert_eq!(status(&dir)?.warning_level, 2);
        connection.execute_batch("INSERT INTO synthetic_fill VALUES(zeroblob(2800000));")?;
        while status(&dir)?.pages < PAGE_LIMIT - 32 {
            connection.execute_batch("INSERT INTO synthetic_fill VALUES(zeroblob(4096));")?;
        }
        assert_eq!(status(&dir)?.warning_level, 3);
        // These large fixture transactions test the database page quota, not
        // pinned-reader WAL growth (covered separately by the writer tests).
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        assert!(store.record(0, Outcome::Intent).await.is_err());
        store.record(intent, Outcome::Unknown).await?;
        connection.execute_batch("DROP TABLE synthetic_fill; VACUUM;")?;
        drop(connection);
        drop(store);
        // Wait for the dedicated writer to release its shared maintenance lock.
        let mut rotated = None;
        for _ in 0..100 {
            if let Ok(value) = rotate(&dir) {
                rotated = Some(value);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let (name, hash) = rotated.ok_or("writer_not_closed")?;
        assert_eq!(hash.len(), 64);
        assert_eq!(
            std::fs::metadata(dir.join(&name))?.permissions().mode() & 0o777,
            0o600
        );
        let archive = Connection::open(dir.join(name))?;
        assert_eq!(
            archive.query_row("SELECT count(*) FROM events_v1", [], |r| r.get::<_, i64>(0))?,
            2
        );
        assert!(archive.execute("DELETE FROM events_v1", []).is_err());
        let active = Connection::open(dir.join("operations.sqlite3"))?;
        assert_eq!(
            active.query_row("SELECT count(*) FROM events_v1", [], |r| r.get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            active.query_row("SELECT count(*) FROM audit_rotations_v1", [], |r| r
                .get::<_, i64>(0))?,
            1
        );
        assert!(
            active
                .execute("DELETE FROM audit_rotations_v1", [])
                .is_err()
        );
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
