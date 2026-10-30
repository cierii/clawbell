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
    if after < 0 || limit == 0 || limit > 100_000 {
        return Err(AuditError);
    }
    let connection = reader(directory)?;
    let mut stmt = connection.prepare("SELECT id,correlation,utc,policy_sha256,outcome,reason,session_id,upstream_sha256 FROM events_v1 WHERE id>?1 ORDER BY id LIMIT ?2").map_err(|_| AuditError)?;
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
            })
        })
        .map_err(|_| AuditError)?;
    for row in rows {
        let event = row.map_err(|_| AuditError)?;
        serde_json::to_writer(&mut *output, &event).map_err(|_| AuditError)?;
        output.write_all(b"\n").map_err(|_| AuditError)?;
    }
    Ok(())
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
    if mode != "delete" {
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
