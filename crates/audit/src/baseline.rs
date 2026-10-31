//! Owner-private SQLite baseline, serviced exclusively by one bounded writer.
//! New and changed catalogs require explicit owner review before forwarding.
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
use tokio::sync::{mpsc, oneshot};
/// Persistence, integrity or queue failure. No SQL/path/payload is exposed.
#[derive(Debug, thiserror::Error)]
#[error("tool_baseline_denied")]
pub struct BaselineError;
struct Check {
    server: String,
    digest: [u8; 32],
    tools: Vec<[u8; 32]>,
    answer: oneshot::Sender<Result<(), BaselineError>>,
}
enum Command {
    Check(Check),
    Review(bool, oneshot::Sender<Result<Vec<Review>, BaselineError>>),
    Accept(i64, oneshot::Sender<Result<(), BaselineError>>),
}
/// Hash-only diff. Metadata is untrusted and is never printed or persisted here.
#[derive(Debug, serde::Serialize)]
pub struct Review {
    /// One-use owner decision identifier.
    pub id: i64,
    /// UTC acceptance time, absent for a pending or superseded proposal.
    pub accepted_utc: Option<String>,
    /// Owner-configured identity (JSON-escaped by the CLI).
    pub server: String,
    /// Previous catalog digest; absent on first launch.
    #[serde(serialize_with = "optional_digest")]
    pub previous: Option<Vec<u8>>,
    /// Proposed catalog digest.
    #[serde(serialize_with = "digest_json")]
    pub proposed: Vec<u8>,
    /// Removed tool signatures.
    #[serde(serialize_with = "digests_json")]
    pub removed: Vec<Vec<u8>>,
    /// Added tool signatures.
    #[serde(serialize_with = "digests_json")]
    pub added: Vec<Vec<u8>>,
}
/// One cloneable handle to a dedicated SQLite thread. Queue overload fails closed.
#[derive(Clone)]
pub struct BaselineStore {
    sender: mpsc::Sender<Command>,
}
impl BaselineStore {
    /// Open inside an existing, owner-controlled 0700 directory. The caller must
    /// keep its ancestors trusted (no untrusted process may replace them).
    /// SQLite files are never exposed to sandboxed processes.
    /// # Errors
    /// Refuses symlinks, group/world permissions and unavailable storage.
    pub async fn open(directory: &Path) -> Result<Self, BaselineError> {
        let directory = directory.to_owned();
        let (sender, mut receiver) = mpsc::channel::<Command>(32);
        let (ready, result) = oneshot::channel();
        std::thread::Builder::new()
            .name("clawbell-baseline".into())
            .spawn(move || {
                let opened = open(&directory);
                let Ok(mut connection) = opened else {
                    let _ = ready.send(Err(BaselineError));
                    return;
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                while let Some(command) = receiver.blocking_recv() {
                    match command {
                        Command::Check(check) => {
                            let _ = check.answer.send(compare(
                                &mut connection,
                                &check.server,
                                &check.digest,
                                &check.tools,
                            ));
                        }
                        Command::Review(history, answer) => {
                            let _ = answer.send(reviews(&connection, history));
                        }
                        Command::Accept(id, answer) => {
                            let result = crate::storage::lock(&directory, "operations.lock", true)
                                .map_err(|_| BaselineError)
                                .and_then(|_lock| accept(&mut connection, id));
                            let _ = answer.send(result);
                        }
                    }
                }
            })
            .map_err(|_| BaselineError)?;
        result.await.map_err(|_| BaselineError)??;
        Ok(Self { sender })
    }
    /// Require an accepted catalog; stage first observation or mismatch for review.
    /// Server identity comes from owner configuration, never MCP serverInfo.
    /// # Errors
    /// A mismatch, database error or saturated queue blocks communication.
    pub async fn check(
        &self,
        server: &str,
        digest: [u8; 32],
        tools: Vec<[u8; 32]>,
    ) -> Result<(), BaselineError> {
        if server.is_empty() || server.len() > 512 || tools.len() > 4096 {
            return Err(BaselineError);
        }
        let (answer, result) = oneshot::channel();
        self.sender
            .try_send(Command::Check(Check {
                server: server.into(),
                digest,
                tools,
                answer,
            }))
            .map_err(|_| BaselineError)?;
        result.await.map_err(|_| BaselineError)?
    }
    /// Read pending hash diffs on the dedicated writer.
    /// # Errors
    /// Refuses unavailable storage or queue saturation.
    pub async fn review(&self) -> Result<Vec<Review>, BaselineError> {
        let (answer, result) = oneshot::channel();
        self.sender
            .try_send(Command::Review(false, answer))
            .map_err(|_| BaselineError)?;
        result.await.map_err(|_| BaselineError)?
    }
    /// Read the latest 256 immutable proposals, including accepted migrations.
    /// # Errors
    /// Refuses storage or queue failure.
    pub async fn history(&self) -> Result<Vec<Review>, BaselineError> {
        let (answer, result) = oneshot::channel();
        self.sender
            .try_send(Command::Review(true, answer))
            .map_err(|_| BaselineError)?;
        result.await.map_err(|_| BaselineError)?
    }
    /// Accept exactly the reviewed candidate; stale/replayed decisions refuse.
    /// Call only for a deliberate authenticated owner action, never MCP input.
    /// # Errors
    /// Refuses stale decisions, storage failure or queue saturation.
    pub async fn accept(&self, id: i64) -> Result<(), BaselineError> {
        let (answer, result) = oneshot::channel();
        self.sender
            .try_send(Command::Accept(id, answer))
            .map_err(|_| BaselineError)?;
        result.await.map_err(|_| BaselineError)?
    }
}
fn open(directory: &Path) -> Result<Connection, BaselineError> {
    let _file = crate::storage::private(directory, "tool-baselines.sqlite3", true)
        .map_err(|_| BaselineError)?;
    let path = directory.join("tool-baselines.sqlite3");
    let connection = Connection::open(path).map_err(|_| BaselineError)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(100))
        .map_err(|_| BaselineError)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA max_page_count=16384;
        CREATE TABLE IF NOT EXISTS tool_baselines_v1 (
            server TEXT PRIMARY KEY NOT NULL,
            digest BLOB NOT NULL CHECK(length(digest)=32)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS tool_signatures_v1 (
            server TEXT NOT NULL REFERENCES tool_baselines_v1(server),
            digest BLOB NOT NULL CHECK(length(digest)=32),
            PRIMARY KEY(server, digest)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS pin_reviews_v1 (
            id INTEGER PRIMARY KEY, server TEXT NOT NULL, previous BLOB, proposed BLOB NOT NULL,
            utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        ) STRICT;
        CREATE TABLE IF NOT EXISTS pin_review_tools_v1 (review INTEGER NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(review,digest)) STRICT;
        CREATE TABLE IF NOT EXISTS pin_previous_tools_v1 (review INTEGER NOT NULL, digest BLOB NOT NULL, PRIMARY KEY(review,digest)) STRICT;
        CREATE TABLE IF NOT EXISTS pin_acceptances_v1 (
            review INTEGER PRIMARY KEY, utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        ) STRICT;
        CREATE TRIGGER IF NOT EXISTS review_no_update BEFORE UPDATE ON pin_reviews_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS review_no_delete BEFORE DELETE ON pin_reviews_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS review_tools_no_update BEFORE UPDATE ON pin_review_tools_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS review_tools_no_delete BEFORE DELETE ON pin_review_tools_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS previous_tools_no_update BEFORE UPDATE ON pin_previous_tools_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS previous_tools_no_delete BEFORE DELETE ON pin_previous_tools_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS acceptance_no_update BEFORE UPDATE ON pin_acceptances_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;
        CREATE TRIGGER IF NOT EXISTS acceptance_no_delete BEFORE DELETE ON pin_acceptances_v1 BEGIN SELECT RAISE(ABORT,'append_only'); END;",
        )
        .map_err(|_| BaselineError)?;
    Ok(connection)
}
fn compare(
    connection: &mut Connection,
    server: &str,
    digest: &[u8; 32],
    tools: &[[u8; 32]],
) -> Result<(), BaselineError> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| BaselineError)?;
    let existing: Option<Vec<u8>> = tx
        .query_row(
            "SELECT digest FROM tool_baselines_v1 WHERE server=?1",
            [server],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| BaselineError)?;
    if existing.as_deref() == Some(digest.as_slice()) {
        let stored = signatures(&tx, server)?;
        if stored.len() != tools.len() || !stored.iter().zip(tools).all(|(a, b)| a == b) {
            return Err(BaselineError);
        }
        return tx.commit().map_err(|_| BaselineError);
    }
    let latest: Option<(i64, Vec<u8>)> = tx
        .query_row(
            "SELECT id,proposed FROM pin_reviews_v1 WHERE server=?1 ORDER BY id DESC LIMIT 1",
            [server],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| BaselineError)?;
    if latest.is_none_or(|(_, pin)| pin != digest) {
        let count: i64 = tx
            .query_row("SELECT count(*) FROM pin_reviews_v1", [], |r| r.get(0))
            .map_err(|_| BaselineError)?;
        if count >= 10000 {
            return Err(BaselineError);
        }
        tx.execute(
            "INSERT INTO pin_reviews_v1(server,previous,proposed) VALUES(?1,?2,?3)",
            params![server, existing, digest.as_slice()],
        )
        .map_err(|_| BaselineError)?;
        let id = tx.last_insert_rowid();
        tx.execute("INSERT INTO pin_previous_tools_v1(review,digest) SELECT ?1,digest FROM tool_signatures_v1 WHERE server=?2",params![id,server]).map_err(|_| BaselineError)?;
        for tool in tools {
            tx.execute(
                "INSERT INTO pin_review_tools_v1(review,digest) VALUES(?1,?2)",
                params![id, tool.as_slice()],
            )
            .map_err(|_| BaselineError)?;
        }
    }
    tx.commit().map_err(|_| BaselineError)?;
    Err(BaselineError)
}
fn signatures(connection: &Connection, server: &str) -> Result<Vec<Vec<u8>>, BaselineError> {
    let mut stmt = connection
        .prepare("SELECT digest FROM tool_signatures_v1 WHERE server=?1 ORDER BY digest")
        .map_err(|_| BaselineError)?;
    stmt.query_map([server], |r| r.get(0))
        .map_err(|_| BaselineError)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BaselineError)
}
fn candidate_tools(connection: &Connection, id: i64) -> Result<Vec<Vec<u8>>, BaselineError> {
    let mut stmt = connection
        .prepare("SELECT digest FROM pin_review_tools_v1 WHERE review=?1 ORDER BY digest")
        .map_err(|_| BaselineError)?;
    stmt.query_map([id], |r| r.get(0))
        .map_err(|_| BaselineError)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BaselineError)
}
fn reviews(connection: &Connection, history: bool) -> Result<Vec<Review>, BaselineError> {
    let sql = if history {
        "SELECT id,server,previous,proposed FROM pin_reviews_v1 ORDER BY id DESC LIMIT 256"
    } else {
        "SELECT id,server,previous,proposed FROM pin_reviews_v1 r WHERE id=(SELECT max(id) FROM pin_reviews_v1 WHERE server=r.server) AND NOT EXISTS(SELECT 1 FROM pin_acceptances_v1 WHERE review=r.id) ORDER BY id LIMIT 256"
    };
    let mut stmt = connection.prepare(sql).map_err(|_| BaselineError)?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|_| BaselineError)?;
    let mut output = Vec::new();
    for row in rows {
        let (id, server, previous, proposed) = row.map_err(|_| BaselineError)?;
        let mut previous_stmt = connection
            .prepare("SELECT digest FROM pin_previous_tools_v1 WHERE review=?1 ORDER BY digest")
            .map_err(|_| BaselineError)?;
        let old = previous_stmt
            .query_map([id], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|_| BaselineError)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| BaselineError)?;
        let accepted_utc = connection
            .query_row(
                "SELECT utc FROM pin_acceptances_v1 WHERE review=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| BaselineError)?;
        let new = candidate_tools(connection, id)?;
        output.push(Review {
            id,
            accepted_utc,
            server,
            previous,
            proposed,
            removed: old.iter().filter(|v| !new.contains(v)).cloned().collect(),
            added: new.iter().filter(|v| !old.contains(v)).cloned().collect(),
        });
    }
    Ok(output)
}
fn accept(connection: &mut Connection, id: i64) -> Result<(), BaselineError> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| BaselineError)?;
    let review = reviews(&tx, false)?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or(BaselineError)?;
    let current: Option<Vec<u8>> = tx
        .query_row(
            "SELECT digest FROM tool_baselines_v1 WHERE server=?1",
            [&review.server],
            |r| r.get(0),
        )
        .optional()
        .map_err(|_| BaselineError)?;
    if current != review.previous {
        return Err(BaselineError);
    }
    tx.execute("INSERT INTO pin_acceptances_v1(review) VALUES(?1)", [id])
        .map_err(|_| BaselineError)?;
    tx.execute("INSERT INTO tool_baselines_v1(server,digest) VALUES(?1,?2) ON CONFLICT(server) DO UPDATE SET digest=excluded.digest", params![review.server,review.proposed]).map_err(|_| BaselineError)?;
    tx.execute(
        "DELETE FROM tool_signatures_v1 WHERE server=?1",
        [&review.server],
    )
    .map_err(|_| BaselineError)?;
    tx.execute("INSERT INTO tool_signatures_v1(server,digest) SELECT ?1,digest FROM pin_review_tools_v1 WHERE review=?2",params![review.server,id]).map_err(|_| BaselineError)?;
    tx.commit().map_err(|_| BaselineError)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
fn digest_json<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex(bytes))
}
#[allow(clippy::ref_option)] // serde serialize_with requires a reference to the field.
fn optional_digest<S: serde::Serializer>(
    bytes: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::Serialize;
    bytes.as_ref().map(|v| hex(v)).serialize(serializer)
}
fn digests_json<S: serde::Serializer>(bytes: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
    use serde::Serialize;
    bytes
        .iter()
        .map(|v| hex(v))
        .collect::<Vec<_>>()
        .serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[tokio::test]
    async fn legacy_pins_survive_additive_review_migration()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("clawbell-legacy-pins-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        crate::storage::private(&dir, "tool-baselines.sqlite3", true)?;
        let db = Connection::open(dir.join("tool-baselines.sqlite3"))?;
        db.execute_batch("CREATE TABLE tool_baselines_v1(server TEXT PRIMARY KEY,digest BLOB NOT NULL) STRICT; CREATE TABLE tool_signatures_v1(server TEXT NOT NULL,digest BLOB NOT NULL,PRIMARY KEY(server,digest)) STRICT;")?;
        db.execute(
            "INSERT INTO tool_baselines_v1 VALUES(?1,?2)",
            params!["legacy", [7_u8; 32].as_slice()],
        )?;
        db.execute(
            "INSERT INTO tool_signatures_v1 VALUES(?1,?2)",
            params!["legacy", [8_u8; 32].as_slice()],
        )?;
        let store = BaselineStore::open(&dir).await?;
        store.check("legacy", [7; 32], vec![[8; 32]]).await?;
        assert!(store.history().await?.is_empty());
        assert!(
            store
                .check("legacy", [9; 32], vec![[10; 32]])
                .await
                .is_err()
        );
        let review = store.review().await?.remove(0);
        assert_eq!(review.previous, Some(vec![7; 32]));
        assert_eq!(review.removed, vec![vec![8; 32]]);
        store.accept(review.id).await?;
        assert_eq!(store.history().await?.len(), 1);
        assert!(store.history().await?[0].accepted_utc.is_some());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    #[tokio::test]
    async fn explicit_review_first_launch_updates_stale_replay_and_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!("clawbell-pin-review-{}", std::process::id()));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let store = BaselineStore::open(&dir).await?;
        assert!(
            store
                .check("synthetic", [1; 32], vec![[2; 32]])
                .await
                .is_err()
        );
        let review = store.review().await?.remove(0);
        assert!(review.previous.is_none());
        assert_eq!(review.added, vec![vec![2; 32]]);
        store.accept(review.id).await?;
        assert!(store.accept(review.id).await.is_err());
        store.check("synthetic", [1; 32], vec![[2; 32]]).await?;
        assert!(
            store
                .check("synthetic", [3; 32], vec![[4; 32]])
                .await
                .is_err()
        );
        let stale = store.review().await?.remove(0);
        assert_eq!(stale.removed, vec![vec![2; 32]]);
        assert!(
            store
                .check("synthetic", [5; 32], vec![[6; 32]])
                .await
                .is_err()
        );
        assert!(store.accept(stale.id).await.is_err());
        let current = store.review().await?.remove(0);
        let active = crate::storage::lock(&dir, "operations.lock", false)?;
        assert!(store.accept(current.id).await.is_err());
        drop(active);
        store.accept(current.id).await?;
        store.check("synthetic", [5; 32], vec![[6; 32]]).await?;
        let db = Connection::open(dir.join("tool-baselines.sqlite3"))?;
        assert_eq!(
            db.query_row("SELECT count(*) FROM pin_acceptances_v1", [], |r| r
                .get::<_, i64>(0))?,
            2
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM pin_reviews_v1", [], |r| r
                .get::<_, i64>(0))?,
            3
        );
        assert!(db.execute("DELETE FROM pin_reviews_v1", []).is_err());
        drop(store);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
