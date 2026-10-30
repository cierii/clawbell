//! Owner-private SQLite baseline, serviced exclusively by one bounded writer.
//! First observation is TOFU, not evidence of tool safety. Mismatches never update
//! a baseline; deliberate migrations require a separately reviewed owner action.
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
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
/// One cloneable handle to a dedicated SQLite thread. Queue overload fails closed.
#[derive(Clone)]
pub struct BaselineStore {
    sender: mpsc::Sender<Check>,
}
impl BaselineStore {
    /// Open inside an existing, owner-controlled 0700 directory. The caller must
    /// keep its ancestors trusted (no untrusted process may replace them).
    /// SQLite files are never exposed to sandboxed processes.
    /// # Errors
    /// Refuses symlinks, group/world permissions and unavailable storage.
    pub async fn open(directory: &Path) -> Result<Self, BaselineError> {
        let directory = directory.to_owned();
        let (sender, mut receiver) = mpsc::channel::<Check>(32);
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
                while let Some(check) = receiver.blocking_recv() {
                    let _ = check.answer.send(compare(
                        &mut connection,
                        &check.server,
                        &check.digest,
                        &check.tools,
                    ));
                }
            })
            .map_err(|_| BaselineError)?;
        result.await.map_err(|_| BaselineError)??;
        Ok(Self { sender })
    }
    /// Persist a first catalog or require exact agreement with the durable pin.
    /// Server identity comes from owner configuration, never MCP serverInfo.
    /// # Errors
    /// A mismatch, database error or saturated queue blocks communication.
    pub async fn check(
        &self,
        server: &str,
        digest: [u8; 32],
        tools: Vec<[u8; 32]>,
    ) -> Result<(), BaselineError> {
        if server.is_empty() || server.len() > 512 || tools.len() > 256 {
            return Err(BaselineError);
        }
        let (answer, result) = oneshot::channel();
        self.sender
            .try_send(Check {
                server: server.into(),
                digest,
                tools,
                answer,
            })
            .map_err(|_| BaselineError)?;
        result.await.map_err(|_| BaselineError)?
    }
}
fn open(directory: &Path) -> Result<Connection, BaselineError> {
    let metadata = std::fs::symlink_metadata(directory).map_err(|_| BaselineError)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(BaselineError);
    }
    let path = directory.join("tool-baselines.sqlite3");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(BaselineError),
    }
    let meta = std::fs::symlink_metadata(&path).map_err(|_| BaselineError)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(BaselineError);
    }
    let connection = Connection::open(path).map_err(|_| BaselineError)?;
    connection
        .busy_timeout(std::time::Duration::from_millis(100))
        .map_err(|_| BaselineError)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS tool_baselines_v1 (
            server TEXT PRIMARY KEY NOT NULL,
            digest BLOB NOT NULL CHECK(length(digest)=32)
        ) STRICT;
        CREATE TABLE IF NOT EXISTS tool_signatures_v1 (
            server TEXT NOT NULL REFERENCES tool_baselines_v1(server),
            digest BLOB NOT NULL CHECK(length(digest)=32),
            PRIMARY KEY(server, digest)
        ) STRICT;",
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
    match existing {
        Some(pin) if pin != digest => return Err(BaselineError),
        Some(_) => {
            let mut statement = tx
                .prepare("SELECT digest FROM tool_signatures_v1 WHERE server=?1 ORDER BY digest")
                .map_err(|_| BaselineError)?;
            let rows = statement
                .query_map([server], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|_| BaselineError)?;
            let stored = rows
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BaselineError)?;
            if stored.len() != tools.len() || !stored.iter().zip(tools).all(|(a, b)| a == b) {
                return Err(BaselineError);
            }
        }
        None => {
            tx.execute(
                "INSERT INTO tool_baselines_v1(server,digest) VALUES (?1,?2)",
                params![server, digest.as_slice()],
            )
            .map_err(|_| BaselineError)?;
            for tool in tools {
                tx.execute(
                    "INSERT INTO tool_signatures_v1(server,digest) VALUES (?1,?2)",
                    params![server, tool.as_slice()],
                )
                .map_err(|_| BaselineError)?;
            }
        }
    }
    tx.commit().map_err(|_| BaselineError)
}
