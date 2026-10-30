//! Independent bounded reader/writer tasks prevent pipe backpressure deadlocks.
use crate::{Direction, Envelope, Error, Gate, Limits, Session, inspect};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::mpsc,
    task::JoinSet,
};

pub(crate) struct Wire {
    pub bytes: Vec<u8>,
    pub version: Option<String>,
}
pub(crate) type Event = Result<(Direction, Vec<u8>), Error>;

/// Relay two already-connected, isolated transports. All four I/O halves run
/// independently. EOF, denial, invalid input or timeout closes the entire session.
/// No raw stderr or payload is written to diagnostics.
///
/// # Errors
/// Returns a static transport/protocol/policy reason; effects may be unknown.
pub async fn relay<CR, CW, SR, SW, G>(
    client_read: CR,
    client_write: CW,
    server_read: SR,
    server_write: SW,
    gate: &mut G,
    limits: Limits,
) -> Result<(), Error>
where
    CR: AsyncRead + Unpin + Send + 'static,
    CW: AsyncWrite + Unpin + Send + 'static,
    SR: AsyncRead + Unpin + Send + 'static,
    SW: AsyncWrite + Unpin + Send + 'static,
    G: Gate,
{
    let limits = match limits.validate() {
        Ok(limits) => limits,
        Err(error) => return complete(gate, Err(error), Limits::default()).await,
    };
    let (events, incoming) = mpsc::channel(limits.queue);
    let (client_tx, client_rx) = mpsc::channel(limits.queue);
    let (server_tx, server_rx) = mpsc::channel(limits.queue);
    let mut tasks = JoinSet::new();
    reader(
        &mut tasks,
        client_read,
        Direction::Client,
        events.clone(),
        limits,
    );
    reader(&mut tasks, server_read, Direction::Server, events, limits);
    writer(&mut tasks, client_write, client_rx, limits);
    writer(&mut tasks, server_write, server_rx, limits);
    drive(
        incoming, client_tx, server_tx, &mut tasks, gate, limits, true,
    )
    .await
}

pub(crate) fn reader<R: AsyncRead + Unpin + Send + 'static>(
    tasks: &mut JoinSet<Result<(), Error>>,
    read: R,
    direction: Direction,
    events: mpsc::Sender<Event>,
    limits: Limits,
) {
    tasks.spawn(async move {
        let mut reader = BufReader::new(read);
        loop {
            let mut line = Vec::new();
            loop {
                let buf = reader.fill_buf().await.map_err(|_| Error::Transport)?;
                if buf.is_empty() {
                    return Err(if line.is_empty() {
                        Error::Closed
                    } else {
                        Error::InvalidMessage
                    });
                }
                let n = buf
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(buf.len(), |p| p + 1);
                if line.len() + n > limits.message_bytes + 1 {
                    return Err(Error::Limit);
                }
                let done = buf[n - 1] == b'\n';
                line.extend_from_slice(&buf[..n]);
                reader.consume(n);
                if done {
                    line.pop();
                    break;
                }
            }
            // Bounded send has its own deadline; overload cannot hang a reader.
            tokio::time::timeout(limits.timeout, events.send(Ok((direction, line))))
                .await
                .map_err(|_| Error::Timeout)?
                .map_err(|_| Error::Closed)?;
        }
    });
}
pub(crate) fn writer<W: AsyncWrite + Unpin + Send + 'static>(
    tasks: &mut JoinSet<Result<(), Error>>,
    mut write: W,
    mut queue: mpsc::Receiver<Wire>,
    limits: Limits,
) {
    tasks.spawn(async move {
        while let Some(wire) = queue.recv().await {
            tokio::time::timeout(limits.timeout, async {
                write.write_all(&wire.bytes).await?;
                write.write_all(b"\n").await?;
                write.flush().await
            })
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Transport)?;
        }
        Ok(())
    });
}
pub(crate) async fn drive<G: Gate>(
    mut incoming: mpsc::Receiver<Event>,
    client: mpsc::Sender<Wire>,
    server: mpsc::Sender<Wire>,
    tasks: &mut JoinSet<Result<(), Error>>,
    gate: &mut G,
    limits: Limits,
    terminate_on_cancel: bool,
) -> Result<(), Error> {
    let mut session = Session::new(limits)?;
    let result = async {
        loop {
            let deadline = session
                .deadline()
                .unwrap_or_else(|| tokio::time::Instant::now() + limits.timeout);
            let event = tokio::select! {
                biased;
                () = tokio::time::sleep_until(deadline) => return Err(Error::Timeout),
                event = incoming.recv() => event.ok_or(Error::Closed)??,
                task = tasks.join_next() => return match task {
                    Some(Ok(Err(error))) => Err(error),
                    Some(Err(_)) => Err(Error::Transport),
                    _ => Err(Error::Closed),
                },
            };
            let (direction, bytes) = event;
            let envelope = Envelope::parse(&bytes, direction, limits.message_bytes)?;
            session.accept(direction, &envelope)?;
            let checked = inspect(gate, direction, &envelope, limits).await?;
            if terminate_on_cancel
                && direction == Direction::Client
                && checked.method() == Some("notifications/cancelled")
            {
                return Err(Error::Cancelled);
            }
            let wire = Wire {
                bytes: checked.encode()?,
                version: session.version().map(str::to_owned),
            };
            let queue = if direction == Direction::Client {
                &server
            } else {
                &client
            };
            queue.try_send(wire).map_err(|_| Error::Limit)?;
        }
    }
    .await;
    session.close();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    complete(gate, result, limits).await
}

/// Finish even when terminal audit fails, so vaults and pending operations close.
async fn complete<G: Gate>(
    gate: &mut G,
    result: Result<(), Error>,
    limits: Limits,
) -> Result<(), Error> {
    let terminal = if let Err(error) = &result {
        tokio::time::timeout(limits.timeout, gate.terminated(error.reason()))
            .await
            .map_err(|_| Error::Timeout)
            .and_then(std::convert::identity)
    } else {
        Ok(())
    };
    let finish = tokio::time::timeout(limits.timeout, gate.finish())
        .await
        .map_err(|_| Error::Timeout)
        .and_then(std::convert::identity);
    terminal?;
    finish?;
    result
}

/// Launch a local MCP server through the mandatory sandbox boundary and bridge
/// client streams. The runner owns whole-tree containment and teardown; this
/// manager owns the direct child, pipes, wait/reap and transport cancellation.
///
/// # Errors
/// Fails closed when launch, pipes, relay or containment cleanup fails.
pub async fn run<R, W, G, S>(
    read: R,
    write: W,
    gate: &mut G,
    runner: &mut S,
    limits: Limits,
) -> Result<(), Error>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    G: Gate,
    S: clawbell_sandbox::Runner,
{
    let limits = match limits.validate() {
        Ok(limits) => limits,
        Err(error) => return complete(gate, Err(error), Limits::default()).await,
    };
    let launch = tokio::time::timeout(limits.timeout, runner.spawn()).await;
    let mut child = match launch {
        Ok(Ok(child)) => child,
        failure => {
            // A timed-out spawn may already have created part of a containment group.
            let _ = tokio::time::timeout(limits.timeout, runner.terminate()).await;
            return complete(
                gate,
                Err(if failure.is_err() {
                    Error::Timeout
                } else {
                    Error::Refused(crate::Reason::IsolationUnavailable)
                }),
                limits,
            )
            .await;
        }
    };
    let stderr = child.stderr.take();
    let result = match (child.stdout.take(), child.stdin.take()) {
        (Some(stdout), Some(stdin)) => {
            let drain = async {
                if let Some(stderr) = stderr {
                    let n = tokio::io::copy(
                        &mut stderr.take(limits.message_bytes as u64 + 1),
                        &mut tokio::io::sink(),
                    )
                    .await
                    .map_err(|_| Error::Transport)?;
                    if n > limits.message_bytes as u64 {
                        return Err(Error::Limit);
                    }
                }
                std::future::pending::<Result<(), Error>>().await
            };
            tokio::select! {
                r = relay(read, write, stdout, stdin, gate, limits) => r,
                r = drain => {
                    complete(gate, r, limits).await
                }
            }
        }
        _ => complete(gate, Err(Error::Transport), limits).await,
    };
    let cleanup = tokio::time::timeout(limits.timeout, runner.terminate()).await;
    let _ = child.start_kill();
    let reaped = tokio::time::timeout(limits.timeout, child.wait())
        .await
        .map_err(|_| Error::Timeout)
        .and_then(|result| result.map_err(|_| Error::Transport));
    let cleanup = cleanup
        .map_err(|_| Error::Timeout)
        .and_then(|result| result.map_err(|_| Error::Transport));
    if let Err(error) = reaped.and(cleanup) {
        return complete(gate, Err(error), limits).await;
    }
    result
}
