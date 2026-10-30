//! Synthetic fixtures only: permissive gates/runners below are never shipped as adapters.
use clawbell_proxy::{Direction, Envelope, Error, Gate, Limits, Phase, Session, http, stdio};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
fn init() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}})
}
fn initialized() -> Value {
    json!({"jsonrpc":"2.0","method":"notifications/initialized"})
}
fn init_result() -> Value {
    json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}})
}
fn ping(id: i64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"ping"})
}
fn result(id: i64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{}})
}
fn parse(v: &Value, d: Direction) -> Result<Envelope, Error> {
    Envelope::parse(
        &serde_json::to_vec(v).map_err(|_| Error::InvalidMessage)?,
        d,
        65536,
    )
}
#[derive(Default)]
struct FixtureGate {
    deny: bool,
    finished: bool,
    seen: usize,
}
impl Gate for FixtureGate {
    fn validate_local_arguments(&self, tool: &str, arguments: &Value) -> Result<(), Error> {
        if tool == "connect" && arguments.get("password").is_some_and(Value::is_string) {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
    async fn inspect(
        &mut self,
        _direction: Direction,
        message: &Envelope,
    ) -> Result<Envelope, Error> {
        tokio::task::yield_now().await;
        self.seen += 1;
        if self.deny
            || message
                .encode()?
                .windows(14)
                .any(|s| s == b"fixture-secret")
        {
            return Err(Error::Denied);
        }
        Ok(message.clone())
    }
    async fn finish(&mut self) -> Result<(), Error> {
        tokio::task::yield_now().await;
        self.finished = true;
        Ok(())
    }
}
async fn send<W: AsyncWriteExt + Unpin>(w: &mut W, value: &Value) -> TestResult {
    w.write_all(&serde_json::to_vec(value)?).await?;
    w.write_all(b"\n").await?;
    w.flush().await?;
    Ok(())
}
async fn recv<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut s = String::new();
    tokio::time::timeout(Duration::from_secs(3), r.read_line(&mut s)).await??;
    Ok(serde_json::from_str(&s)?)
}
fn ready(limits: Limits) -> Result<Session, Error> {
    let mut s = Session::new(limits)?;
    s.accept(Direction::Client, &parse(&init(), Direction::Client)?)?;
    s.accept(
        Direction::Server,
        &parse(&init_result(), Direction::Server)?,
    )?;
    s.accept(
        Direction::Client,
        &parse(&initialized(), Direction::Client)?,
    )?;
    Ok(s)
}
#[test]
fn strict_envelopes_and_lifecycle() -> TestResult {
    for bad in [
        json!([]),
        json!({"jsonrpc":"1.0","id":1,"method":"ping"}),
        json!({"jsonrpc":"2.0","id":null,"method":"ping"}),
        json!({"jsonrpc":"2.0","id":1.2,"method":"ping"}),
        json!({"jsonrpc":"2.0","id":1,"method":"ping","result":{}}),
        json!({"jsonrpc":"2.0","id":1,"method":"unknown/execute"}),
    ] {
        assert!(parse(&bad, Direction::Client).is_err());
    }
    let mut s = Session::new(Limits::default())?;
    assert!(
        s.accept(Direction::Client, &parse(&ping(1), Direction::Client)?)
            .is_err()
    );
    let mut s = ready(Limits::default())?;
    assert_eq!(s.phase(), Phase::Ready);
    assert!(
        s.accept(Direction::Server, &parse(&result(99), Direction::Server)?)
            .is_err()
    );
    s.accept(Direction::Client, &parse(&ping(2), Direction::Client)?)?;
    assert!(
        s.accept(Direction::Client, &parse(&ping(2), Direction::Client)?)
            .is_err()
    );
    s.accept(Direction::Server, &parse(&ping(2), Direction::Server)?)?;
    s.accept(Direction::Client, &parse(&result(2), Direction::Client)?)?;
    s.accept(Direction::Server, &parse(&result(2), Direction::Server)?)?;
    assert!(
        s.accept(
            Direction::Client,
            &parse(&initialized(), Direction::Client)?
        )
        .is_err()
    );
    let mut bad_init = init_result();
    bad_init["result"]["protocolVersion"] = json!("2099-01-01");
    let mut s = Session::new(Limits::default())?;
    s.accept(Direction::Client, &parse(&init(), Direction::Client)?)?;
    assert!(
        s.accept(Direction::Server, &parse(&bad_init, Direction::Server)?)
            .is_err()
    );
    Ok(())
}
#[test]
fn limits_and_depth() -> TestResult {
    assert!(
        Limits {
            queue: 0,
            ..Limits::default()
        }
        .validate()
        .is_err()
    );
    assert!(Envelope::parse(b"{}", Direction::Client, 1).is_err());
    let deep = format!("{}0{}", "[".repeat(140), "]".repeat(140));
    assert!(Envelope::parse(deep.as_bytes(), Direction::Client, 65536).is_err());
    let mut s = ready(Limits {
        pending: 1,
        ..Limits::default()
    })?;
    s.accept(Direction::Client, &parse(&ping(2), Direction::Client)?)?;
    assert!(matches!(
        s.accept(Direction::Client, &parse(&ping(3), Direction::Client)?),
        Err(Error::Limit)
    ));
    Ok(())
}
async fn fixture_server(stream: DuplexStream) -> TestResult {
    let (r, mut w) = tokio::io::split(stream);
    let mut r = BufReader::new(r);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let v: Value = serde_json::from_str(&line)?;
        if v.get("id").is_some() {
            let response = if v["method"] == "initialize" {
                init_result()
            } else {
                json!({"jsonrpc":"2.0","id":v["id"],"result":{}})
            };
            send(&mut w, &response).await?;
        }
    }
}
#[tokio::test]
async fn duplex_backpressure_and_bidirectional_requests() -> TestResult {
    let (client, c) = tokio::io::duplex(32);
    let (s, server) = tokio::io::duplex(32);
    let (cr, cw) = tokio::io::split(c);
    let (sr, sw) = tokio::io::split(s);
    let proxy = tokio::spawn(async move {
        let mut g = FixtureGate::default();
        let r = stdio::relay(cr, cw, sr, sw, &mut g, Limits::default()).await;
        (r, g)
    });
    let (r, mut w) = tokio::io::split(client);
    let mut r = BufReader::new(r);
    let (server_r, mut server_w) = tokio::io::split(server);
    let mut server_r = BufReader::new(server_r);
    send(&mut w, &init()).await?;
    assert_eq!(recv(&mut server_r).await?, init());
    send(&mut server_w, &init_result()).await?;
    assert_eq!(recv(&mut r).await?, init_result());
    send(&mut w, &initialized()).await?;
    recv(&mut server_r).await?;
    // Same ID in opposite directions must not collide.
    send(&mut server_w, &ping(7)).await?;
    assert_eq!(recv(&mut r).await?, ping(7));
    send(&mut w, &ping(7)).await?;
    assert_eq!(recv(&mut server_r).await?, ping(7));
    send(&mut w, &result(7)).await?;
    assert_eq!(recv(&mut server_r).await?, result(7));
    send(&mut server_w, &result(7)).await?;
    assert_eq!(recv(&mut r).await?, result(7));
    drop(w);
    drop(r);
    let (_, gate) = tokio::time::timeout(Duration::from_secs(2), proxy).await??;
    assert!(gate.finished);
    Ok(())
}
#[tokio::test]
async fn denial_and_secret_never_reach_upstream() -> TestResult {
    let (mut client, c) = tokio::io::duplex(4096);
    let (s, mut server) = tokio::io::duplex(4096);
    let (cr, cw) = tokio::io::split(c);
    let (sr, sw) = tokio::io::split(s);
    let proxy = tokio::spawn(async move {
        let mut g = FixtureGate::default();
        let r = stdio::relay(cr, cw, sr, sw, &mut g, Limits::default()).await;
        (r, g)
    });
    let mut request = init();
    request["params"]["clientInfo"]["name"] = json!("fixture-secret");
    send(&mut client, &request).await?;
    let (r, gate) = proxy.await?;
    assert!(matches!(r, Err(Error::Denied)));
    assert!(gate.finished);
    let mut line = String::new();
    assert_eq!(BufReader::new(&mut server).read_line(&mut line).await?, 0);
    Ok(())
}
#[tokio::test]
async fn stalled_request_expires() -> TestResult {
    let (mut client, c) = tokio::io::duplex(4096);
    let (s, _server) = tokio::io::duplex(4096);
    let (cr, cw) = tokio::io::split(c);
    let (sr, sw) = tokio::io::split(s);
    let proxy = tokio::spawn(async move {
        let mut g = FixtureGate::default();
        stdio::relay(
            cr,
            cw,
            sr,
            sw,
            &mut g,
            Limits {
                request_timeout: Duration::from_millis(50),
                idle_timeout: Duration::from_millis(50),
                ..Limits::default()
            },
        )
        .await
    });
    send(&mut client, &init()).await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), proxy).await??,
        Err(Error::Timeout)
    ));
    Ok(())
}
async fn local_http(
    sse: bool,
) -> Result<(String, tokio::task::JoinHandle<TestResult>), Box<dyn std::error::Error + Send + Sync>>
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}/mcp", listener.local_addr()?);
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await?;
            let mut reader = BufReader::new(stream);
            let mut len = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).await?;
                if line == "\r\n" {
                    break;
                }
                if let Some((key, value)) = line.split_once(':')
                    && key.eq_ignore_ascii_case("content-length")
                {
                    len = value.trim().parse::<usize>()?;
                }
            }
            let mut body = vec![0; len];
            tokio::io::AsyncReadExt::read_exact(&mut reader, &mut body).await?;
            let v: Value = serde_json::from_slice(&body)?;
            let (status, kind, body) = if v.get("id").is_none() {
                ("202 Accepted", "application/json", String::new())
            } else {
                let v = if v["method"] == "initialize" {
                    init_result()
                } else {
                    result(v["id"].as_i64().ok_or("bad fixture ID")?)
                };
                if sse {
                    (
                        "200 OK",
                        "text/event-stream",
                        format!(":keepalive\r\ndata: {v}\r\n\r\n"),
                    )
                } else {
                    ("200 OK", "application/json", v.to_string())
                }
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            reader.get_mut().write_all(response.as_bytes()).await?;
        }
    });
    Ok((url, task))
}
#[tokio::test]
async fn stateless_http_json_and_sse() -> TestResult {
    for sse in [false, true] {
        let (url, server) = local_http(sse).await?;
        assert!(
            http::Target::connect(&url, None, Limits::default())
                .await
                .is_err()
        );
        let target =
            http::Target::connect(&url, Some("127.0.0.1".parse()?), Limits::default()).await?;
        let (client, c) = tokio::io::duplex(4096);
        let (cr, cw) = tokio::io::split(c);
        let proxy = tokio::spawn(async move {
            let mut g = FixtureGate::default();
            http::relay(cr, cw, target, &mut g, Limits::default()).await
        });
        let (r, mut w) = tokio::io::split(client);
        let mut r = BufReader::new(r);
        send(&mut w, &init()).await?;
        assert_eq!(recv(&mut r).await?, init_result());
        send(&mut w, &initialized()).await?;
        send(&mut w, &ping(2)).await?;
        assert_eq!(recv(&mut r).await?, result(2));
        drop(w);
        drop(r);
        proxy.await?.err().ok_or("expected closed session")?;
        server.abort();
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "release-only latency experiment; synthetic gate, no durable audit"]
async fn latency_under_three_ms() -> TestResult {
    async fn measure(
        proxied: bool,
    ) -> Result<Vec<Duration>, Box<dyn std::error::Error + Send + Sync>> {
        let (client, c) = tokio::io::duplex(65536);
        let mut tasks = Vec::new();
        if proxied {
            let (s, server) = tokio::io::duplex(65536);
            tasks.push(tokio::spawn(fixture_server(server)));
            let (cr, cw) = tokio::io::split(c);
            let (sr, sw) = tokio::io::split(s);
            tasks.push(tokio::spawn(async move {
                let mut g = FixtureGate::default();
                let _ = stdio::relay(cr, cw, sr, sw, &mut g, Limits::default()).await;
                Ok(())
            }));
        } else {
            tasks.push(tokio::spawn(fixture_server(c)));
        }
        let (r, mut w) = tokio::io::split(client);
        let mut r = BufReader::new(r);
        send(&mut w, &init()).await?;
        recv(&mut r).await?;
        send(&mut w, &initialized()).await?;
        let mut times = Vec::new();
        for i in 2..2202 {
            let start = Instant::now();
            send(&mut w, &ping(i)).await?;
            assert_eq!(recv(&mut r).await?, result(i));
            if i >= 202 {
                times.push(start.elapsed());
            }
        }
        for t in tasks {
            t.abort();
        }
        times.sort_unstable();
        Ok(times)
    }
    let direct = measure(false).await?;
    let proxy = measure(true).await?;
    eprintln!(
        "2000 warmed ping RTTs; direct p50={:?}, p99={:?}; proxy p50={:?}, p95={:?}, p99={:?}, max={:?}; incremental p99={:?}",
        direct[1000],
        direct[1980],
        proxy[1000],
        proxy[1900],
        proxy[1980],
        proxy[1999],
        proxy[1980].saturating_sub(direct[1980])
    );
    assert!(proxy[1980].saturating_sub(direct[1980]) < Duration::from_millis(3));
    Ok(())
}

/// Fixed synthetic process only. Production code has no such unisolated runner.
struct FixtureRunner {
    pid: Option<u32>,
    terminated: bool,
}
impl clawbell_sandbox::Runner for FixtureRunner {
    fn spawn(
        &mut self,
    ) -> impl std::future::Future<
        Output = Result<tokio::process::Child, clawbell_sandbox::LaunchError>,
    > + Send {
        const SCRIPT: &str = r"
import json, sys
sys.stderr.write('x' * 131072)
sys.stderr.flush()
for line in sys.stdin:
    m = json.loads(line)
    if 'id' in m:
        result = {'protocolVersion':'2025-06-18','capabilities':{},'serverInfo':{'name':'fixture','version':'1'}} if m.get('method') == 'initialize' else {}
        print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':result}), flush=True)
";
        let child = tokio::process::Command::new("/usr/bin/python3")
            .args(["-u", "-c", SCRIPT])
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| clawbell_sandbox::LaunchError);
        if let Ok(child) = &child {
            self.pid = child.id();
        }
        std::future::ready(child)
    }
    fn terminate(
        &mut self,
    ) -> impl std::future::Future<Output = Result<(), clawbell_sandbox::LaunchError>> + Send {
        self.terminated = true;
        std::future::ready(Ok(()))
    }
}
#[tokio::test]
async fn child_stderr_does_not_deadlock_and_child_is_reaped() -> TestResult {
    let (client, c) = tokio::io::duplex(4096);
    let (cr, cw) = tokio::io::split(c);
    let proxy = tokio::spawn(async move {
        let mut g = FixtureGate::default();
        let mut runner = FixtureRunner {
            pid: None,
            terminated: false,
        };
        let result = stdio::run(cr, cw, &mut g, &mut runner, Limits::default()).await;
        (result, runner, g)
    });
    let (r, mut w) = tokio::io::split(client);
    let mut r = BufReader::new(r);
    send(&mut w, &init()).await?;
    assert_eq!(recv(&mut r).await?, init_result());
    send(&mut w, &initialized()).await?;
    send(&mut w, &ping(2)).await?;
    assert_eq!(recv(&mut r).await?, result(2));
    send(
        &mut w,
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}),
    )
    .await?;
    let (result, runner, g) = tokio::time::timeout(Duration::from_secs(3), proxy).await??;
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(runner.terminated);
    assert!(g.finished);
    let pid = runner.pid.ok_or("missing pid")?;
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    Ok(())
}
#[test]
fn duplicate_keys_are_rejected() {
    for bytes in [br#"{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}"#.as_slice(),br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fixture","arguments":{"path":"safe","path":"bad"}}}"#.as_slice()] {
        assert!(Envelope::parse(bytes,Direction::Client,65536).is_err());
    }
}

#[tokio::test]
async fn http_rejects_redirect_session_mismatch_and_partial_sse_without_output() -> TestResult {
    let cases = [
        (
            "302 Found",
            "Location: http://169.254.169.254/\r\n",
            "application/json",
            "{}",
        ),
        (
            "200 OK",
            "Mcp-Session-Id: fixture\r\n",
            "application/json",
            "{}",
        ),
        (
            "200 OK",
            "",
            "application/json",
            r#"{"jsonrpc":"2.0","id":999,"result":{}}"#,
        ),
        (
            "200 OK",
            "",
            "text/event-stream",
            "data: {\"fixture-secret\":true}\n",
        ),
        ("200 OK", "", "text/html", "fixture-secret"),
    ];
    for (status, extra, kind, body) in cases {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/mcp", listener.local_addr()?);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut r = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                r.read_line(&mut line).await?;
                if line == "\r\n" {
                    break;
                }
                if let Some((k, v)) = line.split_once(':')
                    && k.eq_ignore_ascii_case("content-length")
                {
                    length = v.trim().parse::<usize>()?;
                }
            }
            let mut request = vec![0; length];
            tokio::io::AsyncReadExt::read_exact(&mut r, &mut request).await?;
            r.get_mut().write_all(format!("HTTP/1.1 {status}\r\n{extra}Content-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let target =
            http::Target::connect(&url, Some("127.0.0.1".parse()?), Limits::default()).await?;
        let (client, c) = tokio::io::duplex(4096);
        let (cr, cw) = tokio::io::split(c);
        let proxy = tokio::spawn(async move {
            let mut g = FixtureGate::default();
            let r = http::relay(cr, cw, target, &mut g, Limits::default()).await;
            (r, g)
        });
        let (r, mut w) = tokio::io::split(client);
        send(&mut w, &init()).await?;
        let (result, g) = tokio::time::timeout(Duration::from_secs(3), proxy).await??;
        assert!(result.is_err());
        assert!(g.finished);
        let mut output = String::new();
        assert_eq!(BufReader::new(r).read_line(&mut output).await?, 0);
        server.await??;
    }
    Ok(())
}

#[test]
fn sdk_custom_fallback_cannot_accept_malformed_known_methods() {
    for v in [
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}),
        json!({"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":42}}),
        json!({"jsonrpc":"2.0","method":"notifications/progress","params":{}}),
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","method":"ping"}),
        json!({"jsonrpc":"2.0","id":1,"method":"notifications/initialized"}),
    ] {
        assert!(parse(&v, Direction::Client).is_err());
    }
}

#[tokio::test]
async fn env_response_is_vaulted_and_local_arguments_are_restored() -> TestResult {
    use clawbell_proxy::dlp::LocalVaultGate;
    let (client, c) = tokio::io::duplex(65536);
    let (s, server) = tokio::io::duplex(65536);
    let (cr, cw) = tokio::io::split(c);
    let (sr, sw) = tokio::io::split(s);
    let proxy = tokio::spawn(async move {
        let mut gate = LocalVaultGate::new(FixtureGate::default(), vec!["connect".into()], 65536)?;
        stdio::relay(cr, cw, sr, sw, &mut gate, Limits::default()).await
    });
    let (r, mut w) = tokio::io::split(client);
    let mut r = BufReader::new(r);
    let (sr, mut sw) = tokio::io::split(server);
    let mut sr = BufReader::new(sr);
    send(&mut w, &init()).await?;
    recv(&mut sr).await?;
    send(&mut sw, &init_result()).await?;
    recv(&mut r).await?;
    send(&mut w, &initialized()).await?;
    recv(&mut sr).await?;
    send(&mut w, &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_env","arguments":{}}})).await?;
    recv(&mut sr).await?;
    // Synthetic .env file returned by the fake MCP server, fragmented on wire.
    let secret = "synthetic-database-password";
    let response = json!({"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":format!("PASSWORD={secret}\nPORT=5432\n")} ]}});
    let wire = serde_json::to_vec(&response)?;
    for chunk in wire.chunks(3) {
        sw.write_all(chunk).await?;
    }
    sw.write_all(b"\n").await?;
    let masked = recv(&mut r).await?;
    assert!(!masked.to_string().contains(secret));
    let text = masked
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .ok_or("missing text")?;
    let token = text
        .strip_prefix("PASSWORD=")
        .and_then(|s| s.split('\n').next())
        .ok_or("missing token")?;
    assert!(token.starts_with("[clawbell:"));
    send(&mut w, &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"connect","arguments":{"password":token}}})).await?;
    let restored = recv(&mut sr).await?;
    assert_eq!(
        restored.pointer("/params/arguments/password"),
        Some(&json!(secret))
    );
    drop(r);
    drop(w);
    let _ = proxy.await?;
    Ok(())
}

#[tokio::test]
async fn vault_denies_wrong_tool_forgery_raw_secrets_and_finished_session() -> TestResult {
    use clawbell_proxy::dlp::LocalVaultGate;
    let mut gate = LocalVaultGate::new(FixtureGate::default(), vec!["connect".into()], 65536)?;
    let response = parse(
        &json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"PASSWORD=synthetic-value"}]}}),
        Direction::Server,
    )?;
    let masked = gate.inspect(Direction::Server, &response).await?;
    let token = masked
        .value()
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .and_then(|s| s.strip_prefix("PASSWORD="))
        .ok_or("missing token")?;
    for (tool, password) in [
        ("other", token),
        ("connect", "[clawbell:forged]"),
        ("connect", "PASSWORD=raw-value"),
    ] {
        let request = parse(
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":tool,"arguments":{"password":password}}}),
            Direction::Client,
        )?;
        assert!(gate.inspect(Direction::Client, &request).await.is_err());
    }
    let request = parse(
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"connect","arguments":{"password":token}}}),
        Direction::Client,
    )?;
    gate.finish().await?;
    assert!(gate.inspect(Direction::Client, &request).await.is_err());
    assert!(!gate.permits_remote());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn reads_after_31_idle_seconds_and_301_session_seconds() -> TestResult {
    let (client, proxy_client) = tokio::io::duplex(65536);
    let (server, proxy_server) = tokio::io::duplex(65536);
    let (cr, cw) = tokio::io::split(proxy_client);
    let (sr, sw) = tokio::io::split(proxy_server);
    let proxy = tokio::spawn(async move {
        let mut gate = FixtureGate::default();
        stdio::relay(cr, cw, sr, sw, &mut gate, Limits::default()).await
    });
    let (read, mut write) = tokio::io::split(client);
    let mut client_read = BufReader::new(read);
    let (read, mut upstream_write) = tokio::io::split(server);
    let mut upstream_read = BufReader::new(read);
    send(&mut write, &init()).await?;
    assert_eq!(recv(&mut upstream_read).await?, init());
    send(&mut upstream_write, &init_result()).await?;
    recv(&mut client_read).await?;
    send(&mut write, &initialized()).await?;
    recv(&mut upstream_read).await?;
    for (id, seconds) in [(2, 31), (3, 270)] {
        tokio::time::advance(Duration::from_secs(seconds)).await;
        send(&mut write, &ping(id)).await?;
        assert_eq!(recv(&mut upstream_read).await?, ping(id));
        send(&mut upstream_write, &result(id)).await?;
        assert_eq!(recv(&mut client_read).await?, result(id));
    }
    // Activity near the lifetime boundary cannot extend the session.
    for id in 4..15 {
        tokio::time::advance(Duration::from_secs(if id == 14 { 298 } else { 300 })).await;
        send(&mut write, &ping(id)).await?;
        assert_eq!(recv(&mut upstream_read).await?, ping(id));
        send(&mut upstream_write, &result(id)).await?;
        recv(&mut client_read).await?;
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(matches!(proxy.await?, Err(Error::Timeout)));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn independent_idle_request_and_absolute_deadlines() -> TestResult {
    // Traffic cannot extend a request deadline. A response is rejected even if
    // an unrelated request arrived immediately before its deadline.
    let limits = Limits {
        request_timeout: Duration::from_secs(10),
        ..Limits::default()
    };
    let mut session = ready(limits)?;
    session.accept(Direction::Client, &parse(&ping(2), Direction::Client)?)?;
    tokio::time::advance(Duration::from_secs(9)).await;
    session.accept(Direction::Client, &parse(&ping(3), Direction::Client)?)?;
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(matches!(
        session.accept(Direction::Server, &parse(&result(2), Direction::Server)?),
        Err(Error::Timeout)
    ));
    for (idle, lifetime, elapsed) in [(5, 100, 6), (100, 5, 6)] {
        let (_client, proxy_client) = tokio::io::duplex(64);
        let (_server, proxy_server) = tokio::io::duplex(64);
        let (cr, cw) = tokio::io::split(proxy_client);
        let (sr, sw) = tokio::io::split(proxy_server);
        let proxy = tokio::spawn(async move {
            let mut gate = FixtureGate::default();
            let result = stdio::relay(
                cr,
                cw,
                sr,
                sw,
                &mut gate,
                Limits {
                    idle_timeout: Duration::from_secs(idle),
                    session_lifetime: Duration::from_secs(lifetime),
                    ..Limits::default()
                },
            )
            .await;
            (result, gate.finished)
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(elapsed)).await;
        let (result, finished) = proxy.await?;
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(finished);
    }
    Ok(())
}
