//! Synthetic gate only: measures transport + OS containment, not durable audit.
#![cfg(target_os = "linux")]
use clawbell_proxy::{Direction, Envelope, Error, Gate, Limits, stdio};
use clawbell_sandbox::native::{NativeConfig, NativeRunner, ResourceLimits};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct FixtureGate;
impl Gate for FixtureGate {
    fn finish(&mut self) -> impl Future<Output = std::result::Result<(), Error>> + Send {
        std::future::ready(Ok(()))
    }
    fn inspect(
        &mut self,
        _: Direction,
        message: &Envelope,
    ) -> impl Future<Output = std::result::Result<Envelope, Error>> + Send {
        std::future::ready(Ok(message.clone()))
    }
}
#[tokio::test]
#[ignore = "release measurement with real delegated cgroup and namespaces"]
async fn native_proxy_packets_under_ten_ms() -> Result {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .canonicalize()?;
    let mut runner = NativeRunner::new(NativeConfig {
        workspace,
        cgroup_parent: std::env::var("CLAWBELL_TEST_CGROUP")?.into(),
        executable: "/usr/bin/python3".into(),
        arguments: vec!["-B".into(), "/workspace/echo_mcp.py".into()],
        limits: ResourceLimits::default(),
    })?;
    let (client, proxy) = tokio::io::duplex(65536);
    let (read, write) = tokio::io::split(proxy);
    let task = tokio::spawn(async move {
        stdio::run(
            read,
            write,
            &mut FixtureGate,
            &mut runner,
            Limits::default(),
        )
        .await
    });
    let (read, mut write) = tokio::io::split(client);
    let mut reader = BufReader::new(read);
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}});
    write.write_all(format!("{init}\n").as_bytes()).await?;
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut line)).await??;
    assert!(serde_json::from_str::<Value>(&line)?["result"].is_object());
    write
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await?;
    let mut samples = Vec::new();
    for id in 2..2202 {
        let packet = format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"ping\"}}\n");
        line.clear();
        let start = Instant::now();
        write.write_all(packet.as_bytes()).await?;
        tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line)).await??;
        let elapsed = start.elapsed();
        assert_eq!(serde_json::from_str::<Value>(&line)?["id"], id);
        if id >= 202 {
            samples.push(elapsed);
        }
    }
    drop(write);
    drop(reader);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await??;
    samples.sort_unstable();
    let max = samples.last().ok_or("no samples")?;
    eprintln!(
        "Native proxy RTT: n={}, p99={:?}, max={max:?}",
        samples.len(),
        samples[1980]
    );
    assert!(*max < Duration::from_millis(10));
    Ok(())
}
