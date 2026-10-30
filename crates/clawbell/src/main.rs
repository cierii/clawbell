//! Terminal monitor client. Its stdout is a UI, never an MCP stdio transport.
use clap::{Parser, Subcommand};
use clawbell_proxy::monitor::{Command, Event, frame};
use std::fmt::Write as _;
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, IsTerminal, Write},
    path::PathBuf,
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::UnixStream,
};

#[derive(Parser)]
#[command(version, about = "Local MCP security monitor")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Monitor a running owner-private IPC endpoint. Commands require Enter.
    Monitor {
        /// Socket in a trusted owner-private directory, outside sandbox mounts.
        #[arg(long)]
        socket: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let Action::Monitor { socket } = Cli::parse().command;
    if run(socket).await.is_err() {
        eprintln!("monitor_failed: verify private socket and running proxy");
        std::process::exit(1);
    }
}

async fn run(socket: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        return Err("terminal_required".into());
    }
    let parent = std::fs::symlink_metadata(socket.parent().ok_or("private_directory_required")?)?;
    let endpoint = std::fs::symlink_metadata(&socket)?;
    if !parent.is_dir()
        || parent.permissions().mode() & 0o777 != 0o700
        || endpoint.file_type().is_symlink()
        || endpoint.permissions().mode() & 0o777 != 0o600
    {
        return Err("unsafe_socket".into());
    }
    let stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != parent.uid() {
        return Err("wrong_owner".into());
    }
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut input = BufReader::new(tokio::io::stdin());
    let mut packets = VecDeque::new();
    let mut pending = BTreeMap::new();
    let mut servers = BTreeMap::new();
    let mut network_buffer = Vec::new();
    let mut input_buffer = Vec::new();
    loop {
        render(&servers, &packets, &pending)?;
        tokio::select! {
            data = frame(&mut reader, &mut network_buffer) => {
                let event: Event = serde_json::from_slice(&data?)?;
                if event.id != 0 { if pending.len() == 32 { pending.pop_first(); } pending.insert(event.id, event.display); }
                else {
                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&event.display)
                        && let Some(server) = value.get("server").and_then(serde_json::Value::as_str) { if servers.len() == 256 { servers.pop_first(); } servers.insert(server.to_owned(), event.display.clone()); }
                    if packets.len() == 12 { packets.pop_front(); }
                    packets.push_back(event.display);
                }
            }
            line = frame(&mut input, &mut input_buffer) => {
                let bytes = line?;
                let text = std::str::from_utf8(&bytes)?.trim();
                if text == "q" { println!("\x1b[0m"); return Ok(()); }
                let mut words = text.split_whitespace();
                if let (Some(action @ ("a" | "d")), Some(id), None) = (words.next(), words.next(), words.next())
                    && let Ok(id) = id.parse::<u64>() && pending.remove(&id).is_some() {
                        let mut bytes = serde_json::to_vec(&Command { id, allow: action == "a" })?;
                        bytes.push(b'\n'); write.write_all(&bytes).await?;

                }
            }
        }
    }
}

// Only this renderer emits ANSI. Escape/control characters from peers are printed
// visibly; terminal OSC links, clipboard commands and cursor injection cannot run.
fn colored(text: &str) -> String {
    let mut output = String::new();
    let mut string = false;
    let mut escaped = false;
    for ch in text.chars().take(2000) {
        if ch.is_control() {
            let _ = write!(output, "\\u{:04x}", u32::from(ch));
            continue;
        }
        if ch == '"' && !escaped {
            string = !string;
            output.push_str(if string { "\x1b[36m" } else { "\x1b[0m" });
        }
        if ch == '[' && string {
            output.push_str("\x1b[33;1m");
        }
        output.push(ch);
        escaped = ch == '\\' && !escaped;
    }
    output.push_str("\x1b[0m");
    output
}
fn render(
    servers: &BTreeMap<String, String>,
    packets: &VecDeque<String>,
    pending: &BTreeMap<u64, String>,
) -> io::Result<()> {
    print!("\x1b[2J\x1b[Hclawbell | MCP security monitor\nServers / sandbox attestation\n");
    for status in servers.values() {
        println!("{}", colored(status));
    }
    println!("\nLive JSON-RPC (cyan strings, yellow masked values)");
    for packet in packets {
        println!("{}", colored(packet));
    }
    println!("\nPending decisions (expired IDs are refused by proxy)");
    for (id, context) in pending {
        println!("{id}: {}", colored(context));
    }
    print!("\na ID = approve once | d ID = deny | q = quit; then Enter\n> ");
    io::stdout().flush()
}

#[cfg(test)]
mod tests {
    #[test]
    fn peer_terminal_controls_are_never_executed() {
        let display = super::colored("\x1b]52;clipboard\x07");
        assert!(!display.contains("\x1b]52"));
        assert!(display.contains("\\u001b"));
        assert!(display.contains("\\u0007"));
    }
}
