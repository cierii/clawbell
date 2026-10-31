//! Owner CLI and fail-closed local MCP launcher.
mod bind;
mod diagnostics;
mod errors;
mod evidence;
mod files;
mod launch;
mod manage;
mod oauth_store;
mod remote;
mod scan;
#[cfg(target_os = "linux")]
mod skill_scan;
#[cfg(target_os = "linux")]
mod transactional;
use crate::errors::Code;
use clap::{Parser, Subcommand};
use clawbell_proxy::monitor::{Command, Event, frame};
use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
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
#[command(version, about = "Local MCP firewall and static skill inspector")]
struct Cli {
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Review and explicitly accept first-launch or changed catalog baselines.
    Pins(manage::Pins),
    /// Inspect, export and rotate the private SQLite operation log.
    Audit(manage::Audit),
    /// Check native host prerequisites; optionally exercise adversarial probes.
    Doctor(diagnostics::Options),
    /// Run the synthetic containment and durable-audit demonstration.
    Demo(diagnostics::DemoOptions),
    /// Bind supported JSON MCP clients through the sandboxed firewall.
    Init {
        /// Explicit JSON client configurations; otherwise use known locations.
        #[arg(long)]
        config: Vec<PathBuf>,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        cgroup_parent: PathBuf,
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Restore unchanged managed configurations from their original .bak files.
    Unbind {
        #[arg(long)]
        config: Vec<PathBuf>,
    },
    /// Inspect an unpacked UTF-8 skill file/package offline (0 clean, 2 findings).
    Scan { path: PathBuf },
    /// Run one local stdio MCP server with mandatory policy, audit and containment.
    Proxy(launch::Options),
    /// Relay stdio to an owner-pinned remote Streamable HTTP MCP endpoint.
    ProxyHttp(remote::Options),
    /// Execute each local tool in private staging, then review and publish its actual diff.
    #[cfg(target_os = "linux")]
    ProxyTransaction(transactional::Options),
    /// Scan exact skill code, invocation, policy and initialization instructions.
    #[cfg(target_os = "linux")]
    SkillScan(skill_scan::Options),
    /// Validate owner policy without executing any tools.
    Policy {
        #[command(subcommand)]
        command: PolicyAction,
    },
    /// Monitor a running owner-private IPC endpoint. Commands require Enter.
    Monitor {
        /// Socket in a trusted owner-private directory, outside sandbox mounts.
        #[arg(long)]
        socket: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Parse and compile the complete strict policy.
    Check {
        #[arg(long)]
        file: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    match dispatch(Cli::parse().command).await {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{}", errors::diagnostic(error.as_ref()));
            std::process::exit(1);
        }
    }
}

fn configurations(config: Vec<PathBuf>) -> files::Result<Vec<PathBuf>> {
    let mut paths = if config.is_empty() {
        let home = std::env::var_os("HOME").ok_or(Code("home_required"))?;
        bind::discover(&PathBuf::from(home), &std::env::current_dir()?)
    } else {
        config
    };
    if paths.len() > 32 {
        return Err(Code("configuration_count_limit").into());
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err(Code("no_supported_configurations").into());
    }
    for path in &mut paths {
        *path = std::path::absolute(&*path)?;
    }
    Ok(paths)
}
async fn dispatch(action: Action) -> files::Result<i32> {
    match action {
        Action::Pins(options) => manage::pins(options).await?,
        Action::Audit(options) => {
            tokio::task::spawn_blocking(move || {
                manage::audit(options).map_err(|_| Code("audit_maintenance_failed"))
            })
            .await??;
        }
        Action::Doctor(options) => diagnostics::run(options).await?,
        Action::Demo(options) => {
            diagnostics::run(diagnostics::Options {
                cgroup_parent: options.cgroup_parent,
                self_test: true,
                report_dir: None,
                session_lifetime_secs: 3600,
            })
            .await?;
        }
        Action::Monitor { socket } => run(socket).await?,
        Action::Scan { path } => return Ok(if scan::run(&path)? { 2 } else { 0 }),
        Action::Policy {
            command: PolicyAction::Check { file },
        } => {
            clawbell_core::policy::Policy::parse(std::str::from_utf8(&files::read(
                &file,
                1024 * 1024,
            )?)?)?;
            println!("policy_valid");
        }
        Action::Proxy(options) => launch::run(options).await?,
        Action::ProxyHttp(options) => remote::run(options).await?,
        #[cfg(target_os = "linux")]
        Action::ProxyTransaction(options) => transactional::run(options).await?,
        #[cfg(target_os = "linux")]
        Action::SkillScan(options) => skill_scan::run(options).await?,
        Action::Init {
            config,
            policy,
            workspace,
            cgroup_parent,
            state_dir,
        } => {
            let settings = bind::Settings {
                binary: std::env::current_exe()?,
                policy: std::fs::canonicalize(policy)?,
                workspace: std::fs::canonicalize(workspace)?,
                cgroup_parent: std::fs::canonicalize(cgroup_parent)?,
                state_dir: std::fs::canonicalize(state_dir)?,
            };
            // Validate and exercise isolation before changing any client file.
            // Launch repeats all checks; preflight is never execution permission.
            clawbell_core::policy::Policy::parse(std::str::from_utf8(&files::read(
                &settings.policy,
                1024 * 1024,
            )?)?)?;
            files::trusted(&settings.state_dir)?;
            files::trusted(&settings.workspace)?;
            files::trusted(
                settings
                    .policy
                    .parent()
                    .ok_or(Code("policy_parent_required"))?,
            )?;
            if std::fs::metadata(&settings.state_dir)?.permissions().mode() & 0o777 != 0o700
                || settings.state_dir.starts_with(&settings.workspace)
                || ["/usr", "/etc", "/var"]
                    .iter()
                    .any(|path| settings.state_dir.starts_with(path))
            {
                return Err(Code("private_external_state_required").into());
            }
            let paths = configurations(config)?;
            for (index, path) in paths.iter().enumerate() {
                bind::preflight(path, &settings, index).await?;
            }
            for (index, path) in paths.iter().enumerate() {
                let changed = bind::init(path, &settings)?;
                println!(
                    "configuration_{index}: {}",
                    if changed { "bound" } else { "already_bound" }
                );
            }
        }
        Action::Unbind { config } => {
            for (index, path) in configurations(config)?.iter().enumerate() {
                let changed = bind::unbind(path)?;
                println!(
                    "configuration_{index}: {}",
                    if changed {
                        "restored_backup_retained"
                    } else {
                        "not_managed"
                    }
                );
            }
        }
    }
    Ok(0)
}

async fn run(socket: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        return Err(Code("terminal_required").into());
    }
    let parent =
        std::fs::symlink_metadata(socket.parent().ok_or(Code("private_directory_required"))?)?;
    let endpoint = std::fs::symlink_metadata(&socket)?;
    if !parent.is_dir()
        || parent.permissions().mode() & 0o777 != 0o700
        || endpoint.file_type().is_symlink()
        || endpoint.permissions().mode() & 0o777 != 0o600
    {
        return Err(Code("unsafe_socket").into());
    }
    let stream = UnixStream::connect(socket).await?;
    if stream.peer_cred()?.uid() != parent.uid() {
        return Err(Code("wrong_owner").into());
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
    fn independent_proxy_deadline_configuration() -> Result<(), Box<dyn std::error::Error>> {
        use super::*;
        for (flag, value) in [
            ("--idle-timeout-secs", "0"),
            ("--request-timeout-secs", "301"),
            ("--session-lifetime-secs", "86401"),
        ] {
            let cli = Cli::try_parse_from([
                "clawbell",
                "proxy",
                "--policy",
                "/policy",
                "--workspace",
                "/workspace",
                "--state-dir",
                "/state",
                "--cgroup-parent",
                "/cgroup",
                "--server",
                "synthetic",
                flag,
                value,
                "--",
                "/usr/bin/true",
            ])?;
            let Action::Proxy(options) = cli.command else {
                return Err(Code("proxy_required").into());
            };
            assert!(options.limits().is_err());
        }
        Ok(())
    }
    #[test]
    fn http_independent_deadlines_and_monitor_parse_before_network_access()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::*;
        for (flag, value, valid) in [
            ("--idle-timeout-secs", "0", false),
            ("--request-timeout-secs", "301", false),
            ("--session-lifetime-secs", "86401", false),
            ("--request-timeout-secs", "3", true),
            ("--idle-timeout-secs", "45", true),
            ("--session-lifetime-secs", "120", true),
        ] {
            let cli = Cli::try_parse_from([
                "clawbell",
                "proxy-http",
                "--url",
                "https://fixture.invalid/mcp",
                "--policy",
                "/policy",
                "--state-dir",
                "/state",
                "--server",
                "synthetic",
                "--monitor-socket",
                "/state/http.sock",
                flag,
                value,
            ])?;
            let Action::ProxyHttp(options) = cli.command else {
                return Err(Code("http_required").into());
            };
            assert_eq!(options.limits().is_ok(), valid);
            assert_eq!(
                options.monitor_socket,
                Some(PathBuf::from("/state/http.sock"))
            );
            if valid {
                let limits = options.limits()?;
                let configured = match flag {
                    "--idle-timeout-secs" => limits.idle_timeout,
                    "--request-timeout-secs" => limits.request_timeout,
                    _ => limits.session_lifetime,
                };
                assert_eq!(configured.as_secs().to_string(), value);
            }
        }
        Ok(())
    }
    #[test]
    fn peer_terminal_controls_are_never_executed() {
        let display = super::colored("\x1b]52;clipboard\x07");
        assert!(!display.contains("\x1b]52"));
        assert!(display.contains("\\u001b"));
        assert!(display.contains("\\u0007"));
    }
}

#[cfg(test)]
mod bind_tests;
