//! Reversible JSON MCP client binding. Configurations are data, never commands
//! to execute during discovery. A private original backup is never overwritten.
use crate::errors::Code;
use crate::files::{self, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
const MAX: usize = 1024 * 1024;
/// Explicit owner settings. Paths are made absolute before generating arguments.
pub struct Settings {
    pub binary: PathBuf,
    pub policy: PathBuf,
    pub workspace: PathBuf,
    pub cgroup_parent: PathBuf,
    pub state_dir: PathBuf,
}
/// Bounded known locations, including project-local clients. Does not recursively
/// traverse a home directory, inspect credentials, or follow discovered symlinks.
pub fn discover(home: &Path, workspace: &Path) -> Vec<PathBuf> {
    [
        home.join(".cursor/mcp.json"),
        home.join(".config/Claude/claude_desktop_config.json"),
        home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        home.join(".config/Code/User/mcp.json"),
        workspace.join(".mcp.json"),
        workspace.join(".cursor/mcp.json"),
        workspace.join(".vscode/mcp.json"),
    ]
    .into_iter()
    .filter(|p| p.exists())
    .collect()
}
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn text(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| Code("non_utf8_path").into())
}
fn remote_url(entry: &serde_json::Map<String, Value>) -> Result<String> {
    if entry
        .keys()
        .any(|k| !["url", "type", "clawbellOAuth"].contains(&k.as_str()))
        || entry
            .get("type")
            .is_some_and(|v| !matches!(v.as_str(), Some("http" | "streamable-http")))
    {
        return Err(Code("unsupported_remote_options").into());
    }
    let url = reqwest::Url::parse(
        entry
            .get("url")
            .and_then(Value::as_str)
            .ok_or(Code("remote_url_required"))?,
    )?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Code("credential_free_https_required").into());
    }
    Ok(url.to_string())
}
fn server_map(config: &mut Value) -> Result<&mut serde_json::Map<String, Value>> {
    let object = config
        .as_object_mut()
        .ok_or(Code("configuration_object_required"))?;
    // Ambiguous formats are refused instead of leaving an unguarded second map.
    if object.contains_key("mcpServers") && object.contains_key("servers") {
        return Err(Code("ambiguous_configuration").into());
    }
    let key = if object.contains_key("mcpServers") {
        "mcpServers"
    } else {
        "servers"
    };
    let servers = object
        .get_mut(key)
        .ok_or(Code("unsupported_configuration"))?;
    let servers = servers.as_object_mut().ok_or(Code("invalid_server_map"))?;
    if servers.is_empty() || servers.len() > 256 {
        return Err(Code("invalid_server_count").into());
    }
    Ok(servers)
}
fn remote_oauth(entry: &serde_json::Map<String, Value>) -> Result<Vec<String>> {
    let Some(value) = entry.get("clawbellOAuth") else {
        return Ok(Vec::new());
    };
    let config = value.as_object().ok_or(Code("invalid_oauth_binding"))?;
    if config
        .keys()
        .any(|k| !["issuer", "client_id", "scopes"].contains(&k.as_str()))
    {
        return Err(Code("invalid_oauth_binding").into());
    }
    let issuer = reqwest::Url::parse(
        config
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or(Code("invalid_oauth_binding"))?,
    )?;
    if issuer.scheme() != "https"
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err(Code("invalid_oauth_binding").into());
    }
    let mut args = vec![
        "--oauth-issuer".into(),
        issuer.to_string(),
        "--oauth-persist".into(),
    ];
    if let Some(client) = config.get("client_id") {
        let client = client
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 1024 && !s.chars().any(char::is_control))
            .ok_or(Code("invalid_oauth_binding"))?;
        args.extend(["--oauth-client-id".into(), client.to_owned()]);
    }
    if let Some(scopes) = config.get("scopes") {
        let scopes = scopes
            .as_array()
            .filter(|s| s.len() <= 32)
            .ok_or(Code("invalid_oauth_binding"))?;
        for scope in scopes {
            let scope = scope
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
                .ok_or(Code("invalid_oauth_binding"))?;
            args.extend(["--oauth-scope".into(), scope.to_owned()]);
        }
    }
    Ok(args)
}
fn wrap_remote(
    entry: &mut serde_json::Map<String, Value>,
    name: &str,
    settings: &Settings,
    scope: &str,
) -> Result<()> {
    let url = remote_url(entry)?;
    let server_id = format!("{}:{name}", &scope[..16]);
    if server_id.len() > 128 {
        return Err(Code("server_identity_limit").into());
    }
    let socket_key = digest(format!("{scope}:{name}").as_bytes());
    let socket = settings
        .state_dir
        .join(format!("monitor-{}.sock", &socket_key[..24]));
    if text(&socket)?.len() > 107 {
        return Err(Code("monitor_socket_path_limit").into());
    }
    let mut args: Vec<String> = [
        "proxy-http",
        "--url",
        &url,
        "--policy",
        text(&settings.policy)?,
        "--state-dir",
        text(&settings.state_dir)?,
        "--server",
        &server_id,
        "--monitor-socket",
        text(&socket)?,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    args.extend(remote_oauth(entry)?);
    *entry = serde_json::from_value(
        json!({"type":"stdio","command":text(&settings.binary)?,"args":args}),
    )?;
    Ok(())
}
fn transform(original: &[u8], settings: &Settings, scope: &str) -> Result<Vec<u8>> {
    let mut config: Value = clawbell_core::json::parse(original)?;
    let servers = server_map(&mut config)?;
    for (name, server) in servers {
        let entry = server.as_object_mut().ok_or(Code("invalid_server"))?;
        if entry.contains_key("url") {
            wrap_remote(entry, name, settings, scope)?;
            continue;
        }
        let command = entry
            .get("command")
            .and_then(Value::as_str)
            .ok_or(Code("stdio_command_required"))?
            .to_owned();
        if !command.starts_with("/usr/bin/") || command.contains("/../") {
            return Err(Code("absolute_usr_bin_command_required").into());
        }
        if entry.contains_key("url")
            || entry.contains_key("envFile")
            || entry.contains_key("cwd")
            || entry
                .get("env")
                .is_some_and(|v| v.as_object().is_none_or(|m| !m.is_empty()))
            || entry.get("type").is_some_and(|v| v != "stdio")
        {
            return Err(Code("unsupported_server_options").into());
        }
        let args = entry.get("args").map_or(Ok(Vec::new()), |v| {
            v.as_array().ok_or(Code("invalid_arguments")).and_then(|v| {
                v.iter()
                    .map(|s| {
                        s.as_str()
                            .map(str::to_owned)
                            .ok_or(Code("invalid_argument"))
                    })
                    .collect()
            })
        })?;
        if args.len() > 256 || args.iter().map(String::len).sum::<usize>() > 131_072 {
            return Err(Code("startup_argument_limit").into());
        }
        // Identity includes client path at composition time through the explicit
        // server ID below; command+args are separately hashed by the launcher.
        let server_id = format!("{}:{name}", &scope[..16]);
        if server_id.len() > 128 {
            return Err(Code("server_identity_limit").into());
        }
        // Stable per-client/per-server endpoint avoids collisions between bindings.
        let socket_key = digest(format!("{scope}:{name}").as_bytes());
        let socket = settings
            .state_dir
            .join(format!("monitor-{}.sock", &socket_key[..24]));
        if text(&socket)?.len() > 107 {
            return Err(Code("monitor_socket_path_limit").into());
        }
        let mut wrapped: Vec<String> = [
            "proxy",
            "--policy",
            text(&settings.policy)?,
            "--workspace",
            text(&settings.workspace)?,
            "--cgroup-parent",
            text(&settings.cgroup_parent)?,
            "--state-dir",
            text(&settings.state_dir)?,
            "--server",
            &server_id,
            "--monitor-socket",
            text(&socket)?,
            "--",
            &command,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        // The runner mounts the selected host directory at /workspace. Translate
        // complete path arguments only; never parse shell source or option text.
        for argument in args {
            if let Ok(relative) = Path::new(&argument).strip_prefix(&settings.workspace) {
                wrapped.push(text(&Path::new("/workspace").join(relative))?.to_owned());
            } else {
                wrapped.push(argument);
            }
        }
        entry.insert("command".into(), json!(text(&settings.binary)?));
        entry.insert("args".into(), json!(wrapped));
    }
    let mut bytes = serde_json::to_vec_pretty(&config)?;
    bytes.push(b'\n');
    if bytes.len() > MAX {
        return Err(Code("bound_configuration_limit").into());
    }
    Ok(bytes)
}
/// Check every server's binding and isolation before any configuration mutation.
/// The only launched program is the runner's fixed trusted probe, never an
/// upstream or its arguments. Report indices and fixed statuses, never names.
pub async fn preflight(path: &Path, settings: &Settings, index: usize) -> Result<()> {
    files::trusted(path.parent().ok_or(Code("parent_required"))?)?;
    let live = files::read(path, MAX)?;
    let receipt = sidecar(path, ".clawbell.json");
    let original = if receipt.exists() {
        let record: Value = serde_json::from_slice(&files::read(&receipt, MAX)?)?;
        let backup = files::read(&sidecar(path, ".bak"), MAX)?;
        if record["bound_sha256"] != digest(&live) || record["original_sha256"] != digest(&backup) {
            return Err(Code("binding_changed_or_incomplete").into());
        }
        if transform(&backup, settings, &digest(text(path)?.as_bytes()))? != live {
            return Err(Code("binding_settings_changed").into());
        }
        backup
    } else {
        live
    };
    // Reuse strict transformation validation without writing its output.
    transform(&original, settings, &digest(text(path)?.as_bytes()))?;
    let config: Value = clawbell_core::json::parse(&original)?;
    let servers = config
        .get("mcpServers")
        .or_else(|| config.get("servers"))
        .and_then(Value::as_object)
        .ok_or(Code("invalid_server_map"))?;
    for (server_index, server) in servers.values().enumerate() {
        if let Some(entry) = server.as_object().filter(|e| e.contains_key("url")) {
            let url = remote_url(entry)?;
            let result = clawbell_proxy::network::Endpoint::connect(
                &url,
                None,
                clawbell_proxy::Limits::default(),
            )
            .await;
            println!(
                "configuration_{index}_server_{server_index}: {}",
                if result.is_ok() {
                    "preflight_passed"
                } else {
                    "preflight_denied"
                }
            );
            result?;
            continue;
        }
        let result = clawbell_sandbox::native::NativeRunner::preflight(
            clawbell_sandbox::native::NativeConfig {
                workspace: settings.workspace.clone(),
                executable: server["command"]
                    .as_str()
                    .ok_or(Code("stdio_command_required"))?
                    .into(),
                arguments: server.get("args").and_then(Value::as_array).map_or_else(
                    Vec::new,
                    |args| {
                        args.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    },
                ),
                cgroup_parent: settings.cgroup_parent.clone(),
                limits: clawbell_sandbox::native::ResourceLimits::default(),
            },
        )
        .await;
        println!(
            "configuration_{index}_server_{server_index}: {}",
            if result.is_ok() {
                "preflight_passed"
            } else {
                "preflight_denied"
            }
        );
        result?;
    }
    Ok(())
}
/// Commit one file, with original backup and hash receipt. A failed/interrupted
/// install keeps its backup; it never guesses recovery or overwrites that backup.
pub fn init(path: &Path, settings: &Settings) -> Result<bool> {
    files::trusted(path.parent().ok_or(Code("parent_required"))?)?;
    if std::fs::symlink_metadata(path)?.mode() & 0o022 != 0 {
        return Err(Code("writable_configuration_refused").into());
    }
    let original = files::read(path, MAX)?;
    let backup = sidecar(path, ".bak");
    let receipt = sidecar(path, ".clawbell.json");
    if receipt.exists() {
        let record: Value = serde_json::from_slice(&files::read(&receipt, MAX)?)?;
        if record["bound_sha256"] == digest(&original)
            && record["original_sha256"] == digest(&files::read(&backup, MAX)?)
        {
            return Ok(false);
        }
        return Err(Code("binding_changed_or_incomplete").into());
    }
    // Separate identical server names in different client configurations without
    // placing client paths in logs or baseline storage.
    let scope = digest(text(path)?.as_bytes());
    let bound = transform(&original, settings, &scope)?;
    files::create(&backup, &original)?;
    // The receipt is durable first. If rename fails, unbind recognizes original
    // bytes and can finish cleanup; a second init refuses inconsistent state.
    files::create(
        &receipt,
        &serde_json::to_vec(
            &json!({"original_sha256": digest(&original), "bound_sha256": digest(&bound)}),
        )?,
    )?;
    files::replace(path, &original, &bound)?;
    Ok(true)
}
/// Restore byte-for-byte only when both receipt hashes match. Later client edits
/// cause refusal, preserving the live file and backup for manual reconciliation.
pub fn unbind(path: &Path) -> Result<bool> {
    files::trusted(path.parent().ok_or(Code("parent_required"))?)?;
    let receipt = sidecar(path, ".clawbell.json");
    let backup = sidecar(path, ".bak");
    if !receipt.exists() {
        return Ok(false);
    }
    let record: Value = serde_json::from_slice(&files::read(&receipt, MAX)?)?;
    let original = files::read(&backup, MAX)?;
    let current = files::read(path, MAX)?;
    if record["original_sha256"] != digest(&original)
        || (record["bound_sha256"] != digest(&current) && current != original)
    {
        return Err(Code("binding_changed_or_incomplete").into());
    }
    if current != original {
        files::replace(path, &current, &original)?;
    }
    std::fs::remove_file(receipt)?;
    // Backup is retained intentionally. New init refuses until owner archives it.
    files::sync_parent(path)?;
    Ok(true)
}
