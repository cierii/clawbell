//! Explicit kernel conformance test for the Seatbelt component, not a Runner test.
#![cfg(target_os = "macos")]
use clawbell_sandbox::macos::profile;
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
#[ignore = "requires macOS Seatbelt; does not certify aggregate resource controls"]
fn seatbelt_mcp_direct_syscall_cannot_read_key() -> Result {
    let root = std::env::temp_dir().join(format!("clawbell-seatbelt-{}", std::process::id()));
    fs::create_dir(&root)?;
    let root = root.canonicalize()?;
    fs::create_dir(root.join("code"))?;
    fs::create_dir_all(root.join("home/.ssh"))?;
    let key = root.join("home/.ssh/id_rsa");
    fs::write(&key, "SYNTHETIC-NOT-A-REAL-PRIVATE-KEY")?;
    std::os::unix::fs::symlink(&key, root.join("code/alias"))?;
    // No MCP tool call is involved: sysopen invokes open(2) directly.
    let attack = r#"use Fcntl; my $request=<STDIN>; for my $p (@ARGV) {
        if (sysopen(my $fh, $p, O_RDONLY)) { exit 10; }
        if (!$!{EACCES} && !$!{EPERM}) { exit 11; }
    } print qq({"jsonrpc":"2.0","id":1,"result":{"blocked":true}}\n);"#;
    let mut child = Command::new("/usr/bin/sandbox-exec")
        .env_clear()
        .args([
            "-p",
            &profile(&root.join("code"))?,
            "/usr/bin/perl",
            "-e",
            attack,
        ])
        .arg(&key)
        .arg(root.join("code/alias"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")?;
    let result = child.wait_with_output()?;
    assert!(result.status.success());
    assert!(String::from_utf8(result.stdout)?.contains("blocked"));
    fs::remove_dir_all(root)?;
    Ok(())
}
