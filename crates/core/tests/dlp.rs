use clawbell_core::dlp::{Scanner, Vault};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn fragmented_secrets_and_session_isolation() -> Result {
    let inputs = [
        "API_KEY=synthetic-api-value",
        "postgres://user:synthetic@db/test",
        concat!(
            "-----BEGIN ",
            "OPENSSH PRIVATE KEY-----\nsynthetic\n",
            "-----END ",
            "OPENSSH PRIVATE KEY-----"
        ),
        "ssh-ed25519 c3ludGhldGlj",
        "sk-abcdefghijklmnopqrstuvwx",
    ];
    for input in inputs {
        let mut vault = Vault::new(65536)?;
        for split in 0..=input.len() {
            let mut scanner = Scanner::new(65536);
            scanner.push(&input.as_bytes()[..split])?;
            scanner.push(&input.as_bytes()[split..])?;
            let masked = scanner.finish(&mut vault)?;
            assert_ne!(masked, input);
            assert_eq!(&*vault.restore(&masked)?, input);
            assert!(Vault::new(65536)?.restore(&masked).is_err());
        }
    }
    Ok(())
}
#[test]
fn fail_closed() -> Result {
    let mut vault = Vault::new(1024)?;
    assert!(
        vault
            .redact("-----BEGIN PRIVATE KEY-----\nunfinished")
            .is_err()
    );
    assert!(vault.restore("[clawbell:forged]").is_err());
    let token = vault.register("synthetic")?;
    assert!(
        vault
            .check_request(&format!("{token} PASSWORD=raw-value"))
            .is_err()
    );
    let mut scanner = Scanner::new(1);
    assert!(scanner.push(b"too long").is_err());
    assert!(scanner.finish(&mut vault).is_err());
    let mut scanner = Scanner::new(10);
    scanner.push(&[255])?;
    assert!(scanner.finish(&mut vault).is_err());
    Ok(())
}
#[test]
#[ignore = "explicit release latency experiment"]
fn dlp_packet_under_five_ms() -> Result {
    let mut vault = Vault::new(1024 * 1024)?;
    let packet = format!(
        "API_KEY=synthetic-benchmark-value\n{}",
        "plain content ".repeat(160)
    );
    for index in 0..64 {
        vault.register(&format!("registered-synthetic-{index:04}"))?;
    }
    let mut times = Vec::new();
    for _ in 0..2200 {
        let start = std::time::Instant::now();
        let mut scanner = Scanner::new(1024 * 1024);
        for chunk in packet.as_bytes().chunks(97) {
            scanner.push(chunk)?;
        }
        let masked = scanner.finish(&mut vault)?;
        assert_eq!(&*vault.restore(&masked)?, &packet);
        times.push(start.elapsed());
    }
    let times = &mut times[200..];
    times.sort_unstable();
    eprintln!(
        "DLP {}-byte packet p99={:?} max={:?}",
        packet.len(),
        times[1979],
        times[1999]
    );
    assert!(times[1999] < std::time::Duration::from_millis(5));
    Ok(())
}
