# Handoff — 2026-10-30: terminal monitor and human approval

## Objective and delivered changes

Added bounded Unix-socket IPC, a terminal monitor client, live redacted packet
telemetry, owner server/sandbox status events and a RequireApproval rendezvous
inside PolicyGate. The immutable call is suspended until a one-use owner decision;
inner audit/DLP and schema/catalog/memory protections remain mandatory.

Files: proxy/src/monitor.rs, proxy/src/policy.rs, core policy/signatures helpers,
clawbell CLI and dependencies/lockfile, integration/unit tests, README, ADR 0005.
AGENTS.md is unchanged at 199 lines. No React/browser panel was added.

## Verified

- Context7 Tokio Unix socket, peer credentials, bounded channel/timeout contracts.
- cargo fmt --all -- --check; clippy workspace/all-targets/locked with -D warnings.
- cargo test --workspace --locked --no-fail-fast passed outside restricted socket
  sandbox. Ordinary sandbox attempts failed on forbidden Unix/loopback binds;
  these were not treated as passing checks. Native OS ignored tests were not rerun.
- cargo build --workspace --release --locked; CLI --help.
- Release monitor_packet_under_five_ms: 2000 warmed complete telemetry publications,
  maximum 7.093 microseconds. This measures added telemetry only, not total proxy
  cost, audit fsync, scheduler worst cases, large packets or human wait.
- Real IPC integration proves zero inner calls before approval and exactly one
  afterward; unit tests cover one-use consumption, rejection, absent owner,
  redaction of a registered synthetic secret, framing bounds/EOF, terminal controls.
- PTY smoke test showed server status, cyan JSON strings, yellow synthetic marker,
  pending queue and `d 1` keyboard command. Synthetic peer received allow=false;
  its deliberate disconnect produced the expected sanitized monitor error.
- Gitleaks history scan after git fetch found no leaks. Final exact candidate
  snapshot is scanned before commit; this does not prove absence of every secret.

## Integration limits and next step

CLI now exposes `monitor --socket PATH`; it does not launch a deployable audited
proxy. Existing repo has no operation-audit Gate composition. Library users must
create/supervise Monitor::serve, register known secrets, attach with_monitor, and
publish runner-verified sandbox status. PolicyGate explicitly reports unattested
sandbox status. Do not fabricate an allow-all adapter for a demo deployment.

Owner-private directory and all ancestors must be trusted, inaccessible to child
sandboxes. Socket survives server termination; explicit owner cleanup is required.
The UI uses cooked terminal input, Enter for commands and bounded history. Expired
IDs may remain visible until local removal/reconnect; proxy always refuses them.
Remote effects remain outside local runner isolation. Full end-to-end latency is
not certified. macOS NativeRunner remains fail-closed as documented in ADR 0004.
Future work must supply durable operation-audit composition and runner-attested
inventory before describing the CLI as a complete firewall deployment.

Toolchain: RUSTUP_HOME=/tmp/clawbell-rustup,
CARGO_HOME=/tmp/clawbell-cargo, /tmp/clawbell-cargo/bin/cargo.
