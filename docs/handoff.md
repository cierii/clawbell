# Handoff — 2026-10-30: audit A-01 / A-02 DLP fixes

## Current result

LocalVaultGate now inspects JSON numbers, booleans and null recursively in both
directions, with credential field context. Secret-bearing scalars refuse without
type conversion or an inner gate call. Server result blocks allow only text and
inline text resources (absent MIME, text/plain, text/markdown); unsupported binary,
image/audio/link/unknown/mixed formats refuse before redaction and the inner gate.
Tool, resource-read and prompt result carriers are covered. No general encoded
secret detection or binary decoder was added. See ADR 0007 for migration/limits.

Changes: crates/proxy/src/dlp.rs, crates/clawbell/src/attack_tests.rs, README.md,
docs/adr/0007-dlp-scalar-and-content-inspection.md and this handoff. Existing
untracked audit and launch documents were preserved and excluded from the commit.
AGENTS.md, dependencies and lockfile are unchanged.

## Verification

- Context7: serde_json Value/scalar serialization and official rmcp content/resource
  contracts. Both production regressions fail against the previous implementation
  and pass after the fix. Four boundary tests cover refusal before the inner gate,
  both directions, nested scalars, public type preservation, misleading MIME,
  mixed/unsupported blocks and allowed text resource redaction.
- scripts/check-local.sh passed: locked fetch, fmt, Clippy all targets/-D warnings,
  workspace tests, release build, CLI help and policy validation. Initial socket
  failures in the restricted tool environment were resolved by running the same
  checks outside that restriction; no product controls or tests were weakened.
- Expanded production gate benchmark: 4,000 warmed packets including inline text
  resources and structured scalars, p99 218.474 us, max 622.019 us (<5 ms each).
- Native Linux suite passed via delegated systemd scope: SSH isolation/lifecycle,
  2,000 transport RTTs (max 146.297 us), five real CLI attacks with unchanged
  synthetic host/memory fixtures, 2,000 full CLI/native/audit/DLP/policy RTTs
  (p99 0.615 ms, max 1.476 ms). Explicit agent-memory protection also passed.
- Checksum-verified gitleaks 8.30.1 scanned fetched Git history and documentation
  with no findings. The exact staged candidate is scanned before commit.
- git diff --check and documentation links checked; AGENTS.md stays at 199 lines.
  No frontend exists or changed, so npm/browser checks do not apply.

Performance results describe warmed bounded packets on this host, not a hard
real-time guarantee under arbitrary load or for maximum-size messages. Remaining
audit findings are outside this task. GitHub CI must validate the pushed commit.

---

# Handoff — 2026-10-30: installer, skill inspector and Linux MVP

## Delivered

CLI now provides `init`, `unbind`, `scan`, `proxy`, `policy check` and the existing
monitor client. Binding discovers bounded known JSON MCP client locations or
explicit paths, uses private exclusive .bak files and hash receipts, preserves
literal arguments and refuses unsafe restoration/tampering. Complete workspace
path arguments translate to the runner's /workspace mount.

The static inspector flags hidden Unicode, standard/URL-safe Base64 (including
bounded nested decoding), network/credential/memory/instruction indicators. It
never runs files or prints payloads. Package/inspection limits fail closed.

The executable Linux launcher composes NativeRunner, strict protocol, immutable
policy, pinned schemas/catalog, session DLP and the new dedicated durable operation
audit writer. Unsupported capabilities/resources/prompts deny. No production
allow-all adapter, unisolated launch, network/write exception or secret restoration.

Files: CLI binding/files/scan/launch and adversarial tests; core skill inspection
and shared strict JSON parser; audit operations writer/tests; real CLI fixture and
attack/performance harness; verification/secret/package scripts; GitHub Actions;
README, ADR 0006 and release notes. AGENTS.md remains unchanged at 199 lines.
Only direct dependencies added were already locked transitively: base64, sha2, libc.

## Verified on this Linux host

- Context7: clap subcommands/trailing arguments, rusqlite durability/transactions,
  bubblewrap descriptor/namespace/build contracts. Official bubblewrap v0.12.0
  tag resolves to 2a76602a8c71f36c1527cf9fc3417d9149822e0c for native CI.
- Full `bash scripts/check-release.sh` passed, with pinned Rust 1.99.1: fetch
  --locked, format, Clippy all targets/-D warnings, workspace tests, release build,
  CLI help/policy validation, explicit native memory/lifecycle/SSH tests and all
  release latency gates. Ordinary restricted sandbox socket tests initially failed
  on denied Unix/loopback binds; full verification outside those environmental
  restrictions passed. Isolation was never weakened to obtain passing tests.
- 4,000 production gate packets (parse/encode, schema/policy, DLP, synchronous FULL
  durable audit): p99 201.432 microseconds, maximum 758.988 microseconds.
- Full real CLI + native process + transport + policy/schema + DLP + durable audit:
  2,000 warmed read-tool RTTs, p99 0.941 ms, maximum 2.211 ms. Every sample <5 ms.
  Five real CLI attacks refused; synthetic host credentials and SOUL.md unchanged.
- Native transport-only RTT maximum 356.967 microseconds; policy gate 17.934 us;
  DLP 2,274-byte packet 324.375 us; monitor publication 9.528 us.
- Backup round trips/idempotence, interrupted install cleanup, tampered backups,
  owner edits, symlink/hardlink/unsafe directory refusal, unsupported JSON/server
  options, duplicate keys, Unicode scalar sweep/nested Base64/budgets, public CLI
  scan statuses, storage refusal and append-only durability covered by tests.
- Python AST, Bash syntax, local documentation links, workflow YAML syntax and
  git diff whitespace checked. Packaging/checksum verification is run before commit.
- Gitleaks fetched Git history: no leaks found. Exact staged candidate is scanned
  before commit; no claim of exhaustive secret detection or remote-fork erasure.

## Release and remaining limits

GitHub Actions builds a checksummed x86-64 Linux archive and publishes only for a
matching v0.1.0 tag after checks and native jobs pass. Hosted native job provisions
bubblewrap/user namespaces/cgroups; unavailable facilities fail, not skip. GitHub
connector returned 404 for this private repository; SSH fetch works. Remote Actions
status/publication must be checked separately; local tests do not certify CI.

The launcher requires a private external state directory and persistent owner
cgroup delegation. Installer does not provision persistent host service-manager
configuration or support JSONC, remote URLs, PATH executables, credential env/cwd.
Static heuristics and TOFU do not establish safety. The selected mounted workspace
must be credential-free. HTTP library adapters remain available, but automatic
HTTP binding, web UI and interactive approval integration are outside this MVP.
macOS/Windows execution remains unavailable/fail-closed. No frontend manifests
exist, so npm/browser UI checks were not applicable or reported as passing.

Latency results cover warmed bounded local packets; startup, schema compilation,
large messages, arbitrary storage contention and scheduler pauses are excluded.
No universal hard real-time guarantee or durability fallback is claimed. Audit has
a hard page quota and no automatic retention. Unfinished intents remain unknown
and never replay; owner-reviewed rotation and legitimate baseline migrations need
future explicit contracts. Backup/receipt recovery is in ADR 0006.

Toolchain environment used locally: RUSTUP_HOME=/tmp/clawbell-rustup,
CARGO_HOME=/tmp/clawbell-cargo, PATH=/tmp/clawbell-cargo/bin:/usr/bin:/bin.
