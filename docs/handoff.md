# Handoff — 2026-10-31: deadlines, pin reviews and audit maintenance

Delivered independent CLI/library request, idle and absolute session limits with
30/600/3600-second production defaults. Native containment receives the same
configured session lifetime. Paused-clock transport tests read successfully after
31 idle seconds and at 301 session seconds, then verify expiration despite later
traffic. Invalid configuration, idle and request deadlines remain fail-closed.

First observations and changed catalogs now stage immutable hash-only proposals
and deny forwarding until explicit owner acceptance. `pins review`, `accept` and
`history` preserve the database, existing legacy pins, previous/proposed tool sets
and UTC acceptance receipts. Superseded/replayed decisions refuse. Existing DLP
and schema validation run before staging; synthetic secret catalogs create no
pin or proposal. Review output is a digest diff, not raw descriptions/schemas;
owners must inspect upstream source independently before accepting.

`audit status`, bounded cursor-based JSONL `view` / private exclusive `export`, and
lossless offline `rotate --accept` are implemented. Dedicated writers warn at 80%,
95% and the last 32 pages; new intents refuse in that final reserve. Rotation
requires all writers stopped, obtains an exclusive SQLite transaction, durably
archives the complete DELETE-journal database with SHA-256 before transactional
retention, preserves receipts/append-only triggers and VACUUMs active pages.
Pin acceptance uses the same exclusive owner maintenance lock to require session
teardown. Rotation refuses WAL, active writers and failed retention. Archives
retain unknown outcomes; they are never replayed or automatically deleted.

Files: proxy limits/stdio/HTTP/protocol; CLI launch/management/composition; audit
storage/maintenance/baseline/operations; CLI/policy/transport/storage regressions;
native real-CLI release harness; README, release notes and ADR 0010. No dependency
version changed: libc, serde, serde_json and sha2 were already locked; added audit
uses are private open flags, typed hash-only output and standard archive hashing.
Tokio test-util is test-only. AGENTS.md remains unchanged at 199 lines. Both
pre-existing untracked owner documents remain untouched and excluded from commit.

Verification of the final implementation:
- MCP Context7: official Tokio time/test-util/deadlines and rusqlite transactions.
- scripts/check-release.sh exited 0: locked fetch, fmt, all-target Clippy with
  denied warnings, all workspace tests, release build, CLI help/policy validation,
  explicit latency gates, native memory/lifecycle/SSH and five real CLI attacks.
- Added public CLI tests cover explicit pin acceptance/replay/history, audit
  status warnings, view/export/private modes/overwrite refusal and offline rotate.
  Storage tests cover legacy pins, stale IDs, active-writer refusal, page warnings
  and intent reserve, archived correlations, rollback on retention failure and WAL
  refusal. The real CLI harness explicitly reviews/accepts its first catalog.
- Final 4,000 warmed encode/parse + policy/schema/DLP/monitor/FULL durable-audit
  packets: p99 377.606 us, maximum 879.837 us. Full real CLI/native RTT, 2,000
  samples: p99 0.907 ms, maximum 1.587 ms. Native transport RTT maximum 231.579 us.
  All measured packets and RTTs stayed below the 5 ms budget.
- Restricted tool sandbox denied local socket tests; the complete suite passed
  outside that restriction using real systemd-delegated cgroups and bubblewrap.
  No product isolation, test or durability requirement was disabled.
- Fetched origin refs; gitleaks scanned all 11 prior commits and the exact staged
  candidate with no findings. Re-scan the final index including this handoff before
  committing. No claim of exhaustive secret detection or remote-fork erasure.
- Python syntax, changed documentation links/fences, git diff whitespace and
  AGENTS.md line count passed. No frontend exists or changed; npm/browser checks
  are not applicable, not claimed as passing.

Operational limits: stop every older binary before maintenance; older versions
lack the cooperative lock. Read commands target the active audit; archives can be
opened with SQLite read-only tools. Start export cursors at zero after rotation.
An interruption before the retention commit can leave an extra archive; only the
active receipt proves committed retention. Archives use additional disk and require
explicit owner retention. Inspect source independently of digest review. Latency
numbers describe warmed bounded workloads on this host, not scheduler/fsync hard
real-time guarantees or maximum-size messages. GitHub Actions status is separate
from local verification. Next step: final index scan, commit/push and verify remote.

---

# Handoff — 2026-10-30: host diagnostics and production approvals

Delivered `doctor`, `doctor --self-test`, `demo`, optional production
`proxy --monitor-socket`, disconnect invalidation, and a repeatable Fedora 44
systemd user-service bootstrap. README and ADR 0009 describe invocation, cleanup,
prerequisites and trust boundaries. Native release checks now exercise all three
diagnostic commands. AGENTS.md is unchanged (199 lines). Existing untracked
owner documents were left untouched and excluded from this commit.

Verification:
- Context7: Tokio cancellation/select, systemd delegation/subgroups/controllers.
- Full scripts/check-release.sh passed: locked fetch, formatting, all-target
  Clippy with denied warnings, workspace tests, release build, help/policy check,
  native isolation/memory/lifecycle tests, adversarial real CLI and latency gates.
- Additional production IPC/audit test passed: no intent before owner decision,
  one-use approval and refusal after disconnect/replay. Monitor tests cover
  actual disconnect invalidation and the 25-second deadline.
- Final formatting and all-target Clippy passed after the added production test
  and monitor-enabled benchmark.
- Fedora 44 real delegated scope: doctor, doctor --self-test and demo passed,
  including outside read/symlink, write, Internet/Unix sockets, detached child
  cleanup and SQLite intent failure through the production AuditGate.
- Monitor-enabled full gate: 4,000 warmed packets, p99 351.135 us, max 813.131 us.
  Full native CLI RTT: 2,000 samples, p99 0.679 ms, max 1.026 ms.
- Bash syntax, extracted systemd unit verification and git diff whitespace passed.
  systemd-analyze emitted environment socket-permission diagnostics but exited 0.
- Checksum-verified gitleaks 8.30.1 found no leaks in fetched Git history;
  the exact staged candidate is scanned before committing.

Limits: bootstrap service installation was not applied to the owner's persistent
user configuration; unit syntax and its cgroup mechanism were verified separately.
It requires an active user manager, installed Python/bubblewrap, and Fedora 44.
Other distributions refuse bootstrap; Linux runner platform support is unchanged.
No frontend exists or changed, so browser/npm checks do not apply. Probes verify
child confinement/cleanup rather than a blanket fork ban. Latency measurements
exclude human approval, startup, arbitrary host contention and large messages.
No exhaustive secret-detection or hard realtime guarantee is claimed.

---

# Handoff — 2026-10-30: audit A-03–A-07 security fixes

## Current result

All five requested findings are addressed. Semantic text units reject secrets
split across blocks and trailing known-secret prefixes before forwarding; linear
matching covers overlaps and discovery precedes final redaction. Secret-bearing
catalogs refuse before the first baseline write, while clean reconnects retain
existing pin checks. No pin reset, raw-secret persistence or arbitrary JSON field
concatenation was added.

Transport terminal failures now have a dedicated fixed-reason audit callback,
including malformed JSON, invalid lifecycle, limits, timeouts and runner failures.
The outer production gate preserves policy/schema/DLP/catalog/method reasons.
Every production event is tied to a distinct session and an owner-derived upstream
digest. Additive transactional migration preserves legacy rows and records version
2. Cross-session/nonexistent intent correlations refuse. Pending effects remain
unknown; audit failure still closes the gate and never authorizes forwarding.

Before mutating any client configuration, init validates all selected servers and
runs the real containment profile with fixed trusted /usr/bin/true. Upstream code
and arguments are never executed. Missing facilities refuse without configs,
backups or receipts; launches repeat checks. Existing managed settings must match.
See ADR 0008 for migration, guarantees and conservative refusal behavior.

Files: core/proxy DLP; proxy error/policy/stdio boundaries; audit operations and
migration; CLI composition/binding/preflight; native runner probe; regression and
native CLI tests; README, ADR 0008, ADR 0006 follow-up and release notes. rusqlite
was added only as a test dependency, reusing the existing locked version/features;
no production dependency or dependency version changed. AGENTS.md is unchanged.
The two pre-existing untracked audit/launch documents remain unchanged and outside
the commit.

## Verification

- MCP Context7: official rusqlite immediate transactions and Tokio child lifecycle,
  cancellation, termination and reaping documentation.
- Final scripts/check-release.sh passed on Rust 1.99.1 / bubblewrap 0.12.0:
  locked fetch, fmt, all-target Clippy with -D warnings, workspace tests, release
  build, CLI help and policy validation, explicit DLP/policy/monitor performance,
  memory isolation, delegated native lifecycle/SSH tests and real CLI attacks.
  Initial socket restrictions in the tool sandbox were resolved by running the
  same suite outside that restriction; no test or security control was weakened.
- 4,000 warmed production gate packets with a learned secret, text/resource blocks
  and structured scalars: p99 270.613 us, maximum 345.454 us. This includes
  encoding/parsing, policy/schema, DLP and synchronous FULL durable audit.
- 2,000 full CLI/native/audit/DLP/policy RTTs: p99 0.600 ms, maximum 2.143 ms.
  All measured packets/RTTs stayed below 5 ms. Native transport maximum 128.554 us.
- Exhaustive small-pattern tests cover overlaps and unreleased completable tails.
  Regressions cover split fields/responses, Unicode, discovery order, no inner
  gate calls on refusal, clean/secret catalog reconnects, terminal audit without
  payloads, preserved refusal reasons, concurrent session identity and migration,
  audit failure, fake-cgroup binding refusal and successful native preflight.
- Real native installer round-trip used /usr/bin/false as the configured upstream
  and succeeded via the fixed trusted probe; unbind restored exact original bytes.
- Fetched all origin refs and scanned Git history with gitleaks 8.30.1: no findings.
  Documentation (including both preserved untracked files) also had no findings.
  The exact staged candidate must pass scripts/check-secrets.sh before commit.
- Python syntax, changed local documentation links, git diff --check and scope
  reviewed. AGENTS.md remains 199 lines. No frontend exists or changed, so npm and
  browser checks do not apply.

## Limits and next step

Prefix refusal can reject innocent text, even a one-character suffix. Guarantees
cover known literal values and defined ordered text units, not arbitrary encoding,
reordering or output sent before a value was learned. Existing poisoned pins need
a separately reviewed owner migration; none is silently erased. Legacy audit rows
cannot be retroactively assigned a session or precise reason. Preflight is a
point-in-time host check, not persistent host provisioning or execution permission.
Warmed measurements are workload/host-specific, not a hard real-time guarantee for
startup, maximum-size messages, storage contention or scheduler pauses. Secret
scanning does not prove absence of every possible secret or erase remote forks.

After the candidate scan, commit/push the requested fix and verify the remote ref.
GitHub Actions status must be checked separately from local verification.

---

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
