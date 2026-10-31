# Handoff — 2026-10-31: durable disk audit latency

The owner supplied the actual Actions failure: 4000 production gate packets,
p95 1.286 ms, p99 2.916 ms, maximum 5.888 ms; the strict 5 ms maximum failed.
Local DELETE journaling also failed on persistent btrfs (max 11.013 ms).
The previous local temporary audit fixtures used /tmp (tmpfs), so those results
did not certify persistent-disk latency; historical evaluation documentation now
states this explicitly. New reports identify audit_filesystem separately from
their output directory filesystem.

OperationStore now uses WAL with FULL synchronous commits, unchanged per-event
acknowledgement and no relaxed budget. IMMEDIATE transactions serialize WAL-size
admission across sessions. Automatic checkpoints and separate 8/16 MiB admission
thresholds bound pinned-reader growth while reserving terminal-event capacity.
Existing sidecars must be private regular single-link files. Offline rotation
requires successful checkpoint and transition to DELETE before copying the main
database; busy storage refuses. ADR 0018 records migration and recovery limits.
No dependencies, schemas, authorization rules or AGENTS.md changes were needed.

Verification:
- check-release.sh passed: locked fetch, fmt, Clippy/-D warnings, workspace tests,
  release build/CLI smoke, HTTP consent/deadlines, every packet budget, real native
  isolation/attack/lifecycle/skills/broker/transaction/diagnostic gates.
- Separate final disk gate, TMPDIR=target/ci-latency-before on btrfs: 4000 packets,
  p95 1.088 ms, nearest-rank p99 1.887 ms, maximum 4.091 ms; every sample <5 ms.
  It ran after other I/O-heavy tests finished. Exploratory runs during concurrent
  work also exceeded 5 ms; WAL is not a hard real-time guarantee on shared hosts.
- Default temporary-fixture full native CLI maximum 0.827 ms; tmpfs gate maximum
  0.380 ms. These are distinct from the persistent-disk gate above.
- Audit regressions cover FULL/WAL settings, private sidecars, unsafe-file refusal,
  forced process death with flushed uncommitted WAL, archive recovery of the
  acknowledged intent without replay, pinned readers, both WAL admission limits,
  terminal reserve, no append on refusal and existing rotation/page-quota behavior.
- MCP Context7: official SQLite WAL, FULL synchronization, checkpoint and journal
  limit documentation. Historical reports are preserved rather than rewritten.

Remote Actions remain unverified because GitHub API/connector access returns 404.
Push the reviewed commit to main and inspect the next hosted checks/native jobs;
do not move existing tags. Native AArch64/clean Ubuntu provisioning were not run
locally. The pre-existing untracked owner documents remain untouched/excluded.

---

# Handoff — 2026-10-31: clean-host CI user-bus regression

The disposable installer gate now exports the owner's XDG_RUNTIME_DIR and
DBUS_SESSION_BUS_ADDRESS before its post-installation user-service restart.
The Python installer only sets its own subprocess environment; those values
cannot propagate back to the non-login Actions shell. A regression runs the
actual gate against private command fixtures with both variables absent. It
failed before the fix and passes afterward, preserving failure propagation and
temporary-configuration cleanup. No production packet-path code changed.

Verified: all eight installer tests, evaluation validation, Bash syntax,
actionlint 1.7.7, diff whitespace and unchanged 199-line AGENTS.md. The complete
check-local.sh and check-release.sh passed on Linux x86-64. Measured maximum
gate packet 0.493 ms, broker packet 1.342 ms and full native CLI RTT 1.619 ms;
every measured packet stayed below 5 ms. Tests ran outside the tool sandbox's
filesystem/socket restrictions without weakening product containment. Gitleaks
8.30.1 found no findings in all 21 fetched commits or the tracked candidate.
MCP Context7 supplied official Actions and systemd documentation.

Remote status remains unverified: SSH access works, but the GitHub connector and
unauthenticated REST API return 404, no GitHub token or browser is available.
The owner reported five failing Linux release checks; exact failing steps/logs
were requested. This reproduced fix does not establish that all five failures
are resolved. Clean Ubuntu provisioning and native AArch64 were not run locally.
Next: inspect those logs and the pushed workflow, fix any remaining failures,
then verify native/installer/package jobs. Do not move existing release tags.
The two pre-existing untracked owner documents remain untouched and excluded.

---

# Handoff — 2026-10-31: Linux release matrix, host provisioning and evaluation

This session prepares version 0.1.1. Linux x86-64/AArch64 have separate packaging,
SBOMs, checksums, bundles and evaluation artifacts. Native and disposable installer
jobs gate package jobs; publication validates each archive with both provenance and
CycloneDX predicates. Actions are pinned to immutable revisions. The tag must match
Cargo workspace/lockfile versions. No production packet-path code changed.

Added source installer: reviewed Fedora 44/Ubuntu 24.04 checkout, signed system
packages, checksum-pinned Rustup, locked build, compatible pinned bubblewrap when
needed, executable-specific AppArmor namespace permission when missing, lingering,
persistent user service with boot/restart controller preparation, private versioned
binary/policy/workspace/state and reversible binding. Directory creation uses
pinned no-follow directory descriptors. Existing conflicts refuse. No persistent
host installer was run on the owner's desktop. Existing bootstrap units need an
explicit reviewed migration; old backups/state are not deleted.

Actual local verification:
- MCP Context7: official GitHub Actions attestations, systemd delegation/lingering,
  Docker network/resource/lifecycle documentation. ADR 0017 records boundaries.
- Full scripts/check-release.sh passed on Linux x86-64: locked fetch, fmt, denied-
  warning Clippy, workspace tests/build, CLI smoke, remote monitor, all packet
  budgets, actual native memory/lifecycle/SSH, five CLI attacks, scanned skills,
  broker, transactional publication/refusals, diagnostics and audit-loss refusal.
- Final scripts/check-local.sh passed after the Rust evaluation changes. Final
  installer tests (7) and report publication validation tests passed, including
  link/no-write refusal, conflicts, startup order and no bind after failed probe.
- Actual temporary delegated user service ran the installer's helper on initial
  start and restart with cpu/memory/pids present; service was stopped afterward.
- Final independent evaluate.py run passed against final relevant source bytes,
  including real native tests. check-evaluation.py verified source/binary/commit,
  sample counts and budgets. Raw logs remain ignored under target/evaluation.
- docs/evaluation.md and its JSON retain all observed false alarms: 11/20 unchanged
  benign stress workflows, 7 false refusals and 2 false redactions. Separate repeated
  native allowed reads completed 2200/2200. No field population rate is claimed.
- Final gate: p95 0.309 ms, p99 0.336 ms, max 1.416 ms (4000 packets). Native CLI
  RTT: p95 0.594 ms, p99 0.644 ms, max 1.626 ms (2000 samples). Every measured
  warmed packet/RTT remained <5 ms. Process-cold start p95 60.732/p99 64.037 ms
  (20 starts, warm OS caches and accepted pins).
- Separately timed FULL durable intent/response p99 0.192/0.196 ms (2000 each).
  This is actual writer acknowledgement cost, not subtracted percentiles.
- Pinned cargo-cyclonedx 0.5.9 generated a normalized native graph; local archive,
  ELF architecture, binary/report identity, included documentation and SHA-256
  verification passed. Local packaging creates no remote attestation.
- Current RustSec scan passed (1395 advisories, 274 dependencies). Fetched all
  origin refs and scanned all 20 prior commits with Gitleaks: no findings. Exact
  final index is scanned before commit; secret absence is not an absolute proof.
- Python/Bash syntax, workflow parsing/dependency graph/pinned revisions, diff
  whitespace and documentation links checked. AGENTS.md stays 199 lines. No UI
  exists or changed; npm/browser checks are not applicable.

Outstanding acceptance items and limits:
- macOS/Windows production NativeRunner adapters were NOT implemented or certified.
  They remain fail-closed. No target hosts/runtime were available. Windows also
  requires porting the existing Unix-only CLI/private file/IPC boundaries. Do not
  replace these requirements with a Docker CLI or unverified Seatbelt fallback.
- Native AArch64 and clean-host installation are scheduled as actual CI gates,
  not claimed locally passed. Only temporary service/helper tests ran on Fedora;
  a complete clean-host provisioning run was not executed on the owner's host.
- SSH fetch/push access works outside the tool sandbox. GitHub connector returned
  404 for cierii/clawbell; no GH_TOKEN/GITHUB_TOKEN or authenticated gh was available.
  No browser session was available. Tagged Actions, published assets and remote
  SBOM/provenance verification must be inspected through authorized GitHub access.
  A pushed tag alone must not be reported as a successfully published release.
- The two pre-existing untracked owner documents are untouched and excluded from
  the commit. Runtime databases, doctor evidence and Python caches stay ignored.

Next: inspect exact branch/tag refs and tagged workflow with authorized GitHub
access; resolve any real native/installer/attestation failures without weakening
security. For macOS/Windows, obtain actual native hosts, choose a trusted Linux VM/
image boundary and implement/test whole-tree limits, cancellation/drop/owner-death
and daemon-failure cleanup plus the platform private-file/IPC port. See ADR 0017.
The final assistant delivery message and Git refs record commit/push outcome;
this handoff deliberately makes no claim of remote CI or release success.

---

# Handoff — 2026-10-31: sandbox broker, complete catalogs and HTTP/OAuth lifecycle

## Delivered

Owner policy now supports named exact GET/POST broker capabilities. Ordinary MCP
and scan-bound skill runners inherit one connected fd 3 without enabling socket
creation, host network access or writes. Broker operations use pinned DNS/TLS,
complete text/structural JSON DLP, shared MCP vault knowledge, durable intent and
bounded response publication. Direct sockets, unknown destinations, raw known
secrets and unsupported formats fail closed. Transaction mode gains no network
capability. Existing ordinary-profile doctor evidence refuses the broker profile.

Resources, resource templates and prompts support bounded exact-cursor enumeration
with per-page and aggregate pins, duplicate/repeated/overlapping-page refusal and
no stale prompt execution while refreshing. Existing nonpaginated pins are retained.

Streamable HTTP adds independent GET, bounded SSE resumption via GET only, strict
stream/session event IDs and a single scoped DELETE on shutdown. The initialized
202 barrier remains mandatory. No effectful POST or MCP operation is replayed.
Interactive reverse capabilities still refuse.

OAuth supports explicit trusted-issuer discovery, explicit public-client dynamic
registration, serialized refresh/rotation and opt-in private persistent tokens.
All access/refresh generations are registered with host DLP before publication.
Atomic 0600 storage in 0700 state uses a session-long lease and a durable tombstone
before refresh; uncertain grants never replay. Runtime expiry is monotonic.
Cached records bind owner configuration, resource, scopes and discovered endpoints.
Records contain plaintext credentials protected by host filesystem permissions;
the runtime never exposes them to client JSON, sandbox mounts, logs or Git.

Init reversibly wraps mixed local stdio/remote HTTPS configurations. Optional
clawbellOAuth carries only issuer/public client/scopes. First login/registration
is an explicit terminal action using the generated wrapper identity. Existing
bindings require unbind, owner backup archival and rebind; no silent migration.
README, broker example policy and ADR 0016 document scope, migration and limits.
AGENTS.md stays unchanged at 199 lines; dependencies and lockfile are unchanged.
The two pre-existing untracked owner documents remain untouched and excluded.

## Verification

Context7 official rmcp GET/session/resumption, oauth2 refresh/custom HTTP and
reqwest DNS/redirect/proxy/deadline contracts consulted, with pinned source checks.
Actual bubblewrap 0.12.0 source and native tests confirm fd inheritance and closure
in supervisor/PID 1 without changing seccomp.

The full scripts/check-release.sh pipeline passed: locked fetch, formatting,
all-target Clippy with warnings denied, workspace/doc tests, release build, CLI
help/policy checks, remote monitor consent/EOF/deadline integration, all latency
gates, actual Linux containment, installer/skills/broker/transactional CLI attacks,
memory isolation, doctor and demo. Final workspace tests and Clippy also cover the
last structural JSON DLP, discovery metadata and SSE compatibility changes.
The broker example policy validates. Python AST, shell syntax, documentation
local links and staged whitespace/scope checks pass. No UI manifests exist;
npm/browser checks are not applicable.

Latest measurements: complete production gate p99 346.256 us/max 465.622 us per
packet; remote resource gate p99 282.385 us/max 749.691 us. Broker with policy,
structural DLP, durable audit and loopback: 2000 warmed packets, p99 438.531 us,
max 937.116 us. Native transport max 448.620 us; complete CLI/native/audit/DLP
2000 RTTs p99 0.728 ms/max 1.676 ms. Every measured warmed packet/RTT stays below
5 ms; startup, large messages, human waits, network/issuer latency and arbitrary
host/storage contention remain outside this reproducible budget. Transaction
snapshot/execution/approval/publication is separate from packet overhead.

Checksum-verified Gitleaks 8.30.1 scanned all 19 fetched existing commits and the
exact reviewed index with no findings. Runtime data, token stores/leases and
installer backups remain ignored. The two original untracked owner documents
are not staged. The final index is rescanned after this verification note.

## Operational limits and next step

Only Linux enforces local execution; other platforms remain fail closed. Broker
bodies are bounded UTF-8 text/plain or JSON responses; no binary/CONNECT/arbitrary
headers or credentials from sandbox data. Network capability applies to the process
and descendants, not to a particular tool call. Heuristics cannot recognize every
encoded or constructed secret. No frontend manifests exist, so UI/npm checks do
not apply.

Discovery cannot expand beyond an explicitly trusted issuer origin; private or
off-origin discovery targets and confidential/managed clients refuse. Live external
provider conformance is not certified by synthetic tests. Token-store crash leases
require explicit owner cleanup after matching sessions stop; a tombstone requires
fresh explicit login. Session loss does not imply remote rollback or automatic
reinitialization. Local results do not certify GitHub Actions or AArch64 execution;
check the workflow associated with the pushed commit separately.

# Handoff — 2026-10-31: diagnostic evidence, HTTP monitoring and live audit

## Delivered

All four requested areas are implemented. Doctor self-tests retain private,
content-addressed, synchronized JSON reports binding binary version/SHA-256,
boot/kernel/architecture, bubblewrap and the exact ordinary native profile,
delegation and budgets. Failed probes retain failed evidence. `proxy --doctor-report`
validates it once before session creation and records its digest in durable audit;
all MCP operations link through session_id. Reports remain local and ignored by Git,
including nested runtime directories. Other runner profiles refuse this evidence.

New init bindings contain deterministic per-client/per-server monitor endpoints.
Normal shutdown reclaims only the service's own socket inode; existing/crash sockets
are never adopted. proxy-http now serves the monitor and exposes independent
request/idle/session deadline flags. Resource/prompt retrieval and enumeration can
require exact one-use owner approval after protocol/schema checks. Shared transport
inspection cancels on pipe EOF/output failure before a late approval can forward.

`audit ... view --follow` streams bounded flushed JSONL pages with exclusive cursors,
250 ms polling and a shared maintenance lease protecting the database generation.
Reads release SQLite transactions before output; operation writers stay concurrent.
README and ADR 0015 document commands, migration and limits. No dependencies,
lockfiles, AGENTS.md rules or UI changed. Existing untracked owner documents
`docs/audyt-mvp-i-rynku-2026-10-30.md` and `docs/uruchomienie-mvp.md` remain untouched
and excluded from the commit.

## Verification

- MCP Context7: official Tokio blocking/timer contracts, rusqlite read-only
  connections and rmcp resource/prompt request models consulted.
- Full scripts/check-release.sh passed: locked fetch, formatting, all-target Clippy
  with warnings denied, workspace/doc tests, release build, help/policy validation,
  actual native enforcement, real installer/skills/transactional CLI regressions,
  doctor/demo and release latency gates. Local sockets require running outside the
  tool environment's socket restrictions; no product isolation or test was weakened.
- New production HTTP CLI test passes exact resource/prompt consent, explicit
  rejection, catalog pinning, EOF with a late approval and all three independent
  deadline flags. IPC tests exercise one-use replies, stale IDs, owner disconnect,
  missing owner and deny precedence. Shared monitor tests cover timeout cleanup.
- Native CLI verifies retained reports, changed-budget refusal before audit session
  creation, proof linkage to every session, live flushed audit rows and maintenance
  refusal while following. Full CLI measurement includes monitor publication and
  an active audit follower: 2000 warmed RTTs, p99 0.748 ms, max 1.647 ms (<5 ms).
- Production policy/schema/DLP/durable-audit gate: 4000 packets, p99 352.357 us,
  max 528.582 us. HTTP resource gate: 4000 packets, p99 269.440 us, max 347.658 us.
  Native transport max 185.211 us; monitor publication max 7.545 us. Each measured
  packet meets the budget; startup, human wait and transaction lifecycle are separate.
- Report tests reject failed results, profile drift, byte tampering, symlinks and
  nonprivate files/directories. Follow tests cover exclusive cursors, bounded pages,
  no duplicates, concurrent append and rotation refusal. Final Clippy and targeted
  evidence regression are repeated after strengthening private-parent validation.
- Gitleaks scanned all 18 fetched existing commits and documentation without findings;
  the exact final index is scanned before commit. Python AST, shell syntax, changed
  documentation links, whitespace and scope checked. AGENTS.md remains 199 lines.
  No UI manifests exist; npm/browser checks are not applicable.

## Operational limits

Evidence is unsigned, owner-local and point-in-time; it never grants execution
permission. Retain reports alongside exports. A changed binary/boot/delegation or
budget requires a new self-test. It does not inventory all host packages or attest
to arbitrary workspace/server behavior; remote/skill/transaction profiles are not
covered. Existing bindings require explicit unbind/backup archival/rebind migration.
Stop followers for offline rotation or baseline acceptance. Crash socket leftovers
still require explicit owner cleanup. Latency figures describe bounded warmed
workloads, not a hard real-time guarantee under arbitrary host/storage load.
GitHub Actions status is separate from these local checks.

# Handoff — 2026-10-31: per-operation MCP publication and HTTP initialization barrier

## Delivered

All four requested changes are implemented. HTTP initialized POSTs form a barrier
until a complete empty 202 response; failures never forward the next queued POST.
Remote baseline/endpoint/DNS/OAuth/composition startup errors close their durable
launch intent with fixed terminal codes. Valid canonical remote identity pins are
preserved; runtime transport outcomes remain unknown rather than claiming rollback.

Production `proxy-transaction` composes existing gates, native Transaction and
handle committer. It starts a fresh unchanged executable per operation, replays only
bounded initialization/catalog exchanges and requires exact metadata equality.
It holds tool output until explicit direct-child reap, whole-group cleanup and
inspection; owner-reviewed publication uses the actual frozen diff. The private
monitor displays redacted invocation, effect scope, review digest and expiry.
Client disconnect cancels pending consent; an already-dispatched publication worker
is joined and its real result audited. Existing ordinary/HTTP proxies and client
bindings do not silently acquire writes. No new dependencies or unsafe code.

Audit migration 3 adds nullable operation/review fingerprints, durable random-session
binding and fixed lifecycle/recovery outcomes. Existing rows remain append-only;
JSONL exports include hex fingerprints and still read v2 logs without migration.
README, example-policy comments and ADR 0014 document opt-in migration, narrow file
support, complete monitor-preview limits and journal recovery. AGENTS.md is unchanged
at 199 lines. The two pre-existing untracked owner documents remain untouched and
will not be included in the commit.

## Verification

- Context7 official rmcp transport/initialization documentation consulted.
- `scripts/check-release.sh` passed: locked fetch, fmt, all-target Clippy/-D warnings,
  workspace/doc tests, release build, help/policy smoke checks, all latency gates,
  real native enforcement, installer, skill and transactional CLI tests and doctor/demo.
- HTTP regression covers delayed acceptance, wrong status, nonempty body, disconnect
  and timeout with pipelined traffic. Remote startup regression covers invalid URL,
  DNS failure, metadata endpoint refusal, OAuth setup and unavailable baseline store.
- Native transactional CLI covers successful publication and ten refusal/recovery
  scenarios: hidden protected-memory write, symlink, tool error, binary result,
  catalog drift, lying read tool, owner rejection, client EOF with late acceptance,
  external-file conflict and existing publication journal. It verifies unchanged
  host canaries on refusal, withheld responses before approval and the complete
  correlated durable audit chain. Existing native fault/crash committer tests pass.
- Bounded warmed production gate: 4000 packets, p99 367.667 us, max 843.328 us.
  Remote-resource gate: 4000 packets, p99 307.172 us, max 1.018430 ms.
  Native transport: 2000 RTTs, max 131.820 us. Full ordinary CLI/native/policy/DLP/
  durable-audit RTT: 2000 samples, p99 0.726 ms, max 0.847 ms. All measured packet
  samples <5 ms; startup/snapshot/review/publication are separate lifecycle costs.
- Final post-review checks explicitly repeat all-target Clippy, workspace tests and
  native transaction tests after strengthening direct-child reap and cancellation.
  The final native run passed; complete transactional read lifecycle (snapshot,
  start, replay, inspect, reap and audit) took 62.228–66.264 ms across four samples,
  separately from packet forwarding overhead and without human approval time.
- Fetched origin refs/tags; gitleaks 8.30.1 scanned all 17 existing commits with no
  findings. The exact final index is scanned before commit. This is detection within
  scanned history/content, not a guarantee about every possible secret or remote fork.
- Python AST/Bash syntax, changed documentation links, whitespace and scope checked.
  No UI manifests exist or changed, so npm/browser checks are not applicable.

## Operational limits and next use

See README and ADR 0014 for `proxy-transaction` invocation. Requires Linux native
prerequisites, private state/socket and a separate durable non-tmpfs journal lane;
/tmp on this host is tmpfs and correctly refuses as publication storage. Add actual
upstream-tool grants plus independent path-scoped `clawbell.commit` grants. Owner
must explicitly accept initial pins, connect monitor and review each complete diff.

Publication replaces existing ordinary UTF-8 files only; no-op/creation/deletion/
metadata/protected-memory changes and previews beyond the current 1800-character
monitor display budget refuse. Servers needing mutable process state or dynamic
initialization/catalog metadata may be incompatible. Only initialization/ping/tools
are supported in this mode. Resources/prompts, scan-bound skills and remote process
transactions are unsupported; no isolation fallback was introduced.

Writes remain non-atomic, even for one file. Keep external writers quiescent and
inspect/archive a successful or interrupted journal explicitly before another
publication; no automatic replay, cleanup, recovery or rollback. Packet measurements
are bounded warmed workloads, not a universal hard real-time guarantee. Final GitHub
Actions status must be checked separately from local verification.

Local tools: RUSTUP_HOME=/tmp/clawbell-audit-rustup,
CARGO_HOME=/tmp/clawbell-audit-cargo, PATH=/tmp/clawbell-audit-cargo/bin:/usr/bin:/bin.

---

# Handoff — 2026-10-31: pinned HTTP, protocol catalogs and scanned Linux skills

## Result and remaining scope

The requested expansion is partially delivered. Implemented: exact-endpoint HTTP
egress with DNS/peer pins, host-only expiring OAuth bearer credentials and
pre-registered PKCE login, a session-aware bounded POST JSON/SSE relay, explicit
resources/prompts policy and metadata pins, nextCursor tool catalogs above 256,
and a private read-only Linux skill snapshot bound to a prior scan and exact
initialize.instructions. Native Linux AArch64 CI was added alongside x86-64.

macOS and Windows native isolation are NOT implemented. NativeRunner continues to
refuse those platforms; no sandbox bypass was added. They need actual backend
implementation plus native limit, escape, filesystem and lifecycle testing before
this user task can be declared fully complete. Do not report ARM CI configuration
as a passed ARM execution test. The sandbox remains network-disconnected; egress
is a trusted host HTTP adapter, not a generic network exception for skill code.

HTTP/OAuth compatibility is intentionally bounded: no GET/resume/DELETE/replay,
protected-resource discovery, dynamic registration, refresh or credential
persistence. Resource/prompt catalogs currently refuse nextCursor; tool catalogs
support it. Protocol require_approval refuses; the monitor authorizes tools only.
These constraints, trust boundaries, migration and commands are in README and
ADR 0013. They must remain visible when describing production compatibility.

## Implementation

- Core: explicit protocol rules, opaque skill execution/shell permission bound to
  exact policy bytes; catalog/tool bounds raised to 4096 and 8 MiB; hashed scoped
  catalog identities preserve server/method/page separation and existing pins.
- Proxy: one pinned egress adapter (reqwest/rustls), OAuth2 S256/state/resource
  binding, optional MCP session identity, finite inspection units on open POST SSE,
  remote credential registration in DLP with no marker restoration, pinned
  resource/prompt metadata and arguments, bounded complete tool page collection.
- Sandbox: scan of UTF-8 package/files, literal arguments and expected instructions;
  invocation/policy/content digest, frozen tmpfs read-only execution, mandatory
  explicit execution AND shell permission, existing seccomp/cgroup containment.
  Static findings are never authorization or proof of safety.
- CLI: proxy-http with explicit OAuth owner login, skill-scan and scan-bound proxy
  flags. Existing JSON installer remains local stdio only. No web UI was added.
- Tests: OAuth binding/refusal, session SSE without EOF, denied destinations and
  token expiry/audience, 300-tool pages and cursor/metadata attacks, exact protocol
  grants/URI/prompt arguments, remote credential echo masking, native code source
  replacement, policy/instruction/command drift, memory/pids exhaustion, CLI skill
  mismatch/refusal and an additional remote-resource durable-gate latency budget.

Only new direct library is oauth2 5.0 with default HTTP backends disabled and
timing-resistant secret equality enabled. It supplies reviewed protocol/PKCE/state
mechanisms instead of custom crypto. Other direct dependencies already existed
in the lockfile; 7 packages (including oauth2) were added without unrelated upgrades.
AGENTS.md remains unchanged at 199 lines. The two pre-existing untracked owner
files docs/audyt-mvp-i-rynku-2026-10-30.md and docs/uruchomienie-mvp.md remain
untouched and excluded from the commit.

## Verification

- Final scripts/check-release.sh passed: locked fetch, format, all-target Clippy
  with -D warnings, workspace tests/doc tests, release build, CLI/default-policy
  smoke checks, all explicit latency budgets, agent-memory protection, delegated
  native containment, real installer round trip and CLI attack/skill probes.
- Five native tests passed: source replacement after scan, exact invocation
  bindings, read-only snapshot writes, memory/task exhaustion and descendant
  cleanup. Real CLI tests also refused missing explicit skill/shell permission,
  changed instructions, stale scan digests and package symlinks.
- 4,000 warmed tool-gate packets: p99 351.967 us, max 599.787 us. 4,000 warmed
  remote-resource gate packets: p99 301.872 us, max 754.971 us. Native transport
  2,000 RTTs: max 447.628 us. Full CLI/native/audit/DLP/policy 2,000 RTTs:
  p99 0.715 ms, max 1.571 ms. Every measured sample was below 5 ms. These are
  bounded warm workload measurements, not a universal latency guarantee.
- Added callback-only regression passed after the full release run: exact
  loopback Host/method/path, duplicate query and Origin refusal, no code echo.
  Final all-target Clippy and format passed with this additional test as well.
- Context7 official rmcp, reqwest and oauth2 documentation consulted. Cargo audit
  fetched the current RustSec database and scanned all 274 locked packages with
  no reported vulnerabilities. Fetched origin refs/tags; gitleaks scanned all 15
  existing commits without findings. The exact reviewed index is scanned before
  commit; detection does not establish exhaustive secret absence or fork erasure.
- New protocol example policy, command help, Python AST/Bash syntax, changed local
  documentation links, diff whitespace and scope checked. AGENTS.md remains 199
  lines. No npm/UI tests apply because no frontend exists or changed.

The ordinary restricted tool environment denied Unix/loopback sockets; checks
were rerun on the host without weakening product controls. Local environment:
Rust 1.99.1, bubblewrap 0.12.0, RUSTUP_HOME=/tmp/clawbell-rustup,
CARGO_HOME=/tmp/clawbell-cargo and the pinned Cargo binaries on PATH.

## Next step

After passing final checks, scan the exact reviewed Git index, commit/push the
requested change and verify origin/main. Remote CI (especially native AArch64)
needs its own result; local x86-64 checks cannot certify it. Complete native macOS
and Windows enforcement in a later platform workstream with suitable native hosts.

---

# Handoff — 2026-10-31: approved file publication and recovery

Delivered the opt-in Linux transaction library committer. `inspect_for_commit`
freezes private bytes only after complete native process cleanup. The authenticated
owner adapter must display the complete redacted JSON-quoted replacement preview,
its digest and expiry before issuing the opaque in-process approval. SHA-256 binds
source/candidate state, exact policy fingerprint (including same-version edits),
session, upstream, complete pinned tool definition, arguments, random nonce and
UTC expiry; an independent monotonic deadline also applies. No transport approval
or tool annotation authorizes publication. Every changed path needs an explicit
`clawbell.commit` write-tool policy; protected memory remains denied.

The narrow writer preflights the whole baseline and all target handles, then
rechecks each pathname and retained inode before writing. It never follows a
symlink for host publication. Durable owner-only journals contain UTC, policy,
session, approval and path/content fingerprints, plus per-file start/fsync and
final completion records. Existing journals block another operation. Partial,
torn and unknown outcomes require explicit owner recovery; no automatic replay,
rollback, journal deletion or retry was added. See ADR 0012 for the exact format,
manual recovery procedure, concurrency contract and migration from ADR 0011.

Scope: existing singly linked UTF-8 regular-file contents only. Create/delete,
binary, type, mode, ownership and SELinux-label changes refuse. In-place writes
are not atomic, even for one file. Independent host writers must be quiesced for
a coherent transaction; state checks are not a kernel CAS against same-account
writers. This is an explicit library boundary, not a new CLI write mode, UI or
per-operation writable MCP endpoint. Existing proxy permissions remain unchanged.
Caller adapters must authenticate the owner, supply trusted invocation digests,
audit before untrusted execution, withhold tool results, and run review/publication
on blocking workers. New ordinary proxy packets do no filesystem traversal.

Files: transaction/commit library and native tests, policy fingerprint accessor,
geteuid syscall adapter, README, ADR 0011 follow-up, ADR 0012, commit-example policy
and this handoff. Direct dependencies reuse already-locked sha2/getrandom/
serde_json/zeroize; no package versions changed. AGENTS.md is unchanged (199 lines).
The two pre-existing untracked owner documents remain untouched and excluded.

Verification:
- MCP Context7: official rustix descriptor-relative/no-follow APIs and RustCrypto
  sha2 incremental hashing documentation.
- Final scripts/check-release.sh passed: locked fetch, fmt, all-target Clippy with
  -D warnings, workspace tests, release build, CLI/default policy validation,
  explicit policy/DLP/monitor/production-audit latency gates, memory protection,
  delegated native containment, installer round trip, real CLI attacks and probes.
- All 19 sandbox unit tests passed, including 11 committer tests for binding,
  expiry, exact policy changes, foreign capabilities, protected SOUL.md with allow,
  edited/replaced/hardlinked/symlinked files, changed parents/modes, redaction,
  unsupported changes, write-effect validation, unsafe/colliding journals,
  partial multi-file/interrupted-file failure and every journal truncation.
- Real native committer test passed for safe writes, staged SOUL.md replacement,
  symlink attack and host edits after approval. Original protected canaries stayed
  unchanged and refusals created no publication journal or target writes.
- Final 4,000 warmed full gate packets: p99 366.414 us, max 3.285709 ms. Native
  transport 2,000 RTTs: max 608.172 us. Full CLI/native/audit/DLP/policy 2,000 RTTs:
  p99 0.679 ms, max 4.317 ms. Every sample was below 5 ms. These are bounded
  workload measurements, not a hard real-time or filesystem transaction guarantee.
- Explicit commit-example policy check passed. Changed documentation links,
  content/scope, diff whitespace, lockfile and final format check passed.
- Fetched all origin refs/tags; gitleaks scanned all 14 prior commits and local
  documentation without findings. The exact reviewed index is scanned before
  commit. Detection is not an exhaustive proof of secret absence or fork erasure.
- No frontend exists or changed; npm/browser checks do not apply. Tests initially
  blocked by tool-environment tmpfs/socket restrictions were rerun outside those
  restrictions; no product control or test was weakened.

Final delivery: scan the reviewed index, perform the requested commit/push and
verify the remote ref. GitHub Actions status is separate from local verification.
Future per-operation MCP/owner-display integration requires its own explicit scope;
never expose the library approve method directly to an untrusted caller.

---

# Handoff — 2026-10-31: transactional regular-file staging

Delivered the scope in ADR 0011, written before code changes: a Linux-only,
one-shot transaction library with private tmpfs staging, read-only originals,
network isolation and trusted whole-tree termination before bounded structural
diff. The default CLI/proxy remains read-only; no host publisher is enabled.
The ADR specifies the separate approval/conflict/durability/crash migration.

Files: crates/sandbox/src/transaction.rs, native Linux mounting/syscall adapter,
native attack tests, README and ADR 0011. No dependencies, lockfiles, AGENTS.md,
policy permissions or packet-path traversal changed. The two pre-existing
untracked owner documents remain untouched and excluded from the commit.

The owner supplies ReadOnly/Write, never the server's annotation. Source and final
trees reject links, special nodes, privileged modes and unsupported xattrs;
SELinux labels are allowed and compared without copying them. Content, type,
permissions, owner/group, mtime/ctime and labels enter a sorted private diff.
ReadOnly changes return transaction_hidden_write. Budgets cap regular-file bytes
at 8 MiB, entries at 4096 and depth at 32. Snapshot/inspection each have ten-second
deadlines. Late blocking workers discard results; they never execute or publish.
Originals are never replaced and all candidate trees are discarded.

Verification:
- Context7 official bubblewrap descriptor-mount/namespace contracts and rustix
  descriptor-relative no-symlink filesystem documentation consulted.
- scripts/check-release.sh passed outside the tool's socket restrictions: locked
  fetch, fmt, all-target Clippy/-D warnings, workspace tests, release build, CLI and
  policy smoke tests, explicit policy/DLP/monitor/audit latency gates, memory/native
  lifecycle and SSH probes, installer round-trip and five real CLI attack cases.
- 4,000 warmed production gate packets: p99 323.062 us, max 624.203 us; native
  transport 2,000 RTTs: max 270.152 us; full CLI/native/audit/DLP/policy 2,000 RTTs:
  p99 0.671 ms, max 1.088 ms. All samples <5 ms. These bounded host measurements
  are not universal real-time or filesystem transaction latency guarantees.
- After final staging deadline/parent checks: all-target Clippy passed; all eight
  sandbox unit tests and both mandatory native tests passed with real delegated
  cgroups. Final locked workspace release build passed.
- Native transaction tests cover writable private staging, unchanged original
  synthetic canary, socket and original-write refusal, detached descendants,
  ReadOnly hidden writes and Write diff. Unit tests cover each metadata/content
  mutation, create/delete/type, sparse/byte/count/depth limits, link/socket/privilege
  refusal, unsupported user xattrs and private copy cleanup.
- Fetched origin refs/tags and scanned all 13 existing commits with gitleaks:
  no findings. Exact staged content and preserved owner documents were scanned
  with no findings before commit. Scans do not prove absence of every possible secret or erase forks.
- Changed documentation links, scope, unsafe adapter contracts and diff whitespace
  reviewed. AGENTS.md is unchanged at 199 lines. No frontend exists or changed;
  npm/browser checks are not applicable.

Limits: this is final-state inspection, not a syscall write trace or an atomic
source snapshot under concurrent owner edits. Atime is excluded. Callers must
authorize and durably audit before spawn, bound/drain pipes, reap the child and
withhold output until inspection succeeds. Abrupt crashes/inaccessible directories
may leave private tmpfs candidates until owner cleanup/reboot. Publication,
per-operation MCP orchestration and approval/durable recovery remain explicit
future migration stages, not enabled functionality.

Next step after candidate scan: commit/push and verify remote HEAD. GitHub Actions
status requires separate remote verification; local checks do not certify CI.

---

# Handoff — 2026-10-31: release security and host diagnostics

Delivered the MIT LICENSE and consistent workspace license metadata, SECURITY.md
with private reporting and artifact verification, current RustSec scanning on
PR/push/tag and daily schedule, and CycloneDX 1.5 SBOM packaging. Publication now
requires dependency/native/ordinary checks and verifies provenance and SBOM
attestations against the repository, workflow, tag and commit before release.
Pinned actions/attest v4 signs both the binary and archive in the tagged build job;
verification bundles and the standalone SBOM/checksums are release assets.

The pinned cargo-cyclonedx 0.5.9 tool runs offline with an unchanged-lockfile guard.
Local workspace component IDs and graph references are normalized to fixed URNs;
local file purls are removed so builder paths are not exported. Graph integrity,
nonempty components and absence of local paths are checked before packaging.
The archive includes LICENSE, SECURITY.md, AGENTS.md and the identical SBOM.
The inventory covers Cargo production/build dependencies, not complete host/native
C dependencies. No runtime dependency or lockfile version changed.

CLI diagnostics replace operation_failed with fixed validation, I/O and typed host
codes plus trusted hints. Unknown errors are never formatted. Paths, credentials,
JSON data, terminal control strings and child stderr stay hidden. Native errors
identify limits, executable/workspace, root, cgroups/controllers, seccomp,
descriptors, bubblewrap/spawn, probe and cleanup failures. Proxy Error::Host retains
startup details while keeping the existing isolation_unavailable audit reason.
LaunchError is now an enum; source consumers must migrate unit constructions and
exhaustive matches. Existing permissions and fail-closed behavior are unchanged.
Probe exit status alone cannot distinguish namespace denial from unsupported
bubblewrap flags; diagnostics document this limit rather than guess.

Verification:
- Context7: official GitHub Actions provenance/SBOM attestation documentation.
  Official cargo-cyclonedx/cargo-audit READMEs and gh verification source checked;
  actions/attest v4 SHA resolved directly from its remote tag.
- cargo-audit 0.22.2 fetched current RustSec data and scanned Cargo.lock (267
  dependencies, 1395 advisories): exit 0, no vulnerabilities reported.
- scripts/check-release.sh: exit 0, locked fetch, formatting, all-target Clippy
  with denied warnings, workspace tests, release build, CLI/policy smoke tests,
  explicit performance, memory/native containment/SSH and real CLI attacks.
  Native tests used a real systemd-delegated scope outside tool socket restrictions.
- 4,000 warmed parse/encode + policy/schema/DLP/monitor/FULL durable-audit packets:
  p99 372.225 us, max 669.950 us. 2,000 full CLI/native/audit round trips:
  p99 0.718 ms, max 1.612 ms. Native transport max 203.075 us. All samples <5 ms;
  bounded workloads on this host do not establish a hard real-time guarantee.
- Final extra tests for retained spawn errors/teardown/no forwarding, invalid
  executable and resource limits passed. Final all-target Clippy passed too.
  CLI tests verify fake cgroup denial without config/backups/receipts/upstream
  effects, and safe host output. Unknown-error Display is never invoked; synthetic
  secrets and terminal controls are not echoed. Existing installer tests pass.
- Package regenerated successfully: 223 SBOM components; graph, workspace path
  removal, root MIT metadata, archive members, exact binary/SBOM bytes and both
  checksums verified. Package secret scan found nothing.
- Fetched origin refs; gitleaks scanned all 12 existing commits with no findings.
  Final staged candidate is scanned before commit. No exhaustive absence-of-secrets
  guarantee or remote-fork erasure is claimed.
- Bash syntax, workflow YAML/release dependency graph, documentation relative links
  and fences, git diff --check and AGENTS.md (unchanged, 199 lines) verified.
  No frontend changed or exists; npm/browser checks are not applicable.

Both pre-existing untracked owner documents remain untouched and excluded.
GitHub connector returns 404 for this repository; SSH fetch is available.
Local checks cannot exercise GitHub OIDC attestations. They execute on a tagged
release and require a GitHub plan supporting attestations for this repository;
missing support blocks publication. No tag or new release was requested/created.
Next step: final candidate scan, commit/push and verify the remote commit. GitHub
Actions status must be checked separately; it is not certified by local tests.

---

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
