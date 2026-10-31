# clawbell — second MVP audit

Date: 2026-10-31. Audited source: `0a487f0d6ad4af8b2e2415f8f799d04596d17370`.

## Scope and evidence

This audit checks implementation defects and delivery of the repairs and features
in `docs/audyt-mvp-i-rynku-2026-10-30.md`. It does not repeat the market research
or propose features outside that document. No implementation, dependency, policy,
client configuration, host service or architecture contract was changed.

The source audit and `docs/uruchomienie-mvp.md` were already untracked owner files.
They remain unchanged and are excluded from this report's commit. The source
audit's SHA-256 is
`21877d074f790a31821d397dff182ee73f61f0363836f1db2443586fb6777c2b`.
Its numbered roadmap items 1–15 are used below; these are roadmap priorities,
not vulnerability severities.

Evidence distinguishes **reproduced** behavior, **source review**, and an
**intentional limitation**. A passing test proves its exercised contract, not
absence of every bypass. P2 below means an integration or auditability defect;
no CVSS score or sandbox escape is claimed.

Reviewed: AGENTS.md, README, handoff, ADR 0001–0013, the five Rust crates,
regression/native tests, example policies, release scripts and GitHub workflow.
MCP Context7 supplied current reqwest and rmcp documentation. Exact behavior was
also checked against downloaded, locked reqwest 0.12.28 and rmcp 3.8.0 source;
latest documentation alone was not treated as the pinned version's contract.

## Defects found

### B-01 — P2: HTTP initialization has no notification completion barrier

**Evidence: reproduced with the real `proxy-http` CLI and a synthetic loopback
HTTP server; source review.**

[HTTP relay](crates/proxy/src/http.rs#L301) starts an independent task for every
outgoing POST. [Session state](crates/proxy/src/protocol.rs#L224) becomes Ready
when the client notification is accepted locally, before its HTTP exchange
finishes. Nothing makes subsequent operations wait for the upstream to accept
`notifications/initialized`.

Reproduction:

1. Start `proxy-http` with the default policy, a fresh private state directory,
   an exact loopback URL and the explicit `--private-ip 127.0.0.1` exception.
2. Complete `initialize` successfully using protocol version `2025-06-18`.
3. Send `notifications/initialized`. The fixture reads that request but delays
   its HTTP 202 response while initialization processing is unfinished.
4. Send `tools/list` through the same client stdio connection.
5. The fixture receives `tools/list` before releasing the notification's 202.

Thus a valid client sequence can reach a server whose initialization is still
unfinished. Concurrent connections can also reorder arrival. A server that
requires initialization completion can reject the request, terminating the
session during catalog acquisition. An eventual failed notification POST cannot
retract requests already sent. The experiment confirms overlap; it does not
claim an unauthorized tool call or a sandbox escape.

The locked official rmcp transport awaits the initialized notification's POST
and validates its response before entering its normal message loop, in
`src/transport/streamable_http_client.rs:1234–1258`. Reference:
[rmcp Streamable HTTP transport](https://docs.rs/rmcp/3.8.0/rmcp/transport/streamable_http_client/index.html).

Acceptance criterion for a later repair: delay/reject the initialization
notification response and verify that no subsequent application request reaches
the upstream; retain concurrency after successful initialization. No repair was made.

### B-02 — P2: HTTP setup failures bypass terminal audit recording

**Evidence: reproduced with the real CLI and SQLite inspection.**

[Remote startup](crates/clawbell/src/remote.rs#L186) records a launch intent, then
uses early `?` returns for endpoint setup, OAuth login and gate construction.
Those failures occur before `relay` can call `Gate::terminated`; the launch's
final recording is also skipped.

Reproduction with a fresh 0700 state directory:

```bash
target/debug/clawbell proxy-http \
  --url http://127.0.0.1:9/mcp \
  --policy /absolute/checkout/policies/default.toml \
  --state-dir /absolute/private-state \
  --server synthetic-audit-server
```

Omit `--private-ip` deliberately. The endpoint correctly refuses loopback access
and the CLI exits 1 without MCP output. Querying
`SELECT outcome, reason FROM events_v1 ORDER BY id` returns exactly
`allow_intent / unspecified`: no denial, terminal reason or correlated completion.
No upstream operation was sent in this probe.

The log therefore cannot distinguish a known setup refusal from an interrupted
launch. OAuth errors/timeouts take the same early-return path by source review;
they were not tested against a live identity provider. This leaves the terminal
audit requirement of source roadmap item 3 incomplete for the new HTTP path,
although the original stdio A-04 regression is repaired.

Acceptance criterion for a later repair: endpoint/DNS/login/setup failures after
intent receive fixed, payload-free terminal reasons and a correlated launch
outcome; audit failure must still prevent forwarding. No repair was made.

## Recheck of the original A-01–A-07 defects

The original regression cases pass in this session. None of their original
exploits was reproduced on the audited source.

- **A-01 — repaired:** non-string scalars are inspected and secret-bearing
  scalars refuse instead of changing type. Production regression:
  `audit_a01_known_numeric_secret_is_not_returned`.
- **A-02 — repaired:** unsupported binary/mixed content refuses before inner
  forwarding. Production regression: `audit_a02_embedded_binary_is_not_returned`.
  This is a text-only boundary, not a new binary decoder.
- **A-03 — repaired within the documented literal-text scope:** ordered content
  blocks and known trailing prefixes are inspected before release. Regression:
  `audit_a03_fragmented_known_secret_never_leaves_production_gate`. Arbitrary
  encoding/reordering and values first learned after disclosure remain outside
  the guarantee described in ADR 0008.
- **A-04 — original stdio case repaired:** malformed JSON, protocol, limit and
  timeout paths receive terminal audit events. Regression:
  `audit_a04_terminal_errors_before_gate_are_durable_and_payload_free`.
  B-02 describes a separate gap in subsequent HTTP startup integration.
- **A-05 — repaired:** events retain fixed reasons, generated session identity
  and owner-derived upstream digest. Production reason and additive-migration/
  cross-session tests pass. Old records correctly retain legacy attribution.
- **A-06 — repaired:** secret-bearing catalogs refuse before pin persistence;
  clean catalogs reconnect consistently. Regression:
  `audit_a06_secret_catalog_refuses_before_first_pin_and_clean_reconnect_succeeds`.
- **A-07 — repaired:** native preflight precedes binding. The public CLI test
  `init_fake_cgroup_refuses_without_binding_backups_or_upstream_execution` passes;
  invalid delegation leaves configuration, backup and receipt untouched.

Implementation evidence: [DLP](crates/proxy/src/dlp.rs),
[production regressions](crates/clawbell/src/attack_tests.rs),
[terminal transport audit](crates/proxy/src/stdio.rs),
[operation storage](crates/audit/src/operations.rs),
[binding](crates/clawbell/src/main.rs), and [CLI tests](crates/clawbell/tests/cli.rs).

## Delivery against the source roadmap

### Items 1–4: original security repairs

Items 1, 2 and 4 are implemented and their regressions pass. Item 3 is implemented
for the original stdio path and session/reason schema, but is not complete across
the added HTTP startup path because of B-02.

### Item 5: doctor, demo and repeatable Linux bootstrap

Implemented in [diagnostics](crates/clawbell/src/diagnostics.rs) and the
[Fedora 44 bootstrap](scripts/bootstrap-fedora-44.sh). Probes exercise actual
containment; the bootstrap supplies a persistent owner service with delegation.
It does not install prerequisite packages or configure lingering automatically.
No host service was installed or changed during this audit.

The stronger supporting feature later in the source document is **partial**:
`doctor --self-test` covers outside reads, writes, sockets, detached descendants
and audit loss, but prints fixed status lines. It does not produce a retained
report bound to binary version/hash and the exact containment profile or attach
such evidence to an MCP operation. See `diagnostics::run`.

### Item 6: production monitor and one-use approvals

Implemented for local tool calls through explicit `proxy --monitor-socket`.
The production approval regression passes, including durable intent after consent
and one-use consumption. Missing owner, timeout and disconnect deny.

Scope remains limited: `init` does not configure the socket automatically;
`proxy-http` has no monitor option, and protocol-level `require_approval` for
resources/prompts refuses. These are remaining integration limits, not approval
bypasses. Evidence: [launch composition](crates/clawbell/src/launch.rs),
[monitor](crates/proxy/src/monitor.rs), [remote CLI](crates/clawbell/src/remote.rs).

### Item 7: independent deadlines

Implemented for local `proxy`: request, idle and absolute lifetime have separately
validated CLI options. Tests `reads_after_31_idle_seconds_and_301_session_seconds`
and `independent_idle_request_and_absolute_deadlines` pass with controlled clocks.
HTTP uses the same independent transport defaults, but does not expose their CLI
configuration. This is a bounded compatibility limitation of the remote command.

### Item 8: explicit baseline review and migration

Implemented: `pins review/accept/history`, exact latest-candidate checks, offline
maintenance locking and append-only acceptance history. Diff output contains
hashes, not raw schema/description text; owners must independently review source.
Existing pins are preserved. Evidence: [baseline store](crates/audit/src/baseline.rs)
and [owner management CLI](crates/clawbell/src/manage.rs).

### Item 9: audit inspection, export, status and rotation

**Partial.** `audit view/export/status/rotate` and visible capacity warnings are
implemented. Rotation preserves a private archive and durable receipt, requires
stopped sessions, and never replays unknown effects. Storage/CLI tests pass.

The requested live `audit tail`/follow workflow is absent: `view` emits one bounded
page using `--after` and `--limit`, then exits. Evidence:
[management command enum](crates/clawbell/src/manage.rs) and
[maintenance](crates/audit/src/maintenance.rs).

### Item 10: licensing and release supply chain

Implemented in source: [MIT license](LICENSE), [security reporting](SECURITY.md),
locked RustSec scans, [SBOM generation](scripts/generate-sbom.sh), packaging,
and tagged-build provenance/SBOM attestations that publication must verify.
The current dependency scan reports no vulnerability in 274 locked packages.

Delivery evidence remains limited: fetched tag `v0.1.0` points to `57b0e54`, before
these additions. Local configuration/tests do not prove a new attested release
was published or that GitHub Actions succeeded. Remote release/attestation status
was not verified. The separately noted AArch64 package remains absent:
[packaging](scripts/package-release.sh) explicitly supports only x86-64, although
the CI native matrix now includes ARM. Configured ARM CI is not a passed ARM run.

### Item 11 and the proposed differentiator: approved filesystem effects

**Partial; the end-user MCP write workflow is still missing.**

[Transaction staging](crates/sandbox/src/transaction.rs) and the
[handle committer](crates/sandbox/src/transaction/commit.rs) implement isolated
execution, frozen candidates, redacted previews, exact-context/expiry-bound
consent, host-conflict checks and persistent recovery journals. Existing-file
UTF-8 replacements are supported; creation/deletion and metadata changes refuse.
In-place writes can be partial and are not atomic; ADR 0012 documents this.

Production `proxy` does not invoke Transaction or the committer. There is no
per-operation MCP integration that privately executes an unmodified server,
associates its actual diff with the tool invocation, obtains owner consent,
publishes the accepted effect and audits that complete chain. Existing monitor
approval authorizes a declared tool call; it does not publish staged changes.
Consequently a CLI `write_file(notes/a.txt)` cannot exercise the differentiating
legal-write-plus-hidden-write-refusal workflow described in the source audit.
Library tests do not establish delivery of that missing production composition.
See [ADR 0011](docs/adr/0011-transactional-file-staging.md),
[ADR 0012](docs/adr/0012-approved-handle-committer.md), and
[launcher](crates/clawbell/src/launch.rs).

### Item 12: policy-enforcing network broker

Implemented for explicitly owner-configured **host HTTP endpoints**:
[Endpoint](crates/proxy/src/network.rs) binds scheme/host/port/path, pins all DNS
addresses, checks the response peer, refuses redirects/retries/ambient proxies,
requires exact private exceptions and confines credentials to HTTPS adapters.

The broader local-process egress workflow remains absent: sandbox sockets are
still denied, and skills/local MCP cannot request controlled network exceptions
through this broker. Endpoint grants are CLI/library owner configuration rather
than general sandbox network policy. This limited broker must not be described
as network access for arbitrary local tools. See
[ADR 0013](docs/adr/0013-broker-protocol-and-scanned-skills.md).

### Item 13: Streamable HTTP/OAuth, resources/prompts and pagination

**Partial.** `proxy-http`, session-scoped POST JSON/SSE, pre-registered OAuth/PKCE,
separate exact-target resource/prompt policy and pinned metadata exist.
Tools support up to 64 pages/4096 tools rather than the previous 256-tool limit.
The existing HTTP/session/OAuth/protocol regressions pass; B-01 remains.

Resource, resource-template and prompt catalogs still reject `nextCursor` and
cursor requests. The complete pagination scope is therefore not delivered.
Remote integration also lacks GET streams, resumption/session deletion,
OAuth discovery/dynamic registration/refresh/persistence, automatic remote client
binding and interactive remote approvals. These are explicit compatibility limits;
they are not all mandatory for every compliant upstream or new independent
roadmap requirements. Evidence: [HTTP](crates/proxy/src/http.rs),
[OAuth](crates/proxy/src/oauth.rs), [catalog policy](crates/proxy/src/content.rs),
and [ADR 0013](docs/adr/0013-broker-protocol-and-scanned-skills.md).

### Item 14: content- and scan-bound skills

Implemented for Linux through `skill-scan` and the explicit scan-bound `proxy`
options. The digest covers the frozen package, invocation, expected instructions
and exact policy; execution requires both skill and shell grants. The runtime
checks initialization instructions and mounts the frozen package read-only.
System runtime/interpreters remain trusted dependencies outside the package hash.
Findings are review evidence, not authorization or proof of safety. Evidence:
[skill snapshot](crates/sandbox/src/transaction/skill.rs),
[instruction gate](crates/proxy/src/skill.rs), [CLI](crates/clawbell/src/skill_scan.rs).

### Item 15: macOS and Windows containment

**Not implemented.** NativeRunner refuses non-Linux execution. macOS profile
generation is not aggregate resource/lifecycle enforcement; Windows has no
production native adapter. No native test results on those platforms were
obtained. This is a delivery gap, not a request for an unisolated fallback.
Evidence: [platform selection](crates/sandbox/src/native.rs) and
[ADR 0013](docs/adr/0013-broker-protocol-and-scanned-skills.md).

### Other explicitly described missing capabilities

- **Measured security and usability corpus — partial:** synthetic attack,
  DLP, baseline and recovery fixtures plus warm latency gates exist. There is
  no published evaluation covering allowed-workflow completion rate, DLP false
  positives, cold start, p95/p99 and separately attributed durable-audit cost
  together. Existing warm RTT maxima do not supply those missing metrics.
- **Optional panel/API — absent:** there is no `ui/`, `serve`, browser API or
  token initialization. The source audit explicitly defers this behind CLI
  approvals/diagnostics; it is not classified here as an MVP security defect.
- **Setup is not one command from a clean host:** prerequisites, build/install,
  delegation, policy/workspace/state preparation and client binding remain
  separate steps. The Fedora bootstrap improves delegation only. A prepared
  `proxy` invocation is not equivalent to a complete one-command installer.

## Verification performed in this session

- **PASS — `bash scripts/check-local.sh`:** locked dependency fetch, rustfmt,
  all-target Clippy with `-D warnings`, workspace tests, release build, CLI help,
  default-policy validation and diff whitespace checks. The ordinary suite reports
  **114 passed, 0 failed, 13 ignored**; mandatory native/performance cases were
  then invoked explicitly below. Ignored cases were not counted as passing.
  The optional synthetic `latency_under_three_ms` experiment was not invoked;
  production/native measurements below provide the relevant latency evidence.
- **PASS — explicit release checks:** the five release packet benchmarks,
  `child_cannot_modify_agent_memory`, and
  `systemd-run --user --scope -p Delegate=yes bash scripts/test-native-linux.sh`.
  The native script passed five containment/staging/commit/skill/resource-limit
  tests, the native transport budget, real installer/CLI attacks, scan-bound CLI
  skill scenarios, `doctor`, `doctor --self-test` and `demo`.
- **PASS — current dependency advisory scan:** cargo-audit 0.22.2 loaded 1395
  RustSec advisories and scanned 274 locked dependencies; exit 0, no reported
  vulnerability. This does not certify unknown vulnerabilities.
- **PASS — supporting syntax checks:** Bash scripts parse with `bash -n` and
  Python scripts/fixtures parse with `ast.parse`.
- **Confirmed findings — independent CLI probes:** B-01 and B-02 reproduced with
  `/tmp/clawbell-audit-http-probes.py`, a disposable local server and private
  SQLite state. No production client configuration was touched.

Warm release measurements, with every measured sample below **5 ms**:

- Complete production tool gate, including parse/encode and durable audit:
  4000 packets; p99 **0.374159 ms**, maximum **0.561574 ms**.
- Remote-resource production gate, including durable audit: 4000 packets;
  p99 **0.272747 ms**, maximum **0.794025 ms**. This measures the gate, not WAN RTT.
- Full real CLI/native/policy/schema/DLP/audit path: 2000 measured warm RTTs;
  p99 **0.678 ms**, maximum **1.799 ms**.
- Native transport: 2000 RTTs; p99 **0.061686 ms**, maximum **0.272356 ms**.
- DLP 2274-byte packet: p99 **0.239454 ms**, maximum **0.251346 ms**;
  policy/schema maximum **0.009578 ms**; monitor maximum **0.008797 ms**.

Environment: Fedora 44, Linux x86-64, Rust 1.99.1 and bubblewrap 0.12.0.
Rust and verification tools were installed under `/tmp`; ordinary restricted
execution cannot resolve network hosts/use the user service bus, so the actual
verification ran with host access. Product isolation and tests were not weakened.
Fresh checks used `RUSTUP_HOME=/tmp/clawbell-audit-rustup`,
`CARGO_HOME=/tmp/clawbell-audit-cargo` and that Cargo bin directory on PATH.

These are bounded, warmed workloads on this host. They do not establish a hard
real-time bound for every permitted frame/schema, cold start, user approvals,
file snapshots/commits, WAN latency or arbitrary scheduler/storage contention.
No packet-processing code was changed in this audit.

Not executed/claimed: npm/Vitest/Playwright or browser checks (no frontend
manifest/UI), macOS/Windows/ARM native runs, a live-provider OAuth flow, new release
packaging/SBOM generation or remote CI/release/attestation verification. The
bootstrap's service installation was reviewed, not rerun against owner settings.

## Repository and secret hygiene

Only `AUDYT2.md` is intended for this commit. Existing owner documents remain
untouched; AGENTS.md remains 199 lines. Probe scripts and disposable databases
were created outside the repository; generated Rust artifacts stay under ignored
`target/`. No real credential was used as test data.

Fetched origin refs/tags and scanned all reachable Git history and the reviewed
index using checksum-verified gitleaks 8.30.1: no findings. Scanner configuration
does not exclude the audit report. The exact final index is scanned before commit.
This is evidence of no detected secrets in the inspected Git content, not a
guarantee covering arbitrary encodings, deleted remote refs, Actions logs,
release assets, forks or previously copied credentials. No history rewrite was
performed or needed on the available evidence.
