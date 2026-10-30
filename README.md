# clawbell

A local Rust MCP firewall with a reversible client installer and an offline skill
inspector. The Linux MVP launches **local stdio servers** through policy checks,
pinned tool schemas, session DLP, durable SQLite audit and native containment.
It runs without cloud telemetry. It is a conservative security boundary, not a
claim to recognize every malicious instruction or arbitrary encoded secret.

## Install and bind a client

Use the Rust version pinned in `rust-toolchain.toml`:

```bash
cargo install --locked --path crates/clawbell
clawbell --help
clawbell policy check --file policies/default.toml
```

The native launcher requires Linux x86-64/AArch64, bubblewrap with `--ro-bind-fd`
and `--disable-userns` (CI pins 0.12.0), usable unprivileged namespaces, seccomp,
`close_range`, and an owner-delegated cgroups v2 subtree with cpu/memory/pids
controllers. No root, direct-process fallback or Docker socket is used. Create
and manage delegation through your host's service manager; a transient test scope
is not a persistent delegation for installed clients. Missing prerequisites refuse
launch. macOS and Windows execution are unsupported; macOS remains fail-closed.

Prepare an owner policy and a **credential-free** workspace containing the server
code. The entire selected workspace is readable by that upstream, irrespective
of tool-argument policy: never select your home, repository containing secrets,
`.ssh`, `.aws`, or another credential tree. All host mounts are read-only; network
sockets and persistent host writes are unavailable in this MVP.

```bash
install -d -m 0700 "$HOME/.local/state/clawbell"
clawbell init \
  --policy /absolute/path/policy.toml \
  --workspace /absolute/path/credential-free-server \
  --state-dir "$HOME/.local/state/clawbell" \
  --cgroup-parent /sys/fs/cgroup/your-persistent-delegation
```

Discovery checks only known locations, never recursively scans your disk:

- `~/.cursor/mcp.json`
- `~/.config/Claude/claude_desktop_config.json`
- `~/Library/Application Support/Claude/claude_desktop_config.json`
- `~/.config/Code/User/mcp.json`
- Project `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`

Use repeated `--config /absolute/file.json` for other locations. Supported files
are strict JSON with one `mcpServers` or VS Code `servers` map. Unknown surrounding
settings are preserved. Every entry must be local stdio, with an absolute
`/usr/bin/` executable and literal string arguments. URLs, `envFile`, `cwd`,
nonempty `env`, JSONC, duplicate keys and ambiguous formats refuse the whole file.
PATH resolution, package installation and remote HTTP binding are not supported.
Complete path arguments inside the selected workspace translate to `/workspace`;
embedded paths such as `--file=/host/path` need explicit sandbox-compatible values.

Before changing any selected configuration, `init` validates every server and
exercises native isolation with a fixed trusted probe. It never executes an
upstream for discovery. Per-server output contains only indices and a fixed
preflight status; missing host prerequisites leave configs/backups untouched.
Launch repeats isolation checks. See [ADR 0008](docs/adr/0008-fragments-audit-and-binding-preflight.md).

For each file, `init` durably creates a **0600 `.bak`** and a hash-only
`.clawbell.json` receipt before atomic replacement. The wrapper invokes the
installed clawbell executable, with the explicit policy/workspace/state/cgroup
settings and original executable/arguments. Repeating an unchanged installation
is a no-op; different settings refuse rather than silently changing or attesting
to an existing binding.
Install the binary at a stable path before binding. The CLI prints file indices
and fixed statuses, never configuration contents or credentials.

```bash
clawbell unbind
clawbell unbind --config /absolute/file.json
```

`unbind` restores the exact original bytes only when both receipt hashes match.
Subsequent owner/client edits, tampering, symlinks, hardlinks, unsafe ancestors and
backup collisions refuse replacement. Backups remain after restoration; archive
or remove a reviewed backup explicitly before a new installation. Recovery from
an interrupted install is described in [ADR 0006](docs/adr/0006-mvp-installer-and-audit.md).
Multiple files are committed independently; earlier files remain protected if a
later one fails. Test configuration changes in temporary fixtures first.

## Inspect downloaded skills before use

Unpack the package yourself without executing it, then run:

```bash
clawbell scan /path/to/SKILL.md
clawbell scan /path/to/unpacked-package
```

The scanner reads every file in deterministic sorted order and reports JSON with
file indices, one-based source lines, stable reason codes and a decoded flag.
It detects hidden Unicode (including zero-width/bidi/tag/control characters),
Base64 carriers and nested decoded network/credential/instruction indicators,
network APIs/URLs, agent-memory references and common instruction overrides.
Payloads, decoded strings and source excerpts are never printed. Exit codes:
**0** no indicators, **2** review required, **1** incomplete/unsupported/error.

Limits: 256 files, 1,024 total entries, 256 entries per directory, depth 16, 1 MiB per file, 8 MiB per
package, 256 findings per file; Base64 inspection has three nested decoding levels
and a 4 MiB decoded-byte budget per file. Symlinks, special files, binary/non-UTF-8
files, archives and exhausted budgets fail rather than return a clean report.
Standard/URL-safe Base64 with optional padding is inspected in contiguous tokens
of at least 16 characters. Arbitrary encryption, split/constructed payloads,
other encodings and Unicode confusables are not comprehensively recognized.
Ordinary encoded data and URLs may produce false positives. A clean report never
grants execution permission; skills outside the controlled runner are unprotected.

## Security composition

`clawbell proxy --help` exposes the launcher used by `init`. Each session has an
immutable strict TOML policy snapshot, independent DLP vault and bounded protocol
state. Arguments must match pinned offline-compiled JSON schemas. Deny overrides
approval and allow; unknown tools/effects/paths deny. Agent-memory writes including
`SOUL.md`, `CLAUDE.md`, `AGENTS.md` and skill directories deny even with allow rules.
The example policy is owner configuration, not an upstream annotation.

The launcher explicitly allows initialization, ping, tool enumeration, policy-gated
tool calls and cancellation. Resources, prompts, sampling, elicitation, reverse
capabilities and other notifications deny; injected resources are stopped before
retrieval. `require_approval` uses the optional `proxy --monitor-socket PATH`
endpoint; without a connected owner it denies. `clawbell monitor --socket PATH`
connects that owner-private IPC endpoint. There is no web panel, HTTP listener or token initialization in this MVP.

Tool catalogs use persistent TOFU pins covering names, descriptions, schemas and
metadata. Changed catalogs or list-change notifications terminate the session;
there is no automatic reset/re-pin. TOFU cannot certify the first catalog or detect
server-code changes with unchanged metadata. Server identity is bound to the
owner name, workspace, command and arguments; installer names also include the
client configuration's path digest.

DLP inspects complete bounded UTF-8 messages in both directions. JSON numbers,
booleans and null are inspected in their serialized representation, including
credential field context; detecting a secret denies the whole message to preserve
the scalar's type and meaning. Result content accepts only text blocks and inline
text resources with no MIME type, `text/plain`, or `text/markdown`. Binary blobs
(including blobs labelled as text), images, audio, resource links, unknown content
variants/fields and other resource MIME types deny before the inner policy/audit
gate. The same format checks cover resource-read and prompt-message results in
library integrations; the CLI still denies those methods. Structured JSON remains
subject to recursive scalar inspection, not arbitrary Base64 decoding.

Ordered tool-result text/inline-resource blocks are inspected together. A secret
spanning blocks refuses the whole message. Text ending in any proper prefix of a
known secret also refuses, preventing completion in a later response; this can
reject innocent text, including one-character suffixes. Resource documents and
prompt messages are separate units; arbitrary JSON fields are not concatenated.
This does not detect secrets first learned after earlier output, arbitrary
reordering/normalization or encodings. A catalog requiring redaction refuses before
its first pin; existing pins are never silently reset. See
[ADR 0008](docs/adr/0008-fragments-audit-and-binding-preflight.md).

Outgoing requests with detected raw secrets refuse rather than changing argument semantics. Server
results are redacted before entering the inner gate. Secret patterns are heuristic;
the launcher does not enable credential injection or marker restoration. Library
callers may explicitly register known secrets and use the narrower restoration
contract in [ADR 0002](docs/adr/0002-in-flight-dlp.md).

A dedicated SQLite writer durably acknowledges every allowed request intent before
forwarding and records inspected responses, protocol errors, denials and unknown
outcomes, including fixed terminal reasons for failures before gate inspection.
The audit contains UTC timestamps, generated session/correlation IDs, an upstream
digest, fixed denial reasons and a policy digest; it stores no raw request IDs, paths, names, arguments or
responses. Responses must reference an intent in the same session. Existing audit
schemas migrate additively; older rows retain explicit legacy identities/reasons.
Intent rows without a corresponding outcome mean **unknown**, including
a process crash. They are never replayed. Append-only triggers prevent routine
updates/deletes, not a compromised owner/administrator. The database is bounded
by 16,384 SQLite pages (normally 64 MiB); exhaustion stops new operations. No
unaudited automatic deletion/retention is implemented. Store audit/baselines in an
existing private 0700 directory outside workspace/system runtime mounts, with
trusted ancestors; files are 0600. See [ADR 0006](docs/adr/0006-mvp-installer-and-audit.md).

The native runner isolates user/PID/mount/network/IPC/UTS namespaces, drops
capabilities, clears inherited environment and exposes only read-only runtime and
workspace plus private temporary storage. Seccomp and cgroups bound the whole
process tree. Cancellation, deadlines and Drop kill descendants. Remote operations
and processes started outside this runner remain outside local enforcement.
See [ADR 0004](docs/adr/0004-native-process-containment.md).

## Verification and release

```bash
bash scripts/check-local.sh
# Requires a namespace-capable Linux user session with delegated cgroups:
bash scripts/check-release.sh
# After staging the exact candidate (requires a verified gitleaks binary):
GITLEAKS_BIN=/path/to/gitleaks bash scripts/check-secrets.sh
bash scripts/package-release.sh
```

Five automated attacks cover `.env` exfiltration, SSH reads/traversal, `SOUL.md`
replacement, persistent catalog rug-pull and resource prompt injection. Unit tests
exercise the production CLI gate composition; the real CLI/native test additionally
checks refused forwarding and unchanged synthetic host/memory fixtures. Storage,
backup tampering, interruption, Unicode, nested Base64, invalid schemas, malformed
protocol, socket IPC, output bounds and lifecycle failures have separate coverage.

Release experiments assert **every measured warmed packet/RTT below 5 ms**. The new
gate benchmark includes encoding/parsing, policy/schema checks, DLP and durable
SQLite audit (4,000 packets); a real CLI/native benchmark measures 2,000 complete
read-tool round trips. Startup, catalog pinning/schema compilation, large messages,
human approval waits and arbitrary storage/scheduler contention are excluded.
These are reproducible release budgets, not a universal hard real-time guarantee.
A failed budget must fail release checks, never trigger a weaker durability mode.

GitHub Actions runs format/lint/tests/build, a pinned checksum-verified gitleaks
history/index scan, production gate latency and native Linux enforcement on
ephemeral hosted runners. Native CI builds pinned bubblewrap 0.12.0 and provisions
namespace/cgroup prerequisites; unavailable facilities fail the job. A `v0.1.0` tag
publishes a checksummed Linux x86-64 archive only after both jobs pass. No tag is
created by `init`, and dependencies/skills never auto-update. Git ignores runtime
state, installer backups, `.env` files and common private-key files. Secret scanning
cannot prove absence of every secret or erase remote copies/forks.

Technical contracts: [rmcp](https://github.com/modelcontextprotocol/rust-sdk),
[MCP transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports),
[bubblewrap](https://github.com/containers/bubblewrap),
[ADR 0003](docs/adr/0003-policy-baseline-memory.md),
[ADR 0005](docs/adr/0005-owner-ipc-approvals.md).

## Host diagnostics and approval monitor

The supported bootstrap target is **Fedora Linux 44**, with an active systemd
user session, Python 3 and bubblewrap supporting `--ro-bind-fd` and
`--disable-userns`. Run `bash scripts/bootstrap-fedora-44.sh` as the owner.
It installs an idempotent user service, keeps its supervisor in a separate
subgroup and enables only cpu/memory/pids delegation. Existing different unit
contents refuse replacement. No root or global namespace settings are changed.
Use the printed cgroup path for clients and diagnostics. The service must remain
running while clients use it. Stop clients before removing it with
`systemctl --user disable --now clawbell-delegation.service`, then remove the
managed unit and run `systemctl --user daemon-reload`. Login persistence follows
the host user-manager lifecycle; unattended boot requires owner/admin-managed
lingering, which this script does not enable.

```bash
clawbell doctor --cgroup-parent /sys/fs/cgroup/your-delegation
clawbell doctor --self-test --cgroup-parent /sys/fs/cgroup/your-delegation
clawbell demo --cgroup-parent /sys/fs/cgroup/your-delegation
```

`doctor` exercises actual native startup. `--self-test` and `demo` additionally
use disposable synthetic fixtures to verify outside-mount reads (including a
symlink), read-only workspace writes, Internet/Unix socket denial, detached
child cleanup after cancellation, and refusal to forward when SQLite rejects
an audit intent. Processes can fork within their task budget; the child check
verifies confinement and removal, not a blanket fork ban. Missing prerequisites
or any failed assertion exit 1; nothing is silently skipped. Python is required
for these active probes. Temporary files are private and removed on exit.

For interactive approval, add `--monitor-socket /private/directory/session.sock`
to `clawbell proxy` and connect from another terminal with
`clawbell monitor --socket /private/directory/session.sock`. The parent must be
owner-private 0700 and outside workspace/runtime mounts. Use one unique socket
per proxy session. Existing endpoints refuse replacement; after the proxy exits,
remove the stale socket explicitly. The installer does not add this optional
flag automatically. Only policy `require_approval` calls wait for approval;
missing owner, disconnect, rejection or the 25-second deadline deny. Replies
apply once to the suspended call and cannot override any independent deny.
Human wait and native startup are excluded from the packet latency budget.
