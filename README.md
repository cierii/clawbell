# clawbell

A local Rust MCP firewall with a reversible client installer, scan-bound skill
runner and pinned remote HTTP relay. Linux launches **local stdio servers** through policy checks,
pinned tool schemas, session DLP, durable SQLite audit and native containment.
It runs without cloud telemetry. It is a conservative security boundary, not a
claim to recognize every malicious instruction or arbitrary encoded secret.

## Understand and contribute

See [architecture and request flow](ARCHITECTURE.md),
[contributor setup](CONTRIBUTING.md) and [security profiles](policies/README.md).

## Try a release without compiling

Release v0.1.4 uses the owner-approved p99 <40 ms durable-audit budget.
Authenticated release assets become available only after all CI gates pass.
The earlier v0.1.2 failure remains documented in [AUDYT_3.md](AUDYT_3.md).

From a reviewed checkout, with Python 3.11+ and GitHub CLI installed/authenticated:

```bash
python3 scripts/install-release.py --version 0.1.4
```

This downloads the exact Linux release, verifies its checksum, GitHub build
provenance and SBOM attestation, runs offline version/help/scan checks, and installs
`~/.local/share/clawbell/releases/0.1.4/clawbell`. The whole command has a 55-second
deadline and refuses on slow downloads or failed verification. It requires the
published release assets; a tag alone is insufficient. It does not provision the
host or bind clients. Full protection needs the host setup below, which downloads
and compiles dependencies and can take several minutes. Windows/macOS are refused.

## Install and bind a client

For a reviewed source checkout on Fedora 44 or Ubuntu 24.04, one invocation
provisions system dependencies, a checksum-pinned Rustup/toolchain, sufficiently
recent bubblewrap, lingering, persistent delegation, private policy/workspace/state,
a versioned binary and reversible client bindings:

```bash
bash scripts/install.sh --config /absolute/path/client.json \
  --workspace /absolute/path/credential-free-server
```

Run as the owner with Bash, sudo access and HTTPS connectivity. The workspace must
be private and credential-free. Omitting `--workspace` prepares an empty private
directory. The supplied default-deny policy requires owner review before tools can
run. See [installation and recovery](docs/installation.md) for exact host changes,
limitations and removal. macOS/Windows execution remains unavailable; the installer
refuses those hosts. The disposable-VM integration gate runs on both Linux CPU
architectures. Local test results do not certify a clean installation on another OS.

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
`.ssh`, `.aws`, or another credential tree. All host mounts are read-only; direct network
sockets and persistent host writes are unavailable in the proxy launcher.
Named host broker capabilities are described below.
The explicit `proxy-transaction` mode and transaction library are described below.

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
settings are preserved. Local entries require an absolute `/usr/bin/` executable
and literal string arguments. Remote entries accept only a credential-free HTTPS `url`, optional
`type: "http"` or `"streamable-http"`, and optional public `clawbellOAuth`
settings described below. Remote preflight checks pinned egress without issuing
MCP requests; local entries still exercise native isolation. `envFile`, `cwd`,
nonempty `env`, remote headers, JSONC, duplicate keys and ambiguous formats refuse
the whole file. PATH resolution and package installation are not supported.
Complete path arguments inside the selected workspace translate to `/workspace`;
embedded paths such as `--file=/host/path` need explicit sandbox-compatible values.

Before changing any selected configuration, `init` validates every server and
exercises native isolation for local entries with a fixed trusted probe. It never
executes an upstream for discovery. Per-server output contains only indices and a fixed
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

## Transactional MCP operations (explicit Linux mode)

`proxy-transaction` runs an unchanged stdio MCP executable in a fresh private
sandbox for each operation. The production policy, schema/catalog pins, DLP and
durable audit apply before execution. Tool results stay private until the complete
process group stops and the actual filesystem changes pass inspection. A write
requires a separate owner approval of the complete redacted diff before the trusted
committer publishes it. Ordinary `proxy` and installed client bindings retain their
read-only host mounts.

```bash
clawbell proxy-transaction \
  --policy /absolute/path/transaction-policy.toml \
  --workspace /absolute/path/credential-free-workspace \
  --state-dir /absolute/path/private-state \
  --journal-dir /absolute/path/private-durable-journal \
  --cgroup-parent /sys/fs/cgroup/your-persistent-delegation \
  --monitor-socket /absolute/path/private-state/owner.sock \
  --server reviewed-local-server \
  -- /usr/bin/python3 -B /workspace/server.py
# In another terminal, as the workspace owner:
clawbell monitor --socket /absolute/path/private-state/owner.sock
```

Create state/journal directories at mode 0700 outside all runner mounts; the journal
must be on persistent storage, not `/tmp` when that is tmpfs. The policy must declare
the upstream tools and independently grant `clawbell.commit` for actual affected
paths; see [commit-example.toml](policies/commit-example.toml). First catalog use
still refuses until the owner reviews/accepts it with `clawbell pins`. A policy
`require_approval` on the upstream tool asks for private-execution consent first;
the later diff approval is always required for publication, even with `allow`.
Connect the owner monitor before requesting approval and remove a stopped socket
only after verifying that its previous process has exited.

This mode supports initialization, ping and tool catalogs/calls with one outstanding
request. It replays initialization/catalog exchanges into each fresh process and
requires their responses to match exactly; it never replays a prior tool call.
Servers relying on persistent process state, changing initialization metadata,
reverse requests or dynamic cursors can refuse. Resources/prompts and scan-bound
skill flags are unsupported here. Every surviving write by a declared read tool
refuses. Supported writes replace existing UTF-8 regular files only; creations,
deletions, protected memory, unsupported metadata, no-op candidates and previews
exceeding the monitor's complete 1800-character display budget refuse.

Publication uses verified file handles and a durable recovery journal, with the
non-atomic write contract below. A completed or partial journal blocks another
publication until the owner inspects and archives it explicitly; there is no
background replay or rollback. Keep external writers quiescent from snapshot to
commit. Client disconnect cancels waiting consent; an already-running commit is
joined and audited even when its response cannot reach the client. Startup,
snapshots, inspection, owner review and publication are measured separately from
the warmed proxy packet latency budget. See [ADR 0014](docs/adr/0014-per-operation-mcp-publication.md).

### Transaction library boundary

Linux integrations can use `clawbell_sandbox::transaction::Transaction` for one
owner-authorized execution. `prepare(NativeConfig, Effect, TreeLimits)` copies a
bounded tree into a private 0700 tmpfs directory. The upstream sees the originals
read-only at `/original` and its independent writable copy at `/workspace`, with
network sockets denied and the existing native cgroup/seccomp limits enforced.
The defaults and hard ceilings are 8 MiB, 4096 entries and depth 32; snapshot
and inspection each have a ten-second deadline. Symlinks,
hardlinks, special files, privileged modes and extended attributes other than the
host SELinux label refuse. No new dependency is needed.

The caller must durably audit authorization before `spawn`, enforce transport
budgets and reap the returned child. Consume the transaction with `inspect` before
releasing results: it kills the entire cgroup, confirms no descendants remain,
then returns a sorted structural diff. Content, type, permissions, ownership,
modification/change timestamps and SELinux label changes are compared. ReadOnly
with a changed workspace returns `transaction_hidden_write`. Reports contain
private untrusted paths, never raw content; redact them before crossing a trust
boundary. Copying and scanning run on blocking workers, outside the packet path.

For explicit owner-reviewed publication, use `inspect_for_commit` instead of
`inspect`, then `Candidate::review` with the immutable policy, original invocation
binding and session Vault. Display its complete redacted `preview()`, `digest()`
and UTC `expires()` through an authenticated owner adapter. Issue `approve` only
after the owner accepts that displayed digest; `commit` consumes both review and
capability and rechecks current policy, context, expiry and baseline state.
[Example policy](policies/commit-example.toml) opts into `clawbell.commit` for a
specific path prefix; protected memory such as SOUL.md always refuses.

The narrow committer replaces contents of existing UTF-8 regular files through
verified handles. Creation/deletion, binary replacements and metadata changes
refuse. Host edits, inode substitutions, symlinks and hardlinks invalidate consent.
Snapshots, review and commit run outside the packet path. The explicit
`proxy-transaction` adapter supplies this lifecycle; persistent `proxy` sessions
do not automatically publish changes.

Provide an owner-only 0700 journal directory on persistent storage outside the
workspace. The committer exclusively creates a private hash-only journal and
synchronizes intent before target writes. An existing journal blocks another
publication until the owner reviews and archives it. `commit_recovery_required`
means files may have been partly written; `recovery` distinguishes a complete
journal from an incomplete/unknown outcome after restart. Never retry or replay
such an operation automatically.

In-place file writes and multi-file publication are not atomic. Quiesce independent
host writers for a coherent snapshot and commit; state checks do not supply a
kernel CAS against same-account writers. Failed/cancelled staging never publishes;
interrupted publication may have partial effects. Abrupt crashes can leave private
tmpfs staging leftovers for owner cleanup/reboot. See
[ADR 0011](docs/adr/0011-transactional-file-staging.md) for staging and
[ADR 0012](docs/adr/0012-approved-handle-committer.md) for the approval, publication,
concurrency and recovery contracts.

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

## Remote Streamable HTTP and protocol operations

Remote upstreams run on their own hosts; clawbell controls traffic, not their
process isolation. Start a separate owner-authorized session manually, or use `init` to wrap
credential-free HTTPS entries in supported client configurations:

```bash
clawbell proxy-http --url https://mcp.example.com/mcp \
  --policy /absolute/path/policy.toml \
  --state-dir /absolute/path/private-state --server reviewed-remote
```

The egress broker binds the exact scheme/host/port/path and checked DNS addresses,
verifies TLS and the connected peer, and refuses every redirect or automatic retry.
No ambient proxy, cookies or credentials from the sandbox are used. An exact
`--private-ip` exception is available for one address at that URL/port; plain HTTP
is restricted to explicit loopback and cannot carry OAuth credentials. The sandbox
itself remains disconnected. Local processes can use only the named capabilities
described in the sandbox broker section below.

For a pre-registered OAuth public client, add the following flags to proxy-http:

```bash
--oauth-login --oauth-client-id public-client-id \
--oauth-authorization-url https://issuer.example.com/authorize \
--oauth-token-url https://issuer.example.com/token --oauth-scope mcp
```

Open the login URL printed to stderr. The provider must accept loopback ephemeral
callback ports. PKCE S256, one-use state, a five-minute deadline and an exact
resource indicator bind the exchange. Every token request uses pinned egress.
Access and refresh credentials, including rotations, are registered with DLP
before any corresponding MCP output is disclosed. Runtime expiry is monotonic;
a received 401 never replays an MCP request or starts an unattended login.

To discover endpoints, explicitly authorize one HTTPS issuer instead of supplying
authorization/token URLs:

```bash
--oauth-login --oauth-issuer https://issuer.example.com/ \
--oauth-client-id public-client-id --oauth-persist --oauth-scope mcp
```

Discovery checks RFC 9728 resource metadata and RFC 8414 issuer metadata, exact
resource/issuer identity, S256 and authorization-code support. Discovered endpoints
must remain on the trusted issuer origin; redirects, private destinations and
untrusted WWW-Authenticate URLs cannot expand that grant. For explicit dynamic
public-client registration, replace `--oauth-client-id` with `--oauth-register`.
Registration requires the explicit login action and never accepts client secrets
or registration-management tokens. Providers requiring those are unsupported.

`--oauth-persist` opts into synchronized **0600** token files inside the private
**0700** host state directory. These files contain credentials: protect the directory
and its backups; they are never sandbox-mounted or copied into client configurations.
On reconnect, use the same settings/scopes and omit `--oauth-login` and
`--oauth-register`. Configuration, discovered endpoint or resource changes refuse
cached credentials. Without persistence, credentials remain in host memory.
A session-long exclusive lease prevents concurrent refresh consumers. Before a
refresh grant, the cache receives a durable tombstone; uncertain grants are never
retried automatically. After a crash, stop all matching sessions, remove only the
matching stale `oauth-<binding>.lease` after owner review, and explicitly log in
again if its token file is empty. Refresh/storage failures close the session.

The binder automatically wraps mixed local stdio and remote HTTPS entries. A
remote entry may include owner-defined public settings:

```json
{
  "url": "https://mcp.example.com/mcp",
  "type": "http",
  "clawbellOAuth": {
    "issuer": "https://issuer.example.com/",
    "client_id": "public-client-id",
    "scopes": ["mcp"]
  }
}
```

The generated stdio wrapper uses `proxy-http`, the exact endpoint, private state
and deterministic monitor socket; backups/receipts keep their existing reversible
contract. OAuth bindings add persistence, issuer and public client/scopes, without
starting registration or login. Before opening the client, run the generated
command/arguments in a terminal with `--oauth-login` once to populate its exact
cache. For a dynamically registered client omit `client_id` from the settings and
add `--oauth-register` to that first terminal invocation. Tokens and confidential
client options are never accepted in binding metadata.

JSON responses, accepted notifications, POST SSE and session IDs are supported.
After the initialized acknowledgement, an independent GET stream can receive
notifications through the same protocol/policy/DLP gate. An explicit 405 disables
this optional stream. Completed SSE IDs enable up to three GET resumptions; a
disconnected POST stream resumes with GET and never repeats POST. IDs are scoped
to that stream/session; partial events remain undisclosed. Duplicate IDs, wrong
response IDs and interactive reverse requests refuse. Shutdown attempts one scoped DELETE, accepting
an empty 200/204 or unsupported 405. Missing sessions are not silently recreated.
Network/session cleanup cannot undo remote effects.

[protocol-example.toml](policies/protocol-example.toml) shows separate resources
and prompts permissions. resources/read and prompts/get match an exact URI/name;
a listing or URI template never grants retrieval permission. Lists are pinned
before publication. Prompt arguments must match the pinned definition; resource
contents must carry the requested URI. Text-only DLP remains mandatory. Resource
subscriptions, list-change notifications and binary content still refuse.
Protocol `require_approval` suspends the exact validated request for one owner decision through the connected monitor,
including lists, resource reads and prompt retrieval. A separate deny still wins;
prompt arguments and catalog pins must pass before asking for approval.

Tools, resources, resource templates and prompts support nextCursor across at
most 64 pages, 4096 entries and 8 MiB per catalog, with the existing per-message
limit. Only the immediately preceding opaque cursor can continue an enumeration;
overlapping requests and non-string/oversized cursors refuse. A fresh prompt
listing immediately invalidates its old definitions, and prompt execution waits
for all pages and the aggregate pin. Nonpaginated content pins remain compatible;
paginated content uses page scopes 0–63 and aggregate scope 64.

For tools, no call runs before the full catalog, schemas and aggregate pin pass. Each exposed page also needs an owner-reviewed
pin: first discovery may require successive review/reconnect cycles for pages and
the aggregate. Changed page partitioning may require review. Repeated/wrong
cursors, duplicate names, empty nonterminal pages and exhausted bounds refuse.

## Sandbox network broker (Linux)

Ordinary local MCP processes and scan-bound skills launched by `proxy` can request
named HTTP exceptions from the immutable owner policy. See
[broker-example.toml](policies/broker-example.toml). No grant means no broker
descriptor or additional capability. Transactional publication mode does not gain
a broker implicitly.

```toml
[[network]]
name = "public-status"
url = "https://api.example.com/public/status"
method = "GET"
decision = "allow"
```

Each grant binds one exact scheme, destination, port, path and GET/POST method.
Only an exact `private_ip` can permit a private target; metadata/link-local
destinations always refuse. Denied entries perform no DNS lookup; duplicate names,
unknown fields and unsupported approval/method values refuse policy load.
DNS is pinned before sandbox execution, TLS is verified, and redirects refuse.

The sandbox receives one already-connected channel at fd 3, identified by
`CLAWBELL_BROKER_FD=3`. Both sides exchange bounded UTF-8 JSONL:

```json
{"endpoint":"public-status","body":""}
{"status":200,"body":"public status"}
```

Requests cannot supply URLs, methods, headers, authentication or CONNECT tunnels.
GET bodies must be empty; POST sends UTF-8 text/plain. Responses accept only UTF-8
text/plain or application/json, returning the inspected body as text. Binary data,
unknown formats, partial/oversized frames and schema-changing request redaction
refuse. Every operation has a deadline and a durable intent before network I/O.
The broker shares the MCP session DLP vault, so a learned secret cannot escape
through the other channel. Denial/failure closes the channel and terminates the
associated sandbox tree; an unfinished intent has unknown outcome and never replays.
The network namespace remains disconnected and seccomp still denies all socket
constructors. This channel is a capability for that process and its descendants,
not an HTTP proxy environment variable or a host filesystem socket mount.

## Execute a reviewed skill snapshot (Linux)

Use an unpacked UTF-8 package and a file containing the exact expected
initialize.instructions. Execution requires both explicit owner policy grants:

```toml
[skills]
allow_execution = true
allow_shell = true
```

Arbitrary interpreter code can launch a shell inside containment; static inspection
cannot prove its absence. Both grants default to false, and even a matching scan
cannot bypass them. Review this scope before enabling it. Scan the exact command
and owner policy first:

```bash
clawbell skill-scan --workspace /absolute/path/package \
  --policy /absolute/path/policy.toml --instructions-file /absolute/path/instructions.txt \
  -- /usr/bin/python3 -B /workspace/server.py
```

Review the package and indexed findings. An empty report does not prove safety.
Use its digest only after deliberate owner review:

```bash
clawbell proxy --workspace /absolute/path/package \
  --policy /absolute/path/policy.toml --state-dir /absolute/path/private-state \
  --cgroup-parent /sys/fs/cgroup/your-persistent-delegation --server reviewed-skill \
  --skill-scan-digest '<reviewed-64-hex-digest>' \
  --skill-instructions-file /absolute/path/instructions.txt \
  -- /usr/bin/python3 -B /workspace/server.py
```

Launch repeats the complete scan and binds package paths, types, permissions and
bytes, exact command/arguments, instructions and exact policy fingerprint. Even
a same-version policy edit invalidates the digest. Execution uses the privately
frozen read-only tmpfs snapshot; subsequent source edits cannot replace it.
initialize.instructions must match the scan before and after DLP; absence, drift
or secret redaction closes the session before disclosure. Hardlinks, symlinks,
special nodes, binary files and incomplete scans refuse. Native network isolation,
resource limits, lifetime, bounded stdio, policy and durable audit stay mandatory.
System interpreters/libraries remain trusted runtime dependencies. The content hash
is reusable scan evidence, not an execution grant or an operation approval.

macOS and Windows native execution remain **unfinished and fail closed**. The new
AArch64 CI job exercises Linux containment; its results must be checked separately.
See [ADR 0013](docs/adr/0013-broker-protocol-and-scanned-skills.md) for trust boundaries,
compatibility, explicit unsupported features and verification limits.

## Security composition

`clawbell proxy --help` exposes the launcher used by `init`. Each session has an
immutable strict TOML policy snapshot, independent DLP vault and bounded protocol
state. Arguments must match pinned offline-compiled JSON schemas. Deny overrides
approval and allow; unknown tools/effects/paths deny. Agent-memory writes including
`SOUL.md`, `CLAUDE.md`, `AGENTS.md` and skill directories deny even with allow rules.
The example policy is owner configuration, not an upstream annotation.

The launcher explicitly allows initialization, ping, tool enumeration, policy-gated
tool calls and cancellation. Resources and prompts require separate exact owner
protocol rules; without them retrieval denies. Sampling, elicitation, reverse
capabilities and other notifications deny. `require_approval` uses the optional
`--monitor-socket PATH` endpoint on `proxy` or `proxy-http`; without a connected owner it denies. `clawbell monitor --socket PATH`
connects that owner-private IPC endpoint. There is no web panel or general HTTP listener. Explicit OAuth login uses a temporary
loopback callback; it never exposes a tool-execution HTTP endpoint.

Tool catalogs use persistent owner-reviewed pins covering names, descriptions,
schemas and metadata. First observation and changed catalogs stage a hash-only
review proposal and terminate the session before the catalog reaches the client.
The owner must review and explicitly accept the proposal, then reconnect; there
is no automatic reset/re-pin. Existing legacy pins remain enforced. A pin cannot
certify catalog safety or detect server-code changes with unchanged metadata.
Server identity is bound to the
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
the explicitly authorized ordinary and HTTP proxy modes; `proxy-transaction`
denies resource/prompt methods. Structured JSON remains
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
by 16,384 SQLite pages (normally 64 MiB). Fixed stderr warnings appear at 80% and
95%; the last 32 pages refuse new intents to reserve space for results. Explicit
owner rotation archives all events before reclaiming active pages; there is no
automatic deletion/retention. Store audit/baselines in an
existing private 0700 directory outside workspace/system runtime mounts, with
trusted ancestors; files are 0600. See [ADR 0006](docs/adr/0006-mvp-installer-and-audit.md).

The operation audit uses WAL with `synchronous=FULL`: every event commits before
acknowledgement. Automatic checkpoints recycle the WAL; a pinned reader causing
8 MiB of growth stops new sessions/intents, with terminal-event reserve until
16 MiB. Stop sessions/readers and resolve storage pressure before reconnecting.
Keep SQLite sidecars with the database; never delete live WAL/SHM files manually.
Offline rotation checkpoints and switches to DELETE before archiving. See
[ADR 0018](docs/adr/0018-durable-wal-audit.md) for migration and durability limits.

The native runner isolates user/PID/mount/network/IPC/UTS namespaces, drops
capabilities, clears inherited environment and exposes only read-only runtime and
workspace plus private temporary storage. Seccomp and cgroups bound the whole
process tree. Cancellation, deadlines and Drop kill descendants. Remote operations
and processes started outside this runner remain outside local enforcement.
See [ADR 0004](docs/adr/0004-native-process-containment.md).

## Deadlines and database maintenance

The launcher exposes independent owner settings:

```bash
clawbell proxy --idle-timeout-secs 600 --request-timeout-secs 30 \
  --session-lifetime-secs 3600 \
  --policy /absolute/policy.toml --workspace /absolute/credential-free-server \
  --state-dir /absolute/private-state --cgroup-parent /sys/fs/cgroup/delegated \
  --server reviewed-upstream -- /usr/bin/python3 -B /workspace/server.py
```

These are the defaults. Idle means silence between complete messages with no
outstanding request; request deadlines are never renewed by unrelated traffic.
`proxy-http` accepts the same three deadline flags and defaults; it applies them
to the common HTTP transport loop and HTTP egress request budget. For example:

```bash
clawbell proxy-http --url https://mcp.example.com/mcp \
  --policy /absolute/policy.toml --state-dir /absolute/private-state \
  --server reviewed-remote --request-timeout-secs 30 --idle-timeout-secs 600 \
  --session-lifetime-secs 3600 --monitor-socket /absolute/private-state/http.sock
```

Session lifetime is absolute, applies to the native process tree, and is not
extended by activity. Idle/lifetime ranges are 1–86400 s, requests 1–300 s. Thus a
healthy session can read after 31 idle seconds and after 301 session seconds.

On the first `tools/list`, expect refusal and a fixed review hint on stderr.
Stop all proxy sessions using the state directory, inspect the upstream package
and proposed catalog/tool SHA-256 differences, then accept the exact review ID:

```bash
clawbell pins --state-dir /absolute/private-state review
clawbell pins --state-dir /absolute/private-state accept --review-id 1 --accept
clawbell pins --state-dir /absolute/private-state history
```

Use the ID actually returned by `review`. The diff lists previous/proposed catalog
hashes and removed/added tool hashes; raw descriptions/schemas are deliberately
not retained. Verify upstream source independently. Changed tools appear as removal
plus addition. Replayed or superseded acceptance refuses. Reconnect after approval.
History keeps immutable proposals, old/new tool signatures and UTC acceptance times;
existing databases are preserved, including previous pins. `history` shows the
latest 256 proposals. A changed catalog never grants execution by itself.

Audit reads do not create sessions or replay operations:

```bash
clawbell audit --state-dir /absolute/private-state status
clawbell audit --state-dir /absolute/private-state view --after 0 --limit 100
clawbell audit --state-dir /absolute/private-state view --follow --after 0 --limit 100
clawbell audit --state-dir /absolute/private-state export \
  --output /absolute/new-audit.jsonl --after 0 --limit 100000
# Stop all sessions before this explicit owner action:
clawbell audit --state-dir /absolute/private-state rotate --accept
```

JSONL exports are new 0600 files and never overwrite existing output. Page through
large logs with the last event ID as exclusive `--after`; `--limit` is bounded at
100000. Start again at `--after 0` after rotation; IDs belong to one database
generation. Status reports allocated pages, page size, quota and warning level. The
writer also emits visible capacity warnings on stderr before intent refusal.

`view --follow` flushes new JSONL rows every 250 ms in pages of 1–1000 events
(default 100). `--after` remains exclusive; each successful page advances its
cursor. SQLite reads finish before output, so a slow terminal does not hold a read
transaction. Ctrl+C stops the follower; broken output or storage errors terminate
with an error. It holds a shared maintenance lease, preventing rotation and
baseline acceptance while following. Stop followers before offline maintenance;
restart at the appropriate cursor for that database generation.

Rotation refuses while any writer or follower is active. It fsyncs a full private SQLite
archive, preserves all sessions/correlations/unknown intents, records its filename,
SHA-256 and UTC time in the active append-only rotation ledger, then reclaims event
pages. Archives stay in the state directory; retain them to retain history. They
consume disk beyond the active quota and are not automatically deleted. Archives
can be inspected with SQLite in read-only mode. Stop older clawbell versions before
maintenance; they do not participate in the new cooperative lock. See
[ADR 0010](docs/adr/0010-timeouts-pins-and-audit-maintenance.md) for migration,
interruption recovery, locking and exact limits.

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

Release experiments with durable audit require **nearest-rank p99 <40 ms and
maximum <1 s** across all measured warmed packets/RTTs. Equality fails either
limit. Tests without durable I/O retain their maximum <10 ms budget. The
gate benchmark includes encoding/parsing, policy/schema checks, DLP and durable
SQLite audit (4,000 packets); a real CLI/native benchmark measures 2,000 complete
read-tool round trips. Startup, catalog pinning/schema compilation, large messages,
human approval waits are excluded. Storage/scheduler pauses during measurement
remain in the samples and reported maximum.
These are reproducible release budgets, not a universal hard real-time guarantee.
A failed budget must fail release checks, never trigger a weaker durability mode.

GitHub Actions runs format/lint/tests/build, a pinned checksum-verified gitleaks
history/index scan, production gate latency and native Linux enforcement on
ephemeral hosted x86-64 and AArch64 Linux runners. Native CI builds pinned bubblewrap 0.12.0 and provisions
namespace/cgroup prerequisites; unavailable facilities fail the job. A matching
version tag publishes separate checksummed Linux x86-64 and AArch64 archives only
after dependency, common, native and clean-host installer gates pass. Each
architecture has its own SBOM, provenance/SBOM bundles and evaluation JSON. The
publisher verifies both attestation predicates for each archive before publication.
No tag is
created by `init`, and dependencies/skills never auto-update. Git ignores runtime
state, installer backups, `.env` files and common private-key files. Secret scanning
cannot prove absence of every secret or erase remote copies/forks.

Technical contracts: [rmcp](https://github.com/modelcontextprotocol/rust-sdk),
[MCP transports](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports),
[bubblewrap](https://github.com/containers/bubblewrap),
[ADR 0003](docs/adr/0003-policy-baseline-memory.md),
[ADR 0005](docs/adr/0005-owner-ipc-approvals.md),
[ADR 0016](docs/adr/0016-sandbox-broker-and-stateful-http-oauth.md).

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

Self-tests and `demo` retain a synchronized 0600 JSON report in
`.local/clawbell/doctor` by default. Use `doctor --self-test --report-dir
/absolute/private-reports` to choose a private 0700 location; reports are retained
until explicit owner removal. Each filename contains the SHA-256 of its exact
bytes. JSON output identifies the file and digest. Reports include failure status
without raw errors, UTC Unix seconds, binary version/SHA-256, boot/kernel/CPU
architecture, bubblewrap SHA-256, the compiled read-only containment profile,
namespace/mount/environment settings, cgroup path/device/inode/controllers and
whole-tree memory/task/CPU/lifetime limits. Unavailable prerequisites produce a
failed report with an unavailable profile, never reusable evidence.

To attach a successful report to ordinary local MCP operations, pass
`proxy --doctor-report /absolute/private-reports/doctor-<sha256>.json` alongside
the usual proxy options. The proxy compares the bytes, binary and complete current
profile before creating its session or spawning an upstream. It durably records a
`containment_evidence` event with the report digest in `binding_sha256`; every MCP
operation in that session is linked through `session_id`. Keep the report with the
audit export. A changed binary, boot, cgroup or resource budget requires a new
self-test; `doctor --session-lifetime-secs` must match the proxy lifetime (default
3600). This is owner-local, point-in-time evidence, not a signed attestation or
execution permission. Native preflight and policy/audit/DLP remain mandatory.
The report does not attest to arbitrary workspace/server contents or host package
changes after testing. Skill/transaction profiles refuse ordinary-profile evidence;
remote HTTP processes cannot receive local containment attestation. See
[ADR 0015](docs/adr/0015-diagnostic-evidence-and-live-monitoring.md).

New `init` bindings automatically add a deterministic, per-client/per-server
`--monitor-socket` under the private state directory. Inspect the generated
configuration for the endpoint, then connect with `clawbell monitor --socket PATH`.
Existing installations remain unchanged; an attempted rebind with changed generated
settings refuses. Stop clients, `unbind`, archive the retained backup and run `init`
again to migrate. The installer does not launch a terminal or a permanent monitor.

For manual interactive approval, add `--monitor-socket /private/directory/session.sock`
to `clawbell proxy` or `proxy-http` and connect from another terminal with
`clawbell monitor --socket /private/directory/session.sock`. The parent must be
owner-private 0700 and outside workspace/runtime mounts. Use one unique socket
per running proxy. Existing endpoints refuse replacement. Normal shutdown removes
only the socket created by that proxy; after a crash, verify the previous process
has exited before explicitly removing a leftover. Monitor service failure closes
the proxy. Only policy `require_approval` requests wait for approval;
missing owner, disconnect, rejection or the 25-second deadline deny. Replies
apply once to the suspended call and cannot override any independent deny.
Human wait and native startup are excluded from the packet latency budget.

## Release security and licensing

clawbell is distributed under the [MIT license](LICENSE). Report vulnerabilities
privately using [SECURITY.md](SECURITY.md); it also documents supported versions,
release verification and attestation limits. CI scans the reviewed Cargo.lock
against RustSec on pull requests, pushes and a daily schedule. Publication requires
a successful scan as well as existing native security and latency checks.

Local release packaging requires pinned development tools (not runtime dependencies):

```bash
cargo install cargo-audit --version 0.22.2 --locked
cargo install cargo-cyclonedx --version 0.5.9 --locked
cargo audit --file Cargo.lock
bash scripts/package-release.sh
```

Build and verify the release binary first with `bash scripts/check-release.sh`.
Packaging generates a CycloneDX 1.5 JSON SBOM using offline Cargo metadata for the
same native x86-64 or AArch64 Linux/default-feature binary graph, includes it with LICENSE and
SECURITY.md in the archive, and publishes a separate SBOM and checksums. Tagged
GitHub builds attest both the binary and archive with provenance and the SBOM;
local packaging does not create attestations. Follow SECURITY.md before running
a downloaded release. The SBOM includes Rust production/build dependencies; it
is not a complete inventory of host tools or bundled C code.

To reproduce completion, DLP false-alarm, process-cold startup, p95/p99 and separately
timed FULL durable-audit measurements, run `python3 scripts/evaluate.py` on an idle
namespace-capable Linux user session with persistent user-manager access. The
exclusive output is `target/evaluation/report.json`; raw local test logs remain
ignored. See the [evaluation report](docs/evaluation.md) for the measured corpus,
results and limits. A failed measurement or packet latency budget prevents a new report.

## Safe error diagnostics

CLI failures exit 1 and write a fixed `code: hint` line to stderr. Proxy stdout
remains exclusively MCP. Host codes distinguish missing paths, permissions,
existing backups, symlinks, read-only/full storage, unsafe workspaces, invalid
limits, missing cgroups/controllers, bubblewrap, seccomp, descriptor setup,
probe timeout/failure and incomplete process cleanup. For example,
`host_cgroup_unavailable` requires an owner-delegated cgroups v2 subtree;
`host_resource_controls_unavailable` requires cpu/memory/pids and cgroup.kill.
Use `clawbell doctor --cgroup-parent <delegation>` after correcting host setup.

A failed trusted probe reports `host_isolation_probe_failed`: namespace denial
and unsupported bubblewrap capabilities cannot be distinguished safely from an
exit status alone. Raw stderr, paths, environment, JSON contents and credentials
are never printed. Owner input validation retains specific static codes such as
`binding_changed_or_incomplete`; unknown error types use
`host_unclassified_failure`. Refusal never authorizes fallback or automatic retry.
The Rust runner now exposes typed `LaunchError` variants; library consumers must
update unit-struct constructions and exhaustive matches. Proxy `Error::Host`
preserves that detail while the audit reason remains `isolation_unavailable`.
