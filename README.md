# clawbell

A local Rust MCP proxy core with declarative policy evaluation, persistent tool
catalog pins, agent-memory protection and session-scoped DLP. Linux is the first
filesystem enforcement platform. The CLI is still a scaffold: these are library
components, not a complete deployable firewall.

## Policy evaluation

`clawbell_core::policy::Policy::parse` loads strict TOML and compiles bounded
regular expressions once. [policies/default.toml](policies/default.toml) is the
owner configuration example. Each tool has an exact name, an effect (`read`,
`write`, `opaque`) and JSON Pointer selectors for its file paths. Server-provided
annotations never determine effects or permissions.

Rules match an exact tool name (or `*`), an optional component-bounded
`path_prefix`, and an optional `arguments_regex` over compact JSON arguments.
All supplied selectors must resolve to strings, and all selected paths must match
when a rule has a prefix. Paths are workspace-relative POSIX paths; absolute
paths, parent traversal, NUL, backslash and colon are refused. This lexical
validation does not resolve symlinks and cannot replace filesystem containment.

Evaluation returns `allow`, `deny` or `require_approval`, with a stable reason
code. Deny overrides approval, which overrides allow; unmatched operations deny.
Unknown effects, tools, fields and invalid regexes fail closed. An immutable
snapshot is held through each session. To reload, parse a replacement first and
install it only after success; existing sessions retain their original snapshot.

`require_approval` can suspend a call through an owner-private Unix socket.
Attach `PolicyGate::with_monitor(Monitor)` and run `Monitor::serve` in a supervised
task. The inner audit/DLP adapter remains mandatory. Register known secrets in the
Monitor before publishing; publish runner-verified sandbox status explicitly.
Start the terminal client with:

```bash
cargo run --locked -p clawbell -- monitor --socket /trusted/private/monitor.sock
```

The socket parent must already exist with mode 0700, outside sandbox mounts.
Commands `a ID`, `d ID`, and `q` require Enter. Strings are cyan and masked values
are highlighted yellow. The display includes bounded live packets, server status
and pending security decisions. Without a connected owner, approval denies.
Decisions expire after 25 seconds and can authorize only one exact suspended call.
See [ADR 0005](docs/adr/0005-owner-ipc-approvals.md) for integration and limits.
The CLI provides the monitor client; a deployable audited proxy launcher remains
unimplemented. Existing library integrations supply that composition.

Opaque commands, shells and recursive filesystem mutations are refused, even
with an allow rule: regexes cannot establish their effects.

## Tool catalog baseline and rug-pull protection

`clawbell_audit::baseline::BaselineStore` owns a bounded, dedicated SQLite writer
thread. Open it in an existing, trusted owner-private directory (0700). The
SQLite file is created with 0600; symlinks and group/world permissions are refused.
Keep the directory and its ancestors inaccessible to untrusted processes, and
never mount this directory inside a child sandbox.

`clawbell_proxy::policy::PolicyGate` decorates a required inner `Gate`. Bind its
server identity to owner configuration (endpoint/command and identity), never to
an upstream's self-reported name. Each instance belongs to one session. On the
first complete `tools/list`, it durably pins a domain-separated SHA-256 digest of
the name-sorted catalog, alongside SHA-256 signatures of each complete tool
definition. Each tool's name, JSON input schema, description and all
other metadata contribute to the digest. Object key order and tool list order
are insignificant; array order and metadata content remain significant. No raw
descriptions or arguments are stored in the baseline database.

A later catalog must match exactly, including additions/removals. A mismatch
blocks communication and never overwrites the pin. A `tools/list_changed`
notification immediately closes the guarded session; reconnecting requires
fetching and checking the complete catalog. Calls before a validated catalog,
paginated catalogs, duplicate names and invalid schemas are refused. Schemas
compile offline with a bounded linear-time regex engine; external references
cannot fetch network or local files. Tool arguments are checked against pinned
schemas on every call. Inner adapters cannot change checked calls or catalogs.

The first observation uses trust on first use (TOFU). It cannot prove that the
initial tool is safe, detect server code changes with identical metadata, or
isolate a remote server's filesystem. Owners must review initial servers and
explicitly plan a baseline migration for legitimate tool upgrades. There is no
automatic reset/re-pin command. A failure is terminal for that session.

## Agent memory guard

Write effects targeting `SOUL.md`, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, or
`skills`, `.skills` and `skillks` path components are denied before forwarding,
regardless of allow rules. Matching is ASCII case-insensitive and also covers
new files and nested agent-specific skill directories. Owner tool bindings must
accurately list every affected file path; arbitrary server behavior cannot be
inferred from tool arguments.

`clawbell_sandbox::memory::MemoryGuard` supplies the filesystem containment part
of a Linux Runner. It pins the workspace using an open directory handle and
prepares bubblewrap with read-only workspace and runtime mounts, a private
volatile `/tmp`, isolated namespaces, dropped capabilities, an empty environment,
and disabled nested user namespaces. There are no writable host mounts. This
conservative profile prevents persistent writes through symlinks, hardlinks,
rename/unlink, newly created files and descendant processes. It protects the
whole mounted workspace, rather than watching filenames after a write occurs.

`prepare` **does not launch a process** and is not a complete `Runner`. The
composition root must also install seccomp, cgroups v2 resource limits and tree
supervision before spawning. Do not add a writable host mount: that invalidates
this profile's guarantee. The setup handle uses stdin; a fixed exec shim replaces
it with `/dev/null` before the owner-authorized program starts. This component is
for skills without stdin; an MCP Runner must arrange a separate inherited handle
for mount setup. Shell authorization is separate. No insecure launcher or
production allow-all gate is provided. Processes started outside a controlled
runner and remote MCP processes remain outside filesystem enforcement.

## Native OS runner

`clawbell_sandbox::native::NativeRunner` implements the existing `Runner` interface
on Linux (x86-64/AArch64). Pass owner-authorized `NativeConfig` with an absolute
credential-free workspace, `/usr/bin/` executable, literal argument vector,
resource limits and a trusted delegated cgroups v2 parent to `NativeRunner::new`,
then supply it to `clawbell_proxy::stdio::run` with the mandatory audited Gate.
No CLI launch command or permissive production Gate is added.

Linux requires bubblewrap with `--ro-bind-fd` and nested-userns disabling, unprivileged namespaces,
`close_range(CLOSE_RANGE_CLOEXEC)`, seccomp and a delegated cgroup v2 subtree with cpu/memory/pids controllers enabled.
The child joins its cgroup before exec. All persistent mounts are read-only;
network sockets and privileged syscalls are denied. No home, SSH agent, credentials,
host socket or cgroup filesystem is exposed. Stdin/stdout carry MCP; stderr must
be consumed by the bounded transport drain. Cancellation, Drop and an absolute
session deadline kill the complete cgroup, including detached grandchildren.
Missing kernel facilities fail closed, never fall back to a direct process.

**macOS is not complete:** `macos::profile` provides a deny-default Seatbelt
component and a native direct-syscall test, but production `NativeRunner` refuses
macOS until resource enforcement and lifecycle supervision are implemented and
verified. Profile unit tests on Linux do not certify macOS kernel enforcement.
See [ADR 0004](docs/adr/0004-native-process-containment.md).

Run real Linux attack, lifecycle and release packet measurements in a fresh user
scope (systemd is a test delegation helper, not a production dependency):

```bash
systemd-run --user --scope -p Delegate=yes bash scripts/test-native-linux.sh
```

The test creates an existing **synthetic** SSH key outside the mounted workspace.
A malicious MCP peer attempts direct `os.open`, `cat` and symlink reads, persistent
writes and socket creation; all must fail. Lifecycle tests cover detached children,
explicit termination, Drop and deadline expiry. Missing delegation fails the test.
The release experiment measures 2000 warmed proxy/native-runner ping round trips,
asserting each below 5 ms. Process startup and a production Gate's audit/DLP/policy
costs are excluded; this is a scoped measurement, not a hard real-time guarantee.
On an actual macOS host, the Seatbelt component test is:

```bash
cargo test -p clawbell-sandbox --locked --test macos -- --ignored --nocapture
```

## Transport and DLP integration

- `stdio::run` requires a trusted `Runner`; `stdio::relay` connects existing I/O.
- `http::relay` supports a stateless HTTPS upstream (or an explicit exact loopback
  exception), pinned DNS, no redirects/retries/environment proxies and bounded
  complete JSON/SSE responses. Stateful HTTP, GET/resume and reverse requests in
  SSE remain unsupported and are refused.
- `protocol` validates JSON-RPC/MCP through `rmcp`, lifecycle, correlation,
  initialization order, duplicate keys, depth, supported methods and versions.
  Queues, messages, IDs, deadlines and concurrent requests are bounded.
- Every direction crosses `Gate`, including resources, prompts, notifications,
  sampling and elicitation. The inner adapter must still authorize those methods,
  redact secrets and durably record intent before execution and outcomes after it.
  Baseline storage is not an operation audit log.

For local token restoration use `LocalVaultGate<PolicyGate<AuditGate>>`. The
outer DLP layer redacts before audit, restores only explicitly authorized local
tool arguments, then calls `validate_local_arguments` on the policy layer to
recheck actual arguments against memory rules, policy and pinned schemas. The
inner audit adapter must also implement this validation; its default denies.
Remote transports reject local restoration. Fresh vaults are required per session.
`Scanner` buffers the whole bounded UTF-8 inspection unit, including secrets split
across fragments; `Vault` encrypts registered values and maintains opaque session
markers. See [ADR 0002](docs/adr/0002-in-flight-dlp.md) for limits and migration.

Transport denial, invalid protocol, EOF, timeout and local cancellation close the
session. Runner teardown must terminate descendants; remote cancellation cannot
undo side effects. Unknown outcomes are never automatically retried. Raw payloads,
upstream stderr and secrets must not appear in diagnostics or exported audit data.

## Verification

Use the pinned toolchain in `rust-toolchain.toml`. Tests use synthetic data only;
HTTP fixtures need permission to bind loopback. The explicit Linux test requires
bubblewrap and usable user/mount/network namespaces; unavailable isolation is a
failure, never a successful skip inside the test.

```bash
cargo fetch --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast
cargo build --workspace --release --locked
cargo test -p clawbell-sandbox --locked child_cannot_modify_agent_memory -- --ignored --nocapture
cargo test -p clawbell-proxy --release --locked policy_packet_under_five_ms -- --ignored --nocapture
```

The attack tests deliver a delayed instruction to append to `SOUL.md`, require a
proxy refusal before the inner adapter sees the call, and separately exercise
real child/grandchild writes, aliases, replacements and new protected files in
bubblewrap. Persistent contents must remain unchanged. Other tests cover durable
rug-pull detection across reopened SQLite connections, failure recovery, invalid
schema/storage, protected paths and decision precedence.

The policy experiment warms 200 calls, then measures 2000 packets through policy
and pinned-schema validation, reporting p99 and maximum and requiring every
measured packet below 5 ms. Catalog compilation, initial SQLite persistence,
durable operation audit, DLP, process startup and network I/O are excluded. This
is a reproducible scoped measurement, not a universal 5 ms bound for the complete
proxy or every packet size. Existing DLP and transport experiments remain in their
respective test files. Full production latency requires the completed composition.

The repository ignores runtime databases, `.local/`, `.env` and private-key
material. Fixtures contain synthetic values. Secret scanning can detect known
patterns; it does not prove the absence of every secret or cover remote forks.

Technical contracts: [MCP transport specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports),
[rmcp](https://github.com/modelcontextprotocol/rust-sdk),
[bubblewrap](https://github.com/containers/bubblewrap),
[ADR 0003](docs/adr/0003-policy-baseline-memory.md).
