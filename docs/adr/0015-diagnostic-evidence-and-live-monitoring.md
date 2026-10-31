# 0015 — Retained diagnostic evidence and complete owner monitoring

Status: implemented, extending the existing owner-local diagnostic/IPC boundary.

## Evidence

`doctor --self-test` and `demo` retain an exclusive, synchronized, owner-private
JSON report, named by its SHA-256. Reports never expire or disappear automatically.
The owner selects `--report-dir` or uses the ignored `.local/clawbell/doctor` lane.
Failed probes retain a failed report; an unavailable host profile is explicitly
marked unavailable. Failure reports cannot authorize or attest to execution.

The profile binds the running binary's exact bytes/version, host boot/kernel and
architecture, bubblewrap bytes, native read-only namespace/mount/environment mode,
whole-tree budgets and the exact delegated cgroup path/device/inode/controllers.
The compiled binary binds the seccomp and descriptor/isolation implementation.
Before/after profiles must match for a successful self-test. This is a synthetic
point-in-time test suite, not exhaustive testing of each resource limit, a package
inventory, proof of arbitrary server behavior or resistance to a malicious owner.

Ordinary `proxy --doctor-report PATH` verifies private bounded strict JSON,
content-addressed filename, successful result and current profile before opening
the session or launching an upstream. It adds a durable `containment_evidence`
record with the report SHA-256 in the existing nullable binding column. Every
operation is linked by the existing random `session_id`, avoiding repeated hashing,
report reads or new fsyncs per packet. No schema migration or wire modification is
needed. Existing exports preserve the link; retain the report alongside the audit.
The report never replaces preflight, policy, one-use consent, DLP or durable intent.

Migration is opt-in. Changed binaries, boots, delegation identity or budgets need a
new test. Self-test lifetime defaults to 3600 seconds and can match a custom proxy
lifetime. Ordinary evidence refuses in skill/transaction modes; remote processes
remain outside local containment. Reports are unsigned owner-controlled evidence;
same-owner tampering is outside the boundary. Runtime packages/workspace contents
are not continuously measured. Store reports outside runner mounts.

## Monitoring and protocol approvals

New installer bindings include stable per-config/per-server monitor paths derived
from both identities. Paths are bounded before configuration mutation. Existing
receipts are never rewritten silently: stop clients, restore with `unbind`, archive
the retained backup and bind again. Concurrent instances of one binding refuse a
socket collision rather than sharing an owner decision channel.

`proxy-http` attaches the same policy monitor and serves its private IPC endpoint
concurrently with the relay. Service failure closes the relay and finalizes pending
audit outcomes as unknown; it never claims to undo a remote effect. The HTTP CLI
passes independent request (1–300 s), idle and absolute lifetime (1–86400 s)
durations to existing validated transport/egress limits. Defaults are unchanged.

Resource/prompt policy returns an approval requirement only after target, cursor,
prompt schema and bounded correlation checks. The exact immutable request waits
on the existing session-local one-use sender, with a 25-second deadline, redacted
preview, method, full parameters, parameter digest and effect scope. Deny retains
precedence. No connected owner, cancellation, stale reply, rejection or timeout
forwards a request. The ordinary transport request/lifetime deadlines can be shorter
than human consent. Catalog changes still close the session. Existing policy pins
and DLP checks precede execution. Lists may also require explicit owner consent.

A service owns only the Unix socket inode it created. Normal shutdown/cancellation
removes that inode after checking type/device/inode; existing sockets are never
adopted or removed. Crash leftovers need explicit owner review/cleanup. Monitor
telemetry remains bounded/lossy and cannot create permission.

## Live audit

`audit ... view --follow` reads bounded pages (1–1000, default 100) after an exclusive
row cursor, flushing each page and polling every 250 ms. Reads run in the existing
blocking control-plane worker, outside Tokio packet handling; SQLite connections
and read transactions close before potentially slow output. Failures terminate
rather than skipping history. The follower's shared operations lease permits
writers but refuses exclusive rotation and baseline acceptance until it exits.
This prevents a rotation-generation gap or silently skipping reset IDs. Existing
`view`/`export` bounds and JSONL fields remain compatible. Ctrl+C stops following;
there is no replay, retention change, new network listener or raw payload log.

Implementation references queried through MCP Context7: official Tokio blocking
workers/timers, rusqlite read-only connections and rmcp resource/prompt models.
