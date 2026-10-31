# 0014 — Per-operation MCP execution and owner-reviewed publication

Status: accepted by the owner's request to integrate transactions and commits into
production MCP. Extends ADR 0011/0012; existing `proxy`, installed bindings and
remote HTTP sessions retain their previous execution boundary.

## Boundary and migration

`proxy-transaction` is an explicit Linux composition of the production protocol,
policy/schema/catalog pins, DLP, durable audit, native Transaction and handle
committer. It requires the same owner-configured executable, credential-free
workspace, private state and cgroup delegation as `proxy`, plus a private owner
monitor socket and durable journal directory outside all runner mounts. It does
not change client bindings automatically or infer write permission from annotations.
No extra dependency, unsafe adapter, network access or direct-process fallback is
introduced. Skill scan flags are refused in this mode: a separately scanned,
read-only skill package cannot silently acquire publication permission.

The adapter serializes the lane with one outstanding request. A second concurrent
request refuses the session rather than creating an ambiguous writable session.
Initialization and bounded tool-catalog exchanges are recorded privately (at most
66 exchanges and 8 MiB). For every request the supervisor prepares a new private
transaction and starts the unchanged MCP executable. It replays only initialization,
initialized and catalog requests, never any earlier tool invocation. Responses must
match the complete prior JSON values, including all metadata. Dynamic serverInfo,
catalogs, cursors or process-local handles that cannot survive a fresh process are
unsupported and refuse; MCP compliance alone does not imply this compatibility.
The initial discovery/control processes are inspected as read-only too.

Only initialize, initialized, tools/list, tools/call and ping are supported here.
Resources, prompts, reverse requests, unsolicited notifications and other methods
refuse. Cancellation closes the outer session and signals the supervisor; execution
cleanup still kills the whole containment group. No previous tool is automatically
replayed to reconstruct state. Initialization/catalog side effects inside the
call's private process are included in that operation's final-state inspection;
this is not syscall-level provenance. There is no direct server-to-host write lane.

## Invocation, review and publication

The outer production gate authorizes the exact tool/arguments/schema before the
supervisor sees the call, including a separate execution approval when its policy
requires one. An execution grant permits only private execution. Owner-configured
`read` runs with hidden-write detection. Owner-configured `write` permits private
changes but grants no host publication. Opaque and unknown effects refuse.

A durable supervisor intent precedes each spawn. After receiving one correlated,
protocol-validated response, the supervisor applies the same complete structured
DLP inspector as the production gate before publication. It then stops the entire
native group and confirms cleanup before inspection. Failed/error tool results
never publish. Read operations release output only after a clean read-only scan.
Write operations freeze the actual candidate, independently enforce every changed
path as `clawbell.commit`, and create the existing complete redacted review. The
immutable binding includes the random durable audit session identity, correlation,
upstream identity, complete tool-definition digest, canonical argument digest and
exact policy fingerprint. The review adds its nonce, original/candidate trees,
redacted preview and 25-second expiry; approval consumes a one-use capability.

The authenticated owner IPC displays the exact review digest, UTC expiry and
complete escaped before/after preview, effect scope and redacted invocation. The existing monitor requires a connected
same-UID owner, refuses stale IDs and never passes approval credentials to the
model/upstream. Its existing 1800-character approval-display bound is retained:
a larger review refuses rather than displaying a truncated diff. The private
candidate supports the ADR 0012 subset: replacements of existing UTF-8 ordinary
files, without creations/deletions, metadata changes or protected memory paths.
No-op write candidates currently refuse because they have no publishable review.
Add explicit `clawbell.commit` path rules; a tool's ordinary allow never suffices.

Only affirmative owner acceptance of that live review permits the trusted
committer. An immutable policy snapshot and all original identities/content are
checked again. The owner must keep external writers quiescent. Publication retains
ADR 0012's in-place, non-atomic file writes and durable recovery journal: an I/O
failure can leave partial contents, and neither cancellation nor an error claims
rollback. The journal cannot be on tmpfs. An existing journal blocks a new commit,
even after success; the owner must inspect and archive it explicitly. There is no
automatic journal deletion, recovery, rollback or operation replay.

Client disconnect/cancellation invalidates waiting review and prevents subsequent
publication. A filesystem commit already running on its blocking worker is always
joined; losing the client does not discard its actual result or invent rollback.
Its outcome is durably recorded even when no response can be delivered. Process
crash during commit leaves the journal and unfinished audit intent for manual review.

## Audit and compatibility

One supervisor correlation records private intent, inspected candidate, offered
review, owner acceptance, synchronized publication and response readiness. Refusals
record fixed reasons; possible partial publication records `outcome_unknown` and
`commit_recovery_required`. The separate production gate also retains its request
intent, response and termination audit. No paths, raw arguments or file bytes enter
either audit. Schema migration 3 adds a nullable `binding_sha256` BLOB to events
and an append-only migration receipt. Intent records hash the canonical request;
review records carry the exact review digest, also recorded in the publication
journal. Existing rows are not rewritten. JSONL exports include the hex fingerprint;
read-only exports of v2 logs return an empty fingerprint without migrating them.
Fingerprints can reveal equality of guessable content; all storage stays private.

The HTTP initialized notification is independently a transport barrier: the relay
does not dequeue another upstream POST until the full empty 202 is validated.
Wrong status/body, timeout and disconnect stop the lane without sending its next
request. Remote startup intent now always gets a terminal event for baseline,
endpoint/DNS, OAuth and gate construction failures after audit startup. Runtime
transport errors remain unknown, never proof of rollback or operation failure.
Configuration/policy failures before an audit store can be opened cannot be audited.

## Performance and verification

Filesystem snapshot/replay/inspection, human review, process startup and fsync
publication are operation lifecycle costs, outside the bounded warmed <5 ms packet
budget. Ordinary proxy forwarding gains no filesystem traversal. Keep the existing
release gates, and test the new production CLI with real native containment and
owner IPC. Required scenarios include withholding results before approval, rejection,
client disconnect with a late approval, original-file conflicts, journal reuse,
protected hidden writes, symlinks, error results, hidden read writes and catalog
changes between discovery and private execution. Synthetic fixtures only.

Context7 consulted the official [rmcp transport documentation](https://docs.rs/rmcp/latest/rmcp/transport/streamable_http_client/index.html)
for initialization, POST response handling and control timeouts. This adapter keeps
its stricter no-retry/no-recovery contract instead of enabling SDK automatic replay.
