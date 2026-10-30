# 0006 — Reversible client binding and conservative audited Linux MVP

Status: implementation of existing constitution boundaries; no permissive bypass.
Session audit metadata, terminal failures and binding preflight are tightened by
[ADR 0008](0008-fragments-audit-and-binding-preflight.md).

## Decision

Compose the existing NativeRunner, stdio transport, PolicyGate, LocalVaultGate and
baseline writer in the CLI. Supply a mandatory dedicated OperationStore writer.
The launcher permits only explicit stdio control/tool methods. Resources, prompts,
reverse capabilities, HTTP, writable mounts, network exceptions, secret restoration
and interactive approvals are not implicitly granted. Unsupported methods deny.
The existing optional monitor client/library remains independently usable.

Each launch is durably recorded before NativeRunner preparation. A fresh session
has its own pending request map (bounded by transport limits), immutable policy,
DLP vault and gate state. Schema/baseline/memory checks precede inner intent writes;
DLP also rejects outgoing raw secrets before the transport can forward. An outer
gate records refusal codes from all inspection layers. Audit stores fixed codes,
policy SHA-256, UTC and generated correlation IDs, never packet contents. Response
rows refer to intent row IDs. Intents with no response are unknown, including crash
recovery; startup never fabricates outcomes or repeats an operation. Session launch
termination is conservatively unknown, not proof of successful tool execution.
Audit acknowledgements use SQLite synchronous=FULL on a dedicated bounded thread.
Database page quota stops new writes. Automatic retention is deliberately absent;
a future audited rotation/migration contract is needed before raising quotas.

Baseline identity hashes owner server identity, absolute workspace, executable and
literal arguments. Installer server identities also namespace the client path.
No upstream self-reported identity grants trust. Initial pins remain TOFU.

## Installer boundary and recovery

Discovery reads a fixed list of known client configuration locations or explicit
owner paths. It does not execute commands or search arbitrary home content. Strict
bounded JSON refuses duplicate keys, unsupported transports/options and ambiguous
maps. Existing commands must be absolute /usr/bin entries. Only complete workspace
path arguments translate to /workspace; there is no shell parser. The original
configuration remains in an exclusive 0600 .bak, which can contain credentials
from unrelated settings and must never be committed/shared. The bound configuration
and a hash-only receipt are 0600 too. All ancestors must be trusted; file reads use
O_NOFOLLOW/nonblocking opens, verify regular files and reject hardlinks. Directory
writers other than the trusted owner are refused; a sticky system temporary parent
is allowed. Same-UID owner compromise remains outside the threat model. This
installer does not claim an openat-based capability boundary against that owner.

The backup and receipt are each fsynced with parent directory durability before
same-directory exclusive-temp-file rename. Current bytes are compared again before
replacement. Unbind requires matching backup and bound hashes, then atomically
restores original bytes and removes only the receipt. A crash before replacement
can be cleaned by unbind when live bytes already equal the original. A crash after
backup but before receipt leaves an untouched live configuration and an original
backup: inspect/archive that backup manually; init never overwrites it. A crash
leaving a temporary file requires owner inspection/cleanup of that private file.
Concurrent/later edits refuse automatic restoration. Each client file is its own
transaction; multi-file failure preserves completed bindings rather than attempting
an unsafe global rollback. Reinstall after restoration requires explicit backup
archival/removal; configuration flags never silently reconfigure an existing bind.

## Scanner boundary

The skill inspector is a pure bounded offline analyzer. It flags Unicode format
controls, Base64 carriers and decoded indicators, network/credential references
and common instruction overrides without returning source or decoded payloads.
The CLI package walker refuses unsupported/binary entries and budget exhaustion.
Findings are review evidence, not authorization. Scanning never launches a skill,
fetches URLs, unpacks archives, claims complete injection detection or changes
execution permissions. Known encoding/heuristic limits are in README.

## Verification and migration

Existing library APIs retain mandatory Gate/Runner contracts. Strict duplicate-key
JSON parsing moves to core so both transport and installer share it. Existing pins
and policy formats are unchanged; the new CLI uses separately namespaced identities.
Existing library launchers are not silently rebound. No constitution changes.

Attack tests use only synthetic data and the production composition. Real Linux
CLI tests exercise the native runner, read-only mounts, durable audit, policy and
DLP, including a 2,000 warmed read-call RTT budget. A separate 4,000-packet experiment
includes gate parse/encode and durable audit. No durability/containment fallback
is permitted for latency. CI gates tagged release publication on normal and native
checks, with fixed action revisions and checksum-verified secret-scanner binaries.
