# 0003 — Policy, catalog pins and read-only agent memory

Status: implementation of the existing constitution; no relaxation of trust boundaries.

## Decision

Keep deterministic owner policy in core and side effects in adapters. Strict TOML
maps exact tool names to trusted effect/path selectors. Deny takes precedence over
approval and allow. Arbitrary shell/opaque effects are refused. Approval decisions
remain non-executable until a separately implemented, bound, one-use approval
workflow exists. Parser failure cannot mutate an installed immutable snapshot.

A per-session PolicyGate requires a complete catalog, validates offline schemas,
and asks a bounded dedicated SQLite writer to compare a canonical SHA-256 catalog
pin and individual tool signatures under an owner-configured server identity. First observation is TOFU; a change
never re-baselines automatically. Pinning the whole catalog also detects additions
and removals. Hashing all metadata covers descriptions, schemas, names and future
annotations. No raw metadata is persisted. A change notification closes the
session immediately, rather than permitting calls during an asynchronous refresh.

The memory rule denies configured write paths to reserved agent memory components.
It does not establish the filesystem effects of a malicious remote server. Local
child protection requires filesystem enforcement, not a post-write watcher. The
MemoryGuard filesystem component pins the workspace by directory handle and mounts
it entirely read-only using bubblewrap; only private volatile scratch is writable.
This also covers hardlinks, symlink aliases, deletion, replacement, new paths and
process descendants without filesystem traversal in the packet path.

## Integration and migration

No previously permitted default becomes executable. Existing transport APIs retain
their mandatory Gate and Runner dependencies. Add PolicyGate around a trusted audit
adapter, and local DLP outside PolicyGate so restored arguments are checked again.
The gate rejects mutation of checked calls/catalogs by inner adapters. Independent
method authorization, request/result DLP and durable operation audit remain required.
The baseline database is not a replacement for append-only operation audit.

Baseline storage requires a trusted 0700 directory and 0600 database. Never mount
it into the workspace or permit a child to replace its ancestors. Deployment must
bind a stable owner identity to each server and review the first catalog. Existing
users have no baseline to migrate; first observation creates it. Legitimate server
upgrades require explicit owner review and a separately designed baseline migration;
there is no reset API in this change. Database errors and mismatches fail closed.

MemoryGuard prepares, but does not spawn, an isolated command. It is not a complete
Runner: seccomp, cgroups limits and process-tree cleanup remain the composition
root's obligations. The stdin directory handle is replaced with /dev/null using a
constant exec shim with positional arguments; untrusted data never becomes shell
source. MCP stdin transport needs a separate inherited setup fd in its future
Runner. There is no unisolated production launcher. This conservative profile
allows no persistent child writes; adding writable mounts requires a reviewed
security design, not just exceptions for known filenames.

## Limits and validation

TOFU does not certify safety, and unchanged metadata cannot attest to unchanged
server code. Remote processes and uncontrolled child launches are not isolated.
Tool effect bindings are trusted owner configuration, not inferred from annotations.
JSON Pointers describe single file paths, not arbitrary command semantics. Absolute
paths and parent traversal are refused; lexical checks do not prove symlink safety.
The read-only child profile supplies that separate filesystem boundary.

Tests cover delayed SOUL.md injection, process descendants, aliases, replacements,
new protected paths, changed metadata across sessions, notifications, deny/approval
precedence and fail-closed schema/storage errors. The warm policy/schema experiment
checks measured packets below 5 ms; catalog compilation and durable initial pins
are control-plane operations outside that measurement. No hard real-time guarantee
is made for scheduler stalls, audit fsync, arbitrary schemas or network latency.
