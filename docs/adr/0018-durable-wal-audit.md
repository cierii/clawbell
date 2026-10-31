# 0018 — FULL-synchronous WAL for the operation audit

## Problem and decision

The hosted release gate observed a 5.888 ms packet, exceeding the unchanged
strict 5 ms maximum. The operation writer used DELETE rollback journaling,
creating, synchronizing and removing a journal for every event. Local temporary
directories can be tmpfs; a fast tmpfs measurement does not certify disk latency.

Use SQLite WAL with `synchronous=FULL`. Every event remains a separate committed
transaction on the dedicated bounded writer; the caller receives acknowledgement
only after commit succeeds. No batching, deferred acknowledgement, NORMAL/OFF
synchronization, retries, filtered outliers or relaxed performance assertions are
introduced. Intent admission and insertion use one IMMEDIATE transaction, including
session admission, to serialize checks across concurrent writers.

Automatic passive checkpoints run at 256 WAL pages. `journal_size_limit=1048576`
bounds recycled storage, but cannot bound a WAL pinned by a long-lived reader.
Therefore session/new-intent admission refuses at 8 MiB of WAL; terminal events
have reserve until 16 MiB, where every event refuses. One bounded admitted
transaction can cross a threshold. The existing main-database page quota remains
independent. Stop sessions/readers and reconnect after resolving storage pressure;
never delete WAL/SHM files manually or retry tool effects automatically.

## Trust boundary and migration

The database, `-wal`, `-shm` and legacy `-journal` sidecars stay in the same private
0700 state directory outside sandbox mounts. Existing sidecars must be regular,
single-link 0600 files. SQLite creates missing sidecars and owns recovery and
cleanup; clawbell never truncates a potentially live journal itself. Results still
contain fixed codes/digests, not request data or secrets. WAL requires local
filesystem shared-memory/locking support; unsupported storage refuses. It does
not establish power-loss durability for volatile filesystems or faulty hardware.

Opening an existing database switches its journal mode through SQLite without
rewriting historical events or inventing outcomes. FULL and WAL configuration
are checked before making the writer available. Unfinished intents remain unknown.

Offline rotation still acquires the exclusive owner maintenance lease. In WAL
mode it requires a successful TRUNCATE checkpoint and a SQLite-managed transition
to DELETE before taking the exclusive archive/retention transaction. Only then
does the existing main-file archive include all committed events. A busy checkpoint
or mode transition refuses before archive creation/retention. Active writers and
followers still block rotation; archives, hashes, append-only triggers and explicit
owner acceptance keep ADR 0010 semantics. Stop all older binaries before migration
or downgrade; never mix legacy DELETE writers with running WAL writers.

## Verification and limits

Tests assert FULL/WAL/checkpoint settings and private sidecars; refuse symlinks,
hardlinks and permissive files without modifying their target; kill a child after
an acknowledged intent and an uncommitted flushed transaction, then verify
integrity, intent preservation and absence of replay. A pinned reader exercises
both admission thresholds, terminal reserve and no append on refusal. Rotation
tests preserve unknown outcomes, archives and failure-before-retention behavior.

Run the existing gate on a persistent filesystem via an explicit private TMPDIR,
separately from other I/O-heavy tests. Keep every measured packet and all checkpoint
costs in the strict maximum. Shared-host scheduling and storage pauses can still
exceed a release budget; a failed measurement must remain a failed release.

MCP Context7 supplied official [SQLite WAL documentation](https://www.sqlite.org/wal.html),
[synchronization and journal limits](https://www.sqlite.org/pragma.html) and
[checkpoint semantics](https://www.sqlite.org/c3ref/wal_checkpoint_v2.html).
