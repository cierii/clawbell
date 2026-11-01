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

## Owner-authorized test budget update (2026-11-01)

The owner explicitly changed the maximum latency criterion from <5 ms to <10 ms.
Apply the strict <10 ms threshold to every measured warmed proxy packet and native
round trip, including policy, DLP, monitor, broker and remote-resource tests and
release-report validation. Exactly 10 ms still fails, matching the existing strict
comparison. Update test names and CI filters together so every gate still runs.
Earlier measurements and their original 5 ms pass/fail outcomes remain historical.
This changes the acceptance budget only: FULL commit acknowledgement, checkpoints,
sample counts, outlier inclusion and isolation requirements remain unchanged.

MCP Context7 supplied official [SQLite WAL documentation](https://www.sqlite.org/wal.html),
[synchronization and journal limits](https://www.sqlite.org/pragma.html) and
[checkpoint semantics](https://www.sqlite.org/c3ref/wal_checkpoint_v2.html).

## Owner-authorized percentile budget (2026-11-01)

Actions run 41256563230 failed on both hosted architectures: the x86-64 gate
maximum was 13,985,821 ns; the AArch64 full CLI RTT maximum was 405,653,223 ns,
with p99 1,955,159 ns. These are failed results under the preceding criterion,
not evidence of a functional containment failure or a specific storage cause.

The owner explicitly approved replacing the maximum-only criterion for tests
including durable audit with nearest-rank **p99 <10 ms and maximum <1 s**.
Equality at either boundary fails. Apply both assertions to the production gate,
remote resource gate, broker gate, full CLI RTT and publication report verifier.
Keep the same measured sample counts and warmup; retain every measured outlier,
including checkpoint and scheduling pauses, in quantiles and the maximum. Tests
without durable I/O retain maximum <10 ms. Rename changed test filters with their
callers so no gate silently stops running.

This is an acceptance-contract change, not a performance optimization or a
hard real-time promise. FULL commit acknowledgement, WAL checkpoints, storage
quotas, mandatory containment and failure-before-execution remain unchanged.
No retry, filtered sample, volatile-storage substitution or durability fallback
is introduced. Historical reports keep their original criteria and outcomes.

Context7 reconfirmed SQLite's [FULL synchronization](https://www.sqlite.org/pragma.html)
and [automatic checkpoints](https://www.sqlite.org/wal.html): FULL WAL commits
synchronize the WAL, and automatic checkpoints may add work to a committing call.

## Owner-authorized 15 ms percentile update (2026-11-01)

Actions run 41324724490 passed checks, dependencies, both installers and native
x86-64. Native AArch64 passed its containment tests but failed the full CLI RTT
budget: nearest-rank p99 12,136,041 ns, maximum 327,243,960 ns. This remains a
failed result under the preceding p99 <10 ms contract; do not relabel it a pass.

The owner explicitly approved **p99 <15 ms with maximum <1 s** for measurements
including durable audit. Apply the new percentile limit consistently to the
production gate, remote resource gate, broker gate, full CLI RTT and publication
report verifier. Exactly 15 ms for p99 or exactly 1 s for maximum still fails.
Tests without durable I/O keep their existing maximum budgets. FULL durability,
checkpointing, isolation, sample counts, warmup and inclusion of every measured
outlier remain unchanged. This updates acceptance criteria only, not runtime
performance or the interpretation of historical reports.

## Owner-authorized 40 ms percentile update (2026-11-01)

The v0.1.2 tagged checks job failed the broker gate with p99 30.213244 ms and
maximum 198.288973 ms. This remains a failure under its original 15 ms contract.
The owner explicitly requested a new **p99 <40 ms with maximum <1 s** criterion
for measurements including durable audit, to permit a new verified release.
Apply it consistently to production/remote-resource/broker gates, the full CLI
RTT and the publication report verifier. Exactly 40 ms or exactly 1 s fails.
Tests without durable I/O retain their current limits. No sample is removed,
no test is retried to cherry-pick a passing run, and no audit acknowledgement,
WAL synchronization, containment, policy or DLP behavior changes. This is an
acceptance-budget change, not a performance improvement or a real-time guarantee.

Boundary regressions accept the earlier 30.213244 ms measurement and 39,999,999 ns,
and reject 40,000,000 ns and 40,000,001 ns for both report packet metrics.
Publish as v0.1.3; never move the earlier v0.1.2 source tag.

## Concurrent initialization follow-up (v0.1.4)

The ARM64 v0.1.3 job failed the concurrent legacy migration test before latency
measurements. Local reproduction identified SQLite DatabaseBusy at the initial
journal-mode/schema batch. SQLite does not guarantee invoking its busy handler
for journal-mode lock upgrades. Serialize initialization with a new private
`operations-init.lock`, using the existing no-follow/single-link/0600 file checks.
Only contention waits, for at most 100 ms; every other failure refuses immediately.
The dedicated writer holds the lease through connection setup/migration and then
releases it. This is not a retry of a tool effect or a relaxation of a test.
Existing maintenance leases, SQLite write transactions, FULL acknowledgement, WAL
budgets and all packet-path limits remain intact. Unsafe/held lock regressions
verify refusal before any database creation or modification of a link target.
New binaries cooperate through this file; stop older sessions before upgrading,
as older binaries do not participate in the initialization lease.

Context7 reconfirmed SQLite's [busy-handler limitations](https://www.sqlite.org/c3ref/busy_handler.html).
