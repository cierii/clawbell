# 0010 — Independent deadlines and owner database maintenance

## Independent deadlines

The owner CLI configures three separate durations, in seconds:

- `--request-timeout-secs` defaults to 30 (range 1–300). It bounds outstanding
  requests, inspection, individual writes, queue delivery, startup and cleanup.
  Unrelated traffic never renews an outstanding request's absolute deadline.
- `--idle-timeout-secs` defaults to 600 (range 1–86400). It bounds silence between
  complete inspected messages when no request is outstanding. Partial frames do
  not renew it. An outstanding request uses its own deadline instead.
- `--session-lifetime-secs` defaults to 3600 (range 1–86400). It is absolute and
  activity cannot renew it. The production native runner receives this same value
  for its whole-process-tree watchdog; it no longer independently expires at 300 s.

A timeout closes/audits the session and tears down the runner; it does not undo
remote effects or replay a request. The library's `Limits.timeout` was renamed
`request_timeout`; callers must also select `idle_timeout` and `session_lifetime`
or use the defaults. Both stdio and the HTTP library use the common deadline loop.
Existing generated client bindings inherit the new defaults; no client-file rewrite
is needed. NativeRunner's standalone resource defaults remain unchanged; the
production composition explicitly overrides its lifetime with the owner value.

## First launch and baseline updates

Previously first observation silently established a pin. New owner identities now
stage a candidate and close the session **before forwarding the catalog or allowing
tool calls**. Changed accepted catalogs follow the same path. The existing DLP and
offline schema checks precede staging; secret-bearing catalogs never create pins
or review proposals. Identity still binds owner server, workspace and literal argv.

The owner stops proxy sessions, runs `pins --state-dir ... review`, reviews upstream
source/package changes and compares the proposed SHA-256 catalog/tool signatures,
then runs `pins --state-dir ... accept --review-id N --accept`. Reconnect is required.
The diff is deliberately **hash based**, not a textual schema/description diff:
raw untrusted names, descriptions and schemas are not retained or printed. A changed
tool is shown as a removed and added signature; description-only changes also alter
catalog/tool digests. A hash is an identity check, never evidence of safety. Inspect
the upstream source independently; the proxy cannot attest to unchanged server code.

An immediate SQLite transaction accepts only the latest proposal for that identity
and the exact previous active digest. Replays, superseded IDs and storage errors
refuse. Acceptance changes active pins, preserving the database, immutable proposal
and previous/proposed tool sets, UTC timestamps and append-only acceptance ledger.
`pins ... history` exposes the latest 256 proposals and their acceptance timestamps.
Proposals are capped at 10,000 and the database at 16,384 pages; saturation denies
new proposals rather than discarding history. No MCP instruction can call this
owner-only CLI control plane. Approvals for individual tool effects are unchanged.

Migration is additive: existing accepted v1 pins remain enforced, never silently
reset or weakened. New review/history tables start empty; historical acceptance
cannot be fabricated. Existing pins are grandfathered as legacy owner state. The
next mismatch needs the new explicit workflow. There is no database reset command.

## Audit inspection, warnings and offline rotation

`audit --state-dir ... status` reports page count, size, quota and warning level.
`view` streams ordered JSONL; `export --output /absolute/new.jsonl` writes an exclusive
0600 file and syncs it and its parent. Both use exclusive `--after` row-ID cursors
and bounded `--limit` (1–100000), without creating a session or replaying events.
Only already payload-free event columns are exposed, JSON-escaped. Legacy events
retain their legacy identity/reason. The operator must migrate a pre-v2 audit by
opening it normally before these schema-specific readers can export it.

A dedicated writer reports fixed stderr warnings at 80% and 95% of its 16,384-page
quota and at its last 32 pages. New intents refuse in that reserve; result/unknown
records can still use remaining pages, subject to actual disk/quota availability.
Status also warns visibly. Warnings never include request data or untrusted names,
and stdio stdout remains exclusively MCP. No silent retention or durability fallback
is introduced. Capacity checks run on the existing writer thread.

Every operation writer holds a shared owner-private `operations.lock` file lock for
its entire lifetime. Baseline acceptance and audit rotation take its exclusive,
nonblocking lock. This forces production sessions to stop before either operation,
invalidating their in-memory catalogs and effect approvals through normal teardown.
The locks coordinate clawbell processes; they do not resist a malicious owner or
administrator. All participating processes must use this version: stop older
binaries before maintenance, as older versions do not acquire this lock.

`audit ... rotate --accept` additionally obtains an exclusive SQLite transaction (rollback-journal DELETE mode only),
copies the complete stable database to a fresh private `operations-<random>.sqlite3`
archive, computes SHA-256, fsyncs the archive and directory, and only then performs
transactional retention of active events/sessions. Append-only triggers are restored
inside that same transaction, and an immutable rotation receipt records the archive,
digest and UTC time. Migration and earlier rotation ledgers remain in the active
file. VACUUM reclaims freed pages after commit. Archives retain append-only triggers,
all correlation/session records and unresolved intents; they are never replayed.
Correlation IDs in an archive belong to that database generation, not future events.

A copy/transaction failure retains the original events. A crash before commit can
leave an extra full or partial archive; an archive without an active rotation receipt
is not evidence that retention committed. A crash after commit but before VACUUM
leaves valid retained history and an intact archive; retry rotation can reclaim
space, but makes another archive. Never remove the sole archive of retained events.
Archive retention is an explicit owner filesystem responsibility; archives consume
disk space beyond the active database quota. There is no automatic archive deletion.
This is a lossless offline rotation, not a promise of administrator-proof audit.

## Verification contract

Use Tokio's paused clock to verify successful reads after 31 idle seconds and at
301 session seconds, traffic near absolute expiration, independent request deadlines
and idle/lifetime refusal. Public CLI tests cover required explicit acceptance,
replay, history, private bounded exports, overwrite refusal and active-writer refusal.
SQLite tests cover warning thresholds/reserve, preserved archives, unknown effects
and append-only triggers. Release performance tests include durable audit and the
production/native path with the existing 5 ms per-packet budget on warmed workloads.
No scheduler/fsync hard-real-time guarantee is possible on arbitrary host load.

Implementation references were checked through MCP Context7: official
[Tokio time](https://docs.rs/tokio/latest/tokio/time/index.html) and
[rusqlite transactions](https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html#method.transaction_with_behavior).
