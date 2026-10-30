# 0008 — Semantic DLP units, session audit and binding preflight

## Context

Audit findings A-03–A-07 exposed independent gaps in the existing boundary:
per-field inspection missed ordered text fragments, transport failures could
precede auditing, denial reasons/session identity were lost, session markers
contaminated catalog pins, and binding did not exercise host isolation.
This decision tightens those boundaries and grants no new execution permissions.

## DLP units and catalog pins

Treat `result.content` text and inline-resource text as one ordered display unit.
Resource-read documents and role-bearing prompt messages are individually inspected
units. Arbitrary structured JSON properties, arguments, metadata and schemas are
not mechanically concatenated. Existing recursive scalar/credential inspection
continues in both directions. Discover individual credentials before inspecting
units, then redact again from the original message: a later JSON field cannot
cause an earlier occurrence of the same value to escape.

A complete secret crossing text fields refuses the entire message before the
inner gate. A trailing nonempty proper prefix of a known secret also refuses,
including a one-character prefix, so a later response cannot complete a released
prefix. Matching handles overlapping occurrences in linear time per known value;
unit bytes and vault capacity retain their existing limits. Whole occurrences
contained in a field continue to receive session-stable opaque markers. Refusal
avoids rewriting block boundaries, roles or argument semantics.

This deliberately favors confidentiality over availability. Innocent text ending
in a known prefix can refuse. Guarantees concern ordered literal UTF-8 text,
values already known at inspection time, and detectable credential patterns.
They do not cover a secret first learned after earlier responses were released,
arbitrary extraction/reordering across unrelated fields, normalization, encryption
or general encodings. Separate sessions never share vault values or suffix state.
No unbounded buffer, delayed response, network request or background task is added.

Refuse any catalog response requiring DLP redaction **before** PolicyGate can
persist its first pin. Clean catalogs keep their existing deterministic signatures;
random presentation markers and raw secrets never become baseline inputs. Existing
pins are neither deleted nor automatically migrated. Previously poisoned pins still
require a separately reviewed owner migration; this change supplies no reset or
silent re-baselining capability. Owners must remove secret-bearing metadata at the
upstream before establishing a new legitimate baseline.

## Audit boundary and additive migration

`Gate::terminated` receives only a fixed `Reason`, including errors from framing,
JSON parsing, lifecycle checks, limits, deadlines and transport/runner failures.
The transport stops its tasks before terminal auditing and calls `finish` even
when that audit fails, closing vaults and leaving pending effects unknown. The
production outer gate persists terminal events independently of `inspect` and
preserves fixed DLP, schema, catalog, method and policy denial reasons. Audit
failures remain failures; no fallback allows further forwarding.

Each production launch opens a distinct session. SQLite generates a 128-bit random
identifier for correlation, not authentication. An append-only `sessions_v1` row
binds it to the policy digest and SHA-256 of the owner-configured upstream identity,
workspace, executable and literal arguments. Every new event carries that session,
the same upstream digest and a fixed reason; operation responses refer to intent
row IDs within that session. Cross-session and nonexistent correlations refuse.
Neither upstream-provided identity nor raw names, paths, IDs or payloads are logged.

At open, an immediate transaction adds `session_id`, `upstream_sha256` and `reason`
to `events_v1`, creates the session table and appends migration version 2 to
`operation_migrations_v1`. Historical events retain their values and are explicitly
labelled `legacy` / `legacy_unspecified`, never attributed retroactively. Migration
and session records receive append-only triggers. Existing synchronous FULL,
private file modes, dedicated bounded writer and page quota remain mandatory.
Incomplete intents still mean unknown and are never replayed. The compatibility
`OperationStore::open` API uses a zero digest for an unspecified upstream; the
production launcher uses `open_session` with its actual owner-derived digest.

## Installer preflight

Before changing **any** selected client configuration, validate all server entries
and run the actual native containment profile with a fixed trusted `/usr/bin/true`.
Validate the configured executable without executing it. The probe exercises
bubblewrap flags, namespaces, seccomp, descriptor setup, cgroup controllers and
resource limits, and requires successful exit and cleanup. It creates only a
temporary containment group/process; it does not execute upstream arguments,
discover tools, write workspace/client files or provision host delegation.

Report only configuration/server indices with `preflight_passed` or
`preflight_denied`. Any failure leaves live configs, backups and receipts untouched.
An already managed binding must also match the supplied settings; otherwise refuse
rather than attest to different settings. Existing binding/restore recovery remains
unchanged. Launch repeats isolation checks: successful preflight is a point-in-time
readiness check, never authorization or a promise that future host state is stable.

## Verification

Regressions cover split blocks and response prefixes, Unicode and overlapping
values, field-order discovery, refusal before the inner gate, clean catalog
reconnects and absence of secret-bearing pins, malformed/protocol/limit/timeout
terminal audit, fixed denial reasons, concurrent sessions and legacy migration,
storage failures, fake cgroups without config mutation, and real native preflight
without upstream execution. Release measurements include parse/encode, policy,
schema, DLP with a learned secret, synchronous durable audit and native CLI RTT.
Their per-packet budget remains 5 ms on the measured warmed workloads; arbitrary
message sizes, startup, storage contention and scheduler pauses are not a hard
real-time guarantee.

Implementation references were checked through MCP Context7 against the official
[rusqlite transaction API](https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html#method.transaction_with_behavior)
and [Tokio child lifecycle API](https://docs.rs/tokio/latest/tokio/process/struct.Child.html).
