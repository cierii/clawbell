# 0016 — Sandbox broker capabilities, complete catalogs and stateful HTTP/OAuth

Status: implements owner-authorized extensions of the existing trust boundaries.
Supersedes the unsupported-feature lists in ADR 0001 and ADR 0013. No change to
AGENTS.md, default deny, mandatory containment or durable-before-execution audit.

## Sandbox network capability

The owner policy may grant up to 32 uniquely named exact HTTP endpoints, each
binding URL, GET/POST and an optional exact private IP exception. Deny creates no
endpoint; unsupported require_approval refuses rather than implying permission.
Broker preparation resolves/pins every allowed endpoint before untrusted launch.

Ordinary local MCP and scan-bound skill runners can inherit one connected Unix
stream at descriptor 3. In this profile workspace/seccomp/staging descriptors shift
to 4/5/6; all arbitrary inherited descriptors retain CLOEXEC. The bwrap supervisor
and PID 1 close their channel copies; the unprivileged executable inherits only
the explicitly duplicated capability. The existing socket/socketpair seccomp deny,
disconnected namespace and resource budgets are unchanged. No listener, credential,
host socket pathname, home mount or ambient proxy is exposed.

The sequential bounded JSONL protocol selects a capability name and UTF-8 body.
No client URL/header/method/proxy parameter is accepted. GET bodies must be empty;
POST content type is fixed text/plain. Responses accept bounded complete UTF-8
text/plain/application/json bodies and expose only status/redacted body. Unknown
formats refuse. A durable intent precedes each dispatch; responses/refusals use
fixed audit codes. Cancellation leaves uncertain intents unknown, never replayed.
The launch session ID links these operations to the actor and policy fingerprint.

MCP and broker share one encrypted in-memory session vault. Locks are released
before human approval/network I/O; knowledge is checked again before forwarding.
An unlabelled secret learned on either channel cannot bypass the other inspector.
No active broker request has an unbounded frame, body, write or execution deadline.
An unused capability does not create an artificial 30-second MCP idle timeout.
Broker failure terminates the associated process group. This capability is
process-wide, including descendants; it is not per-tool authorization.
Doctor's ordinary-profile evidence cannot attest the additional fd profile.
Transaction publication mode stays without a broker.

## Content catalog completeness

Resources, resource templates and prompts have independent enumeration state.
Each catalog permits at most 64 pages, 4096 unique keys and 8 MiB, retaining the
transport's message bound. Requests can continue only the exact preceding opaque
nextCursor, at most 1024 bytes. Repeated cursors, duplicate entries, overlapping
enumerations, empty nonterminal pages and invalid cursor types refuse.

Every page passes SDK models, DLP immutability and a reviewed scoped pin before
publication. Existing nonpaginated scope 0 remains compatible. Paginated pages use
0–63 and a separate aggregate scope 64. A new prompt enumeration immediately
invalidates old executable definitions; only the completed pinned aggregate
publishes new definitions to prompts/get. Listing errors discard incomplete state.
Resources/read retains its independent exact-URI policy; listing never grants it.

## Streamable HTTP lifecycle

GET starts only after the complete initialized 202 barrier. Notifications pass the
same session correlation, policy and complete-message DLP gate as POST responses.
A 405 disables the optional GET stream. Unknown capabilities and interactive
reverse requests remain denied. HTTP headers and body reads have explicit deadlines;
a long GET stream is bounded by idle and absolute session deadlines rather than
a client-wide total POST timeout.

Incremental SSE framing retains at most one bounded pending buffer, emits complete
events and tracks graphic-ASCII IDs of at most 1024 bytes. Duplicate IDs refuse;
partial bytes never cross the gate or become a resume cursor. Up to three GET
resumptions are permitted per stream. A POST stream can resume through GET with its
last complete event ID and original response ID, never by repeating POST. Streams
keep separate cursors, scoped to the exact endpoint/session. Events without IDs
disable resumability until a new ID arrives. Server-provided retry delays cannot
produce unbounded loops or replay requests. Missing/expired sessions fail closed.

After workers stop, shutdown attempts one DELETE with the exact session/version
headers. Empty 200/204 and unsupported 405 are accepted. Cleanup never asserts
remote rollback, and 404 never creates a new session. The durable launch intent
covers lifecycle traffic; MCP calls keep their own operation intents/results.

## OAuth trust and persistence

Explicit owner issuer configuration authorizes discovery only on the resource and
issuer origins. RFC 9728 metadata must identify the exact resource and selected
issuer; RFC 8414 metadata must identify that issuer, code responses and S256.
Discovered authorization/token/registration endpoints must be HTTPS on the same
issuer origin. No WWW-Authenticate value grants network authority. Explicit
pre-registered endpoint configuration still supports independently trusted HTTPS
authorization/token endpoints. Each endpoint retains the existing pinned network
adapter, peer verification and redirect/retry refusal.

Dynamic public-client registration is an explicit login-only owner action, with
its own durable intent. It requests authorization_code/refresh_token, loopback
redirect and token_endpoint_auth_method=none. Callback drift, client secrets or
management credentials refuse. PKCE, one-use timing-resistant state and bounded
callback validation remain mandatory. Providers needing confidential clients,
registration management or off-origin discovery endpoints are unsupported.

TokenSession serializes refresh before expiry. A poisoned flag is set before
dispatch and survives cancellation: no uncertain grant is retried in that process.
New access and refresh tokens enter the host DLP registry before use/publication;
old rotated tokens remain registered for that session. Runtime expiry uses Instant.
A 401 never replays MCP or starts authorization automatically. Refresh intents,
bounded replies, rotation and persistence failure are audited without token values.

Persistence is opt-in, host-only, using 0700 state and atomically replaced/synchronized
0600 files with no links or unsafe parents. The records contain credentials in
plaintext protected by filesystem permissions; encrypted disk/backups are the
owner's responsibility, and administrator/owner-account compromise is outside
the threat model. Secrets use SecretString/Zeroizing where practical; HTTP/JSON
libraries can own transient buffers. No claim of zero secret copies is made.

The file name binds owner server/resource/OAuth settings/scopes; its content binding
also covers discovered endpoint URLs. Metadata/configuration drift refuses cache
reuse. A session-long exclusive crash lease prevents parallel refresh consumers.
Before refresh, persistence durably replaces the old record with an empty tombstone.
After a successful response, the rotated record is synchronized before MCP dispatch.
Crashes leave either a usable rotated record or a tombstone requiring explicit login;
stale leases require owner review/removal after all matching sessions have stopped.
No silent fallback to old credentials or nondurable operation is provided.

## Client migration

Init can reversibly wrap mixed local stdio and credential-free remote HTTPS maps.
Remote preflight validates pinned egress without sending MCP traffic. Remote options
are strictly url/type and optional clawbellOAuth public issuer/client_id/scopes.
Headers, embedded credentials, URL query/fragment and unrelated remote options
refuse the whole transform. Existing backup/receipt/hash semantics remain intact.

OAuth bindings use persistence and public settings without starting a login.
The owner runs the generated command in a terminal with --oauth-login once (and
--oauth-register for a client without client_id), then starts the client normally.
The identical generated identity/flags locate its private host cache. Existing
bindings are not silently rewritten: unbind, archive the reviewed backup and rebind.
A private-IP endpoint still requires explicit proxy-http configuration; init never
opens loopback/private ranges. Skill receipts change when the owner policy changes.

## Validation and performance

Tests cover exact cursors/pins for all three catalogs, stale definitions, duplicate
metadata, refusals without network effects, split secret responses, shared-vault
knowledge, GET resume/DELETE, no POST replay, token rotation, storage failure,
private files/leases and actual Linux descriptor/seccomp containment. Release
checks include the new broker packet budget with real DLP/durable SQLite audit
and loopback, alongside existing complete production and native gate measurements.
Every measured warmed packet/RTT must stay below 5 ms. DNS, startup, large messages,
human waits, issuer/network latency and arbitrary scheduler/storage stalls are
outside that measurement; no universal real-time guarantee is claimed.

Context7 supplied official rmcp GET/session/resumption, oauth2 refresh/custom client
and reqwest DNS/redirect/proxy/timeout contracts. Pinned dependency sources confirmed
the exact APIs. Bubblewrap 0.12.0 source confirms inherited descriptors reach the
executable while supervisor/PID-1 copies are closed:

- https://docs.rs/rmcp/3.8.0/rmcp/transport/streamable_http_client/index.html
- https://docs.rs/oauth2/5.0.0/oauth2/
- https://docs.rs/reqwest/0.12.28/reqwest/struct.ClientBuilder.html
- https://github.com/containers/bubblewrap/blob/v0.12.0/bubblewrap.c
