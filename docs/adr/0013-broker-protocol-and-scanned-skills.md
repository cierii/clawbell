# 0013 — Pinned HTTP egress, catalog pages and scan-bound skill execution

Status: Linux implementation; macOS and Windows execution remain unsupported and
fail closed. AArch64 enforcement code is unchanged; native CI coverage is added.
This decision implements existing security boundaries without a permissive mode.

## Network and OAuth boundary

`proxy::network::Endpoint` owns one exact owner-configured URL. Scheme, hostname,
port and path cannot be supplied by MCP data. DNS is resolved once with a deadline
and at most 32 addresses; every address must pass checks. Each connection uses
those addresses while retaining TLS hostname/certificate validation. The actual
response peer must belong to the pinned socket set. No ambient proxies, cookies,
automatic retries or redirects are enabled. Every redirect, including 307/308,
refuses rather than replaying a potentially effectful POST. Changing a destination
requires an independent owner endpoint grant. HTTP is restricted to an explicitly
excepted loopback IP; credentials always require HTTPS. Metadata, link-local,
unspecified, multicast and IPv4-mapped IPv6 addresses refuse even with exceptions.
IPv6 transition/documentation and IPv4 special-use ranges are conservative denies
without an exact permitted private exception. No whole-loopback exception exists.

The adapter is a host API for already-inspected, durably audited requests, not a
raw unauthenticated forward proxy. The sandbox retains its disconnected network
and denied socket syscalls. No environment proxy variable or credential is
injected into a sandbox, and no generic sandbox network exception is added.

OAuth uses oauth2 5.0 with default HTTP backends disabled, S256 PKCE, a five-minute
one-use flow, timing-resistant state equality, a pre-registered public client,
resource indicators and separately owner-selected HTTPS authorization/token URLs.
Token exchange uses the same pinned broker. Token responses must be bearer tokens
with an explicit lifetime no greater than 24 hours. Credentials stay in host
memory, bind to the exact resource endpoint and expire monotonically. No refresh
or operation replay is automatic. The remote DLP vault registers the access token
before any result can be disclosed, including token echoes without field labels.
The remote vault cannot restore markers. SecretString and Zeroizing reduce copies;
HTTP/OAuth dependencies still own transient request/header/response buffers.

`proxy-http --oauth-login` explicitly starts login and prints only the owner login
URL to stderr, including public client ID, state and PKCE challenge. The owner
opens it. A bounded, five-minute loopback callback checks method, path, Host,
parameter uniqueness and state. Credentials/codes are never CLI arguments, files
or stdout. The provider must support RFC 8252 loopback ephemeral callback ports.
This first implementation requires explicit trusted endpoint/client configuration:
no protected-resource discovery, dynamic registration, token persistence, refresh,
confidential-client secrets or automatic reauthorization after 401 is provided.
A failed/expired login closes the session. The local callback can be denied service
by a local connection; it never accepts a callback without state and PKCE binding.

## Streamable HTTP

`Target::streamable` supports JSON POST results, accepted notifications, bounded
POST SSE and optional MCP session IDs. Session IDs are graphic ASCII, capped at
256 bytes, learned only on initialize and attached only to that exact endpoint.
A changed ID refuses. SSE stops at a complete correlated response event without
waiting for connection EOF. Complete inspection units remain buffered before gate
publication. Wrong IDs, reverse requests, unknown content types and truncated SSE
refuse. The legacy `Target::connect` API retains its stateless restriction.

No GET stream, SSE resumption, Last-Event-ID replay, session DELETE or automatic
reconnect is implemented. Remote server-initiated interactive capabilities remain
denied. The adapter cannot revoke remote side effects or claim that disconnect
terminates a remote process. Upstream servers requiring these optional features
are not supported. Automatic JSON client installation remains local stdio only;
remote sessions are explicitly started with `proxy-http`.

## Catalogs, resources and prompts

Tool enumeration supports up to 4096 tools, 64 pages and 8 MiB total (individual
messages retain transport bounds). A cursor is an opaque session string of at most
1024 bytes. Only the exact preceding nextCursor may continue enumeration. Empty
nonterminal pages, repeated cursors, overlapping requests and duplicate names
across pages refuse. Starting a new enumeration invalidates execution immediately.
Tool calls cannot run until all pages, offline schemas and the aggregate pin pass.

Each exposed partial page has an independent owner-reviewed pin, and the complete
catalog retains its existing aggregate pin. Scoped identities hash the tuple of
server, method and page number in a reserved namespace; cursors are not persistent
identities. First use of a paginated catalog may need successive review/reconnect
cycles: approve each page and finally the aggregate through the existing owner
pin workflow. This avoids leaking unapproved metadata while discovering pages.
Changing page partition/order can require review even if the aggregate is equal.
Non-paginated pins and their digest domain remain compatible. Larger catalog and
policy bounds do not grant any additional tool permissions.

Owner `[[protocol]]` rules separately authorize resources/list,
resources/templates/list, resources/read, prompts/list and prompts/get. Read/get
require an exact URI/name target. No wildcard or URI-template permission exists;
deny overrides allow. require_approval remains refused for these new operations
(the interactive monitor currently authorizes tools only). Subscriptions, list
change notifications, sampling and elicitation continue to refuse.

Resource/prompt list metadata is fully pinned before publication using scoped
identities. These catalogs currently refuse nextCursor rather than silently
truncating. Prompt calls require a pinned prompt definition, required string
arguments and no undeclared arguments. Resource responses must carry the exact
requested URI; SDK result schemas and existing complete text-only DLP apply.
Binary/mixed content and secret-bearing pinned metadata refuse.

## Scan-bound skills

Linux `ScannedSkill` freezes the credential-free package in private tmpfs before
any untrusted execution. Existing descriptor-pinned traversal rejects links,
hardlinks, special nodes, privileged metadata and races; budgets cap tree bytes,
entries, depth and inspection time. Each file and the exact expected initialization
instructions receive the bounded UTF-8 static inspection. Every literal argument,
including inline interpreter code, is also scanned and reported by index. Binary
packages refuse.
Findings remain review evidence, never authorization or proof of safety.

The v2 scan digest binds domain, sorted paths, node kinds, permissions and bytes,
exact interpreter/argument vector, instructions and exact policy fingerprint.
`skill-scan` prints only digest and indexed findings. A later `proxy` invocation
repeats the full snapshot/scan and requires the owner-reviewed digest; code,
command, instructions or even a same-version policy edit invalidate it. A new
session always requires native containment and durable launch audit as before.
The digest is reusable content evidence, not a one-use operation approval.

Execution additionally requires explicit [skills] allow_execution=true and
allow_shell=true in the immutable owner policy. Both default to false. An opaque
SkillPermission captures them with the exact fingerprint; scanner output cannot
manufacture this permission. Arbitrary interpreter code can exec a shell, so the
runner conservatively requires shell permission for every such invocation rather
than claiming static analysis proves that no shell will run.

The runner exposes only the frozen snapshot read-only, never the mutable source
package or credentials. Read-only mounts, seccomp, network disconnection, whole-
group memory/pids/CPU/lifetime controls and bounded stdio remain mandatory.
SkillGate checks initialize.instructions before and after inner inspection; absence,
drift or DLP changes refuse before forwarding. The exact expected field must be
present, including when the expected text is empty. Host system interpreters and
libraries remain trusted runtime dependencies; they are not package-hashed. No implicit shell authorization, writes, host publication or downloaded skills
are introduced. Libraries must compose the instruction gate, policy, audit and stdio
supervisor; the CLI supplies that composition.

## Platform delivery and migration

Linux x86-64 is verified locally; the same mandatory native suite is scheduled on
GitHub ubuntu-24.04-arm in addition to x86-64. Tests include memory/task exhaustion,
descendant termination, read-only snapshot execution after source replacement,
changed scan bindings and real CLI instruction drift. Missing facilities fail.
CI configuration alone is not evidence that the AArch64 run passed.

macOS Seatbelt profile generation is still insufficient for the required aggregate
resources, pinned workspace and process lifecycle. Windows has no production
AppContainer/restricted-token/Job Object adapter in this change. Neither platform
is advertised as implemented or allowed to execute without isolation. Native
implementation and adversarial verification on both platforms remain unfinished.

Existing owner configurations remain default-deny; new protocol grants and remote
launches are explicit opt-ins. No owner files or pins are silently migrated. New
scope pins are reviewed separately. No schema/data migrations or AGENTS.md edits
are required. Audit, DLP and durable-before-execution behavior are retained.

## Verification sources and performance contract

Context7 supplied the official rmcp StreamableHttpClient/session/SSE contracts,
reqwest DNS/redirect/no_proxy APIs and oauth2 PKCE/custom HTTP documentation.
Pinned dependency source confirmed the exact types used here:

- [rmcp Streamable HTTP client](https://docs.rs/rmcp/3.8.0/rmcp/transport/streamable_http_client/index.html)
- [reqwest 0.12.28](https://docs.rs/reqwest/0.12.28/reqwest/struct.ClientBuilder.html)
- [oauth2 5.0](https://docs.rs/oauth2/5.0.0/oauth2/)
- [GitHub runner architectures](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

The packet path does not rescan skill files, resolve DNS or configure cgroups.
Release checks require every measured warmed packet/RTT below 5 ms, including
policy/DLP/durable audit and the new resource path. Network/issuer latency, startup,
scan/catalog compilation, owner review and arbitrary scheduler/storage contention
are excluded; no universal hard real-time guarantee is asserted.
