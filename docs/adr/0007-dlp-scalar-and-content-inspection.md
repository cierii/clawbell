# 0007 — Fail-closed scalar and result content inspection

## Context

Audit findings A-01 and A-02 demonstrated that the session DLP boundary skipped
non-string JSON scalars and treated inline Base64 blobs as ordinary strings.
Denying `resources/read` does not prevent an allowed tool from returning an
embedded resource. This decision tightens the existing inspection boundary;
it grants no new resource, prompt, network or restoration permission.

## Decision

Inspect numbers, booleans and null using their serialized JSON representation.
Object values also include their field name as credential-assignment context,
just as string values already do. A detected secret in a non-string scalar
refuses the complete message instead of changing its type or meaning. This
applies recursively to both directions, before calling the inner gate. Numeric
inspection uses serde_json's parsed representation, not equivalence across every
possible arithmetic/encoded representation of a secret.

Before redaction, server results allow only `text` content blocks and inline
`resource` blocks containing UTF-8 `text`. Inline text resource MIME types are
absent (implicit text), `text/plain` or `text/markdown`, matched exactly. Resource
fields are limited to `uri`, `text`, `mimeType`, `_meta`; block fields are limited
to their type/payload plus `annotations` and `_meta`. Metadata still undergoes
recursive DLP inspection. Unknown fields/types, resource links, images, audio,
blobs and all other resource MIME types refuse the entire message. A blob is
unsupported even if it declares `text/plain` or also contains a `text` field.

Validate tool `result.content`, resource-read `result.contents`, and prompt
`result.messages[].content`. Library callers must still authorize those methods;
the production CLI continues to deny resources and prompts. Arbitrary structured
JSON is recursively inspected as JSON, with no general Base64/encryption scanner
or promise to detect arbitrary encoded secrets. No decoder, dependency, I/O or
background job is added. Existing size/depth/vault limits remain in force.

## Migration and verification

No configuration or storage migration is required. Previously forwarded binary
results now terminate/refuse inspection; upstreams needing binary output must
return inspectable text or wait for a separately designed bounded inspector.
Do not label binary data as text to bypass this contract.

Regression tests reproduce both audit attacks using the production composition;
both fail against the previous implementation. Boundary tests verify no inner
gate call on refusal, scalar nesting and both directions, misleading MIME and
mixed text/blob blocks, unsupported variants, and successful redaction of allowed
text resources. The production latency benchmark also includes public scalar
values and an inline text resource while retaining the per-packet 5 ms limit.
