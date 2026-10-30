# 0012 — Owner-approved handle committer and explicit recovery

Status: accepted by the owner's safe-write implementation request. Extends ADR
0011 with an opt-in Linux library publisher; persistent MCP sessions and the CLI
remain read-only. No old tool annotation, policy allow or transport approval
implicitly grants publication permission.

## Trust boundary and migration

`Transaction::inspect_for_commit` first kills the complete native containment
group and confirms cleanup, then freezes a bounded candidate in supervisor memory.
No live upstream, staging pathname, writable mount or caller-provided patch can
enter the committer. The upstream still never receives host write access.
`inspect` remains available and still discards candidates without publishing.

This first publisher supports content replacement of existing, singly linked
UTF-8 regular files. Creation, deletion, node-type, permissions, owner/group and
SELinux-label changes refuse. Changes to timestamps arising from content writes
are expected; metadata-only staged changes are never applied. Arbitrary filesystem
transactions, binary patches, network writes and automatic rollback are outside
this boundary. The baseline captures source device/inode, content, mode,
owner/group, timestamps and supported attributes before making the private copy.
The independent staging baseline retains its own identities for hidden-write
inspection. Source and staging identities are never confused.

Each actual changed path is independently evaluated against an immutable owner
policy as `clawbell.commit` with `{"path":"relative/name"}`. The owner must add
this explicit write tool, its `/path` selector and suitable path-scoped rules;
see `policies/commit-example.toml`. Existing policies refuse the unknown tool.
The protected-memory guard, including case-insensitive SOUL.md and skill directory
components, is independently enforced and cannot be overridden by approval.
The trusted composition root supplies the original session, upstream, complete
pinned tool-definition digest (including tool name, schema and metadata, as
produced by core `signatures::tool_digests`) and canonical argument digest. The
Binding field named `schema` carries that complete definition, not a schema-only
hash. It must authenticate the owner, apply
existing operation/schema checks and durably audit execution before spawning.
This library does not expose an unauthenticated approval HTTP/IPC endpoint or
wire arbitrary model calls into a writable persistent session.

## Review and cryptographic consent

`Candidate::review` discovers secrets across all changed filenames and complete
old/new text units using the session Vault before producing a replacement preview.
It then redacts every unit and JSON-quotes paths and old/new content to escape
control characters. The preview includes every complete changed file; it is not
a truncated summary or an inferred description. Unsupported UTF-8 and exhausted
DLP/preview budgets refuse. Render `Review::preview()` as untrusted text, never raw
HTML; terminal applications must preserve the escaping. Raw candidates have no
Debug/serialization interface; their file-content buffers are zeroized when their
nodes are dropped.
Temporary verification buffers are zeroized too; this does not promise to erase
all kernel, filesystem, allocator, swap or pre-existing upstream copies.

The owner adapter displays both the redacted preview and `Review::digest()` plus
`expires()`. Only after authenticating an affirmative decision for that displayed
digest does it call `approve(digest)`. RustCrypto SHA-256 binds a domain-separated,
length-framed manifest containing the complete source/candidate trees, redacted
preview, OS-random per-review nonce, exact policy-source fingerprint, original
session/upstream/tool-definition/argument digests and UTC expiry. A same-version policy
edit invalidates consent. TTL is greater than zero and at most five minutes;
a monotonic deadline prevents a backwards wall-clock adjustment extending it.

The approval is a private, non-cloneable, non-deserializable in-process capability,
not a transferable signature or a user-supplied hash that grants permission.
Review and approval are consumed together. Repeated issuance for the same Review
cannot execute twice because publication consumes that Review; a fresh Review has
a new nonce. Context, policy, digest and expiry are checked again at execution,
and each affected file is checked against policy again. Approval cannot override
deny. Raw preview data never enters diagnostics or the publication journal.

## Narrow publication and concurrency contract

Publication runs synchronously on a dedicated blocking worker, outside Tokio's
packet-processing tasks. It has no detached timeout/retry worker: cancellation
must not report that an already-running filesystem write was undone. Integrators
must retain the worker result or consult its journal after loss of the caller.

Before durable intent, the complete original tree is rescanned and compared to
the exact baseline. Every changed file is then opened through component-by-component
no-follow directory handles. O_PATH pins the final entry before file-type checks;
only an approved ordinary inode is reopened for writable I/O through its descriptor.
No device/FIFO is opened for I/O before validation. Content, device/inode, link
count, metadata and attributes are verified on those handles, without truncation.
All target handles are acquired before the first target write.

Immediately before each write, the current pathname is independently reopened
without following symlinks and both its identity/state and the retained writable
handle are rechecked. Data is written only to the retained inode, then truncated
to the approved length and fsynced. No string-based rename or path-based write
can redirect an approved write to a substituted symlink target. A detected host
edit invalidates consent rather than silently replacing owner changes.

Unlike the proposed rename publisher in ADR 0011, this implementation deliberately
uses in-place writes to verified handles. Linux does not provide an atomic
compare-baseline-and-rename primitive. Handle writes prevent path redirection but
are **not atomic even for one file**: readers can see partial contents. An I/O
failure can leave a partially written file. Independent host writers must be
quiesced from snapshot/review through commit when a coherent transaction is
required. Metadata comparisons are checks, not a lock against a malicious process
with the owner's credentials. We do not claim a kernel-enforced CAS against
non-cooperating same-account writers or resistance to an administrator.

## Durable journal and recovery

The owner provides a pinned, owner-owned 0700 journal directory outside the
workspace on persistent storage. Tmpfs refuses. It must have trusted ancestors,
be inaccessible to the upstream and be reused for this workspace's publication
lane. `publication.journal` is exclusively created at 0600. An existing journal
blocks another commit, including after restart and even after successful completion.
The owner must review and archive it explicitly before reopening the lane. The
committer never erases, truncates, automatically rolls back or replays a journal.

Version 1 consists of fixed 65-byte frames: one kind byte, 32 bytes of payload
(zero-padded), then SHA-256 of those first 33 bytes. This checksum detects torn or
corrupt frames; it is not an administrator-proof audit authenticator. The order is:

- `I`: approval/correlation digest; `T`: little-endian UTC nanoseconds as u128;
  `P`: exact policy fingerprint; `S`: session digest; `N`: u64 planned file count.
- For each sorted changed path, `R`, `B`, `A`: SHA-256 of relative path bytes,
  baseline content and approved content respectively. No names or raw bytes persist.
- For each file index, `W` before writing and `F` after file fsync, carrying u64 index.
- `C`: approval digest after every planned file has synchronized successfully.

Every frame is fsynced. The complete intent/manifest and directory entry are
synchronized before target writes. Failure establishing intent returns
`commit_journal_unavailable` and starts no target writes, though a conservative
incomplete journal may remain. Any failure after intent returns
`commit_recovery_required`. Expiry/conflict between files also leaves recovery
required; earlier successful writes are never described as rolled back.

`recovery(&File)` checks the entire bounded sequence, count, checksums, file indices
and final digest. Only a complete sequence reports Complete. Empty, truncated,
corrupt, intent-only and partial journals report Required. A file fsync followed
by a lost completion record remains unknown. Keep the journal private and inspect
actual files against the path/content fingerprints and trusted owner records.
The owner decides which data to retain or restore and archives that decision with
the journal. This API supplies explicit detection and evidence, not an automatic
recovery executor. Hashes can expose equality of guessable data; the journal is
private and never sent to the model or a remote service.

## Verification and performance

Unit tests cover exact context/policy/expiry binding, foreign-review capabilities,
redaction and terminal escaping, unsupported mutations, SOUL.md with explicit allow,
changed content/inode/modes, symlinks/hardlinks/parents, private journal collisions,
partial multi-file and interrupted-file failures, and every truncation of a complete
journal. A real native test exercises safe publication, a staged SOUL.md attack,
a symlink attack and a host edit after review through the actual Transaction API.

No file traversal or hashing was added to ordinary proxy packet handling. The
existing release gates measure warmed bounded proxy packets against 5 ms; complete
file snapshots, human review, fsync and multi-file commits have separate costs
and no 5 ms or hard real-time guarantee. No UI was added; the trusted owner adapter
must display the returned preview before issuing a capability.

## Sources

MCP Context7: official [rustix descriptor-relative APIs](https://github.com/bytecodealliance/rustix/blob/main/src/fs/openat2.rs)
and [RustCrypto sha2 incremental hashing](https://docs.rs/sha2/latest/sha2/).
The implementation reuses existing descriptor helpers/libc and already-locked
sha2, getrandom, serde_json and zeroize packages; no new package versions or custom
cryptographic primitive is introduced. The only added unsafe adapter call is
geteuid, with no pointer arguments, used to check journal-directory ownership.
