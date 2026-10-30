# Handoff — 2026-10-30

## Objective and result

Implement declarative policy evaluation, persistent MCP rug-pull pins and agent
memory protection; block a delayed SOUL.md injection, check repository secrets,
commit and push. Delivered library components integrated with the existing Gate
boundary. The CLI remains a scaffold; no permissive gate or incomplete Runner is
exposed as a deployable firewall.

## Changes

- core/policy.rs: strict bounded TOML, owner-defined tool effects and JSON Pointer
  file selectors, component-bounded path prefixes, precompiled bounded argument
  regexes; default deny, deny > approval > allow and static reason codes.
  Unknown/opaque effects are denied. Immutable session snapshot via Arc.
- core/signatures.rs: domain-separated SHA-256 of canonical tool metadata,
  individual tool signatures and a name-sorted complete catalog digest. Detects
  descriptions, schemas, names, other metadata and additions/removals.
- audit/baseline.rs: bounded dedicated SQLite writer thread, FULL synchronous
  transactions, 0700 storage directory / 0600 file, no raw tool metadata, TOFU
  once and no overwrite on mismatch. Owner must protect directory ancestors.
- proxy/policy.rs: mandatory decorator over an existing trusted Gate. Full catalog
  required before calls; offline pinned JSON Schema validation with bounded Rust
  regex engine. Notifications close sessions immediately. Approval remains blocked.
  Checked calls/catalogs cannot be changed by inner adapters; resolved DLP arguments
  pass through the same policy/schema checks. Non-tool authorization and durable
  operation audit remain the inner Gate's obligations.
- sandbox/memory.rs: an open directory handle pins a read-only bubblewrap workspace.
  All persistent mounts are read-only; scratch is private volatile storage. The
  profile isolates namespaces, drops capabilities, clears env and disables nested
  user namespaces. A fixed exec shim replaces the directory stdin with /dev/null;
  arguments are positional, never interpolated into shell code.
- policies/default.toml, English README and ADR 0003 document exact behavior,
  integration and limits. AGENTS.md remains unchanged at 199 lines. .gitignore
  also covers SQLite rollback journals and sidecars.
- New dependencies implement requested functions: toml for declarative parsing,
  RustCrypto sha2 for standard hashing, rusqlite/bundled SQLite for local durable
  pins and jsonschema (network/file retrieval features disabled) for pinned schema
  validation. Cargo.lock records the intentional dependency additions.

## Verification

Passed fmt, clippy --workspace --all-targets --locked with -D warnings, full
workspace tests and release build. Full workspace: 26 ordinary tests and one
rustdoc, four explicit tests/experiments ignored by default. HTTP fixtures require
loopback permission outside this environment's sandbox; rerunning the full suite
with that permission passed. The earlier restricted run failed only TCP binds.

Explicit bubblewrap test passed on this Linux host. Delayed injection cannot
append to SOUL.md; it also checks new CLAUDE.md/AGENTS.md/.cursorrules and skill
files, symlinks/hardlinks, unlink/rename and a grandchild write. The workspace is
renamed after opening the handle to verify that its identity stays pinned. The
file remains unchanged. The test fails if required host isolation is unavailable.
A separate proxy test rejects delayed append before the inner adapter sees it.
Rug-pull tests reopen SQLite and verify changes, notification closure, unchanged
pins after refusal, additions/removals, schema changes and separate server identity.

Explicit release policy/schema experiment: 200 warmups, 2000 measured packets;
p99 1.834 microseconds, maximum 10.691 microseconds, every measured packet <5 ms.
This excludes catalog compilation and first pin, operation audit fsync, DLP,
process startup and network I/O. It does NOT establish a hard bound for the full
production proxy, arbitrary schemas, packet sizes or scheduling conditions.

Gitleaks 8.30.1 scanned all fetched Git refs (four existing commits) with no leaks
found. The final 38-file candidate snapshot was scanned separately with no leaks found. No actual
credentials were added; test strings are synthetic. Secret scanning cannot prove
absence of all possible secrets or inspect remote forks.

## Remaining integration boundaries

MemoryGuard prepares a filesystem profile; it does not start a process and is
not a complete Runner. The composition root must still supply seccomp, cgroups v2,
resource limits and process-tree supervision. Its setup handle occupies stdin;
a future MCP Runner needs a separate inherited fd. Adding writable host mounts
invalidates this conservative memory guarantee and needs a reviewed design.

Use LocalVaultGate<PolicyGate<AuditGate>> for local restoration, a fresh instance
per session/upstream, an owner-bound server identity, and a trusted private
baseline directory outside sandbox mounts. An approval UI/redemption flow is not
implemented, so require_approval always blocks execution. TOFU cannot attest to
initial safety or server code changes with unchanged metadata. Remote processes
and skills launched outside a controlled Runner remain outside filesystem
containment. No UI/serve CLI checks were claimed: those components do not exist.

Toolchain/cache for this environment: RUSTUP_HOME=/tmp/clawbell-rustup,
CARGO_HOME=/tmp/clawbell-cargo, /tmp/clawbell-cargo/bin/cargo. A complete Linux
Runner and durable operation audit composition remain prerequisites for a
production launch; do not bypass the mandatory adapter boundary.
