# 0017 — Per-architecture releases and explicit owner host provisioning

Status: implements existing Linux enforcement boundaries. macOS and Windows
production containment is not established by this decision.

## Decision and trust boundary

Publish native Linux x86-64 and AArch64 artifacts separately. Both architectures
must pass the actual enforcement suite and clean-host installer gate. Generate
each SBOM from that native binary's locked default-feature graph. Artifact names,
checksums and verification bundles include architecture to prevent overwrite when
merging Actions artifacts. A matching version tag alone is insufficient to publish:
all prerequisite jobs, provenance and CycloneDX attestations must verify first.
Verify one archive per CLI invocation; shell glob expansion is not multiple-archive
verification. Never move a published tag or silently bypass unavailable attestation.

The source installer is an explicit owner administrative operation. Sudo installs
signed system packages, a pinned unprivileged-built bubblewrap, a narrowly attached
AppArmor namespace profile when missing, and owner lingering. It does not infer
administrative authority from skills, MCP content, a tool result or client JSON.
Runner children remain non-root with the existing mandatory isolation. No packet
path or audit durability semantics change.

Owner data, runtime state, toolchain and binary remain outside sandbox mounts.
Workspace selection is explicit; installation never searches the home directory
for code or credentials. Missing enforcement refuses binding. A persistent user
unit has a supervisor subgroup and prepares cpu/memory/pids controllers during
every start, including restart/boot. A one-time transient scope is not presented
as a persistent delegation.

## Migration and failure behavior

Previously installed bindings, backups, policy, state and older bootstrap units
remain untouched when their settings conflict. Stop sessions, unbind, archive
reviewed conflicting files, install the versioned binary/service and rebind.
Per-file client transactions and durable backup receipts keep ADR 0006 semantics.
Host package/service provisioning is not atomic and is not automatically rolled
back when later binding fails. Removal and lingering/shared-package caveats are
documented in [installation](../installation.md).

Evaluation uses fixed synthetic inputs through production composition and reports
every false alarm. Durable audit cost is measured directly on the dedicated writer
with FULL acknowledgement, separately for intent and response. It is never inferred
by subtracting unrelated percentile distributions. Every report binds source bytes,
binary SHA-256, architecture, kernel, toolchain and metric sample counts. Release
packaging rejects a different source/binary or an incomplete/over-budget report.
No release-time performance exception disables fsync, isolation or DLP.

## Platform limit

A Docker CLI invocation or Seatbelt profile alone does not establish production
containment. A macOS/Windows adapter additionally needs trusted local VM/image
identity, an empty child environment, safe workspace exposure, disconnected network,
whole-tree resource ceilings and cleanup on timeout, cancellation, owner process
death and daemon disconnect. Windows also needs a port of existing Unix-only
private files/IPC/audit ownership checks. Native adversarial tests must execute on
each target, including detached descendants, VM failure and resource exhaustion.
These mechanisms are not introduced without target-host verification; unsupported
platforms continue to refuse in NativeRunner. This release does not claim that the
requested macOS/Windows production adapters or native tests are complete.

## Sources

MCP Context7 consulted official [GitHub Actions attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations),
[systemd delegation](https://github.com/systemd/systemd/blob/main/docs/CGROUP_DELEGATION.md)
and [Docker resource/lifecycle options](https://github.com/docker/docs/blob/main/data/cli/engine/docker_run.yaml).
The documented Docker controls are necessary inputs to a future adapter, not
evidence that a portable production runner already exists.
