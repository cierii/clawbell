# Release security and actionable host errors

- Distribute the MIT license and private vulnerability reporting policy.
- Gate release publication on a current RustSec scan; scan daily for new advisories.
- Include a CycloneDX JSON SBOM, publish checksums and create GitHub provenance/SBOM
  attestations for the binary and archive from the tagged build job.
- Replace generic CLI failure output with payload-free host and validation codes;
  preserve typed isolation failures through proxy startup. Missing facilities still
  refuse installation before backups, receipts or upstream execution.
- Runner library consumers must migrate from the unit LaunchError to typed variants.
  See [README](../README.md) and [SECURITY.md](../SECURITY.md) for verification and limits.

# Owner deadlines and database maintenance

- Split proxy request, idle and absolute session limits; defaults are 30/600/3600 s.
  The production runner uses the same configured absolute lifetime.
- New identities and changed catalogs require explicit `pins review` / `accept`;
  hash-only diffs and `history` preserve previous pins and migration receipts.
- Add `audit status`, bounded JSONL `view` / private `export` and lossless offline
  `rotate --accept`. Warn at 80%/95% capacity and reserve 32 pages for outcomes.
- Stop sessions before pin acceptance or rotation. Existing pins remain enforced;
  databases are not reset. See [ADR 0010](adr/0010-timeouts-pins-and-audit-maintenance.md).

# Security fixes — audit A-03–A-07

- Inspect semantic text fragments and deny incomplete known-secret prefixes before
  forwarding; preserve redaction regardless of JSON field discovery order.
- Persist terminal pre-gate failures, fixed denial reasons, session IDs and private
  upstream digests. Additive migration preserves legacy events and records version 2.
- Refuse secret-bearing catalogs before pinning, keeping presentation markers out
  of baselines; clean catalogs reconnect normally.
- Exercise native isolation before client binding without executing upstream code;
  refuse missing prerequisites without changing configs, backups or receipts.
- See [ADR 0008](adr/0008-fragments-audit-and-binding-preflight.md) for conservative
  prefix refusals, migration, guarantees and remaining limits.

# clawbell 0.1.0 — Linux MVP

- Reversible `init` / `unbind` for supported local JSON MCP clients, exclusive
  private backups, integrity receipts and atomic replacement.
- Offline `scan` for hidden Unicode, standard/URL-safe nested Base64 carriers,
  credential/memory/instruction indicators and suspicious network references.
- Executable `proxy` composition with strict policy, pinned schemas/catalogs,
  DLP, dedicated durable append-only audit and Linux native containment.
- Five synthetic attack scenarios, real CLI/native execution tests, storage and
  installer recovery tests, explicit warmed packet/RTT latency release gates.
- CI checks, checksum-verified secret scanning, checksummed Linux x86-64 artifacts
  and publication after both ordinary and native release gates pass.

Requires an unprivileged namespace-capable Linux host, recent bubblewrap, seccomp,
and persistent delegated cgroups v2. No direct-process fallback. macOS/Windows
execution, HTTP binding, network/write exceptions, web UI and interactive approval
in the MVP launcher remain unsupported and fail closed. Static scanning/TOFU do
not establish trust or guarantee detection of all attacks. See README for precise
limits, deployment prerequisites, backup recovery and performance measurement scope.
