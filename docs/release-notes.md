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
