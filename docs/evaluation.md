# Release evaluation — Linux x86-64, 2026-10-31

The [machine-readable report](evaluation/linux-x86_64-2026-10-31.json) records the
actual production composition and native runner on Fedora 44, kernel
7.2.8-200.fc44.x86_64, btrfs and Rust 1.99.1. Measurements completed at
2026-10-31T16:17:21 UTC. This local source-tree evaluation is separate from GitHub
Actions, a tagged release, AArch64 certification and macOS/Windows native tests.

The report records the pre-commit base revision and a SHA-256 fingerprint of
relevant source bytes, including reviewed unstaged changes. Its binary SHA-256 is
`5d0fef6885187a3e7d0f622f8688250b78a21cd29a540b2a701bece4d7937560`.
It does not claim that the base commit alone contains these changes. Tagged CI
regenerates a report from the exact tagged checkout on each Linux architecture;
packaging rejects a different commit, source fingerprint, binary or architecture.
Local documentation results are not substituted for that tagged evidence.

These are historical measurements before [ADR 0018](adr/0018-durable-wal-audit.md).
The current operation writer uses FULL-synchronous WAL. Also, the historical
report's filesystem field describes its output directory; temporary audit fixtures
may reside on a different filesystem, including tmpfs. Those values must not be
interpreted as persistent-disk audit certification. New timing evidence must
identify the actual audit-fixture filesystem and retain every measured outlier.

When `scripts/evaluate.py` fails, it reports the fixed measurement index and
exit/timeout/spawn status. Recognized packet metrics may also report a bounded
integer `max_ns`; raw child output, arguments and unknown fields stay in the local
ignored log. A failed measurement never produces a publication report. These
failure diagnostics do not retry a test, discard outliers or relax the 5 ms gate.

## Permitted workflow completion and DLP false alarms

The real MCP fixture completed **2,200/2,200 allowed read calls (100%)**, with the
production CLI, monitor publication, concurrent live audit reader, durable audit,
pinned schemas, DLP and native containment active. These are repeated reads of one
public fixture path, not 2,200 different real-world agent tasks. All 20 measured
new-process initialize/catalog workflows also completed with already accepted pins.

A separate labeled benign-text corpus exercised **20 independent permitted
read-tool workflows** through the production policy/schema/DLP/pin/audit stack.
Each session first learned the same synthetic credential through its server DLP
boundary. Eleven workflows returned unchanged public text: **11/20 (55%)**.
The other **9/20 (45%)** produced false alarms: **7 DLP refusals and 2 unnecessary
redactions**. Non-DLP errors abort evaluation rather than being counted as alarms.

The full corpus is fixed in `release_evaluation_corpus_and_durable_audit` in
`crates/clawbell/src/attack_tests.rs`. It includes ordinary prose, Unicode, public
URLs, benign words ending in a known-secret prefix and documentation-only
credential examples. This deliberately stresses conservative prefix/pattern
handling. The denominator includes every case, including refusals and changed
public examples. The measured 45% is a result for this small stress corpus; it is
not a field false-alarm estimate. No production rule was relaxed to improve it.
Representative task datasets and confidence intervals require a separate study.

## Packet overhead and process-cold startup

All percentiles below use nearest rank on sorted raw nanosecond samples, with
conversion to milliseconds only for presentation. No percentile is obtained by
subtracting other percentiles.

- **Production gate, 4,000 warmed packets:** p50 0.261 ms, p95 **0.309 ms**,
  p99 **0.336 ms**, maximum **1.416 ms**. Includes encode/parse, policy/schema,
  session DLP, monitor publication and FULL durable audit acknowledgement.
  Request and response packets are timed separately after 200 warmup round trips.
- **Full native CLI round trip, 2,000 warmed reads:** p50 0.528 ms,
  p95 **0.594 ms**, p99 **0.644 ms**, maximum **1.626 ms**. Includes transport,
  fixture execution and both packet directions, after 200 warmup reads.
- **Process-cold start, 20 sessions:** p50 56.417 ms, p95 **60.732 ms**,
  p99/maximum **64.037 ms**, measured from CLI process creation through successful
  MCP initialize/catalog. OS caches are warm and pins already approved. Compilation,
  dependency downloads, first-owner approval and an OS page-cache flush are excluded.
  With only 20 starts, nearest-rank p99 is simply the maximum; it is not a stable
  population tail estimate.

Every measured warmed gate packet and native RTT passed the strict **<5 ms**
release assertion. Startup and transactional snapshot/approval/publication are
separate lifecycle costs. The budget does not cover human waits, issuer/network
latency, maximum-size messages, arbitrary host contention or scheduler pauses.
These observations are not a universal hard real-time guarantee. No packet-path
production code or durability/containment requirement was weakened for this work.

## Independently measured durable audit cost

The experiment calls the actual `OperationStore::record` API, waits for the
dedicated writer's durable acknowledgement, then times the correlated response
event independently. It discards 200 warmup intent/response pairs and measures
2,000 of each. SQLite retains DELETE journaling and `synchronous=FULL` on the same
filesystem. Timing includes queue handoff, validation, transaction/SQLite and
fsync acknowledgement; it does not claim to isolate the kernel fsync syscall.

- **Intent event:** p50 0.118 ms, p95 **0.133 ms**, p99 **0.192 ms**,
  maximum **0.625 ms**.
- **Response event:** p50 0.119 ms, p95 **0.135 ms**, p99 **0.196 ms**,
  maximum **0.431 ms**.

These costs are timed directly. They are not estimated by subtracting an
audit-disabled proxy from the full gate; there is no audit-disabled production
benchmark or release fallback. Disk/device caches and btrfs implementation affect
the measurements. Different storage must be measured independently.

## Reproduction and publication checks

On an idle, namespace-capable Linux host with the pinned Rust toolchain in PATH,
bubblewrap 0.12.0, an active systemd user manager and usable cgroup delegation:

```bash
bash scripts/check-release.sh
python3 scripts/evaluate.py --output target/evaluation/report.json
python3 scripts/check-evaluation.py target/evaluation/report.json target/release/clawbell
```

`evaluate.py` builds with `--locked`, runs the gate and corpus/audit experiments,
then executes `scripts/test-native-linux.sh` in a fresh delegated user scope.
Missing facilities or a failed command/5 ms assertion abort publication. Existing
output files refuse replacement. Raw logs remain in ignored `target/evaluation`;
published JSON contains fixed metric fields, source/binary identities and platform
metadata, without owner paths, client JSON, tokens or raw audit/tool payloads.
The source fingerprint is checked before and after measurement.

The release verifier rejects incomplete sample counts, invalid percentile order,
changed source/binary/architecture/commit, failed allowed reads and inconsistent
corpus accounting. CI runs native x86-64/AArch64 measurements separately and
requires the report binary hash to match the packaged executable. Report JSON
has its own checksum and build-provenance subject. The archive and binary also
require CycloneDX SBOM attestations. A tag or a local pass alone does not prove
that these remote jobs or attestations succeeded.

Local verification passed the complete release suite, including five real CLI
attack scenarios, native resource/lifecycle/agent-memory protection, broker,
scanned skills, transactional publication, remote monitor consent/deadlines,
diagnostics and audit-loss refusal. Installer unit tests and the actual temporary
delegation-service start/restart passed. The disposable clean-host installation
job, AArch64 execution, release attestation verification and production
macOS/Windows containment remain separate acceptance items; they are not marked
passed by this local report.
