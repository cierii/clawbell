# clawbell — third audit and publication assessment

Date: 2026-11-01. Baseline: `c7be1addab516e6da6fab551a78198448631d36c`.
Candidate version: 0.1.2. This report is written in English as requested for
repository documentation. The audit includes authorized delivery changes; the
owner clarified that bug fixes, installer and CI changes are permitted.

## Verdict

**Suitable for source publication as an experimental Linux security tool, with
explicit limitations. Binary release v0.1.2 is blocked by its CI latency gate.
Not complete against the full AGENTS.md product contract, and not a universal
production security guarantee.** The Rust implementation contains real
policy, DLP, isolation and durable-audit enforcement; it is substantially more than
a scaffold. No newly reproduced Rust security defect was established in this
session. This statement is limited to the inspected boundaries and executed tests;
it is not an independent penetration-test certification or proof of no bypasses.

Do not advertise a complete cross-platform product, browser dashboard, exhaustive
prompt-injection protection, arbitrary-secret detection or full installation in
under a minute. A binary CLI trial can be bounded to under a minute, but reliable
host provisioning requires signed system packages, namespaces, bubblewrap and
persistent systemd/cgroup configuration. Downloads and compilation take longer.

## Scope and method

Reviewed the constitution, README, handoff, ADRs, workspace/dependency manifests,
policy/protocol/network/DLP boundaries, audit admission, native sandbox profile,
CLI composition and release/installer scripts. Examined the existing adversarial
and integration tests and ran the release suite locally. Manual review focused
on trust transitions; this is not a claim of exhaustive line-by-line analysis,
fuzzing, formal verification, live third-party OAuth certification or every client.

MCP Context7 supplied current official GitHub Actions guidance on immutable action
SHAs, least privilege and attestations. Actual workflow configuration was checked
against those contracts. Relevant official references:
[Actions security](https://docs.github.com/en/actions/reference/security/secure-use),
[artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
No repository code, client configuration or credentials were sent to documentation
search. The market assessment uses the primary sources linked below.

## Significant deviations and release gaps

### C-01 — High product-completeness gap: browser panel and API are absent

There is no `ui/`, package-lock, pinned Node version, React/Vite application,
Axum HTTP/SSE API, `serve` subcommand or panel-token initializer. The constitution
specifies these components. The terminal monitor and owner-private Unix IPC
(ADR 0005) provide useful approvals/inspection but do not implement that contract.
Consequently npm/Vitest/Playwright/browser/CSRF checks cannot be marked passed.
This is a missing product component, not evidence of an exposed unauthenticated
HTTP panel. Keep the constitution unchanged and describe the actual Linux CLI
scope publicly; implementing the panel is outside this audit's delivery scope.

### C-02 — Medium integration gap: conservative client compatibility

Binding supports strict JSON and constrained absolute executables; JSONC,
package-manager/PATH launchers, arbitrary environment/cwd/headers are refused.
This protects the boundary but excludes common real-world client configurations.
The entire selected workspace is readable by the server. Tool-argument rules do
not hide other files in that workspace. Credential-free workspace selection is
therefore a real deployment prerequisite, not an optional recommendation.
The README documents these restrictions; broader compatibility needs dedicated
client/version acceptance tests, not simply more permissive parsing.

### C-03 — Medium usability risk: known DLP false alarms

The checked-in evaluation documents 9/20 false alarms on a deliberately stressful
benign corpus: seven refusals and two unnecessary redactions. The conservative
known-secret-prefix rule can reject innocuous suffixes. This is not a field rate,
but it materially limits claims of transparent everyday use. Known literal values
and supported text units are inspected; arbitrary encodings and unknown secrets
are not comprehensively covered. Do not weaken rules during release preparation.
Collect representative workflow evidence before claiming low false positives.
See [evaluation](docs/evaluation.md) and the fixed corpus in
`crates/clawbell/src/attack_tests.rs`.

### C-04 — Medium delivery gap: a main-branch build is not a published release

At audit start GitHub returned no releases. Existing v0.1.0/v0.1.1 tags did not
provide a downloadable authenticated release. The exact baseline's
[Actions run](https://github.com/cierii/clawbell/actions/runs/41327481173) succeeded:
checks, RustSec dependencies, both native jobs, both clean installers and both
packages passed; publish was correctly skipped for a branch push.
A new tag must additionally pass provenance/SBOM creation and verification.
Private-repository plan restrictions may block attestations; do not remove this
check to ship binaries. Final release status must be verified separately.

### C-05 — Medium portability gap: supported Linux hosts are deliberately narrow

Production containment is Linux x86-64/AArch64. The installer accepts Fedora 44
and Ubuntu 24.04; usable namespaces, seccomp and delegated cgroups v2 are mandatory.
Windows has Unix API portability gaps; macOS does not have a verified production
adapter. Other distributions, older glibc, unusual filesystems, restricted hosts,
offline machines and actual third-party MCP deployments are not certified by the
local test results. Unsupported hosts must continue refusing execution.

### C-06 — Low maintainability gap: contracts outpace operational documentation

AGENTS.md describes future scaffold commands; `serve` and frontend commands remain
unimplemented. Historical ADRs/handoff records intentionally describe earlier
states and timing budgets. There is no live policy-file reload service: immutable
session snapshots are used and sessions must restart to load owner changes.
The configured `tracing` diagnostics stack is absent; fixed-code stderr diagnostics
are used. These are completeness/maintenance gaps, not demonstrated permission
bypasses. The long handoff is useful evidence but difficult onboarding material.
README/installation remain the operational entry points. No architectural
contract was silently rewritten to declare missing features complete.

## Security controls supported by evidence

- Deterministic default-deny policy, deny precedence, strict schemas and immutable
  session snapshots; pinned server/catalog identity and explicit pin acceptance.
- One-use bound approvals, unavailable-owner refusal and redacted terminal IPC.
- Complete bounded DLP units, split-secret/scalar/content tests, refusal for
  unsupported carriers and no automatic restoration to arbitrary upstreams.
- DNS/address pins, exact private exceptions, TLS verification, no ambient proxies,
  no redirects/retries for tool effects, host-only OAuth credentials.
- Non-root bubblewrap namespaces, read-only mounts, empty allowlisted environment,
  seccomp and whole-tree cgroup ceilings/cleanup. Native tests exercise forbidden
  access and cancellation rather than assuming configuration alone proves safety.
- Dedicated bounded SQLite writer; FULL WAL acknowledgement before execution,
  quotas, unknown interrupted outcomes, sidecar protection and explicit retention.
- Controlled broker capabilities and staged file publication with approved handles;
  scan receipts alone are not treated as proof that arbitrary code is safe.

These controls apply only inside the proxy/runner boundary. A compromised owner,
kernel, trusted upstream adapter or bypassed runner is outside the stated model.
Synthetic attacks do not establish resistance to every manipulation.

## Repository hygiene and changes delivered

- Preserved existing MIT license and private vulnerability reporting procedure.
  Added CONTRIBUTING.md with reproducible checks and refusal requirements.
- Removed the explicitly obsolete AUDYT2.md. Preserved owner-edited handoff and
  two pre-existing untracked notes; excluded those local notes with explicit ignore
  entries instead of deleting unrelated owner work.
- Extended ignore rules for assistant/credential directories, logs, crash dumps,
  token/credential files and downloaded archives. Ignore rules are prevention only;
  they cannot remove tracked files or rotate an exposed credential.
- Added a separate exact-version authenticated binary trial installer and failure
  tests. It requires GitHub CLI/Python, verifies checksum/provenance/SBOM before
  execution, reads only one regular binary archive member, installs privately and
  refuses on conflict or a 55-second overall deadline. It does not bind clients.
- Bumped workspace packages to 0.1.2 without dependency version changes. Existing
  CI already runs formatting, all-target lint, unit/integration/native checks,
  clean-host installation, RustSec, secret scans and both native release builds.
  New installer tests now run through the same mandatory local/CI entry point.
  Tagged publication also exercises the binary installer against published assets.
- Gitleaks 8.30.1 was checked against the pinned archive checksum. Initial scan of
  all fetched branch/tag history (32 commits) and the tracked candidate found no
  leaks. A targeted history search found no owner-specific home paths. Generic
  `/home/sandbox` and synthetic fixture paths are intentional, not private paths.
  No sensitive object was identified to justify rewriting commit ancestry.
  This cannot prove absence of every unknown secret or erase remote forks/caches.
- Old version tags are to be removed only in the authorized release operation;
  the new v0.1.2 tag must point to the reviewed commit and match Cargo metadata.

## Verification evidence

The baseline `bash scripts/check-release.sh` passed locally with pinned Rust
1.99.1 and bubblewrap 0.12.0, including locked fetch, fmt, Clippy `-D warnings`,
workspace tests, release build, CLI help/policy checks, HTTP/monitor tests, all
explicit latency gates, memory isolation and delegated native/CLI attack tests,
skills, broker, transactions, doctor/self-test/demo. Config restoration was exact;
forbidden host writes and agent-memory modification were refused, descendants
were removed and audit loss blocked forwarding.

Baseline measurements on this host: production gate p99 0.256 ms/max 0.569 ms;
full CLI RTT p99 about 0.64 ms/max 2.004 ms, 2,200/2,200 allowed reads completed.
These are workload-specific observations, not universal latency guarantees or
persistent-disk certification. Existing durable gates require p99 <15 ms and
maximum <1 s per owner-approved ADR 0018; non-durable gates retain their budgets.

The first restricted-environment test attempt failed on installer trust checks
because the tool environment exposes altered host permissions. The same full
suite outside those restrictions passed; no test, isolation or audit requirement
was disabled. The clean-host provisioning test was not run destructively on the
owner's desktop; both baseline Ubuntu architectures passed it in GitHub Actions.
No UI exists, so frontend checks are unavailable rather than passed.

Candidate-specific checks and exact remote release results are recorded in the
release follow-up/handoff after verification. The preceding baseline evidence
must not be relabeled as verification of a later tagged commit.

## Honest GitHub adoption assessment

**A credible niche project, with low prospects for broad adoption in its current
form.** There is no defensible numeric star-growth probability from this audit.
The private repository and placeholder description provide no evidence of public
traction. Strong engineering alone does not establish demand or distribution.

The useful differentiator is local, explicit Linux containment plus durable audit,
constrained networking and transactional publication, without required cloud
telemetry. That can appeal to security engineers and advanced Linux agent users.
A narrowly demonstrated boundary is more credible than a general “AI firewall”
claim. MIT licensing and reproducible adversarial tests lower contribution friction.

The market is already occupied. Docker documents an
[MCP Gateway security boundary](https://github.com/docker/mcp-gateway/blob/main/docs/security.md);
Invariant's [MCP-Scan documentation](https://invariantlabs-ai.github.io/docs/mcp-scan/)
describes scanning, runtime proxying and pinning. These are overlapping alternatives,
not evidence that their guarantees equal clawbell's. No comparative benchmark or
claim of superior security was established here.

The main adoption obstacles are privileged host setup, narrow client/platform
support, no browser UI, conservative false alarms and a technical README that
requires considerable prior knowledge. A quick CLI trial helps discovery but does
not resolve the effort needed for useful protected workflows. Before a broad
launch, demonstrate a real supported-client workflow from installation through
blocked synthetic attack, published authenticated artifacts, and ordinary-task
completion evidence with explicit limits. Publish now only with experimental
Linux scope; calling the full constitutional product finished would be misleading.

## Candidate 0.1.2 local verification

The complete `scripts/check-release.sh` passed again after the version and
installer changes: ordinary Python/Rust checks, all explicit ignored release gates,
native CLI attacks, skills/broker/transactions, doctor and demo. Full CLI RTT was
p99 about 0.74 ms, maximum 1.802 ms; all 2,200 allowed reads completed. Four new
installer test methods cover successful private installation, four independent
verification/identity failures, archive symlink refusal and invalid-version refusal.
A real release-binary offline scan also passed. Current cargo-audit 0.22.2 found
no advisory in the 274-dependency lockfile (1,395 loaded RustSec advisories).

Native x86-64 packaging with cargo-cyclonedx 0.5.9 passed, including archive/SBOM
checksums. Python AST, Bash syntax, workflow YAML syntax, local documentation
links and diff whitespace checks passed. AGENTS.md remains 199 lines. Exact
staged contents and fetched history are scanned before commit. Local packaging
does not produce GitHub attestations; remote tag publication and its final
download/verification trial remain separate checks, never inferred from these
local results.

## Persistent-filesystem evaluation of the tagged candidate

A separate full evaluation of `73ebbf5`/v0.1.2 passed on btrfs, including the actual
audit-fixture filesystem. The [machine-readable report](docs/evaluation/linux-x86_64-2026-11-01.json)
binds commit, source fingerprint and binary hash. The report verifier passed.
All 2,200/2,200 allowed native reads completed. Full CLI RTT: p99 3.189 ms,
maximum 5.108 ms. Production gate: p99 1.769 ms, maximum 11.924 ms; every
measured outlier remains included. Both satisfy the current p99 <15 ms/maximum
<1 s durable-audit contract. The 20-workflow stress corpus again produced 9 false
alarms (45% for this corpus only). These results do not certify another host.

Two earlier additional evaluation attempts did not complete and produced no success
report: a deeply nested TMPDIR exceeded the existing 107-byte monitor socket-path
limit, and a short TMPDIR under /var collided with the deliberate CLI prohibition
on runtime state under /var. Their gate/corpus measurements passed, but the native
binding assertion refused. Correcting only the fixture location to a short private
owner directory on btrfs allowed the full evaluation to pass. No threshold, outlier,
audit durability, sandbox or production path rule changed. Failed attempts are not
counted as successful evaluations.

## C-07 — Release blocker: tagged CI broker latency failure

The exact v0.1.2/`73ebbf5` [tag run](https://github.com/cierii/clawbell/actions/runs/41332957282)
failed the broker packet gate in the checks job. Ordinary formatting, lint, tests,
build, CLI checks and the production packet gate passed first. Broker measurement:
**p99 30.213244 ms, maximum 198.288973 ms**. The assertion requires p99 <15 ms
and maximum <1 s; the percentile failed. Both clean-host installers and the
RustSec job passed; native AArch64 also completed successfully. This failure is
not relabeled as success because local checks or the previous revision passed.

No replay, outlier removal, automatic retry, threshold relaxation, tmpfs
substitution, disabled audit or unsigned/manual release was introduced. The
measurement alone does not identify storage versus scheduler/network/runtime
contention, or establish a functional sandbox escape. Root-cause diagnosis needs
phase-specific measurements on the failing host before a justified production
optimization. A speculative code change would not establish a repair.

The failed prerequisite prevents packaging/publication. Thus this session does
not establish a successful downloaded-release trial: the installer is implemented
and locally failure-tested, and its real published-asset test is configured, but
that test cannot execute until the release gates pass. The source tag exists;
there is no successful v0.1.2 binary release to advertise. The requested fully
verified binary publication remains incomplete.

## Owner follow-up: 40 ms budget and v0.1.3

After the audit, the owner explicitly approved changing durable-audit p99 from
<15 ms to <40 ms, retaining maximum <1 s. Tests, report validation and boundary
regressions are updated together under ADR 0018. The earlier v0.1.2 CI failure
remains a failure under its original contract. v0.1.3 must pass all gates and
artifact attestations independently; the budget change alone does not establish
publication or improve runtime performance.
