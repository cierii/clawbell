# Security policy

## Supported versions

Security fixes target the latest tagged release and the main branch. Older
releases do not receive a separate backport commitment. Before the first tag,
only main is maintained. Update deliberately after reviewing release notes.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/cierii/clawbell/security/advisories/new).
If reporting is unavailable, request a private contact channel from the maintainer
without disclosing exploit details. Do not open a public issue with a working
exploit, credentials, raw client configurations or private audit data.

Include the commit/version, Linux/kernel and bubblewrap versions, affected
boundary, expected/actual behavior and a minimal reproduction using synthetic
data. Describe required permissions and whether the proxy/runner was bypassed.
Never send real secrets. There is no guaranteed response or remediation deadline;
coordinate disclosure with the maintainer before publishing exploit details.

## Scope and limits

clawbell enforces local owner policy only for traffic and processes routed through
its proxy and runner. Remote MCP processes, skills executed outside the runner,
owner-account compromise and a compromised kernel are outside containment. DLP
patterns and static skill findings cannot establish complete secret detection or
absence of prompt injection. The audit is not administrator-tamper-proof.
Missing policy, isolation or durable audit fails closed. See [AGENTS.md](AGENTS.md)
and the [architecture decisions](docs/adr/) for the full contracts.

## Release verification

Release publication requires tests, native isolation/latency gates, secret scanning
and a fresh RustSec dependency scan. Scheduled scans check newly disclosed
advisories even without code changes; unavailable scanners/databases fail the job.
No advisory is silently ignored or fixed by an automatic dependency update.

Each Linux archive includes this policy, the [MIT license](LICENSE), and a
CycloneDX JSON SBOM of the selected Rust binary's production and build dependency
graph. The same SBOM is published beside the archive. It describes Cargo metadata,
not a complete inventory of the Linux runtime, system bubblewrap or bundled C
source inside crates. Upstream dependency licenses still apply.

Tagged builds generate GitHub build provenance and SBOM attestations for the
archive and the enclosed binary in the build job. Publication requires both.
Checksums detect corruption; they do not authenticate the publisher. Before
executing downloaded code, authenticate the archive with GitHub CLI:

```bash
sha256sum --check clawbell-0.1.3-linux-aarch64.tar.gz.sha256
gh attestation verify clawbell-0.1.3-linux-aarch64.tar.gz \
  --repo cierii/clawbell --signer-workflow cierii/clawbell/.github/workflows/ci.yml \
  --source-ref refs/tags/v0.1.3
```

Use the tag matching the version you downloaded. After verifying the archive, the
extracted binary can also be verified with the same command and signer constraints.
To verify the SBOM statement, add `--predicate-type https://cyclonedx.org/bom`.
Verification requires GitHub access; never execute an artifact whose required
verification failed. Attestations establish workflow provenance, not that the
software is vulnerability-free. GitHub attestation availability for private
repositories depends on the account plan; unavailable attestation fails publication
rather than silently releasing unsigned artifacts. No attestation is produced by
local packaging alone.
