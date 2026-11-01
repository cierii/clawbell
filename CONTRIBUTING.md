# Contributing

Read [AGENTS.md](AGENTS.md) and the relevant [ADRs](docs/adr/) before changing a
trust boundary. Keep changes small and describe the trigger, expected behavior,
security impact and verification in your pull request. Write code and public
project documentation in English. Use synthetic fixtures only.

## Development

Use Linux x86-64 or AArch64, the toolchain pinned in `rust-toolchain.toml`, and
Python 3.11+. Install Rust with rustfmt and Clippy. Commit `Cargo.lock`; do not
regenerate it to bypass `--locked` failures.

```bash
bash scripts/check-local.sh
```

This runs Python installer/evaluation tests, locked fetch, formatting, all-target
Clippy, workspace tests, release build and CLI smoke tests. Ordinary tests leave
native and performance experiments explicitly ignored; they are mandatory for a
release:

```bash
bash scripts/check-release.sh
```

The full suite needs namespace-capable bubblewrap, seccomp, cgroups v2 with
cpu/memory/pids delegation and an active systemd user manager. See
[installation](docs/installation.md). Do not run `test-install-clean.sh` on your
desktop: it provisions a disposable host. Missing isolation must fail, never skip
or fall back to an unconfined process. Review timing failures with all samples;
do not weaken budgets or audit durability to make a build pass.

Before committing, stage only intended files and use a reviewed Gitleaks binary:

```bash
bash scripts/check-secrets.sh
git diff --cached --check
```

Tests for behavior changes must cover refusal and absence of forbidden side
effects, including synthetic secret leakage where applicable. Document security
contract changes in an ADR. Avoid new dependencies without a functional or
security justification. Report vulnerabilities using [SECURITY.md](SECURITY.md),
not public issues. The project uses the [MIT license](LICENSE); contributions
must be compatible with it. There is currently no browser frontend to build/test.
