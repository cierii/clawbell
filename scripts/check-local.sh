#!/usr/bin/env bash
# Ordinary local checks. Native enforcement is a separate mandatory release check.
set -euo pipefail
python3 scripts/test-installer.py
python3 scripts/test-evaluation.py
cargo fetch --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked --no-fail-fast
cargo build --workspace --release --locked
cargo run --locked -p clawbell -- --help
cargo run --locked -p clawbell -- policy check --file policies/default.toml
git diff --check
