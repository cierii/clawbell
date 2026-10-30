#!/usr/bin/env bash
# Run inside a fresh systemd --user scope with Delegate=yes. No root is required.
set -euo pipefail
relative=$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)
parent="/sys/fs/cgroup${relative}"
mkdir "$parent/supervisor"
printf '%s\n' "$$" > "$parent/supervisor/cgroup.procs"
printf '+cpu +memory +pids\n' > "$parent/cgroup.subtree_control"
export CLAWBELL_TEST_CGROUP="$parent"
cargo test -p clawbell-sandbox --locked --test native -- --ignored --nocapture
cargo test -p clawbell-proxy --release --locked --test native_runner -- --ignored --nocapture
cargo build --release --locked -p clawbell
python3 scripts/test-mvp-cli.py
target/release/clawbell doctor --cgroup-parent "$parent"
target/release/clawbell doctor --self-test --cgroup-parent "$parent"
target/release/clawbell demo --cgroup-parent "$parent"
