#!/usr/bin/env bash
# All release latency budgets are explicit. Never turn an unavailable prerequisite
# into a skip. Run on an idle Linux host with systemd user-session delegation.
set -euo pipefail
bash scripts/check-local.sh
cargo test --locked --release -p clawbell complete_mvp_gate_packets_under_five_ms -- --ignored --nocapture
cargo test --locked --release -p clawbell remote_resource_gate_packets_under_five_ms -- --ignored --nocapture
cargo test --locked --release -p clawbell-core dlp_packet_under_five_ms -- --ignored --nocapture
cargo test --locked --release -p clawbell-proxy policy_packet_under_five_ms -- --ignored --nocapture
cargo test --locked --release -p clawbell-proxy monitor_packet_under_five_ms -- --ignored --nocapture
cargo test --locked -p clawbell-sandbox child_cannot_modify_agent_memory -- --ignored --nocapture
systemd-run --user --scope -p Delegate=yes bash scripts/test-native-linux.sh
