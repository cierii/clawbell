#!/usr/bin/env bash
# Use an explicit binary; download nothing and print no findings/secret values.
set -euo pipefail
scanner="${GITLEAKS_BIN:-gitleaks}"
"$scanner" git . --redact --no-banner --log-opts=--all
candidate=$(mktemp -d /tmp/clawbell-secret-candidate-XXXXXX)
trap 'rm -rf "$candidate"' EXIT
# Export only the reviewed index, not ignored runtime data or private worktrees.
git checkout-index --all --prefix="$candidate/"
"$scanner" dir "$candidate" --redact --no-banner
