#!/usr/bin/env bash
# Bundle the already-verified native x86-64 Linux binary; no build/install hooks.
set -euo pipefail
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')
name="clawbell-${version}-linux-x86_64"
test "$(uname -m)" = x86_64
bash scripts/generate-sbom.sh
mkdir -p "target/package/$name"
install -m 0755 target/release/clawbell "target/package/$name/clawbell"
install -m 0644 LICENSE SECURITY.md AGENTS.md target/package/clawbell.cdx.json "target/package/$name/"
install -m 0644 README.md "target/package/$name/README.md"
mkdir -p "target/package/$name/policies"
install -m 0644 policies/default.toml "target/package/$name/policies/default.toml"
mkdir -p "target/package/$name/docs/adr"
install -m 0644 docs/adr/*.md "target/package/$name/docs/adr/"
install -m 0644 docs/release-notes.md "target/package/$name/docs/release-notes.md"
tar -C target/package -czf "target/package/$name.tar.gz" "$name"
(cd target/package && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
(cd target/package && sha256sum clawbell.cdx.json > clawbell.cdx.json.sha256)
