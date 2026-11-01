#!/usr/bin/env bash
# Bundle the already-verified native Linux binary; no build/install hooks.
set -euo pipefail
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')
test "$(uname -s)" = Linux
architecture=$(uname -m)
case "$architecture" in
    x86_64|aarch64) ;;
    *) echo 'unsupported native release architecture' >&2; exit 1 ;;
esac
host=$(rustc -vV | sed -n 's/^host: //p')
test "$host" = "$architecture-unknown-linux-gnu"
name="clawbell-${version}-linux-$architecture"
test ! -e "target/package/$name"
bash scripts/generate-sbom.sh
mkdir -p "target/package/$name"
install -m 0755 target/release/clawbell "target/package/$name/clawbell"
install -m 0644 LICENSE SECURITY.md CONTRIBUTING.md AGENTS.md target/package/clawbell.cdx.json "target/package/$name/"
install -m 0644 README.md "target/package/$name/README.md"
mkdir -p "target/package/$name/policies"
install -m 0644 policies/default.toml "target/package/$name/policies/default.toml"
mkdir -p "target/package/$name/docs/adr"
install -m 0644 docs/adr/*.md "target/package/$name/docs/adr/"
install -m 0644 docs/release-notes.md "target/package/$name/docs/release-notes.md"
install -m 0644 docs/installation.md docs/evaluation.md "target/package/$name/docs/"
mkdir -p "target/package/$name/docs/evaluation"
install -m 0644 docs/evaluation/*.json "target/package/$name/docs/evaluation/"
# Stable archive metadata; the source commit remains bound by provenance.
epoch=$(git show -s --format=%ct HEAD)
tar -C target/package --sort=name --mtime="@$epoch" --owner=0 --group=0 \
  --numeric-owner -cf - "$name" | gzip -n > "target/package/$name.tar.gz"
mv target/package/clawbell.cdx.json "target/package/$name.cdx.json"
(cd target/package && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
(cd target/package && sha256sum "$name.cdx.json" > "$name.cdx.json.sha256")
