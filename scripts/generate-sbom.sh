#!/usr/bin/env bash
# No runtime hooks. Inspect the same locked default-feature Linux binary graph.
set -euo pipefail
test "$(cargo cyclonedx --version | awk '{print $NF}')" = '0.5.9'
test "$(rustc -vV | sed -n 's/^host: //p')" = x86_64-unknown-linux-gnu
# The generator has no --locked flag. Force offline resolution and verify that
# it did not rewrite the reviewed lockfile; never accept a silently updated graph.
generated=crates/clawbell/clawbell_bin.cdx.json
test ! -e "$generated"
trap 'rm -f "$generated"' EXIT
lock_before=$(sha256sum Cargo.lock)
CARGO_NET_OFFLINE=true cargo cyclonedx --manifest-path crates/clawbell/Cargo.toml \
  --format json --spec-version 1.5 --describe binaries \
  --target x86_64-unknown-linux-gnu
test "$lock_before" = "$(sha256sum Cargo.lock)"
mkdir -p target/package
# Cargo package IDs contain absolute builder paths. Replace only local component
# identities and their graph references; do not publish workstation usernames.
python3 - "$generated" target/package/clawbell.cdx.json <<'PY'
import json
import sys
from pathlib import Path

source, destination = map(Path, sys.argv[1:])
bom = json.loads(source.read_text())
assert bom['bomFormat'] == 'CycloneDX' and bom['specVersion'] == '1.5'
components = [bom['metadata']['component'], *bom['components']]
identities = {}
for component in components:
    reference = component['bom-ref']
    if reference.startswith('path+file://'):
        identities[reference] = f"urn:clawbell:workspace:{component['name']}:{component['version']}"
        component.pop('purl', None)

def normalize(value):
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    if isinstance(value, str):
        return identities.get(value, value)
    return value

bom = normalize(bom)
encoded = json.dumps(bom, indent=2) + '\n'
assert 'file://' not in encoded, 'unmapped local path in SBOM'
assert str(Path.cwd()) not in encoded, 'builder path in SBOM'
references = {item['bom-ref'] for item in [bom['metadata']['component'], *bom['components']]}
assert len(references) == len(components), 'duplicate SBOM identity'
for dependency in bom['dependencies']:
    assert dependency['ref'] in references
    assert set(dependency.get('dependsOn', [])) <= references
assert len(bom['components']) > 0, 'empty SBOM'
destination.write_text(encoded)
PY
