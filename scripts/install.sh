#!/usr/bin/env bash
# Run from a reviewed source checkout as the owner; never pipe a URL to a shell.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
[[ -f Cargo.lock && -f rust-toolchain.toml && -f scripts/install.py ]]
if [[ ${1:-} == --help ]]; then
    printf '%s\n' 'Usage: bash scripts/install.sh --config /absolute/client.json [--config ...] [--workspace /absolute/code]' \
      'Provisions Fedora 44 or Ubuntu 24.04 as the current non-root owner.' \
      'Uses sudo for signed system packages, bubblewrap, AppArmor and lingering.'
    exit 0
fi
[[ $(id -u) != 0 && $(uname -s) == Linux ]]
case "$(uname -m)" in x86_64|aarch64) ;; *) exit 1 ;; esac
# Validate the complete argument shape before any machine-wide change.
[[ $# -ge 2 && $(( $# % 2 )) == 0 ]]
for ((i=1; i<=$#; i+=2)); do
    [[ ${!i} == --config || ${!i} == --workspace ]]
    j=$((i+1)); [[ ${!j} == /* && ! -L ${!j} ]]
    if [[ ${!i} == --config ]]; then [[ -f ${!j} ]]; fi
done
. /etc/os-release
case "$ID:$VERSION_ID" in
    fedora:44) bootstrap=(dnf install -y python3) ;;
    ubuntu:24.04) bootstrap=(apt-get install --no-install-recommends -y python3) ;;
    *) echo 'installer_unsupported_distribution' >&2; exit 1 ;;
esac
if ! command -v python3 >/dev/null; then
    if [[ $ID == ubuntu ]]; then sudo apt-get update; fi
    sudo "${bootstrap[@]}"
fi
exec python3 scripts/install.py "$@"
