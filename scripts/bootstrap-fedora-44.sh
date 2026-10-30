#!/usr/bin/env bash
# Persistent owner-only delegation on Fedora 44. No root, package installs or
# global namespace changes. Run as the owner from an active systemd user session.
set -euo pipefail
if [[ $(id -u) == 0 ]]; then exit 1; fi
. /etc/os-release
[[ $ID == fedora && $VERSION_ID == 44 ]]
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
unit="$unit_dir/clawbell-delegation.service"
mkdir -p "$unit_dir"
candidate=$(mktemp)
trap 'rm -f "$candidate"' EXIT
cat > "$candidate" <<'UNIT'
# Managed by clawbell bootstrap-fedora-44.sh
[Unit]
Description=clawbell owner cgroups delegation
[Service]
Type=exec
Delegate=cpu memory pids
DelegateSubgroup=supervisor
ExecStart=/usr/bin/sleep infinity
Restart=on-failure
[Install]
WantedBy=default.target
UNIT
if [[ -e $unit || -L $unit ]]; then
    [[ -f $unit && ! -L $unit ]] && cmp -s "$candidate" "$unit"
else
    (set -o noclobber; cat "$candidate" > "$unit")
fi
systemctl --user daemon-reload
systemctl --user enable --now clawbell-delegation.service
relative=$(systemctl --user show -p ControlGroup --value clawbell-delegation.service)
[[ $relative == /* && $relative != / && $relative != *..* ]]
parent="/sys/fs/cgroup$relative"
[[ -z $(cat "$parent/cgroup.procs") ]]
printf '+cpu +memory +pids\n' > "$parent/cgroup.subtree_control"
for controller in cpu memory pids; do
    [[ " $(cat "$parent/cgroup.subtree_control") " == *" $controller "* ]]
done
printf 'Delegation ready. Use --cgroup-parent %q\n' "$parent"
