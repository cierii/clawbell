#!/usr/bin/env bash
# Destructive provisioning test: disposable Ubuntu 24.04 VM only, never a desktop.
set -euo pipefail
[[ ${CLAWBELL_DISPOSABLE_HOST:-} == yes ]]
temporary=$(mktemp -d "$HOME/clawbell-clean-install-XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
printf '%s\n' '{"mcpServers":{"fixture":{"command":"/usr/bin/false"}}}' > "$temporary/client.json"
cp "$temporary/client.json" "$temporary/original.json"
bash scripts/install.sh --config "$temporary/client.json"
binary=$(python3 - "$temporary/client.json" <<'PY'
import json
import sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_bytes())
command = config['mcpServers']['fixture']['command']
assert command.endswith('/clawbell') and Path(command).is_file()
print(command)
PY
)
"$binary" unbind --config "$temporary/client.json"
cmp "$temporary/client.json" "$temporary/original.json"
[[ $(loginctl show-user "$(id -u)" -p Linger --value) == yes ]]
# The Python installer configures its own child environment. Non-login CI shells
# must connect to that same owner user manager explicitly after it returns.
export XDG_RUNTIME_DIR="/run/user/$(id -u)"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
# Exercise the same preparation path used after boot, not only the installation.
systemctl --user restart clawbell-delegation.service
relative=$(systemctl --user show clawbell-delegation.service -p ControlGroup --value)
parent="/sys/fs/cgroup$relative"
[[ -z $(cat "$parent/cgroup.procs") ]]
for controller in cpu memory pids; do
    [[ " $(cat "$parent/cgroup.subtree_control") " == *" $controller "* ]]
done
"$binary" doctor --self-test --cgroup-parent "$parent"
printf '%s\n' 'clean_host_install_bind_restore_and_service_restart_passed'
