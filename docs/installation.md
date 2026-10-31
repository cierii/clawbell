# Source installation and recovery

Use a reviewed source checkout, Bash, an unprivileged owner with sudo access,
HTTPS connectivity and an existing strict JSON client configuration. The installer
supports Fedora 44 and Ubuntu 24.04 on x86-64/AArch64 with systemd 254 or newer and
cgroups v2. Other systems refuse before provisioning. This is a source installer;
it is not embedded in the binary release archive. Authenticate downloaded source
before executing it. It does not use curl-to-shell, accept new vendor agreements,
install clients, retrieve skills, or discover/copy server code from the home tree.

```bash
bash scripts/install.sh --config /absolute/path/client.json \
  --workspace /absolute/path/credential-free-server
```

Repeat `--config` to bind several files. Select a private directory containing the
server code needed by the configured `/usr/bin/` interpreter. The entire workspace
is readable to the server. Never select a home/credential directory or a checkout
containing credentials. Without `--workspace`, installation prepares an empty
private workspace; existing external server scripts will need explicit relocation
and client configuration review. Literal absolute paths inside the selected
workspace are translated by the existing binder. Client format limitations in
[README](../README.md#install-and-bind-a-client) still apply.

## Changes made to the host

1. Install signed distribution build/runtime packages with dnf or apt. Python is
   bootstrapped when absent. No root Cargo build or dependency installation hook
   runs. The source tree is built using `--locked` and its pinned toolchain.
2. Install Rustup 1.28.2 from the official Rust distribution, verifying the
   architecture-specific SHA-256 embedded in `scripts/install.py`, into private
   `~/.local/share/clawbell/{cargo,rustup}`. It never changes shell startup files.
3. If the system bubblewrap lacks required flags, build commit
   `2a76602a8c71f36c1527cf9fc3417d9149822e0c` unprivileged and install the resulting
   executable as `/usr/bin/bwrap`. This replaces the system executable deliberately;
   future distribution upgrades may require reinstalling a compatible version.
4. On AppArmor-restricted Ubuntu, preserve and load the distribution/administrator
   `/etc/apparmor.d/bwrap` profile. If none exists, install an executable-specific
   unconfined profile granting user namespaces. No global namespace sysctl is
   lowered. A stricter existing profile can cause the real containment probe to
   refuse; installation does not weaken that administrator choice.
5. Install `~/.local/share/clawbell/releases/<version>/{clawbell,delegate.py}`;
   private directories are 0700, data files 0600 and the binary 0700. Existing
   different files refuse replacement. No global executable search path is edited.
6. Enable `loginctl enable-linger <owner-uid>` and start the owner's user manager.
   Create/enable `~/.config/systemd/user/clawbell-delegation.service` with
   `Delegate=cpu memory pids` and `DelegateSubgroup=supervisor`. `ExecStartPost`
   enables/checks all controllers on **every** service start, including boot.
7. Prepare private policy and workspace under `~/.local/share/clawbell` and state
   under `~/.local/state/clawbell`. An explicit workspace remains in its selected
   location. Existing private files are preserved; the default policy denies tools
   until explicitly configured by the owner.
8. Validate policy and run the real `doctor --self-test`, then invoke `init` with
   explicit paths. The configured upstream is never run during binding. The
   installed versioned executable path is embedded in the client configuration.

The shell entry point validates argument shape, architecture and distribution
before system provisioning. Python validates client paths before installing the
remaining dependencies. The production binder performs bounded strict JSON and
native preflight checks before client replacements. System provisioning and each
client-file replacement are separate transactions: a later failure retains
completed host setup and any earlier bindings. Output never dumps client JSON or
captured subprocess stderr. Package-manager bootstrap output, if Python is absent,
contains package diagnostics only. Review sudo/package-manager errors locally.

## Failure diagnostics

Each subprocess reports a fixed `installer_step=<stage>` to stderr before it
starts. Failure reports the same stage and `status=exit_<code>`, `timeout` or
`spawn_failed`. Arguments, owner paths, client content and captured stdout/stderr
are never included. For example, `step=delegation_start` identifies user-service
startup, while `step=containment_probe` identifies the mandatory native self-test.
A progress line is not a success acknowledgement; only `installation_complete`
confirms the entire installation and binding sequence completed.

Use the reported stage to inspect the relevant package manager, toolchain or user
service locally. Review diagnostic data before sharing it. A failed stage retains
completed provisioning and does not authorize overwriting conflicting files or
bypassing the isolation probe. Rerun only after resolving the reported prerequisite.

## Repetition, upgrades and removal

Repeating installation with identical settings is idempotent. Conflicting existing
policy, unit, binary or client receipts refuse rather than overwrite. An older
`bootstrap-fedora-44.sh` unit is intentionally a conflict: stop all sessions, review
and archive the old unit, then install the new persistent preparation contract.
Version upgrades similarly require a reviewed unit migration. Existing client
wrappers keep their old versioned executable until explicitly unbound/rebound.

Use the installed executable's `unbind --config /absolute/path/client.json` to
restore each unchanged client from its private backup. Never publish those backups.
An owner/client edit, symlink, hardlink or receipt mismatch refuses restoration.
See [ADR 0006](adr/0006-mvp-installer-and-audit.md) for interrupted bind recovery.

After unbinding every client and stopping every active clawbell session, disable
the user service with `systemctl --user disable --now clawbell-delegation.service`.
Archive/remove its reviewed unit and reload the user manager. Retain private audit
state until the owner explicitly authorizes retention/removal. Remove the private
version/toolchain directories only after checking that no wrapper references them.
Lingering can support other applications: disable it only after the owner checks
their services. Restore the distribution bubblewrap/package policy through its
package manager if desired. The installer does not automatically uninstall shared
system packages, disable lingering, remove audit data or roll back host changes.

## Verification

`python3 scripts/test-installer.py` verifies exclusive writes, collisions, link and
unsafe-directory refusals, fixed error output and persistent service construction.
`scripts/test-install-clean.sh` requires `CLAWBELL_DISPOSABLE_HOST=yes`; run it only
on a disposable supported VM. It actually provisions/builds, binds `/usr/bin/false`
without executing it, restores the client, verifies lingering and restarts the
service before rechecking controllers and native self-tests. CI schedules this
gate on Ubuntu x86-64/AArch64. Scheduling a test is not evidence that it passed;
inspect the exact tagged workflow. Fedora clean-host installation and native
macOS/Windows execution must not be inferred from Ubuntu or local unit results.
