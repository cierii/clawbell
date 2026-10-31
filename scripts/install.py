"""Owner-driven source installation. Every subprocess uses literal argv.

System package repositories, the pinned Rust distribution and the reviewed
checkout are trusted. Client content never becomes a command. Failure leaves
completed provisioning in place and never reports a bound client as successful.
"""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import stat
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
RUSTUP = {
    "x86_64": "20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c",
    "aarch64": "e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c",
}
BWRAP_COMMIT = "2a76602a8c71f36c1527cf9fc3417d9149822e0c"
DELEGATE = '''"""Enable delegated controllers on every service start, including boot."""
from pathlib import Path
entries = Path('/proc/self/cgroup').read_text().splitlines()
relative, = [line[3:] for line in entries if line.startswith('0::')]
if not relative.startswith('/') or '..' in relative.split('/') or not relative.endswith('/.control'):
    raise SystemExit('delegation_path_refused')
parent = Path('/sys/fs/cgroup' + relative).parent
if (parent / 'cgroup.procs').read_text().strip():
    raise SystemExit('delegation_parent_populated')
(parent / 'cgroup.subtree_control').write_text('+cpu +memory +pids\\n')
if not {'cpu', 'memory', 'pids'} <= set((parent / 'cgroup.subtree_control').read_text().split()):
    raise SystemExit('delegation_controllers_unavailable')
'''


class Refused(Exception):
    """A fixed installation failure, never client content or captured stderr."""


def run(arguments, *, env=None, timeout=1800):
    """Bound execution and suppress command output that could contain owner data."""
    try:
        return subprocess.run(arguments, cwd=ROOT, env=env, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise Refused("installer_step_failed") from error


def trusted(path):
    """Reject link traversal and foreign writable ancestors before host writes.

    Same-owner concurrent tampering is outside the project threat model. A sticky
    root-owned temporary ancestor is allowed for isolated installation tests.
    """
    if not path.is_absolute() or ".." in path.parts or any(ord(c) < 32 for c in str(path)):
        raise Refused("installer_path_refused")
    for entry in [*reversed(path.parents), path]:
        try:
            info = entry.lstat()
        except FileNotFoundError:
            continue
        sticky = info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX
        if (stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.getuid())
                or (info.st_mode & 0o022 and not sticky)):
            raise Refused("installer_path_refused")


def directory(path):
    """Create/traverse private directories using pinned no-follow directory FDs.

    Never follow a directory inserted between validation and creation. Every new
    component is private before the next component can be exposed to a writer.
    """
    trusted(path)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            try:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            next_descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            info = os.fstat(descriptor)
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not sticky):
                raise Refused("installer_path_refused")
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Refused("installer_private_directory_required")
    finally:
        os.close(descriptor)
    return path


def exclusive(path, data, mode=0o600):
    """Idempotent exclusive creation; never replace an existing owner file."""
    trusted(path)
    if path.exists():
        info = path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode
                or path.read_bytes() != data):
            raise Refused("installer_existing_file_conflict")
        return
    with path.open("xb") as output:
        os.fchmod(output.fileno(), mode)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def service(helper):
    """Escape a trusted absolute path for systemd, including specifier syntax."""
    quoted = str(helper).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'''# Managed by clawbell source installer
[Unit]
Description=clawbell owner cgroups delegation
[Service]
Type=exec
Delegate=cpu memory pids
DelegateSubgroup=supervisor
ExecStart=/usr/bin/sleep infinity
ExecStartPost=/usr/bin/python3 "{quoted}"
Restart=on-failure
[Install]
WantedBy=default.target
'''.encode()


def provision_dependencies(distribution):
    if distribution == ("fedora", "44"):
        run(["sudo", "dnf", "install", "-y", "gcc", "gcc-c++", "make", "git", "curl",
             "ca-certificates", "meson", "ninja-build", "libcap-devel", "pkgconf-pkg-config",
             "bubblewrap", "systemd", "dbus-daemon"])
    elif distribution == ("ubuntu", "24.04"):
        run(["sudo", "apt-get", "update"])
        run(["sudo", "apt-get", "install", "--no-install-recommends", "-y",
             "build-essential", "git", "curl", "ca-certificates", "meson", "ninja-build",
             "libcap-dev", "pkg-config", "bubblewrap", "dbus-user-session", "apparmor"])
    else:
        raise Refused("installer_unsupported_distribution")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, action="append", required=True)
    parser.add_argument("--workspace", type=Path,
                        help="Credential-free private code directory; otherwise prepare an empty workspace")
    options = parser.parse_args()
    if os.getuid() == 0 or platform.system() != "Linux" or platform.machine() not in RUSTUP:
        raise Refused("installer_unsupported_host")
    os.umask(0o077)
    home = Path.home()
    for config in options.config:
        trusted(config)
        if not config.is_file():
            raise Refused("installer_configuration_missing")
    distribution = platform.freedesktop_os_release()
    provision_dependencies((distribution["ID"], distribution["VERSION_ID"]))
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    base = directory(home / ".local/share/clawbell")
    release = directory(base / "releases" / version)
    cargo_home = directory(base / "cargo")
    rustup_home = directory(base / "rustup")
    environment = os.environ.copy()
    environment.update(CARGO_HOME=str(cargo_home), RUSTUP_HOME=str(rustup_home),
                       PATH=f"{cargo_home}/bin:/usr/bin:/bin")
    rustup = cargo_home / "bin/rustup"
    if not rustup.exists():
        with tempfile.TemporaryDirectory(prefix="clawbell-toolchain-") as temporary:
            installer = Path(temporary) / "rustup-init"
            triple = platform.machine() + "-unknown-linux-gnu"
            run(["curl", "--fail", "--location", "--proto", "=https", "--tlsv1.2",
                 "--output", str(installer),
                 f"https://static.rust-lang.org/rustup/archive/1.28.2/{triple}/rustup-init"])
            if hashlib.sha256(installer.read_bytes()).hexdigest() != RUSTUP[platform.machine()]:
                raise Refused("installer_toolchain_checksum_failed")
            installer.chmod(0o700)
            run([str(installer), "-y", "--no-modify-path", "--profile", "minimal",
                 "--default-toolchain", "none"], env=environment)
    run([str(rustup), "toolchain", "install", toolchain, "--profile", "minimal"], env=environment)
    build_directory = ROOT / "target/install-build"
    run([str(rustup), "run", toolchain, "cargo", "build", "--release", "--locked",
         "--target-dir", str(build_directory), "-p", "clawbell"],
        env=environment)
    binary = release / "clawbell"
    exclusive(binary, (build_directory / "release/clawbell").read_bytes(), 0o700)
    # Build the pinned namespace-capable bubblewrap unprivileged, install only
    # the resulting fixed executable as root. No dependency script runs as root.
    help_text = run(["/usr/bin/bwrap", "--help"])
    if b"--ro-bind-fd" not in help_text or b"--disable-userns" not in help_text:
        with tempfile.TemporaryDirectory(prefix="clawbell-bwrap-") as temporary:
            source = Path(temporary) / "source"
            run(["git", "clone", "--filter=blob:none", "https://github.com/containers/bubblewrap.git", str(source)])
            run(["git", "-C", str(source), "checkout", "--detach", BWRAP_COMMIT])
            if run(["git", "-C", str(source), "rev-parse", "HEAD"]).strip().decode() != BWRAP_COMMIT:
                raise Refused("installer_bubblewrap_revision_failed")
            run(["meson", "setup", str(source / "build"), str(source), "--buildtype=release"])
            run(["meson", "compile", "-C", str(source / "build")])
            run(["sudo", "install", "-m", "0755", str(source / "build/bwrap"), "/usr/bin/bwrap"])
    restriction = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if restriction.exists() and restriction.read_text().strip() == "1":
        # Narrow executable-specific namespace permission; never lower the global sysctl.
        profile = b'abi <abi/4.0>,\ninclude <tunables/global>\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n'
        target = Path("/etc/apparmor.d/bwrap")
        # Preserve the administrator/distribution profile when present, including
        # stricter choices. The subsequent real doctor probe must still succeed.
        if not target.exists():
            with tempfile.TemporaryDirectory(prefix="clawbell-apparmor-") as temporary:
                candidate = Path(temporary) / "bwrap"
                candidate.write_bytes(profile)
                run(["sudo", "install", "-m", "0644", str(candidate), str(target)])
        run(["sudo", "apparmor_parser", "-r", str(target)])
    helper = release / "delegate.py"
    exclusive(helper, DELEGATE.encode())
    unit_dir = home / ".config/systemd/user"
    trusted(unit_dir)
    unit_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    unit = unit_dir / "clawbell-delegation.service"
    exclusive(unit, service(helper))
    run(["sudo", "loginctl", "enable-linger", str(os.getuid())])
    run(["sudo", "systemctl", "start", f"user@{os.getuid()}.service"])
    environment.update(XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}",
                       DBUS_SESSION_BUS_ADDRESS=f"unix:path=/run/user/{os.getuid()}/bus")
    run(["systemd-analyze", "--user", "verify", str(unit)], env=environment)
    run(["systemctl", "--user", "daemon-reload"], env=environment)
    run(["systemctl", "--user", "enable", "--now", "clawbell-delegation.service"], env=environment)
    relative = run(["systemctl", "--user", "show", "-p", "ControlGroup", "--value",
                    "clawbell-delegation.service"], env=environment).decode().strip()
    if not relative.startswith("/") or relative == "/" or ".." in relative.split("/"):
        raise Refused("installer_delegation_refused")
    parent = "/sys/fs/cgroup" + relative
    workspace = directory(options.workspace if options.workspace else base / "workspace")
    state = directory(home / ".local/state/clawbell")
    policy = base / "policy.toml"
    exclusive(policy, (ROOT / "policies/default.toml").read_bytes())
    run([str(binary), "policy", "check", "--file", str(policy)], env=environment)
    run([str(binary), "doctor", "--self-test", "--cgroup-parent", parent], env=environment)
    arguments = [str(binary), "init", "--policy", str(policy), "--workspace", str(workspace),
                 "--state-dir", str(state), "--cgroup-parent", parent]
    for config in options.config:
        arguments.extend(["--config", str(config)])
    run(arguments, env=environment)
    print("installation_complete; clients_bound; policy_default_deny")


if __name__ == "__main__":
    try:
        main()
    except Refused as error:
        raise SystemExit(f"{error}; completed_provisioning_retained; inspect prerequisites before retry") from None
    except (OSError, KeyError, ValueError):
        # No captured command output, configuration content or owner paths.
        raise SystemExit("installation_failed; completed_provisioning_retained; inspect prerequisites before retry") from None
