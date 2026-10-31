"""Host-write refusal and provisioning contract tests; no sudo or network."""
import importlib.util
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install.py"))
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class InstallationTests(unittest.TestCase):
    def test_clean_host_gate_reconnects_to_user_manager_without_login_environment(self):
        """The installer child cannot export its session into the CI parent shell.

        Stop at a fake restart: this test never provisions the host or touches
        real services/cgroups. All files, including shell cleanup, stay private.
        """
        script = Path(__file__).with_name("test-install-clean.sh").resolve()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            commands = root / "bin"
            commands.mkdir()
            (root / "scripts").mkdir()
            data = root / "data"
            data.mkdir()
            fixtures = {
                "mktemp": 'printf "%s\\n" "$CLAWBELL_FIXTURE_DATA"\n',
                "loginctl": 'printf "%s\\n" yes\n',
                "systemctl": '''test "$*" = '--user restart clawbell-delegation.service' || exit 74
test "${XDG_RUNTIME_DIR:-}" = "/run/user/$(id -u)" || exit 75
test "${DBUS_SESSION_BUS_ADDRESS:-}" = "unix:path=$XDG_RUNTIME_DIR/bus" || exit 76
printf '%s\\n' user_manager_session_verified
exit 73
''',
            }
            for name, body in fixtures.items():
                target = commands / name
                target.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
                target.chmod(0o700)
            binary = commands / "clawbell"
            binary.write_text('''#!/usr/bin/env python3
import shutil
import sys
from pathlib import Path
assert sys.argv[1:3] == ['unbind', '--config']
config = Path(sys.argv[3])
shutil.copyfile(config.with_name('original.json'), config)
''')
            binary.chmod(0o700)
            (root / "scripts/install.sh").write_text('''python3 - "$2" <<'PY'
import json
import os
import sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({'mcpServers': {'fixture': {
    'command': os.environ['CLAWBELL_FIXTURE_BINARY']}}}))
PY
''')
            environment = os.environ.copy()
            for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
                environment.pop(name, None)
            environment.update(PATH=f"{commands}:{os.defpath}", CLAWBELL_DISPOSABLE_HOST="yes",
                               CLAWBELL_FIXTURE_DATA=str(data), CLAWBELL_FIXTURE_BINARY=str(binary))
            result = subprocess.run(["bash", str(script)], cwd=root, env=environment,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 73, result.stderr)
            self.assertIn("user_manager_session_verified", result.stdout)
            self.assertFalse(data.exists(), "the gate must clean up its temporary configuration")

    def test_exclusive_write_preserves_owner_data_and_refuses_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "policy"
            INSTALLER.exclusive(target, b"original")
            INSTALLER.exclusive(target, b"original")
            with self.assertRaises(INSTALLER.Refused):
                INSTALLER.exclusive(target, b"replacement")
            alias = root / "alias"
            alias.symlink_to(target)
            with self.assertRaises(INSTALLER.Refused):
                INSTALLER.exclusive(alias, b"replacement")
            self.assertEqual(target.read_bytes(), b"original")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_hardlink_and_writable_ancestor_refuse_without_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            INSTALLER.exclusive(target, b"original")
            (root / "hardlink").hardlink_to(target)
            with self.assertRaises(INSTALLER.Refused):
                INSTALLER.exclusive(target, b"original")
            root.chmod(0o777)
            with self.assertRaises(INSTALLER.Refused):
                INSTALLER.exclusive(root / "new", b"new")
            self.assertFalse((root / "new").exists())
            root.chmod(0o700)

    def test_unknown_distribution_never_invokes_package_manager(self):
        with patch.object(INSTALLER, "run") as run:
            with self.assertRaises(INSTALLER.Refused):
                INSTALLER.provision_dependencies(("unknown", "1"))
            run.assert_not_called()

    def test_workspace_creation_refuses_link_traversal_without_creating_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "destination"
            destination.mkdir(mode=0o700)
            (root / "alias").symlink_to(destination, target_is_directory=True)
            with self.assertRaises(INSTALLER.Refused):
                INSTALLER.directory(root / "alias/nested")
            self.assertFalse((destination / "nested").exists())
            created = INSTALLER.directory(root / "private/nested")
            self.assertEqual(created.stat().st_mode & 0o777, 0o700)
            self.assertEqual(created.parent.stat().st_mode & 0o777, 0o700)

    def test_subprocess_failure_never_discloses_output(self):
        errors = [
            (subprocess.CalledProcessError(17, ["synthetic-private-argument"],
                                          output=b"synthetic-private-output",
                                          stderr=b"synthetic-private-error"), "exit_17"),
            (subprocess.TimeoutExpired(["synthetic-private-argument"], 1,
                                       output=b"synthetic-private-output"), "timeout"),
            (OSError("synthetic-private-path"), "spawn_failed"),
        ]
        for error, status in errors:
            with self.subTest(status=status):
                output = io.StringIO()
                with patch.object(subprocess, "run", side_effect=error), contextlib.redirect_stderr(output):
                    with self.assertRaises(INSTALLER.Refused) as caught:
                        INSTALLER.run(["synthetic-private-argument"], step="containment_probe")
                self.assertEqual(str(caught.exception),
                                 f"installer_step_failed; step=containment_probe; status={status}")
                self.assertEqual(output.getvalue(), "installer_step=containment_probe\n")

    def test_invalid_diagnostic_step_never_executes_or_prints(self):
        output = io.StringIO()
        with patch.object(subprocess, "run") as run, contextlib.redirect_stderr(output):
            with self.assertRaises(INSTALLER.Refused):
                INSTALLER.run(["fixture"], step="synthetic-private-path\n")
            run.assert_not_called()
        self.assertEqual(output.getvalue(), "")

    def test_service_prepares_controllers_on_every_boot(self):
        unit = INSTALLER.service(Path('/private/owner% name/"delegate.py')).decode()
        self.assertIn('DelegateSubgroup=supervisor', unit)
        self.assertIn('ExecStartPost=/usr/bin/python3 "/private/owner%% name/\\"delegate.py"', unit)
        self.assertIn('Restart=on-failure', unit)
        compile(INSTALLER.DELEGATE, "delegate.py", "exec")

    def test_pipeline_starts_user_manager_before_verify_and_never_binds_failed_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "owner"
            home.mkdir(mode=0o700)
            base = home / ".local/share/clawbell"
            base.mkdir(parents=True, mode=0o700)
            cargo = base / "cargo"
            cargo.mkdir(mode=0o700)
            (cargo / "bin").mkdir(mode=0o700)
            (cargo / "bin/rustup").write_bytes(b"synthetic-tool-fixture")
            source = root / "source"
            source.mkdir()
            (source / "Cargo.toml").write_text('[workspace.package]\nversion="0.1.1"\n')
            (source / "rust-toolchain.toml").write_text('[toolchain]\nchannel="1.99.1"\n')
            (source / "policies").mkdir()
            (source / "policies/default.toml").write_text('version="test"\n')
            built = source / "target/install-build/release"
            built.mkdir(parents=True)
            (built / "clawbell").write_bytes(b"synthetic-binary-fixture")
            config = home / "client.json"
            config.write_text('{"mcpServers":{}}')
            commands = []

            def run(arguments, **_options):
                commands.append(arguments)
                if arguments == ["/usr/bin/bwrap", "--help"]:
                    return b"--ro-bind-fd --disable-userns"
                if arguments[:3] == ["systemctl", "--user", "show"]:
                    return b"/synthetic.slice/clawbell.service\n"
                if "--self-test" in arguments:
                    raise INSTALLER.Refused("installer_synthetic_probe_failure")
                return b""

            with patch.object(INSTALLER, "ROOT", source), patch.object(Path, "home", return_value=home), \
                    patch.object(INSTALLER.platform, "freedesktop_os_release", return_value={"ID": "fedora", "VERSION_ID": "44"}), \
                    patch.object(sys, "argv", ["install.py", "--config", str(config)]), \
                    patch.object(INSTALLER, "run", side_effect=run):
                with self.assertRaises(INSTALLER.Refused):
                    INSTALLER.main()
            start = next(i for i, command in enumerate(commands) if command[:3] == ["sudo", "systemctl", "start"])
            verify = next(i for i, command in enumerate(commands) if command[:3] == ["systemd-analyze", "--user", "verify"])
            self.assertLess(start, verify)
            self.assertFalse(any(len(command) > 1 and command[1] == "init" for command in commands))
            self.assertEqual(config.read_text(), '{"mcpServers":{}}')


if __name__ == "__main__":
    unittest.main()
