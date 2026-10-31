"""Host-write refusal and provisioning contract tests; no sudo or network."""
import importlib.util
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
        error = subprocess.CalledProcessError(1, ["fixture"], stderr=b"synthetic-private-value")
        with patch.object(subprocess, "run", side_effect=error):
            with self.assertRaises(INSTALLER.Refused) as caught:
                INSTALLER.run(["fixture"])
        self.assertEqual(str(caught.exception), "installer_step_failed")

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
