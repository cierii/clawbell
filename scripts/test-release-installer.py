"""Synthetic release tests: verification failures must never install or execute."""
import hashlib
import importlib.util
import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("release", Path(__file__).with_name("install-release.py"))
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class ReleaseTests(unittest.TestCase):
    def exercise(self, failure=None, member_type=tarfile.REGTYPE):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            commands = []
            name = "clawbell-0.1.3-linux-x86_64"

            def run(arguments):
                commands.append(arguments)
                if arguments[1:3] == ["release", "download"]:
                    root = Path(arguments[-1])
                    archive = root / (name + ".tar.gz")
                    with tarfile.open(archive, "w:gz") as package:
                        member = tarfile.TarInfo(name + "/clawbell")
                        member.type = member_type
                        member.size = 6 if member_type == tarfile.REGTYPE else 0
                        member.linkname = "/etc/passwd" if member_type == tarfile.SYMTYPE else ""
                        package.addfile(member, io.BytesIO(b"binary"))
                    digest = "0" * 64 if failure == "checksum" else hashlib.sha256(archive.read_bytes()).hexdigest()
                    archive.with_name(archive.name + ".sha256").write_text(digest + "  " + archive.name + "\n")
                elif arguments[1:3] == ["attestation", "verify"]:
                    if failure == "provenance" or (failure == "sbom" and "--predicate-type" in arguments):
                        raise subprocess.CalledProcessError(1, arguments)
                elif arguments[1] == "--version":
                    return b"clawbell 0.1.3\n" if failure != "identity" else b"clawbell 0.1.0\n"
                return b""

            with patch.object(RELEASE.platform, "system", return_value="Linux"), \
                 patch.object(RELEASE.platform, "machine", return_value="x86_64"), \
                 patch.object(RELEASE.Path, "home", return_value=home), \
                 patch.object(RELEASE, "run", side_effect=run):
                if failure or member_type != tarfile.REGTYPE:
                    with self.assertRaises((RELEASE.INSTALLER.Refused, subprocess.CalledProcessError)):
                        RELEASE.install("0.1.3")
                    self.assertFalse((home / ".local").exists())
                    if failure != "identity":
                        self.assertFalse(any(c[0] != "gh" for c in commands))
                else:
                    RELEASE.install("0.1.3")
                    binary = home / ".local/share/clawbell/releases/0.1.3/clawbell"
                    self.assertEqual(binary.read_bytes(), b"binary")
                    self.assertEqual(binary.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(sum(c[1:3] == ["attestation", "verify"] for c in commands), 2)

    def test_verified_release_installs_private_binary(self):
        self.exercise()

    def test_failed_checksum_provenance_sbom_or_identity_never_installs(self):
        for failure in ("checksum", "provenance", "sbom", "identity"):
            with self.subTest(failure=failure):
                self.exercise(failure=failure)

    def test_archive_symlink_never_executes_or_installs(self):
        self.exercise(member_type=tarfile.SYMTYPE)

    def test_invalid_version_never_downloads(self):
        with patch.object(RELEASE, "run") as run:
            with self.assertRaises(RELEASE.INSTALLER.Refused):
                RELEASE.install("../../main")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
