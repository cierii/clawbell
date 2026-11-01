"""Install an authenticated Linux release for a bounded, offline CLI trial.

Requires Python 3.11+ and an authenticated GitHub CLI supporting attestations.
No source compilation, host provisioning, client binding or policy grants occur.
The 55-second deadline includes downloads and verification; slow/unavailable
services refuse rather than bypassing authenticity or claiming successful setup.
"""
import argparse
import hashlib
import importlib.util
import platform
import re
import signal
import subprocess
import tarfile
import tempfile
from pathlib import Path

REPOSITORY = "cierii/clawbell"
SPEC = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install.py"))
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def run(arguments):
    """Bound child lifetime; never expose remote content, paths or stderr."""
    return subprocess.run(arguments, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=45).stdout


def install(version):
    """Verify archive provenance/SBOM/checksum before reading or executing it."""
    if not re.fullmatch(r"0\.[0-9]+\.[0-9]+", version):
        raise INSTALLER.Refused("release_version_refused")
    architecture = platform.machine()
    if platform.system() != "Linux" or architecture not in ("x86_64", "aarch64"):
        raise INSTALLER.Refused("release_platform_refused")
    tag = "v" + version
    name = f"clawbell-{version}-linux-{architecture}"
    with tempfile.TemporaryDirectory(prefix="clawbell-release-") as temporary:
        root = Path(temporary)
        archive = root / (name + ".tar.gz")
        run(["gh", "release", "download", tag, "--repo", REPOSITORY,
             "--pattern", archive.name, "--pattern", archive.name + ".sha256",
             "--dir", str(root)])
        if archive.stat().st_size > 64 * 1024 * 1024:
            raise INSTALLER.Refused("release_size_refused")
        checksum = archive.with_name(archive.name + ".sha256").read_text()
        expected = hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n"
        if checksum != expected:
            raise INSTALLER.Refused("release_checksum_failed")
        verify = ["gh", "attestation", "verify", str(archive), "--repo", REPOSITORY,
                  "--signer-workflow", REPOSITORY + "/.github/workflows/ci.yml",
                  "--source-ref", "refs/tags/" + tag]
        run(verify)
        run([*verify, "--predicate-type", "https://cyclonedx.org/bom"])
        # Never extract archive paths, links, permissions or special files.
        with tarfile.open(archive, "r:gz") as package:
            members = [member for member in package if member.name == name + "/clawbell"]
            if len(members) != 1 or not members[0].isreg() or not 0 < members[0].size <= 128 * 1024 * 1024:
                raise INSTALLER.Refused("release_binary_refused")
            with package.extractfile(members[0]) as source:
                data = source.read()
        candidate = root / "clawbell"
        INSTALLER.exclusive(candidate, data, 0o700)
        if run([str(candidate), "--version"]).strip() != f"clawbell {version}".encode():
            raise INSTALLER.Refused("release_identity_failed")
        run([str(candidate), "--help"])
        # Exercise the real offline inspector before committing the installation.
        fixture = root / "public.md"
        fixture.write_text("Public documentation for a local example.\n")
        run([str(candidate), "scan", str(fixture)])
        destination = INSTALLER.directory(Path.home() / ".local/share/clawbell/releases" / version)
        INSTALLER.exclusive(destination / "clawbell", data, 0o700)
    print("release_installed; cli_trial_passed; client_binding_requires_host_setup")


def deadline(_signal, _frame):
    """Abort without treating a timeout as successful verification."""
    raise INSTALLER.Refused("release_deadline_exceeded")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Exact reviewed release, e.g. 0.1.3")
    arguments = parser.parse_args()
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(55)
    try:
        install(arguments.version)
    except (INSTALLER.Refused, OSError, subprocess.SubprocessError, tarfile.TarError, ValueError):
        raise SystemExit("release_install_refused; no_security_fallback") from None
    finally:
        signal.alarm(0)
