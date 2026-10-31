"""Run real release measurements; publish only fixed, payload-free metric fields.

Requires the pinned Rust toolchain in PATH, a Linux systemd user session and native
containment prerequisites. Logs remain under ignored target/evaluation. A failed
command or latency gate prevents publication of a report. This does not flush
the OS page cache, time human approval, or claim a population-wide DLP rate.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
PREFIX = "CLAWBELL_EVALUATION="


def source_fingerprint():
    """Hash relevant source bytes, including this session's unstaged source edits."""
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT)
    digest = hashlib.sha256()
    for name in sorted(set(names.split(b"\0")) - {b""}):
        relative = name.decode()
        if relative.startswith(("crates/", "scripts/", ".github/", "policies/", "tests/")) or relative in (
                "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "AGENTS.md"):
            digest.update(name + b"\0" + (ROOT / relative).read_bytes() + b"\0")
    return digest.hexdigest()


def execute(arguments, log, timeout=1800):
    with log.open("wb") as output:
        subprocess.run(arguments, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                       check=True, timeout=timeout)
    return log.read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/evaluation/report.json")
    options = parser.parse_args()
    if options.output.exists() or options.output.is_symlink():
        raise SystemExit("evaluation_output_already_exists")
    if platform.system() != "Linux":
        raise SystemExit("evaluation_requires_native_linux")
    os.umask(0o077)
    logs = ROOT / "target/evaluation"
    logs.mkdir(parents=True, exist_ok=True)
    before = source_fingerprint()
    execute(["cargo", "build", "--release", "--locked", "-p", "clawbell"], logs / "build.log")
    commands = [
        ["cargo", "test", "--locked", "--release", "-p", "clawbell",
         "complete_mvp_gate_packets_under_five_ms", "--", "--ignored", "--nocapture"],
        ["cargo", "test", "--locked", "--release", "-p", "clawbell",
         "release_evaluation_corpus_and_durable_audit", "--", "--ignored", "--nocapture"],
        ["systemd-run", "--user", "--scope", "-p", "Delegate=yes", "bash", "scripts/test-native-linux.sh"],
    ]
    metrics = {}
    for index, command in enumerate(commands):
        output = execute(command, logs / f"measurement-{index}.log")
        for line in output.splitlines():
            if line.startswith(PREFIX):
                fragment = json.loads(line[len(PREFIX):])
                if metrics.keys() & fragment.keys():
                    raise ValueError("duplicate_evaluation_metric")
                metrics.update(fragment)
    required = {"gate_packet", "benign_corpus", "durable_audit_intent", "durable_audit_response",
                "process_cold_start", "native_cli_rtt", "native_allowed_reads"}
    if metrics.keys() != required or source_fingerprint() != before:
        raise ValueError("evaluation_incomplete_or_source_changed")
    corpus = metrics["benign_corpus"]
    corpus["completion_rate"] = corpus["completed_unchanged"] / corpus["workflows"]
    corpus["false_alarm_rate"] = corpus["dlp_false_alarms"] / corpus["workflows"]
    report = {
        "schema_version": 1,
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_fingerprint_sha256": before,
        "source_base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
        "binary_sha256": hashlib.sha256((ROOT / "target/release/clawbell").read_bytes()).hexdigest(),
        "environment": {"os": platform.system(), "kernel": platform.release(), "architecture": platform.machine(),
                        "rust": subprocess.check_output(["rustc", "--version"]).decode().strip(),
                        "filesystem": subprocess.check_output(["stat", "-f", "--format=%T", str(logs)]).decode().strip(),
                        "audit_filesystem": subprocess.check_output(
                            ["stat", "-f", "--format=%T", tempfile.gettempdir()]).decode().strip()},
        "metrics": metrics,
        "limitations": [
            "Synthetic deterministic read-tool corpus, not representative field completion or DLP incidence.",
            "Process-cold startup with warm OS caches and already accepted pins; excludes build and owner approval.",
            "Audit cost is separately timed production queue/transaction/FULL fsync acknowledgement per event, not a subtraction.",
            "Warm bounded packets; no hard real-time claim under arbitrary host contention or maximum-size inputs.",
            "Native macOS, Windows and AArch64 results require execution on those hosts and are not inferred here.",
        ],
    }
    options.output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive publication prevents replacing an owner's report accidentally.
    with options.output.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print("evaluation_complete; report_written")


if __name__ == "__main__":
    main()
