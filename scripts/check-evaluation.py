"""Refuse an incomplete report, mismatched platform/source/binary or budget failure."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from evaluate import source_fingerprint

report_path, binary = map(Path, sys.argv[1:])
report = json.loads(report_path.read_bytes())
if (report["schema_version"] != 1
        or report["binary_sha256"] != hashlib.sha256(binary.read_bytes()).hexdigest()
        or report["environment"]["architecture"] != platform.machine()
        or report["source_fingerprint_sha256"] != source_fingerprint()
        or report["source_base_commit"] != subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()):
    raise SystemExit("evaluation_identity_mismatch")
for name in ("gate_packet", "native_cli_rtt"):
    if report["metrics"][name]["unit"] != "ns" or report["metrics"][name]["max"] >= 5_000_000:
        raise SystemExit("evaluation_packet_budget_failed")
required_counts = {"gate_packet": 4000, "native_cli_rtt": 2000, "process_cold_start": 20,
                   "durable_audit_intent": 2000, "durable_audit_response": 2000}
for name, count in required_counts.items():
    metric = report["metrics"][name]
    if (metric["samples"] != count or metric["unit"] != "ns"
            or metric["quantile"] != "nearest_rank"
            or not 0 < metric["p50"] <= metric["p95"] <= metric["p99"] <= metric["max"]):
        raise SystemExit("evaluation_measurements_incomplete")
corpus = report["metrics"]["benign_corpus"]
if (corpus["workflows"] != 20
        or corpus["completed_unchanged"] + corpus["dlp_false_alarms"] != corpus["workflows"]
        or corpus["dlp_false_refusals"] + corpus["dlp_false_redactions"] != corpus["dlp_false_alarms"]):
    raise SystemExit("evaluation_corpus_incomplete")
reads = report["metrics"]["native_allowed_reads"]
if reads != {"attempted": 2200, "completed": 2200}:
    raise SystemExit("evaluation_allowed_workflow_failed")
print("evaluation_identity_and_budget_verified")
