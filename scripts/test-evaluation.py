"""Reject incomplete, foreign and over-budget publication evidence."""
import copy
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from evaluate import ROOT, source_fingerprint


class EvaluationTests(unittest.TestCase):
    def test_publication_requires_complete_bound_measurements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "clawbell"
            binary.write_bytes(b"synthetic-binary-fixture")
            report = {
                "schema_version": 1,
                "source_base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
                "source_fingerprint_sha256": source_fingerprint(),
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "environment": {"architecture": platform.machine()},
                "metrics": {name: {"samples": samples, "unit": "ns", "quantile": "nearest_rank",
                                   "p50": 1, "p95": 2, "p99": 3, "max": 4}
                            for name, samples in [("gate_packet", 4000), ("native_cli_rtt", 2000),
                                                  ("process_cold_start", 20), ("durable_audit_intent", 2000),
                                                  ("durable_audit_response", 2000)]},
            }
            report["metrics"].update(
                benign_corpus={"workflows": 20, "completed_unchanged": 11, "dlp_false_alarms": 9,
                               "dlp_false_refusals": 7, "dlp_false_redactions": 2},
                native_allowed_reads={"attempted": 2200, "completed": 2200})

            def check(candidate):
                path = root / "report.json"
                path.write_text(json.dumps(candidate))
                return subprocess.run([sys.executable, str(ROOT / "scripts/check-evaluation.py"),
                                       str(path), str(binary)], cwd=ROOT, capture_output=True).returncode

            self.assertEqual(check(report), 0)
            for field in ("binary_sha256", "source_base_commit", "source_fingerprint_sha256"):
                with self.subTest(field=field):
                    candidate = copy.deepcopy(report)
                    candidate[field] = "0" * 64
                    self.assertNotEqual(check(candidate), 0)
            for metric in report["metrics"]:
                if "samples" not in report["metrics"][metric]:
                    continue
                with self.subTest(metric=metric):
                    candidate = copy.deepcopy(report)
                    candidate["metrics"][metric]["samples"] = 0
                    self.assertNotEqual(check(candidate), 0)
            for metric in ("gate_packet", "native_cli_rtt"):
                candidate = copy.deepcopy(report)
                candidate["metrics"][metric]["max"] = 5_000_000
                self.assertNotEqual(check(candidate), 0)
            candidate = copy.deepcopy(report)
            candidate["metrics"]["native_allowed_reads"]["completed"] -= 1
            self.assertNotEqual(check(candidate), 0)
            candidate = copy.deepcopy(report)
            candidate["metrics"]["benign_corpus"]["dlp_false_alarms"] -= 1
            self.assertNotEqual(check(candidate), 0)


if __name__ == "__main__":
    unittest.main()
