"""Reject incomplete, foreign and over-budget publication evidence."""
import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from evaluate import ROOT, EvaluationFailure, execute, failure_metrics, source_fingerprint


class EvaluationTests(unittest.TestCase):
    def test_failed_command_preserves_only_numeric_packet_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "measurement.log"
            output = io.StringIO()
            script = '''import sys
print('synthetic-private-output')
print('CLAWBELL_EVALUATION={"native_cli_rtt":{"unit":"ns","max":6000000,"secret":"synthetic-private-field"}}')
sys.exit(17)
'''
            with contextlib.redirect_stdout(output), self.assertRaises(EvaluationFailure) as caught:
                execute([sys.executable, "-c", script], log)
            self.assertEqual(str(caught.exception), "evaluation_command_failed; status=exit_17")
            self.assertEqual(output.getvalue(),
                             "evaluation_failed_packet_metric; metric=native_cli_rtt; max_ns=6000000\n")
            self.assertIn("synthetic-private-output", log.read_text())
            self.assertFalse((Path(temporary) / "report.json").exists())

    def test_failed_metrics_refuse_unknown_malformed_and_non_integer_fields(self):
        fragments = [None, [], {"unknown": {"unit": "ns", "max": 6000000}}]
        fragments.extend({"gate_packet": {"unit": unit, "max": value}}
                         for unit, value in [("secret", 1), ("ns", "synthetic-private-value"),
                                             ("ns", True), ("ns", -1), ("ns", 2**63), ("ns", 1.5)])
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "measurement.log"
            log.write_text("CLAWBELL_EVALUATION=malformed\n" + "\n".join(
                "CLAWBELL_EVALUATION=" + json.dumps(fragment) for fragment in fragments))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                failure_metrics(log)
                failure_metrics(log.with_name("missing.log"))
            self.assertEqual(output.getvalue(), "")
            for error, status in [(subprocess.TimeoutExpired(["synthetic-private-argv"], 1), "timeout"),
                                  (OSError("synthetic-private-path"), "spawn_failed")]:
                with patch("evaluate.subprocess.run", side_effect=error), \
                        self.assertRaises(EvaluationFailure) as caught:
                    execute(["synthetic-private-argv"], log)
                self.assertEqual(str(caught.exception), "evaluation_command_failed; status=" + status)

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
                for maximum, accepted in [(5_000_000, True), (9_999_999, True),
                                          (10_000_000, True), (405_653_223, True),
                                          (999_999_999, True), (1_000_000_000, False),
                                          (1_000_000_001, False)]:
                    with self.subTest(metric=metric, maximum=maximum):
                        candidate = copy.deepcopy(report)
                        candidate["metrics"][metric]["max"] = maximum
                        self.assertEqual(check(candidate) == 0, accepted)
            for metric in ("gate_packet", "native_cli_rtt"):
                for percentile, accepted in [(10_000_000, True), (12_136_041, True),
                                             (14_999_999, True), (15_000_000, False),
                                             (15_000_001, False)]:
                    with self.subTest(metric=metric, p99=percentile):
                        candidate = copy.deepcopy(report)
                        candidate["metrics"][metric].update(p99=percentile, max=999_999_999)
                        self.assertEqual(check(candidate) == 0, accepted)
            candidate = copy.deepcopy(report)
            candidate["metrics"]["native_allowed_reads"]["completed"] -= 1
            self.assertNotEqual(check(candidate), 0)
            candidate = copy.deepcopy(report)
            candidate["metrics"]["benign_corpus"]["dlp_false_alarms"] -= 1
            self.assertNotEqual(check(candidate), 0)


if __name__ == "__main__":
    unittest.main()
