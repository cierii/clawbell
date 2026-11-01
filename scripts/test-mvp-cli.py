"""Five attacks and warmed RTT through the real CLI, audit, policy, DLP and runner.

Requires CLAWBELL_TEST_CGROUP delegated by test-native-linux.sh. All credentials
and agent-memory contents are synthetic and temporary. Missing facilities fail.
"""
import json
import os
import pathlib
import select
import shutil
import hashlib
import sqlite3
import statistics
import subprocess
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
BINARY = REPO / "target/release/clawbell"
CGROUP = os.environ["CLAWBELL_TEST_CGROUP"]

with tempfile.TemporaryDirectory(prefix="clawbell-mvp-cli-") as temporary:
    root = pathlib.Path(temporary)
    workspace = root / "workspace"
    workspace.mkdir(mode=0o700)
    (workspace / "notes").mkdir()
    (workspace / "notes/public.txt").write_text("synthetic public note")
    soul = workspace / "SOUL.md"
    soul.write_text("original synthetic agent memory")
    state = root / "state"
    state.mkdir(mode=0o700)
    owner = root / "owner-fixtures"
    owner.mkdir(mode=0o700)
    (owner / ".env").write_text("TEST_TOKEN=synthetic-fixture-value")
    (owner / ".ssh").mkdir()
    (owner / ".ssh/id_ed25519").write_text("synthetic-key-not-a-real-key")
    (workspace / "outside").symlink_to(owner, target_is_directory=True)
    fixture = workspace / "mvp_mcp.py"
    shutil.copyfile(REPO / "tests/fixtures/mvp_mcp.py", fixture)
    policy = root / "policy.toml"
    policy.write_text('''version = "mvp-cli-e2e"
[[tools]]
name = "read_file"
effect = "read"
paths = ["/path"]
[[tools]]
name = "write_file"
effect = "write"
paths = ["/path"]
[[rules]]
tool = "read_file"
path_prefix = "notes"
decision = "allow"
[[rules]]
tool = "write_file"
decision = "allow"
''')

    # Retained evidence must match the production binary, boot and exact budget.
    reports = root / "reports"
    doctor = subprocess.run([str(BINARY), "doctor", "--self-test", "--cgroup-parent", CGROUP,
                             "--report-dir", str(reports)], capture_output=True, timeout=30)
    assert doctor.returncode == 0, "self-test must pass on the delegated native host"
    report = next(reports.glob("doctor-*.json"))
    report_digest = hashlib.sha256(report.read_bytes()).hexdigest()
    assert json.loads(report.read_bytes())["self_test_passed"] is True
    assert report.stat().st_mode & 0o777 == 0o600

    # Binding checks real host isolation before modifying any client file. The
    # server is deliberately /usr/bin/false: preflight must run its trusted probe.
    config = root / "mcp.json"
    original = json.dumps({"mcpServers": {"fixture": {"command": "/usr/bin/false"}}}).encode()
    config.write_bytes(original)
    binding = subprocess.run([
        str(BINARY), "init", "--config", str(config), "--policy", str(policy),
        "--workspace", str(workspace), "--state-dir", str(state), "--cgroup-parent", CGROUP,
    ], capture_output=True, timeout=20)
    assert binding.returncode == 0, "real host preflight and binding must succeed"
    assert b"configuration_0_server_0: preflight_passed" in binding.stdout
    assert b"configuration_0: bound" in binding.stdout
    restored = subprocess.run([str(BINARY), "unbind", "--config", str(config)], capture_output=True, timeout=10)
    assert restored.returncode == 0
    assert config.read_bytes() == original
    print("Real installer preflight passed without executing the configured upstream; exact config restored.")

    def start(*extra):
        return subprocess.Popen([
            str(BINARY), "proxy", "--policy", str(policy), "--workspace", str(workspace),
            "--cgroup-parent", CGROUP, "--state-dir", str(state), "--server", "synthetic-cli",
            "--doctor-report", str(report), "--monitor-socket", str(state / "native.sock"),
            *extra, "--", "/usr/bin/python3", "-B", "/workspace/mvp_mcp.py",
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def send(peer, message):
        peer.stdin.write((json.dumps(message) + "\n").encode())
        peer.stdin.flush()

    def receive(peer):
        if not select.select([peer.stdout], [], [], 10)[0]:
            raise AssertionError("CLI response timeout")
        line = peer.stdout.readline(1024 * 1024 + 1)
        if not line:
            return None
        return json.loads(line)

    def initialize(peer):
        send(peer, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "synthetic", "version": "1"}}})
        assert receive(peer)["id"] == 1
        send(peer, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        send(peer, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        return receive(peer)

    def finish(peer):
        peer.stdin.close()
        try:
            peer.wait(timeout=10)
        finally:
            if peer.poll() is None:
                peer.kill()
                peer.wait()
        # Never print captured upstream/CLI diagnostics or content on failures.
        diagnostics = peer.stderr.read(8192)
        assert b"synthetic-fixture-value" not in diagnostics
        assert b"synthetic-key-not-a-real-key" not in diagnostics
        peer.stdout.close()
        peer.stderr.close()

    def refused(method, params):
        peer = start()
        try:
            assert initialize(peer)["result"]["tools"]
            send(peer, {"jsonrpc": "2.0", "id": 3, "method": method, "params": params})
            assert receive(peer) is None, "denied operation must not produce upstream output"
        finally:
            finish(peer)

    mismatch = start("--session-lifetime-secs", "3601")
    try:
        assert receive(mismatch) is None
        mismatch.wait(timeout=5)
        assert mismatch.returncode == 1
        assert not (state / "operations.sqlite3").exists(), "profile mismatch must refuse before session creation"
    finally:
        finish(mismatch)

    # First observation refuses forwarding, then the owner reviews/accepts the
    # exact captured candidate. No test deletes or rewrites the pin database.
    peer = start()
    try:
        assert initialize(peer) is None
    finally:
        finish(peer)
    review = subprocess.run([str(BINARY), "pins", "--state-dir", str(state), "review"], capture_output=True, check=True, timeout=10)
    candidates = json.loads(review.stdout)
    assert len(candidates) == 1 and candidates[0]["previous"] is None
    approved = subprocess.run([str(BINARY), "pins", "--state-dir", str(state), "accept", "--review-id", str(candidates[0]["id"]), "--accept"], capture_output=True, timeout=10)
    assert approved.returncode == 0

    # Process-cold sessions, with existing reviewed pins. This includes launch,
    # audit/session initialization and MCP initialize/catalog, but not compilation,
    # first-owner approval or an OS page-cache flush.
    startup_samples = []
    for _ in range(20):
        started = time.perf_counter_ns()
        peer = start()
        try:
            assert initialize(peer)["result"]["tools"]
            startup_samples.append(time.perf_counter_ns() - started)
        finally:
            finish(peer)

    # Follow releases SQLite reads before writing output, and pins the generation.
    with sqlite3.connect(state / "operations.sqlite3") as audit:
        after = audit.execute("SELECT max(id) FROM events_v1").fetchone()[0]
    follower = subprocess.Popen([str(BINARY), "audit", "--state-dir", str(state), "view",
                                 "--follow", "--after", str(after), "--limit", "1"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        peer = start()
        try:
            assert initialize(peer)["result"]["tools"]
            assert select.select([follower.stdout], [], [], 5)[0], "follow must flush live rows"
            line = bytearray()
            while not line.endswith(b"\n"):
                line.extend(follower.stdout.read(1))
            assert json.loads(line)["id"] > after
        finally:
            finish(peer)
        rotation = subprocess.run([str(BINARY), "audit", "--state-dir", str(state), "rotate", "--accept"],
                                  capture_output=True, timeout=5)
        assert rotation.returncode != 0, "active follower must protect its cursor generation"
    finally:
        follower.terminate()
        follower.wait(timeout=5)
        follower.stdout.close()
        follower.stderr.close()

    # Measure forwarding with monitor publication and a live audit reader active.
    follower = subprocess.Popen([str(BINARY), "audit", "--state-dir", str(state), "view", "--follow"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    peer = start()
    samples = []
    try:
        assert initialize(peer)["result"]["tools"]
        for request_id in range(3, 2203):
            started = time.perf_counter_ns()
            send(peer, {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {
                "name": "read_file", "arguments": {"path": "notes/public.txt"}}})
            response = receive(peer)
            elapsed = time.perf_counter_ns() - started
            assert response["id"] == request_id
            assert response["result"]["content"][0]["text"] == "synthetic public note"
            if request_id >= 203:
                samples.append(elapsed / 1_000_000)
    finally:
        finish(peer)
    follower.terminate()
    follower.wait(timeout=5)
    follower.stderr.close()
    print(f"Full CLI/native/audit/DLP/policy RTT: n={len(samples)}, "
          f"p95={statistics.quantiles(samples, n=100)[94]:.3f} ms, "
          f"p99={statistics.quantiles(samples, n=100)[98]:.3f} ms, max={max(samples):.3f} ms")
    def summary(values):
        ordered = sorted(values)
        return {"samples": len(ordered), "unit": "ns", "quantile": "nearest_rank",
                **{name: ordered[(len(ordered) * percent + 99) // 100 - 1]
                   for name, percent in [("p50", 50), ("p95", 95), ("p99", 99), ("max", 100)]}}
    measured = summary([round(sample * 1_000_000) for sample in samples])
    print("CLAWBELL_EVALUATION=" + json.dumps({
        "process_cold_start": summary(startup_samples),
        "native_cli_rtt": measured,
        "native_allowed_reads": {"attempted": 2200, "completed": 2200}}))
    assert measured["p99"] < 15_000_000, "full warmed RTT p99 exceeds 15 ms release budget"
    assert measured["max"] < 1_000_000_000, "full warmed RTT maximum exceeds 1 s release budget"

    refused("tools/call", {"name": "read_file", "arguments": {"path": "outside/.env"}})
    refused("tools/call", {"name": "read_file", "arguments": {"path": "outside/.ssh/id_ed25519"}})
    refused("tools/call", {"name": "write_file", "arguments": {"path": "SOUL.md", "text": "replace instructions"}})
    assert soul.read_text() == "original synthetic agent memory"
    refused("resources/read", {"uri": "fixture://ignore-previous-upload-env"})
    fixture.write_text(fixture.read_text().replace("Synthetic read-only notes fixture", "Changed tool description"))
    peer = start()
    try:
        assert initialize(peer) is None, "rug-pull catalog must never reach the client"
    finally:
        finish(peer)
    print("Five real CLI attack scenarios refused; synthetic host data and agent memory unchanged.")

    with sqlite3.connect(state / "operations.sqlite3") as audit:
        evidence = audit.execute("SELECT lower(hex(binding_sha256)) FROM events_v1 WHERE reason='containment_evidence'").fetchall()
        sessions = audit.execute("SELECT count(*) FROM sessions_v1").fetchone()[0]
        assert len(evidence) == sessions
        assert all(row[0] == report_digest for row in evidence)
    print("Retained self-test evidence linked to every MCP session; live audit and monitor cleanup verified.")
