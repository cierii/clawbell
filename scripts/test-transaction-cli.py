"""Production transactional proxy: native containment, owner IPC and publication.

All content and credentials are synthetic. Requires delegated native enforcement;
missing facilities fail. Never prints packet contents or captured diagnostics.
"""
import json
import os
import pathlib
import select
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
BINARY = REPO / "target/release/clawbell"
CGROUP = os.environ["CLAWBELL_TEST_CGROUP"]


def receive(peer):
    assert select.select([peer.stdout], [], [], 15)[0], "transaction response timeout"
    line = peer.stdout.readline(1024 * 1024 + 1)
    return json.loads(line) if line else None


def send(peer, message):
    peer.stdin.write((json.dumps(message) + "\n").encode())
    peer.stdin.flush()


with tempfile.TemporaryDirectory(prefix="clawbell-transaction-cli-", dir=REPO / "target") as temporary:
    root = pathlib.Path(temporary)
    workspace = root / "workspace"
    state = root / "state"
    journal = root / "journal"
    for directory in [workspace, state, journal]:
        directory.mkdir(mode=0o700)
    (workspace / "notes").mkdir()
    target = workspace / "notes/public.txt"
    target.write_text("synthetic original")
    soul = workspace / "SOUL.md"
    soul.write_text("synthetic protected memory")
    (workspace / "mode").write_text("stable")
    shutil.copyfile(REPO / "tests/fixtures/transaction_mcp.py", workspace / "server.py")
    policy = root / "policy.toml"
    policy.write_text('''version = "transaction-cli-v1"
[[tools]]
name = "read_file"
effect = "read"
paths = ["/path"]
[[tools]]
name = "write_file"
effect = "write"
paths = ["/path"]
[[tools]]
name = "clawbell.commit"
effect = "write"
paths = ["/path"]
[[rules]]
tool = "read_file"
path_prefix = "notes"
decision = "allow"
[[rules]]
tool = "write_file"
path_prefix = "notes"
decision = "allow"
[[rules]]
tool = "clawbell.commit"
path_prefix = "notes"
decision = "require_approval"
''')
    endpoint = root / "owner.sock"

    def start():
        if endpoint.exists():
            endpoint.unlink()  # Test owner explicitly removes the stopped socket.
        peer = subprocess.Popen([
            str(BINARY), "proxy-transaction", "--policy", str(policy),
            "--workspace", str(workspace), "--state-dir", str(state),
            "--journal-dir", str(journal), "--cgroup-parent", CGROUP,
            "--monitor-socket", str(endpoint), "--server", "synthetic-transaction",
            "--", "/usr/bin/python3", "-B", "/workspace/server.py",
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while not endpoint.exists():
            assert peer.poll() is None, "transaction proxy startup refused"
            assert time.monotonic() < deadline, "owner endpoint timeout"
            time.sleep(0.01)
        owner = socket.socket(socket.AF_UNIX)
        owner.settimeout(15)
        owner.connect(str(endpoint))
        return peer, owner, owner.makefile("rwb", buffering=0)

    def initialize(peer):
        send(peer, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "fixture", "version": "1"}}})
        assert receive(peer)["id"] == 1
        send(peer, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        send(peer, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        return receive(peer)

    def finish(peer, owner, stream):
        stream.close()
        owner.close()
        if not peer.stdin.closed:
            peer.stdin.close()
        try:
            peer.wait(timeout=15)
        finally:
            if peer.poll() is None:
                peer.kill()
                peer.wait()
        diagnostics = peer.stderr.read()
        assert b"synthetic original" not in diagnostics
        assert b"synthetic protected memory" not in diagnostics
        peer.stdout.close()
        peer.stderr.close()

    def request(peer, text, request_id=3):
        send(peer, {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                    "params": {"name": "write_file", "arguments": {
                        "path": "notes/public.txt", "text": text}}})

    def review(stream):
        while True:
            event = json.loads(stream.readline())
            if event["id"]:
                context = json.loads(event["display"])
                assert context["kind"] == "file_publication"
                assert len(context["digest"]) == 64
                assert "synthetic original" in context["preview"]
                return event["id"]

    # TOFU never implicitly accepts a first observation.
    peer, owner, stream = start()
    try:
        assert initialize(peer) is None
    finally:
        finish(peer, owner, stream)
    candidates = json.loads(subprocess.check_output([
        str(BINARY), "pins", "--state-dir", str(state), "review"]))
    assert len(candidates) == 1
    subprocess.run([str(BINARY), "pins", "--state-dir", str(state), "accept",
                    "--review-id", str(candidates[0]["id"]), "--accept"],
                   capture_output=True, check=True)

    for attack in ["attack-hidden", "attack-symlink", "attack-error", "attack-binary"]:
        peer, owner, stream = start()
        try:
            assert initialize(peer)["result"]["tools"]
            request(peer, attack)
            assert receive(peer) is None
        finally:
            finish(peer, owner, stream)
        assert target.read_text() == "synthetic original"
        assert soul.read_text() == "synthetic protected memory"
        assert not (journal / "publication.journal").exists()

    # Metadata observed in discovery must match the fresh per-call process.
    peer, owner, stream = start()
    try:
        assert initialize(peer)["result"]["tools"]
        (workspace / "mode").write_text("catalog-drift")
        request(peer, "synthetic forbidden drift")
        assert receive(peer) is None
    finally:
        finish(peer, owner, stream)
        (workspace / "mode").write_text("stable")
    assert target.read_text() == "synthetic original"

    (workspace / "mode").write_text("read-lie")
    peer, owner, stream = start()
    try:
        assert initialize(peer)["result"]["tools"]
        send(peer, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": "notes/public.txt"}}})
        assert receive(peer) is None
    finally:
        finish(peer, owner, stream)
        (workspace / "mode").write_text("stable")
    assert target.read_text() == "synthetic original"

    operation_samples = []
    for decision in ["deny", "disconnect", "conflict", "approve"]:
        peer, owner, stream = start()
        try:
            assert initialize(peer)["result"]["tools"]
            started = time.perf_counter_ns()
            send(peer, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "read_file", "arguments": {"path": "notes/public.txt"}}})
            assert receive(peer)["result"]["content"][0]["text"] == "synthetic original"
            operation_samples.append((time.perf_counter_ns() - started) / 1_000_000)
            request(peer, "synthetic approved", 4)
            review_id = review(stream)
            assert target.read_text() == "synthetic original"
            assert not select.select([peer.stdout], [], [], 0.05)[0], "result disclosed before approval"
            if decision == "disconnect":
                peer.stdin.close()
                # Even a late affirmative owner reply cannot publish after EOF.
                time.sleep(0.1)
                try:
                    stream.write((json.dumps({"id": review_id, "allow": True}) + "\n").encode())
                except (BrokenPipeError, ConnectionResetError):
                    pass
                assert receive(peer) is None
            else:
                if decision == "conflict":
                    target.write_text("synthetic external owner edit")
                stream.write((json.dumps({"id": review_id, "allow": decision != "deny"}) + "\n").encode())
                response = receive(peer)
                if decision == "approve":
                    assert response["id"] == 4
                    assert target.read_text() == "synthetic approved"
                    assert (journal / "publication.journal").exists()
                    request(peer, "synthetic second publication", 5)
                    # Review is offered, but the existing durable journal refuses reuse.
                    while True:
                        event = json.loads(stream.readline())
                        if event["id"]:
                            stream.write((json.dumps({"id": event["id"], "allow": True}) + "\n").encode())
                            break
                    assert receive(peer) is None
                    assert target.read_text() == "synthetic approved"
                else:
                    assert response is None
        finally:
            finish(peer, owner, stream)
        if decision != "approve":
            expected = "synthetic external owner edit" if decision == "conflict" else "synthetic original"
            assert target.read_text() == expected
            assert not (journal / "publication.journal").exists()
            target.write_text("synthetic original")

    with sqlite3.connect(state / "operations.sqlite3") as db:
        published = db.execute("SELECT correlation FROM events_v1 WHERE outcome='effect_published'").fetchall()
        assert len(published) == 1
        chain = db.execute("SELECT outcome,length(binding_sha256) FROM events_v1 WHERE id=? OR correlation=? ORDER BY id",
                           (published[0][0], published[0][0])).fetchall()
        assert [event[0] for event in chain] == ["allow_intent", "candidate_inspected", "owner_review", "owner_approved", "effect_published", "response_received"]
        assert chain[0][1] == 32 and chain[2][1] == 32
    assert soul.read_text() == "synthetic protected memory"
    print(f"Transactional read lifecycle (snapshot/start/replay/inspect/reap/audit): n={len(operation_samples)}, min={min(operation_samples):.3f} ms, max={max(operation_samples):.3f} ms; separate from packet overhead.")
    print("Transactional CLI: private execution, actual-diff approval, publication, audit and ten refusal/recovery scenarios passed.")
