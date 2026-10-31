"""Synthetic loopback integration for HTTP deadlines and exact protocol consent.

Uses the production binary, pinned endpoint adapter, policy/DLP/audit composition
and owner Unix IPC. No provider credentials or external service are required.
"""
import http.server
import json
import pathlib
import select
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time

BINARY = pathlib.Path(__file__).resolve().parent.parent / "target/release/clawbell"
REQUESTS = []
DELAY = threading.Event()


class Upstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        message = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = message["method"]
        REQUESTS.append(method)
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if DELAY.is_set():
            time.sleep(2)
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"resources": {}, "prompts": {}},
                      "serverInfo": {"name": "synthetic", "version": "1"}}
        elif method == "prompts/list":
            result = {"prompts": [{"name": "summarize", "arguments": [{"name": "text", "required": True}]}]}
        elif method == "prompts/get":
            result = {"messages": [{"role": "user", "content": {"type": "text", "text": "public"}}]}
        else:
            result = {"contents": [{"uri": "fixture://public", "text": "public"}]}
        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def send(peer, method, params=None, request_id=2):
    message = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        message["id"] = request_id
    if params is not None:
        message["params"] = params
    peer.stdin.write(json.dumps(message).encode() + b"\n")
    peer.stdin.flush()


def receive(peer):
    assert select.select([peer.stdout], [], [], 6)[0], "HTTP CLI response timeout"
    data = peer.stdout.readline()
    return json.loads(data) if data else None


def finish(peer):
    if not peer.stdin.closed:
        peer.stdin.close()
    peer.wait(timeout=6)
    peer.stdout.close()
    peer.stderr.close()


with tempfile.TemporaryDirectory(prefix="clawbell-http-monitor-") as temporary:
    root = pathlib.Path(temporary)
    state = root / "state"
    state.mkdir(mode=0o700)
    policy = root / "policy.toml"
    policy.write_text("""version='http-monitor'
tools=[]
rules=[]
[[protocol]]
method='resources/read'
target='fixture://public'
decision='require_approval'
[[protocol]]
method='prompts/list'
decision='allow'
[[protocol]]
method='prompts/get'
target='summarize'
decision='require_approval'
""")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = state / "http.sock"

    def start(*extra):
        return subprocess.Popen([str(BINARY), "proxy-http", "--url", f"http://127.0.0.1:{server.server_port}/mcp",
                                 "--private-ip", "127.0.0.1", "--policy", str(policy),
                                 "--state-dir", str(state), "--server", "synthetic-remote",
                                 "--monitor-socket", str(endpoint), *extra],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def initialize(peer):
        send(peer, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "synthetic", "version": "1"}}, 1)
        assert receive(peer)["id"] == 1
        send(peer, "notifications/initialized", request_id=None)

    # First prompt catalog must still pass explicit owner pin review.
    peer = start()
    initialize(peer)
    send(peer, "prompts/list")
    assert receive(peer) is None
    finish(peer)
    review = subprocess.run([str(BINARY), "pins", "--state-dir", str(state), "review"],
                            capture_output=True, check=True, timeout=6)
    for proposal in json.loads(review.stdout):
        subprocess.run([str(BINARY), "pins", "--state-dir", str(state), "accept", "--review-id",
                        str(proposal["id"]), "--accept"], capture_output=True, check=True, timeout=6)

    for method, allow, disconnect in [("resources/read", True, False), ("resources/read", False, False),
                                      ("prompts/get", True, False), ("resources/read", True, True)]:
        peer = start()
        initialize(peer)
        if method == "prompts/get":
            send(peer, "prompts/list")
            assert receive(peer)["result"]["prompts"]
        owner = socket.socket(socket.AF_UNIX)
        owner.settimeout(6)
        owner.connect(str(endpoint))
        reader = owner.makefile("rb")
        json.loads(reader.readline())  # Subscription/snapshot barrier.
        before = REQUESTS.count(method)
        params = {"uri": "fixture://public"} if method == "resources/read" else {"name": "summarize", "arguments": {"text": "public"}}
        send(peer, method, params, 3)
        while True:
            event = json.loads(reader.readline())
            if event["id"]:
                break
        assert json.loads(event["display"])["params"] == params
        assert REQUESTS.count(method) == before, "unapproved request reached HTTP upstream"
        if disconnect:
            peer.stdin.close()
            peer.wait(timeout=3)
            # A late approval is harmless even if the monitor connection has closed.
            try:
                owner.sendall(json.dumps({"id": event["id"], "allow": True}).encode() + b"\n")
            except BrokenPipeError:
                pass
            assert REQUESTS.count(method) == before
        else:
            owner.sendall(json.dumps({"id": event["id"], "allow": allow}).encode() + b"\n")
            response = receive(peer)
            assert (response is not None) == allow
            assert REQUESTS.count(method) == before + int(allow)
        reader.close()
        owner.close()
        finish(peer)
        assert not endpoint.exists()

    # Each exposed deadline must actually reach the HTTP transport.
    for flag in ["--idle-timeout-secs", "--session-lifetime-secs", "--request-timeout-secs"]:
        peer = start(flag, "1")
        started = time.monotonic()
        if flag == "--request-timeout-secs":
            DELAY.set()
            send(peer, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                      "clientInfo": {"name": "synthetic", "version": "1"}}, 1)
        assert receive(peer) is None
        peer.wait(timeout=5)
        assert peer.returncode == 1
        assert 0.5 < time.monotonic() - started < 5
        DELAY.clear()
        finish(peer)
    with sqlite3.connect(state / "operations.sqlite3") as audit:
        assert audit.execute("SELECT count(*) FROM events_v1 WHERE reason='operation_timeout'").fetchone()[0] >= 3
    server.shutdown()
    server.server_close()
print("HTTP CLI: resource/prompt consent, rejection, EOF cancellation, pinning and independent deadlines passed.")
