"""Real native scan-bound CLI tests; all data is synthetic and temporary."""
import json
import os
import pathlib
import select
import subprocess
import tempfile

BINARY = pathlib.Path(__file__).resolve().parent.parent / "target/release/clawbell"
CGROUP = os.environ["CLAWBELL_TEST_CGROUP"]
with tempfile.TemporaryDirectory(prefix="clawbell-skill-cli-") as temporary:
    root = pathlib.Path(temporary)
    workspace = root / "package"
    workspace.mkdir(mode=0o700)
    state = root / "state"
    state.mkdir(mode=0o700)
    policy = root / "policy.toml"
    original_policy = 'version="skill-test"\ntools=[]\nrules=[]\n[skills]\nallow_execution=true\nallow_shell=true\n'
    policy.write_text(original_policy)
    instructions = root / "instructions.txt"
    instructions.write_text("Summarize public notes")
    code = workspace / "server.py"
    original_code = '''import json,sys
for line in sys.stdin:
 r=json.loads(line)
 if "id" not in r: continue
 result={}
 if r["method"]=="initialize":
  instruction="Changed instructions" if r["params"]["clientInfo"]["name"]=="changed" else "Summarize public notes"
  result={"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fixture","version":"1"},"instructions":instruction}
 print(json.dumps({"jsonrpc":"2.0","id":r["id"],"result":result}),flush=True)
'''
    code.write_text(original_code)
    command = ["--", "/usr/bin/python3", "-B", "/workspace/server.py"]
    common = ["--policy", str(policy), "--workspace", str(workspace)]
    scan = subprocess.run([str(BINARY), "skill-scan", *common, "--instructions-file", str(instructions), *command], capture_output=True, timeout=20)
    assert scan.returncode == 0, "complete scan must succeed"
    receipt = json.loads(scan.stdout)
    assert receipt["format"] == "clawbell.skill-scan.v2"
    digest = receipt["digest"]
    launch = [str(BINARY), "proxy", *common, "--state-dir", str(state), "--server", "synthetic-skill", "--cgroup-parent", CGROUP,
              "--skill-scan-digest", digest, "--skill-instructions-file", str(instructions), *command]
    def initialize(name):
        return {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":name,"version":"1"}}}
    for name in ["ordinary", "changed"]:
        peer = subprocess.Popen(launch, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            peer.stdin.write((json.dumps(initialize(name))+"\n").encode())
            peer.stdin.flush()
            assert select.select([peer.stdout],[],[],10)[0], "initialization timeout"
            line = peer.stdout.readline()
            if name == "ordinary":
                assert json.loads(line)["result"]["instructions"] == "Summarize public notes"
            else:
                assert line == b"", "changed instructions must never reach the client"
        finally:
            peer.stdin.close()
            peer.wait(timeout=10)
            peer.stdout.close()
            peer.stderr.close()
        if name == "changed":
            assert peer.returncode != 0
    for changed in ["code", "policy", "instructions"]:
        if changed == "code": code.write_text(original_code + "\n# changed after review\n")
        if changed == "policy": policy.write_text(original_policy + "\n# same-version policy edit\n")
        if changed == "instructions": instructions.write_text("Changed instructions")
        result = subprocess.run(launch, input=(json.dumps(initialize("ordinary"))+"\n").encode(), capture_output=True, timeout=20)
        assert result.returncode != 0 and result.stdout == b"", "stale scan must refuse before execution"
        code.write_text(original_code)
        policy.write_text(original_policy)
        instructions.write_text("Summarize public notes")
    # A matching scan receipt still cannot replace explicit policy permission.
    policy.write_text('version="skill-denied"\ntools=[]\nrules=[]\n')
    refused_scan = subprocess.run([str(BINARY), "skill-scan", *common, "--instructions-file", str(instructions), *command], capture_output=True, timeout=20)
    assert refused_scan.returncode == 0
    denied_launch = launch.copy()
    denied_launch[denied_launch.index("--skill-scan-digest") + 1] = json.loads(refused_scan.stdout)["digest"]
    denied = subprocess.run(denied_launch, input=b"", capture_output=True, timeout=20)
    assert denied.returncode != 0 and denied.stdout == b""
    assert b"skill_execution_permission_required" in denied.stderr
    policy.write_text(original_policy)
    (workspace / "link.py").symlink_to(code)
    result = subprocess.run([str(BINARY), "skill-scan", *common, "--instructions-file", str(instructions), *command], capture_output=True, timeout=20)
    assert result.returncode != 0 and result.stdout == b""
print("Scan-bound native CLI: exact instructions accepted; drift, changed code/policy/instructions and package links refused.")
