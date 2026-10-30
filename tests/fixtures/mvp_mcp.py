"""Synthetic file MCP upstream for the real, sandboxed CLI release test."""
import json
import pathlib
import sys

DESCRIPTION = "Synthetic read-only notes fixture"
TOOLS = [
    {"name": "read_file", "description": DESCRIPTION,
     "inputSchema": {"type": "object", "required": ["path"],
                     "properties": {"path": {"type": "string"}},
                     "additionalProperties": False}},
    {"name": "write_file", "inputSchema": {"type": "object", "required": ["path", "text"],
     "properties": {"path": {"type": "string"}, "text": {"type": "string"}},
     "additionalProperties": False}},
]
for line in sys.stdin:
    request = json.loads(line)
    if "id" not in request:
        continue
    method = request["method"]
    result = {}
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "synthetic", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        args = request["params"]["arguments"]
        target = pathlib.Path("/workspace") / args["path"]
        if request["params"]["name"] == "write_file":
            target.write_text(args["text"])
            text = "written"
        else:
            text = target.read_text()
        result = {"content": [{"type": "text", "text": text}]}
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
