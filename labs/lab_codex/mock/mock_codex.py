"""Minimal OpenAI Responses API mock for the Codex lab.

First call returns a function_call for the first declared tool (shell/exec),
the follow-up call (function_call_output present) returns a final message.
Codex executes the tool itself, so the lab exercises its real runtime.
"""
import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOL_COMMAND = "curl -k -s --connect-to api.openai.com:443:tls:443 https://api.openai.com/v1/models | head -c 80"


def sse(event, payload):
    return ("event: " + event + "\ndata: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode()


def has_tool_output(items):
    for item in items or []:
        if isinstance(item, dict) and str(item.get("type", "")).endswith("_output"):
            return True
    return False


def first_tool(request):
    tools = request.get("tools") or []
    if tools and isinstance(tools[0], dict):
        return tools[0].get("name") or tools[0].get("type") or "shell"
    return "shell"


def tool_arguments(name, schema):
    props = (schema or {}).get("properties") or {}
    if "cmd" in props:
        return json.dumps({"cmd": TOOL_COMMAND})
    if "command" in props:
        kind = props["command"].get("type")
        if kind == "array":
            return json.dumps({"command": ["bash", "-lc", TOOL_COMMAND]})
        return json.dumps({"command": TOOL_COMMAND})
    if "code" in props:
        return json.dumps({"code": TOOL_COMMAND})
    return json.dumps({"input": TOOL_COMMAND})


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/v1/models"):
            self._json(200, {"object": "list", "data": [{"id": "gpt-5-codex", "object": "model"}]})
        else:
            self._json(404, {"error": {"message": "not found"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": {"message": "invalid JSON"}})
            return
        model = request.get("model") or "gpt-5-codex"
        response_id = "resp_" + uuid.uuid4().hex[:12]

        def base(status):
            return {"id": response_id, "object": "response", "status": status, "model": model,
                    "output": [], "usage": {"input_tokens": 20, "output_tokens": 10, "total_tokens": 30}}

        events = []
        if has_tool_output(request.get("input")):
            item = {"type": "message", "id": "msg_" + uuid.uuid4().hex[:8], "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": "Fetched the OpenAI models endpoint with curl.",
                                 "annotations": []}]}
            events = [
                ("response.created", {"type": "response.created", "response": base("in_progress")}),
                ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": item}),
                ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item}),
                ("response.completed", {"type": "response.completed", "response": {**base("completed"), "output": [item]}}),
            ]
        else:
            tools = request.get("tools") or []
            name = first_tool(request)
            schema = (tools[0].get("parameters") or tools[0].get("input_schema") or {}) if tools else {}
            item = {"type": "function_call", "id": "fc_" + uuid.uuid4().hex[:8],
                    "call_id": "call_" + uuid.uuid4().hex[:8], "name": name,
                    "arguments": tool_arguments(name, schema), "status": "completed"}
            events = [
                ("response.created", {"type": "response.created", "response": base("in_progress")}),
                ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": item}),
                ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item}),
                ("response.completed", {"type": "response.completed", "response": {**base("completed"), "output": [item]}}),
            ]

        if not request.get("stream", True):
            self._json(200, events[-1][1]["response"])
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for name, payload in events:
            self.wfile.write(sse(name, payload))
            self.wfile.flush()
        self.close_connection = True


if __name__ == "__main__":
    import os
    TOOL_COMMAND = os.environ.get("MOCK_TOOL_COMMAND", TOOL_COMMAND)
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("MOCK_PORT", "4010"))), Handler).serve_forever()
