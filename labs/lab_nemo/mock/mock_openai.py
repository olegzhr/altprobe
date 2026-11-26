#!/usr/bin/env python3
"""Minimal OpenAI-compatible chat completions mock for the NeMo lab."""
import json
import os
from pathlib import Path
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AUDIT_LOCK = threading.Lock()


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
            self._json(200, {"object": "list", "data": [
                {"id": "gpt-4o-mini", "object": "model", "owned_by": "lab"}]})
            return
        self._json(404, {"error": {"message": "not found"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": {"message": "invalid JSON"}})
            return
        messages = request.get("messages") or []
        user_text = " ".join(
            str(item.get("content", "")) for item in messages if item.get("role") == "user")
        directory = Path("/evidence")
        directory.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOCK, (directory / "mock.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps({"run_id": os.getenv("LAB_RUN_ID", "manual"),
                                  "time": int(time.time()*1000),
                                  "markers": re.findall(r"\[altprobe-run:([A-Za-z0-9-]+):(safe|jailbreak)\]", user_text)}) + "\n")
        if "self check" in user_text.lower() or "is this" in user_text.lower():
            content = "yes"
        else:
            content = "This is a mock OpenAI response from the NeMo lab."
        print(f"mock completion: chars={len(user_text)}", flush=True)
        response = {
            "id": "chatcmpl-" + uuid.uuid4().hex[:12],
            "object": "chat.completion",
            "created": int(time.time()),
            "model": request.get("model", "gpt-4o-mini"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        self._json(200, response)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 4010), Handler).serve_forever()
