#!/usr/bin/env python3
"""Минимальный Anthropic Messages API mock для lab_outbound.

Первый запрос получает tool_use (Bash), после tool_result — текстовый ответ.
Реальные события coding_agent пишет установленный Prempti hook, их забирает
shipper; мок отвечает только за провайдера.
"""
import argparse
import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOL_COMMAND = "true"


def sse(event, payload):
    return ("event: " + event + "\ndata: " + json.dumps(payload, ensure_ascii=False) + "\n\n").encode()


def has_tool_result(messages):
    for message in messages:
        content = message.get("content")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    return True
    return False


def tool_use_events(model):
    tool_id = "toolu_mock_" + uuid.uuid4().hex[:12]
    args = json.dumps({"command": TOOL_COMMAND, "description": "Fetch OpenAI models"}, ensure_ascii=False)
    start = {"type": "message_start", "message": {"id": "msg_mock_" + uuid.uuid4().hex[:8], "type": "message",
             "role": "assistant", "model": model, "content": [], "stop_reason": None,
             "stop_sequence": None, "usage": {"input_tokens": 12, "output_tokens": 1}}}
    block = {"type": "content_block_start", "index": 0,
             "content_block": {"type": "tool_use", "id": tool_id, "name": "Bash", "input": {}}}
    delta = {"type": "content_block_delta", "index": 0,
             "delta": {"type": "input_json_delta", "partial_json": args}}
    return [("message_start", start), ("content_block_start", block), ("content_block_delta", delta),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use",
                                                                  "stop_sequence": None},
                               "usage": {"output_tokens": 24}}),
            ("message_stop", {"type": "message_stop"})]


def text_events(model):
    start = {"type": "message_start", "message": {"id": "msg_mock_" + uuid.uuid4().hex[:8], "type": "message",
             "role": "assistant", "model": model, "content": [], "stop_reason": None,
             "stop_sequence": None, "usage": {"input_tokens": 20, "output_tokens": 1}}}
    block = {"type": "content_block_start", "index": 0,
             "content_block": {"type": "text", "text": ""}}
    delta = {"type": "content_block_delta", "index": 0,
             "delta": {"type": "text_delta", "text": "Fetched the OpenAI models endpoint with curl."}}
    return [("message_start", start), ("content_block_start", block), ("content_block_delta", delta),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn",
                                                                  "stop_sequence": None},
                               "usage": {"output_tokens": 16}}),
            ("message_stop", {"type": "message_stop"})]


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
            self._json(200, {"data": [{"id": "claude-sonnet-4-5", "type": "model",
                                       "display_name": "Claude Sonnet 4.5"}],
                             "has_more": False, "first_id": "claude-sonnet-4-5",
                             "last_id": "claude-sonnet-4-5"})
            return
        self._json(404, {"error": {"type": "not_found_error", "message": "not found"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": {"type": "invalid_request_error", "message": "invalid JSON"}})
            return
        model = request.get("model") or "claude-sonnet-4-5"
        messages = request.get("messages") or []
        events = text_events(model) if has_tool_result(messages) else tool_use_events(model)

        if request.get("stream", True):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            for name, payload in events:
                self.wfile.write(sse(name, payload))
                self.wfile.flush()
            self.close_connection = True
            return

        content = []
        stop_reason = "end_turn"
        for name, payload in events:
            if name == "content_block_start":
                block = dict(payload["content_block"])
                block.setdefault("input", {})
                if block.get("type") == "tool_use":
                    block["input"] = json.loads(json.dumps({"command": TOOL_COMMAND,
                                                            "description": "Fetch OpenAI models"}))
                    stop_reason = "tool_use"
                content.append(block)
        self._json(200, {"id": "msg_mock", "type": "message", "role": "assistant", "model": model,
                         "content": content, "stop_reason": stop_reason, "stop_sequence": None,
                         "usage": {"input_tokens": 12, "output_tokens": 20}})


def main():
    global TOOL_COMMAND
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=4010)
    parser.add_argument("--agent-redis-host", default="")
    parser.add_argument("--agent-redis-port", type=int, default=6379)
    args = parser.parse_args()
    import os
    TOOL_COMMAND = os.environ.get(
        "MOCK_TOOL_COMMAND",
        "curl -k -s --connect-to api.openai.com:443:tls:443 https://api.openai.com/v1/models | head -c 80")
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
