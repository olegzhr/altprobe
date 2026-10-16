"""Private HTTP -> Redis RPUSH relay for the Wasm filter (Python stdlib only)."""
import json
import os
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer


def push(payload):
    parts = [b"RPUSH", os.getenv("REDIS_KEY", "log_proxy").encode(), payload]
    command = b"*3\r\n" + b"".join(
        b"$%d\r\n" % len(part) + part + b"\r\n" for part in parts
    )
    with socket.create_connection(
        (os.getenv("REDIS_HOST", "redis"), int(os.getenv("REDIS_PORT", "6379"))), timeout=2
    ) as connection:
        connection.sendall(command)
        with connection.makefile("rb") as reader:
            if not reader.readline(4096).startswith(b":"):
                raise OSError("Redis did not acknowledge RPUSH")


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.connection.settimeout(3)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if self.path != "/events" or not 0 < length <= 262144:
                self.send_error(400)
                return
            raw = self.rfile.read(length)
            if len(raw) != length or not isinstance(json.loads(raw), dict):
                self.send_error(400)
                return
            push(raw)
        except (ValueError, OSError):
            self.send_error(503)
            return
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    # Internal Docker network only; do not publish this listener to untrusted peers.
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
