import os
import mimetypes
import base64
import json
from datetime import datetime
from urllib.parse import unquote

from .models import GreetingLanguage


class ResourceEmulator:
    def __init__(self, data_dir: str = "./data"):
        self.base_dir = os.path.abspath(data_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def make_greeting(self, name: str, language: str = "en") -> str:
        template = GreetingLanguage.GREETINGS.get(
            language, GreetingLanguage.GREETINGS[GreetingLanguage.EN]
        )
        return template.format(name=name)

    def list_files(self) -> list[dict]:
        resources = []
        for fname in os.listdir(self.base_dir):
            full_path = os.path.join(self.base_dir, fname)
            if not os.path.isfile(full_path):
                continue
            mime, _ = mimetypes.guess_type(full_path)
            resources.append({
                "uri": f"file://{fname}",
                "name": fname,
                "description": f"File: {fname}",
                "mimeType": mime or "application/octet-stream",
            })
        return resources

    def read_resource(self, uri: str) -> dict:
        if uri.startswith("hello://"):
            name = unquote(uri[len("hello://"):])
            return {
                "uri": uri,
                "mimeType": "text/plain",
                "text": self.make_greeting(name),
            }

        if uri.startswith("file://"):
            fname = unquote(uri[len("file://"):])
            safe_path = os.path.abspath(os.path.join(self.base_dir, fname))
            if not safe_path.startswith(self.base_dir) or not os.path.isfile(safe_path):
                raise FileNotFoundError(f"File not found or access denied: {fname}")

            mime, _ = mimetypes.guess_type(safe_path)
            mime = mime or "application/octet-stream"

            with open(safe_path, "rb") as f:
                raw = f.read()

            if mime.startswith("text") or "json" in mime:
                return {
                    "uri": uri,
                    "mimeType": mime,
                    "text": raw.decode("utf-8", errors="replace"),
                }
            return {
                "uri": uri,
                "mimeType": mime,
                "blob": base64.b64encode(raw).decode(),
            }

        raise ValueError(f"Unknown resource scheme: {uri}")

    def get_templates(self) -> list[dict]:
        return [
            {
                "uriTemplate": "hello://{name}",
                "name": "Hello Greeting",
                "mimeType": "text/plain",
            }
        ]

    def get_current_time(self, fmt: str = "24h") -> str:
        now = datetime.now()
        if fmt == "12h":
            return now.strftime("%I:%M:%S %p")
        if fmt == "iso":
            return now.isoformat()
        return now.strftime("%H:%M:%S")

    def echo_text(self, text: str, repeat: int = 1) -> str:
        return " ".join([text] * repeat)
