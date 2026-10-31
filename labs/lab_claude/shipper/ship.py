#!/usr/bin/env python3
"""Tail real sensor logs and push them into the lab Redis queues.

Inputs (inside the shipper container):
  /var/log/falco/events.json        Falco JSON alerts (file_output)
  /var/log/suricata/eve.json        Suricata EVE (TLS/HTTP)
  /lab-home/.prempti/log/falco.log  Prempti JSON alerts (coding_agent)
"""
import json
import os
import socket
import time
from pathlib import Path

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
LAB_HOST = os.environ.get("LAB_HOST", "lab-real")
AGENT_PID_FILE = Path("/lab-home/agent.pid")
PARENTS = {}


def observe(kind, doc):
    """Track process spawns so connect events can carry their ancestors."""
    if kind != "falco":
        return False
    fields = doc.get("output_fields") or {}
    if fields.get("evt.type") not in ("execve", "clone", "fork", "vfork"):
        return False
    try:
        pid = int(fields.get("proc.pid", 0))
        ppid = int(fields.get("proc.ppid", 0))
    except (TypeError, ValueError):
        return True
    if pid > 0:
        PARENTS[pid] = ppid
        if len(PARENTS) > 20000:
            PARENTS.pop(next(iter(PARENTS)))
    return True


def ancestors(pid):
    chain = []
    seen = set()
    while pid and pid not in seen and len(chain) < 16:
        seen.add(pid)
        parent = PARENTS.get(pid, 0)
        if not parent:
            break
        chain.append(parent)
        pid = parent
    return chain

SOURCES = [
    (Path("/var/log/falco/events.json"), "log_falco", "falco"),
    (Path("/var/log/suricata/eve.json"), "log_suri", "suricata"),
    (Path("/lab-home/.prempti/log/falco.log"), "log_agent", "prempti"),
]


def push(key, value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    with socket.create_connection((REDIS_HOST, REDIS_PORT), timeout=5) as sock:
        sock.sendall(b"*3\r\n$5\r\nLPUSH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n"
                     % (len(key), key.encode(), len(payload), payload))
        sock.recv(128)


def keep(kind, doc):
    if kind == "falco":
        fields = doc.get("output_fields") or {}
        return fields.get("evt.type") == "connect"
    if kind == "suricata":
        return doc.get("event_type") == "tls" and bool((doc.get("tls") or {}).get("sni"))
    if kind == "prempti":
        fields = doc.get("output_fields") or {}
        return doc.get("source") == "coding_agent" and bool(
            fields.get("agent.pid") or fields.get("tool.name") or fields.get("agent.session_id"))
    return False


def normalize(kind, doc):
    if kind == "suricata":
        doc["host_name"] = LAB_HOST
    else:
        doc["hostname"] = LAB_HOST
    if kind == "falco":
        # Non-blocking connect reports EINPROGRESS; the collector expects the
        # completed-connect encoding (0) for outbound correlation.
        fields = doc.setdefault("output_fields", {})
        if str(fields.get("evt.rawres")) == "-115":
            fields["evt.rawres"] = 0
        if "proc.apid" not in fields:
            try:
                chain = ancestors(int(fields.get("proc.ppid", 0)))
            except (TypeError, ValueError):
                chain = []
            if chain:
                fields["proc.apid"] = ":".join(str(pid) for pid in chain)
    if kind == "prempti":
        # Prempti 0.2.1 does not always expose agent.pid; the claude container
        # writes its PID to the shared volume, which is the same process.
        fields = doc.setdefault("output_fields", {})
        if "agent.pid" not in fields:
            try:
                fields["agent.pid"] = int(AGENT_PID_FILE.read_text().strip())
            except (OSError, ValueError):
                pass
    return doc


class Tail:
    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.inode = None

    def read(self):
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return []
        if self.inode != stat.st_ino:
            self.inode = stat.st_ino
            self.offset = 0
        if stat.st_size < self.offset:
            self.offset = 0
        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            lines = stream.readlines()
            self.offset = stream.tell()
        return [line for line in lines if line.endswith(b"\n")]


def main():
    tails = [(Tail(path), key, kind) for path, key, kind in SOURCES]
    print(f"shipper ready: redis {REDIS_HOST}:{REDIS_PORT}", flush=True)
    while True:
        for tail, key, kind in tails:
            for line in tail.read():
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if observe(kind, doc):
                    continue
                if not keep(kind, doc):
                    continue
                try:
                    push(key, normalize(kind, doc))
                    print(f"{kind} -> {key}", flush=True)
                except OSError as error:
                    print(f"redis push failed: {error}", flush=True)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
