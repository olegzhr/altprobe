"""Shared helpers for the Altprobe lab tests.

Configuration comes from the environment so the same suite runs against any lab:

    LAB_BASE         gateway URL (default http://localhost:9080)
    LAB_OS_BASE      OpenSearch URL (default http://localhost:9200)
    LAB_INDEX_WAIT   seconds to wait for indexing (default 10)
    LAB_REDIS_HOST   Redis host (default localhost)
    LAB_REDIS_PORT   Redis port (default 16379)
    LAB_REDIS_KEY    Redis list used for Suricata emulation (default log_suricata)
"""

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

LAB_BASE = os.environ.get("LAB_BASE", "http://localhost:" + os.environ.get("LAB_PORT", "9080"))
LAB_OS_BASE = os.environ.get("LAB_OS_BASE", "http://localhost:9200")
LAB_INDEX_WAIT = int(os.environ.get("LAB_INDEX_WAIT", "10"))
LAB_REDIS_HOST = os.environ.get("LAB_REDIS_HOST", "localhost")
LAB_REDIS_PORT = int(os.environ.get("LAB_REDIS_PORT", "16379"))
LAB_REDIS_KEY = os.environ.get("LAB_REDIS_KEY", "log_suricata")

OSCF = {
    "dns": "ocsf-1.1.0-4001-dns_activity*",
    "http": "ocsf-1.1.0-4002-http_activity*",
    "network": "ocsf-1.1.0-4005-network_activity*",
    "tls": "ocsf-1.1.0-4007-tls_activity*",
    "detection": "ocsf-1.1.0-2004-detection_finding*",
    "vulnerability": "ocsf-1.1.0-2002-vulnerability_finding*",
    "api": "ocsf-1.1.0-6003-api_activity*",
}


def http(method, url, data=None, headers=None, timeout=20):
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def get(url, headers=None):
    return http("GET", url, headers=headers)


def status(url, headers=None):
    return get(url, headers=headers)[0]


def post_json(url, obj, headers=None):
    merged = {"Content-Type": "application/json"}
    if headers:
        merged.update(headers)
    return http("POST", url, data=json.dumps(obj).encode(), headers=merged)


def post_form(url, fields, headers=None):
    merged = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        merged.update(headers)
    return http("POST", url, data=urllib.parse.urlencode(fields).encode(), headers=merged)


def body_json(response):
    _, raw = response
    if not raw:
        return {}
    return json.loads(raw.decode())


def os_count(pattern, query=None):
    if query is None:
        code, raw = http("GET", "{}/{}/_count".format(LAB_OS_BASE, pattern))
    else:
        code, raw = http(
            "POST",
            "{}/{}/_count".format(LAB_OS_BASE, pattern),
            data=json.dumps({"query": query}).encode(),
            headers={"Content-Type": "application/json"},
        )
    try:
        return json.loads(raw.decode()).get("count", 0)
    except Exception:
        return 0


def os_search(pattern, body):
    code, raw = http(
        "POST",
        "{}/{}/_search".format(LAB_OS_BASE, pattern),
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        return json.loads(raw.decode() or "{}")
    except Exception:
        return {}


def wait_for(predicate, timeout=None, interval=2):
    timeout = LAB_INDEX_WAIT if timeout is None else timeout
    deadline = time.time() + timeout
    while True:
        try:
            if predicate():
                return True
        except Exception:
            pass
        if time.time() >= deadline:
            return False
        time.sleep(interval)


# --- minimal Redis client (RESP over a plain socket) -------------------------

def redis_command(*args):
    payload = b"*%d\r\n" % len(args)
    for arg in args:
        data = str(arg).encode()
        payload += b"$%d\r\n%s\r\n" % (len(data), data)
    with socket.create_connection((LAB_REDIS_HOST, LAB_REDIS_PORT), timeout=5) as sock:
        sock.sendall(payload)
        reply = b""
        while not reply.endswith(b"\r\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            reply += chunk
    line = reply.split(b"\r\n", 1)[0]
    if not (line.startswith(b"+") or line.startswith(b":")):
        raise RuntimeError("redis error: %r" % reply)
    return line[1:].decode()


def redis_available():
    try:
        return redis_command("PING") == "PONG"
    except Exception:
        return False


def redis_push(key, *values):
    return redis_command("RPUSH", key, *values)


def redis_del(key):
    return redis_command("DEL", key)
