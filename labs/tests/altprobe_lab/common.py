"""Shared helpers for the Altprobe lab tests.

HTTP and OpenSearch access for the environment-driven lab suite. HTTP uses the
standard ``requests`` library.

Configuration comes from the environment so the same suite runs against any lab:

    LAB_BASE         gateway URL (default http://localhost:9080)
    LAB_OS_BASE      OpenSearch URL (default http://localhost:9200)
    LAB_INDEX_WAIT   seconds to wait for indexing (default 10)
"""

import json
import os
import time

import requests

LAB_BASE = os.environ.get("LAB_BASE", "http://localhost:" + os.environ.get("LAB_PORT", "9080"))
LAB_OS_BASE = os.environ.get("LAB_OS_BASE", "http://localhost:9200")
LAB_INDEX_WAIT = int(os.environ.get("LAB_INDEX_WAIT", "10"))

OSCF = {
    "http": "ocsf-1.1.0-4002-http_activity*",
    "detection": "ocsf-1.1.0-2004-detection_finding*",
    "vulnerability": "ocsf-1.1.0-2002-vulnerability_finding*",
    "api": "ocsf-1.1.0-6003-api_activity*",
}

SESSION = requests.Session()


def http(method, url, data=None, headers=None, timeout=20):
    """Return ``(status_code, body_bytes)`` for any HTTP status."""
    response = SESSION.request(method, url, data=data, headers=headers or {}, timeout=timeout)
    return response.status_code, response.content


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
    return http("POST", url, data=fields, headers=merged)


def body_json(response):
    _, raw = response
    if not raw:
        return {}
    return json.loads(raw.decode())


def os_count(pattern, query=None):
    if query is None:
        response = SESSION.get("{}/{}/_count".format(LAB_OS_BASE, pattern), timeout=20)
    else:
        response = SESSION.post("{}/{}/_count".format(LAB_OS_BASE, pattern),
                                json={"query": query}, timeout=20)
    try:
        return response.json().get("count", 0)
    except Exception:
        return 0


def os_search(pattern, body):
    response = SESSION.post("{}/{}/_search".format(LAB_OS_BASE, pattern),
                            json=body, timeout=20)
    try:
        return response.json()
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
