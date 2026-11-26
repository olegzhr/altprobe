#!/usr/bin/env python3
"""Small LangChain client in a simulated OpenShell sandbox.

The real OpenShell supervisor writes the same OCSF 1.8 JSONL records. This
container makes the lab deterministic and exercises every class OpenShell can
emit without requiring a GPU or a live gateway.
"""
from __future__ import annotations
import json
import os
import time
import urllib.request
from pathlib import Path

from langchain_core.runnables import RunnableLambda

OUT = Path(os.getenv("OPENSHELL_OCSF_LOG", "/tmp/openshell-ocsf.jsonl"))
OUT.parent.mkdir(parents=True, exist_ok=True)
HOST = os.getenv("OPENSHELL_HOST", "openshell-sandbox")
CONTAINER = os.getenv("OPENSHELL_CONTAINER", "ai-client")


def base(cls, name, activity, action=None, severity=1, **extra):
    event = {
        "class_uid": cls, "class_name": name,
        "category_uid": {0: 0, 1007: 1, 2004: 2, 3002: 3, 4001: 4, 4002: 4, 4007: 4,
                         5019: 5, 6002: 6, 6003: 6}[cls],
        "activity_id": activity,
        "type_uid": cls * 100 + activity,
        "time": int(time.time() * 1000),
        "severity_id": severity,
        "severity": {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}[severity],
        "metadata": {"version": "1.8.0", "product": {"name": "OpenShell Sandbox Supervisor",
                                                     "vendor_name": "OpenShell", "version": "0.1.7"},
                     "uid": f"seed-{cls}-{int(time.time() * 1000)}"},
        "device": {"hostname": HOST, "type_id": 99, "type": "Sandbox",
                   "os": {"name": "Linux", "type_id": 200, "type": "Linux"},
                   "container": {"name": CONTAINER, "uid": "sandbox-uid"}},
        "actor": {"process": {"name": "python", "pid": 42,
                               "cmd_line": "python langchain_client.py"}},
    }
    if action is not None:
        event["action_id"] = action
        event["action"] = {1: "Allowed", 2: "Denied"}[action]
        event["disposition_id"] = 1 if action == 1 else 2
        event["disposition"] = "Allowed" if action == 1 else "Blocked"
    event.update(extra)
    return event


def events():
    yield base(0, "Base Event", 0, action=1, message="OpenShell supervisor started")
    yield base(1007, "Process Activity", 1, action=1,
               process={"name": "python", "pid": 42, "cmd_line": "python langchain_client.py"})
    yield base(3002, "Authentication", 1, status_id=1, status="Success",
               user={"name": "ai-client", "type": "User"}, auth_protocol="sandbox_jwt",
               src_endpoint={"ip": "10.42.0.20"})
    yield base(4001, "Network Activity", 1, action=1,
               src_endpoint={"ip": "10.42.0.20", "port": 43110},
               dst_endpoint={"domain": "api.openai.com", "ip": "198.51.100.10", "port": 443},
               connection_info={"protocol_name": "TCP"})
    yield base(4001, "Network Activity", 1, action=2, severity=3,
               src_endpoint={"ip": "10.42.0.20", "port": 43111},
               dst_endpoint={"domain": "blocked.example", "ip": "203.0.113.9", "port": 443},
               status_id=2, status="Failure", status_detail="network_not_allowed",
               connection_info={"protocol_name": "TCP"})
    model_url = os.getenv("MODEL_URL", "http://apisix:9080/test-api/v1/chat/completions")
    code = 0
    try:
        request = urllib.request.Request(model_url, data=json.dumps({
            "model": "lab", "messages": [{"role": "user", "content": "OpenShell lab"}]}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=10) as response:
            code = response.status
    except Exception as error:
        code = getattr(error, "code", 503)
    yield base(4002, "HTTP Activity", 3, action=1 if code < 400 else 2,
               http_request={"method": "POST", "url": model_url,
                             "user_agent": "langchain/0.3"},
               http_response={"code": code}, src_endpoint={"ip": "10.42.0.20"},
               dst_endpoint={"ip": "198.51.100.10", "port": 443})
    yield base(4007, "SSH Activity", 1, action=1,
               src_endpoint={"ip": "10.42.0.20"}, dst_endpoint={"ip": "198.51.100.10", "port": 22})
    yield base(5019, "Device Config State Change", 1, action=1,
               device={"hostname": HOST}, status_id=1, status="Success")
    yield base(6002, "Application Lifecycle", 1, action=1,
               app={"name": "langchain-client", "version": "0.3"})
    yield base(6003, "API Activity", 1, action=1,
               api={"operation": "chat.completions.create"},
               resources=[{"name": "openai", "type": "API"}])
    yield base(2004, "Detection Finding", 1, action=2, severity=4,
               finding_info={"uid": "openshell-deny", "title": "Outbound connection denied",
                             "desc": "OpenShell policy blocked provider egress"},
               resources=[{"name": "blocked.example", "type": "Network"}])


def main():
    # A LangChain runnable is the client boundary; its output is the audit event.
    chain = RunnableLambda(lambda item: item)
    with OUT.open("a", encoding="utf-8") as handle:
        for event in events():
            record = chain.invoke(event)
            handle.write(json.dumps(record, separators=(",", ":")) + "\n")
            handle.flush()
            print(json.dumps({"class_uid": record["class_uid"]}), flush=True)
    # Keep the sandbox alive for repeated scrape runs.
    while True:
        time.sleep(30)


if __name__ == "__main__":
    main()

