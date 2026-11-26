#!/usr/bin/env python3
"""End-to-end check for the NeMo Guardrails lab.

The LangChain agent sends a safe and a jailbreak prompt through APISIX. NeMo
blocks the jailbreak with its input rail. Altprobe consumes the APISIX Redis
log, asks NeMo for a guard verdict, and writes OCSF 6003 content assessments.
"""
from __future__ import annotations
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB.parent))
from lab_support import evidence_path, fresh, load_run, query

RUN = None

OS_URL = os.getenv("OS_URL", "http://127.0.0.1:19200").rstrip("/")
WAIT_SECONDS = int(os.getenv("NEMO_WAIT", "300"))
INDEX = "ocsf-1.8.0-6003-api_activity*"


def request(path: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        OS_URL + path,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


def findings() -> list[dict]:
    payload = {"size": 500, "sort": [{"time": {"order": "desc"}}],
               "query": query(RUN)}
    try:
        result = request("/" + INDEX + "/_search", payload)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise
    return [hit["_source"] for hit in result.get("hits", {}).get("hits", [])
            if fresh(RUN, hit["_source"]) and
            "lab_run_id=" + RUN["run_id"] in (hit["_source"].get("api") or {}).get("operation", "")]


def check_enforcement(run: dict):
    directory = evidence_path(LAB, run)
    agent = json.loads((directory / "agent.json").read_text(encoding="utf-8"))
    assert agent["run_id"] == run["run_id"], "agent evidence from another run"
    results = {row["case"]: row for row in agent["results"]}
    assert set(results) == {"safe", "jailbreak"}, "incomplete agent cases"
    safe = results["safe"]
    blocked = results["jailbreak"]
    assert all(row["run_id"] == run["run_id"] for row in results.values())
    assert not safe["blocked"] and "mock OpenAI response" in safe["response"], "safe prompt did not complete via mock"
    assert blocked["blocked"] and "Blocked by NeMo Guardrails" in blocked["response"], "agent did not receive refusal"
    audits = [json.loads(line) for line in (directory / "mock.jsonl").read_text().splitlines()]
    audits = [row for row in audits if row.get("run_id") == run["run_id"] and fresh(run, row)]
    markers = [marker for row in audits for marker in row.get("markers", []) if marker[0] == run["run_id"]]
    assert [run["run_id"], "safe"] in markers, "safe prompt did not reach mock"
    assert [run["run_id"], "jailbreak"] not in markers, "blocked prompt reached mock"


def main() -> int:
    global RUN
    RUN = load_run(LAB)
    deadline = time.monotonic() + WAIT_SECONDS
    unsafe = safe = None
    while time.monotonic() < deadline and (unsafe is None or safe is None):
        try:
            for item in findings():
                guard = (item.get("unmapped") or {}).get("llm_guard") or {}
                operation = (item.get("api") or {}).get("operation", "")
                if guard.get("provider") != "nemo":
                    continue
                if (guard.get("safety") == "Unsafe" and guard.get("field") == "request.body" and
                    "lab_case=jailbreak" in operation):
                    unsafe = item
                elif (guard.get("safety") == "Safe" and guard.get("field") == "request.body" and
                      "lab_case=safe" in operation):
                    safe = item
        except (urllib.error.URLError, TimeoutError):
            pass
        if unsafe is None or safe is None:
            time.sleep(5)

    assert unsafe is not None, "no unsafe NeMo request finding in OpenSearch"
    guard = unsafe["unmapped"]["llm_guard"]
    assert guard.get("status") == "checked", guard
    assert guard.get("categories") == ["Jailbreak"], guard
    assert guard.get("refusal") == "Yes", guard
    assert guard.get("model") == "altprobe", guard
    operation = (unsafe.get("api") or {}).get("operation", "")
    assert "/v1/chat/completions" in operation, operation
    assert (unsafe.get("metadata") or {}).get("log_name", "").startswith("guard_nemo"), unsafe.get("metadata")

    assert safe is not None, "no safe NeMo request finding in OpenSearch"
    assert (safe.get("unmapped") or {}).get("llm_guard", {}).get("categories") == ["None"]

    while True:
        try:
            check_enforcement(RUN)
            break
        except (FileNotFoundError, json.JSONDecodeError):
            if time.monotonic() >= deadline:
                raise AssertionError("agent/mock evidence did not complete for this run")
            time.sleep(1)
    load_run(LAB)  # Reject restarts/source drift during the verification window.
    print("PASS: NeMo input rail blocked the jailbreak prompt; run=" + RUN["run_id"])
    print("  unsafe:", operation.strip(), guard.get("categories"))
    print("  safe  :", (safe.get("unmapped") or {}).get("llm_guard", {}).get("categories"))
    print("status=PASS checks=3")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print("status=FAIL", error, file=sys.stderr)
        raise SystemExit(1)
