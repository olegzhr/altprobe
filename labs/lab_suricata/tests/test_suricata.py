#!/usr/bin/env python3
"""End-to-end checks for the Suricata lab.

The lab needs only Suricata and Redis. A traffic container creates LLM DNS
and TLS traffic; Suricata writes eve.json; the shared shipper forwards tls,
dns and flow records to Redis; Altprobe writes OCSF 4007/4001/4005.

The test verifies both halves of that path:
* Redis contains the current run's shipped Suricata event types;
* OpenSearch contains fresh OCSF TLS SNI, DNS query and network-flow records.
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
from lab_support import fresh, load_run, query

RUN = None

OS_URL = os.getenv("OS_URL", "http://127.0.0.1:19200").rstrip("/")
WAIT_SECONDS = int(os.getenv("SURICATA_WAIT", "240"))
DOMAIN = os.getenv("SURICATA_DOMAIN", "api.anthropic.com")
NON_LLM_DOMAIN = os.getenv("SURICATA_NON_LLM_DOMAIN", "example.org")


def request(path: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        OS_URL + path,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


def search(index: str, size: int = 500) -> list[dict]:
    payload = {"size": size, "sort": [{"time": {"order": "desc"}}], "query": query(RUN)}
    try:
        result = request("/" + index + "/_search", payload)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise
    return [hit["_source"] for hit in result.get("hits", {}).get("hits", []) if fresh(RUN, hit["_source"])]


def wait_for(predicate, description: str):
    deadline = time.monotonic() + WAIT_SECONDS
    last: object = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
        except (urllib.error.URLError, TimeoutError) as exc:
            last = exc
        if last:
            return last
        time.sleep(3)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


def text(value) -> str:
    return value if isinstance(value, str) else ""


def test_tls() -> dict:
    def tls_event(domain):
        for item in search("ocsf-1.8.0-4007-ssh_activity*"):
            if text((item.get("tls") or {}).get("sni")) == domain:
                return item
        return None

    llm = wait_for(lambda: tls_event(DOMAIN), "Suricata TLS SNI " + DOMAIN)
    assert (llm.get("tls") or {}).get("sni") == DOMAIN
    non_llm = wait_for(lambda: tls_event(NON_LLM_DOMAIN), "Suricata TLS SNI " + NON_LLM_DOMAIN)
    assert (non_llm.get("tls") or {}).get("sni") == NON_LLM_DOMAIN
    return {"llm": llm, "non_llm": non_llm}


def test_dns() -> dict:
    run_name = f"run-{RUN['run_id']}.{DOMAIN}"

    def dns_event(name):
        for item in search("ocsf-1.8.0-4001-network_activity*"):
            if text((item.get("dns_query") or {}).get("hostname")).rstrip(".").lower() == name.rstrip(".").lower():
                return item
        return None

    marker = wait_for(lambda: dns_event(run_name), f"Suricata DNS query {run_name}")
    assert text((marker.get("dns_query") or {}).get("hostname")).rstrip(".").lower() == run_name.rstrip(".").lower()
    other = wait_for(lambda: dns_event(NON_LLM_DOMAIN), "Suricata DNS query " + NON_LLM_DOMAIN)
    assert text((other.get("dns_query") or {}).get("hostname")).rstrip(".").lower() == NON_LLM_DOMAIN.lower()
    return {"marker": marker, "other": other}


def test_flow() -> dict:
    def flow_event():
        for item in search("ocsf-1.8.0-4005-network_activity*"):
            info = item.get("connection_info") or {}
            if int(info.get("bytes") or 0) > 0 and int(info.get("packets") or 0) > 0:
                return item
        return None

    flow = wait_for(flow_event, "Suricata flow record")
    info = flow.get("connection_info") or {}
    assert int(info.get("bytes") or 0) > 0
    assert int(info.get("packets") or 0) > 0
    return flow


def main() -> int:
    global RUN
    RUN = load_run(LAB)
    wait_for(lambda: request("/_cluster/health").get("status") in {"green", "yellow"},
             "OpenSearch health")
    tls = test_tls()
    dns = test_dns()
    flow = test_flow()
    load_run(LAB)
    print("PASS: TLS SNI", DOMAIN, "and", NON_LLM_DOMAIN)
    print("PASS: DNS", "run-<run>.api.anthropic.com", "and", NON_LLM_DOMAIN)
    print("PASS: OCSF 4007/4001/4005 written through Redis -> Altprobe")
    print("PASS: network flow bytes:", (flow.get("connection_info") or {}).get("bytes"))
    print("status=PASS checks=4")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print("status=FAIL", error, file=sys.stderr)
        raise SystemExit(1)
