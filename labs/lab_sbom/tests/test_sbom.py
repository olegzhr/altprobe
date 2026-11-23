#!/usr/bin/env python3
"""End-to-end check for the SBOM lab.

Trivy scans the pinned npm project in ``target/``; Altprobe must convert the
CycloneDX vulnerabilities into OCSF 2002 findings and write them to
OpenSearch.
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
WAIT_SECONDS = int(os.getenv("SBOM_WAIT", "600"))
INDEX = "ocsf-1.8.0-2002-vulnerability_finding*"
EXPECTED = {
    "CVE-2021-23337": "lodash@4.17.4",
    "CVE-2021-3749": "axios@0.21.1",
    "CVE-2021-44906": "minimist@1.2.0",
}


def request(path: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        OS_URL + path,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


def fetch_findings() -> list[dict]:
    payload = {"size": 2000, "sort": [{"time": {"order": "desc"}}],
               "query": query(RUN)}
    try:
        result = request("/" + INDEX + "/_search", payload)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise
    return [
        hit["_source"] for hit in result.get("hits", {}).get("hits", [])
        if fresh(RUN, hit["_source"]) and
        (hit["_source"].get("metadata") or {}).get("log_name") == "altprobe_sbom" and
        (hit["_source"].get("metadata") or {}).get("uid", "").startswith("sbom-target-" + RUN["run_id"] + ":")
    ]


def main() -> int:
    global RUN
    RUN = load_run(LAB)
    deadline = time.monotonic() + WAIT_SECONDS
    findings: list[dict] = []
    while time.monotonic() < deadline:
        try:
            request("/_cluster/health")
            findings = fetch_findings()
        except (urllib.error.URLError, TimeoutError):
            findings = []
        if set(EXPECTED).issubset({item.get("vulnerability", {}).get("uid") for item in findings}):
            break
        time.sleep(5)

    if not findings:
        raise AssertionError("no OCSF 2002 findings with metadata.log_name=altprobe_sbom")

    by_cve = {item.get("vulnerability", {}).get("uid"): item for item in findings}
    missing = [cve for cve in EXPECTED if cve not in by_cve]
    assert not missing, f"missing CVEs: {missing}; observed={sorted(by_cve)[:20]}"

    for cve, component in EXPECTED.items():
        item = by_cve[cve]
        title = str((item.get("vulnerability") or {}).get("title", ""))
        assert component in title, (cve, title)
        assert item.get("class_uid") == 2002, item.get("class_uid")
        assert item.get("severity"), cve
        assert (item.get("vulnerability") or {}).get("desc"), cve

    load_run(LAB)
    print(f"PASS: {len(findings)} OCSF 2002 findings; run={RUN['run_id']}")
    for cve, component in EXPECTED.items():
        item = by_cve[cve]
        print(f"  {cve}: {item['vulnerability']['title']} [{item.get('severity')}]")
    print("status=PASS checks=3")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print("status=FAIL", error, file=sys.stderr)
        raise SystemExit(1)
