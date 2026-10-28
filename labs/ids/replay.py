#!/usr/bin/env python3
"""Replay paired sensor observations; no external AI service is contacted."""
import datetime as dt
import json
import os
import socket
import time
import urllib.request
import urllib.error
import uuid


def redis_push(key, value):
    args = [b"RPUSH", key.encode(), json.dumps(value).encode()]
    request = b"*3\r\n" + b"".join(b"$%d\r\n" % len(a) + a + b"\r\n" for a in args)
    with socket.create_connection((os.getenv("REDIS_HOST", "redis"), 6379), timeout=5) as conn:
        conn.sendall(request)
        response = conn.recv(256)
        if not response.startswith(b":"):
            raise RuntimeError(f"Redis rejected replay: {response!r}")


def timestamp(offset=0):
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=offset)).isoformat()


def verify_flows(os_url):
    """Wait for OCSF 4005 docs and exercise the dashboard composite aggregation."""
    query = {
        "size": 0,
        "aggs": {
            "table": {
                "composite": {
                    "size": 100,
                    "sources": [
                        {"stk1": {"terms": {"field": "src_endpoint.ip"}}},
                        {"stk2": {"terms": {"field": "dst_endpoint.ip"}}},
                    ],
                }
            },
            "bytes": {"max": {"field": "connection_info.bytes"}},
        },
    }
    deadline = time.monotonic() + 40
    last = {}
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(
                os_url + "/ocsf-1.1.0-4005-network_activity*/_search",
                data=json.dumps(query).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                last = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
        aggregations = last.get("aggregations", {})
        buckets = aggregations.get("table", {}).get("buckets", [])
        max_bytes = (aggregations.get("bytes") or {}).get("value") or 0
        if buckets and max_bytes > 0:
            return len(buckets)
        time.sleep(1)
    raise AssertionError(
        "No OCSF 4005 source/destination flow buckets with connection bytes; "
        f"last response was {last!r}"
    )


def main():
    run = "ids-" + uuid.uuid4().hex[:12]
    expected = {"direct", "reordered", "dns-connect", "ipv6"}
    for i, case in enumerate(["direct", "reordered", "dns-connect", "ipv6", "proxy", "dns-only", "non-provider", "wrong-port", "accept", "failed", "stale", "wrong-node"]):
        client, server = f"10.88.0.{i+10}", f"203.0.113.{i+10}"
        if case == "ipv6":
            client, server = "2001:db8:1::4", "2001:db8:2::8"
        event_time = timestamp(-200 if case == "stale" else 0)
        fields = {"evt.type": "accept" if case == "accept" else "connect", "evt.rawres": -1 if case == "failed" else 0,
                  "fd.is_server": case == "accept", "fd.cip": client, "fd.sip": server, "fd.cport": 50000+i,
                  "fd.sport": 443, "fd.l4proto": "tcp", "proc.name": "python", "proc.pid": 100+i,
                  "container.id": run+case, "container.name": "lab-ai-agent", "k8s.pod.name": run+"-"+case,
                  "k8s.ns.name": "ai-gateway" if case == "proxy" else "ai"}
        falco = {"time": event_time, "hostname": "lab-ai-node", "rule": "AI Outbound Connect", "priority": "Notice", "output_fields": fields}
        eve = {"timestamp": event_time, "host_name": "other-node" if case == "wrong-node" else "lab-ai-node", "event_type": "tls", "src_ip": client, "dest_ip": server,
               "src_port": 51000+i if case == "wrong-port" else 50000+i, "dest_port": 443, "proto": "TCP", "flow_id": 1000+i,
               "tls": {"sni": "api.openai.com.attacker.invalid" if case == "non-provider" else "api.openai.com", "version": "TLS 1.3"}}
        if case in {"dns-connect", "dns-only"}:
            eve.update(event_type="dns", src_ip="10.88.0.53", dest_ip=client, src_port=53, dest_port=53000,
                       dns={"version": 3, "type": "answer", "rcode": "NOERROR", "queries": [{"rrname": "api.openai.com", "rrtype": "A"}],
                            "answers": [{"rrname": "api.openai.com", "rrtype": "A", "rdata": server}]})
            eve.pop("tls")
        pair = [("log_falco", falco), ("log_suri", eve)]
        if case == "reordered":
            pair.reverse()
        if case == "dns-only":
            pair = [("log_suri", eve)]
        for key, event in pair:
            redis_push(key, event)

    # Synthetic Suricata flow records populate the Network Flows (4005)
    # dashboard: counts, top talkers and the source->destination IP Sankey.
    # They contain no Falco tuple, so they cannot become bypass findings.
    flows = [
        ("10.88.10.10", "203.0.113.10", 1200, 2400, 12, 9),
        ("10.88.10.10", "203.0.113.11", 800, 1600, 8, 6),
        ("10.88.10.11", "203.0.113.10", 600, 900, 7, 5),
        ("10.88.10.11", "203.0.113.12", 400, 700, 5, 4),
        ("10.88.10.12", "203.0.113.11", 300, 500, 4, 3),
        ("2001:db8:1::4", "2001:db8:2::8", 500, 800, 6, 4),
    ]
    for i, (client, server, sent, received, packets_sent, packets_received) in enumerate(flows):
        flow = {
            "timestamp": timestamp(0),
            "host_name": "lab-ai-node",
            "event_type": "flow",
            "src_ip": client,
            "src_port": 60000 + i,
            "dest_ip": server,
            "dest_port": 443,
            "proto": "TCP",
            "app_proto": "tls",
            "flow_id": 2000 + i,
            "flow": {
                "pkts_toserver": packets_sent,
                "pkts_toclient": packets_received,
                "bytes_toserver": sent,
                "bytes_toclient": received,
                "start": timestamp(-5),
                "end": timestamp(0),
            },
        }
        redis_push("log_suri", flow)

    os_url = os.getenv("OS_URL", "http://opensearch:9200").rstrip("/")
    query = {"size": 100, "query": {"prefix": {"outbound_ai.pod_name": run+"-"}}}
    deadline = time.monotonic() + 40
    seen = set()
    while time.monotonic() < deadline:
        try:
            request = urllib.request.Request(os_url+"/ocsf-1.1.0-6003-api_activity*/_search", data=json.dumps(query).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.load(response)
            seen = {hit["_source"]["outbound_ai"]["pod_name"].removeprefix(run+"-") for hit in result["hits"]["hits"]}
            if seen - expected:
                raise AssertionError(f"Unexpected bypass findings: {seen - expected}")
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
        if seen == expected:
            # Allow asynchronous queues to expose a negative-case regression.
            time.sleep(3)
            with urllib.request.urlopen(request, timeout=5) as response:
                final = json.load(response)
            final_cases = {h["_source"]["outbound_ai"]["pod_name"].removeprefix(run+"-") for h in final["hits"]["hits"]}
            assert final_cases == expected, final_cases
            flow_buckets = verify_flows(os_url)
            print(
                f"PASS {run}: {sorted(expected)}; negative cases produced no bypass findings; "
                f"{flow_buckets} source->destination flow buckets indexed"
            )
            return
        time.sleep(1)
    raise AssertionError(f"Expected {expected}, observed {seen}. Use an IDS-capable rebuilt collector binary.")


if __name__ == "__main__":
    main()
