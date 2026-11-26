#!/usr/bin/env python3
"""Replay synthetic Suricata EVE records and verify the OCSF documents Altprobe writes.

The overlay feeds the shared `log_suri` Redis list directly, so it exercises the
Suricata source, the OCSF mapping and the OpenSearch sinks without a live sensor.
"""
import datetime as dt
import json
import os
import socket
import time
import urllib.error
import urllib.request
import uuid

TLS_INDEX = "ocsf-1.8.0-4007-ssh_activity*"
DNS_INDEX = "ocsf-1.8.0-4001-network_activity*"
FLOW_INDEX = "ocsf-1.8.0-4005-network_activity*"


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


def count_with_field(os_url, index, field, deadline=40):
    """Wait until at least one stored document carries ``field``; return the count."""
    query = {"size": 0, "query": {"exists": {"field": field}}}
    last = {}
    stop = time.monotonic() + deadline
    while time.monotonic() < stop:
        try:
            request = urllib.request.Request(
                os_url + "/" + index + "/_search",
                data=json.dumps(query).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                last = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
        total = ((last.get("hits") or {}).get("total") or {}).get("value") or 0
        if total:
            return total
        time.sleep(1)
    raise AssertionError(f"No documents with {field} in {index}; last response {last!r}")


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
                os_url + "/" + FLOW_INDEX + "/_search",
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

    # TLS sessions with provider SNI evidence.
    for i, sni in enumerate(["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com"]):
        redis_push("log_suri", {
            "timestamp": timestamp(0),
            "host_name": "lab-ai-node",
            "event_type": "tls",
            "src_ip": f"10.88.0.{10 + i}",
            "src_port": 50000 + i,
            "dest_ip": f"203.0.113.{10 + i}",
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": 1000 + i,
            "tls": {"sni": sni, "version": "TLS 1.3"},
        })

    # DNS answers that resolve a provider name.
    for i, hostname in enumerate(["api.openai.com", "api.anthropic.com"]):
        redis_push("log_suri", {
            "timestamp": timestamp(0),
            "host_name": "lab-ai-node",
            "event_type": "dns",
            "src_ip": "10.88.0.53",
            "src_port": 53,
            "dest_ip": f"10.88.0.{20 + i}",
            "dest_port": 53000 + i,
            "proto": "UDP",
            "flow_id": 1500 + i,
            "dns": {
                "version": 3,
                "type": "answer",
                "rcode": "NOERROR",
                "queries": [{"rrname": hostname, "rrtype": "A"}],
                "answers": [{"rrname": hostname, "rrtype": "A", "rdata": f"203.0.113.{20 + i}"}],
            },
        })

    # Synthetic flows populate the Network Flows (4005) dashboard: counts, top
    # talkers and the source->destination IP Sankey.
    flows = [
        ("10.88.10.10", "203.0.113.10", 1200, 2400, 12, 9),
        ("10.88.10.10", "203.0.113.11", 800, 1600, 8, 6),
        ("10.88.10.11", "203.0.113.10", 600, 900, 7, 5),
        ("10.88.10.11", "203.0.113.12", 400, 700, 5, 4),
        ("10.88.10.12", "203.0.113.11", 300, 500, 4, 3),
        ("2001:db8:1::4", "2001:db8:2::8", 500, 800, 6, 4),
    ]
    for i, (client, server, sent, received, packets_sent, packets_received) in enumerate(flows):
        redis_push("log_suri", {
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
        })

    os_url = os.getenv("OS_URL", "http://opensearch:9200").rstrip("/")
    tls_docs = count_with_field(os_url, TLS_INDEX, "tls.sni")
    dns_docs = count_with_field(os_url, DNS_INDEX, "dns_query.hostname")
    flow_buckets = verify_flows(os_url)
    print(
        f"PASS {run}: OCSF 4007 TLS documents={tls_docs}, "
        f"4001 DNS documents={dns_docs}, {flow_buckets} source->destination flow buckets indexed"
    )


if __name__ == "__main__":
    main()
