# lab_suricata: real Suricata -> shipper -> Redis -> Altprobe

Self-contained Suricata lab. A small traffic generator makes outbound LLM DNS
and TLS requests against local DNS/TLS endpoints; real Suricata records
`tls`, `dns` and `flow` events in `eve.json`. The shared
`connectors/shipper_altprobe` forwards those events to the Redis list
`log_suri`, and Altprobe writes OCSF 4007 (TLS), 4001 (DNS) and 4005 (network
flow) to OpenSearch.

The lab verifies the Suricata sensor path only.

```text
traffic generator
  ├─ DNS query ───────────────► dns (CoreDNS 172.28.0.20)
  └─ TLS ClientHello ────────► tls (SNI api.anthropic.com / example.org)
                                      │
                                      ▼
                              Suricata (host net, br-<network-id>)
                                      │
                              shipper (tls/dns/flow)
                                      │
                                      ▼
                                   Redis log_suri
                                      │
                                      ▼
                         Altprobe (SOURCES_SURICATA_REDIS)
                                      │
                                      ▼
                    OCSF 4007 / 4001 / 4005 -> OpenSearch
```

## Components

| Service | Role |
|---|---|
| `traffic` | Generates deterministic LLM DNS + TLS traffic on the lab bridge |
| `dns` | CoreDNS local resolver; answers every A query with the TLS endpoint |
| `tls` | Local TLS endpoint with SNI `api.anthropic.com`; no external provider |
| `suricata` | Real Suricata 7.0 on the host network, captures the lab `br-<network-id>` bridge (`tls`, `dns`, `flow`, `http`) |
| `shipper` | Shared `connectors/shipper_altprobe`; normalises Suricata records and pushes to `log_suri` |
| `altprobe` | Collector with only the Suricata source |
| `opensearch` / `opensearch-dashboards` | OCSF storage and dashboards |

## Start

```bash
# From the repository root
python3 labs/run_source_lab.py suricata start
```

The runner creates a unique `LAB_RUN_ID`; the traffic generator uses it in a
DNS name (`run-<run-id>.api.anthropic.com`), so tests reject old events.

## Open

- OpenSearch: `http://127.0.0.1:19200`
- Dashboards: `http://127.0.0.1:5601/app/dashboards`
- TLS activity: `OCSF TLS Activity (4007)`
- DNS activity: `OCSF DNS Activity (4001)`
- Network flows: `OCSF Network Flows (4005)`

## Test

```bash
python3 labs/run_source_lab.py suricata test
```

Expected: `status=PASS checks=4`.

The test verifies:

1. Redis `log_suri` contains current `tls` and `dns` events from the shipper.
2. OCSF 4007 has TLS SNI `api.anthropic.com` and a non-LLM `example.org` SNI.
3. OCSF 4001 has the run-specific DNS query and `example.org`.
4. OCSF 4005 has a flow with non-zero bytes and packets.

## Stop

```bash
python3 labs/run_source_lab.py suricata stop
```

`stop` and a plain `docker compose down` keep the OpenSearch data, Suricata logs
and spool volumes. For a fully clean repeat, reset the lab **destructively**:

```bash
docker compose down -v --remove-orphans
```

> `-v` deletes the lab volumes (`opensearch-data`, `suricata-logs`,
> `altprobe-data`). Indexed events, Suricata logs and queued records are lost.

## Security notes

- This lab is local-only. Published ports bind `127.0.0.1`, OpenSearch runs with
  its security plugin disabled and the credentials are lab placeholders.
- The `suricata` container runs `privileged` on `network_mode: host` because it
  needs raw packet capture of the lab bridge. Run it on a disposable host or lab
  VM, not on a shared or production machine.
- The traffic generator only talks to the local `dns` and `tls` containers
  (`curl -k` accepts their self-signed certificate); no external provider is
  contacted.

## Notes

- No real Anthropic/OpenAI endpoint is contacted. TLS and DNS are local.
- The traffic generator is intentionally a simple container, so the test is
  about Suricata and the shipping path, not about a coding agent.
- Suricata writes only to its log volume; the shipper reads `eve.json` and
  selects `tls`, `dns`, `flow` and `http` event types.
- The run receipt records container/image/start time and the release package digest; a
restart or release/lab change requires a new `start`.
