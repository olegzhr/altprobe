# OpenResty / Altprobe MVP lab

OpenResty captures proxy telemetry in Lua (request/response, capped at 64 KiB)
and writes it to Redis `log_proxy`; Altprobe shares the network namespace,
consumes the queue and indexes OCSF events in OpenSearch. This lab runs
**without policy**: it makes no access decisions. Other gateway labs (APISIX,
Envoy, Kong OSS, Traefik, Higress) are available under `labs/`.

## Start

From this folder:

    docker compose build --no-cache altprobe
    docker compose up -d --build --wait

Altprobe is installed from the published `1.0.2` package and checked against its
pinned SHA-256. No collector source checkout is required. See the
[package and rebuild guide](../README.md#collector-package) for version overrides.

| Service | Host port |
| --- | --- |
| OpenResty | 9080 |
| Collector mock | 8000 |
| OpenSearch | 9200 |
| Dashboards | 5601 |
| Redis | 16379 |

All proxy routes are open telemetry paths (`/mcp`, `/test-api/*`,
`/ai-gateway/*`; the AI Gateway path is rewritten to `/test-api/v1/chat/completions`).
Only `/health` is handled locally. The lab never requires Alertflex:
`SINKS_AF_URL` defaults to the bundled mock (`http://mock:8000`); set
`ALERTFLEX_URL` only to integrate a real deployment.

## Telemetry

Gateway logs go to Redis `log_proxy` (consumer_name empty, since there is no
authentication). Request and response capture is capped at 64 KiB and records
missing/truncated sizes. A timer sends the Redis telemetry because cosockets are
unavailable in log phase. Logs are telemetry only.

Suricata Redis input `log_suricata` is configured as a telemetry source.

## TLS

SINKS_AF_TLS_VERIFY and SINKS_OS_TLS_VERIFY explicitly default to false. Override
them for HTTPS certificate verification and optionally mount PEM CA files using
SINKS_AF_TLS_CA_FILE / SINKS_OS_TLS_CA_FILE. These HTTP lab mocks do not use TLS.
PEM CA files are mounted into Altprobe via SINKS_AF_TLS_CA_FILE / SINKS_OS_TLS_CA_FILE.

## Tests

The unified suite in `labs/tests/altprobe_lab` covers the proxy plugin and its
OpenSearch output. Run from `labs/tests` with the lab running:

    cd ../tests
    LAB_BASE=http://localhost:9080 python3 run_tests.py

See the [shared test guide](../tests/README.md).

Implementation references: [OpenResty Lua API](https://github.com/openresty/lua-nginx-module), [Docker image](https://github.com/openresty/docker-openresty).
