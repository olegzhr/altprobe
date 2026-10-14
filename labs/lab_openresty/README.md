# OpenResty / Altprobe MVP lab

OpenResty captures proxy telemetry in Lua (request/response, capped at 64 KiB)
and writes it to Redis `log_proxy`; Altprobe shares the network namespace,
consumes the queue and indexes OCSF events in OpenSearch. This lab runs
**without policy**: it makes no access decisions. APISIX and Envoy retain their
existing labs. Kong and stdio-proxy are deferred.

## Start

From this folder, when a matching GitHub release is available:

    docker compose up -d --build

Altprobe is downloaded from GitHub Releases by the runtime Dockerfile; local
sources are not compiled by this lab. Set ALTPROBE_VERSION to a published
package. The retained default 1.0.2 is not a claim that the current workspace
changes have been published.

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
See [TLS settings](../../src/doc/tls_clients.md).

## Tests

The unified suite in `labs/tests/altprobe_lab` covers the proxy plugin and its
OpenSearch output. Run from `labs/tests` with the lab running:

    cd ../tests
    LAB_BASE=http://localhost:9080 python3 run_tests.py

See the [shared test guide](../tests/README.md).

Implementation references: [OpenResty Lua API](https://github.com/openresty/lua-nginx-module), [Docker image](https://github.com/openresty/docker-openresty).
