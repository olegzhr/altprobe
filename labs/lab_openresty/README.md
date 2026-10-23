# OpenResty / Altprobe MVP lab

OpenResty captures proxy telemetry in Lua (request/response, capped at 64 KiB)
and writes it to Redis `log_proxy`; Altprobe shares the network namespace,
consumes the queue and indexes OCSF events in OpenSearch. Policy is enforced on
dedicated routes (`/policy-check`, `/policy-other`, `/policy-unknown`) through a
loopback Altprobe sidecar; the detector routes stay open. Other gateway labs
(APISIX, Envoy, Kong OSS, Traefik, Higress) are available under `labs/`.

## Policy on the proxy side

The gateway enforces Policy; Altprobe only evaluates its local inventory snapshot.

- `openresty/lua/policy.lua` runs as `access_by_lua_file` on the policy routes. It
  authenticates the `apikey` header against the demo keys
  (`lab-policy-active-key` -> `policy-active`,
  `lab-policy-blocked-key` -> `policy-blocked`,
  `lab-policy-unknown-key` -> `policy-unknown`), sends the APISIX-shaped
  `input.type=http` envelope to the Altprobe sidecar at
  `POST http://127.0.0.1:8181/v1/data/altprobe/allow`, and enforces
  `result.allow` / `result.status_code`.
- `openresty/nginx.conf`: `location ~ ^/(policy-check|policy-other|policy-unknown)$`
  uses `access_by_lua_file /etc/openresty/lua/policy.lua`. `location /`
  (`/mcp`, `/test-api/*`, AI Gateway alias) has no policy handler.
- Altprobe (`docker-compose.yaml`): `POLICY_ENABLED=true`,
  `POLICY_TYPE_AGENT=openresty`, `POLICY_SIDECAR_HTTP_ENABLED=true` (loopback
  8181), `POLICY_UNKNOWN_AGENT=deny`, `POLICY_UNKNOWN_ENDPOINT=deny`.

Demo keys: `apikey: lab-policy-active-key` (allowed), `lab-policy-blocked-key`
(403), `lab-policy-unknown-key` (403). A missing or invalid key returns 401.

### Run without policy

Disable it on **both** sides:

1. Set `POLICY_ENABLED=false` in `docker-compose.yaml` (stops the Altprobe sidecar).
2. Remove `access_by_lua_file /etc/openresty/lua/policy.lua` from the policy
   `location` block in `openresty/nginx.conf` (or delete that block). Otherwise
   the gateway keeps calling the stopped sidecar and requests fail closed (503).

All detector routes (`/mcp`, `/test-api/*`, `/ai-gateway/*`) already run without
Policy.

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

Detector routes are open telemetry paths (`/mcp`, `/test-api/*`, `/ai-gateway/*`;
the AI Gateway path is rewritten to `/test-api/v1/chat/completions`). Only the
three policy routes above require credentials, and `/health` is handled locally.
The lab never requires Alertflex: `SINKS_AF_URL` defaults to the bundled mock
(`http://mock:8000`); set `ALERTFLEX_URL` only to integrate a real deployment.

## Telemetry

Gateway logs go to Redis `log_proxy`. The authenticated consumer is set on the
policy routes and is the identity (`auth:openresty:<consumer>`); open detector
routes carry no consumer, so Altprobe falls back to the observed source address
(`ip:<host>:<remote_addr>`). Client-supplied identity headers are ignored, and
MCP session id/method are protocol metadata only. Request and response capture
is capped at 64 KiB and records missing/truncated sizes. A timer sends the Redis
telemetry because cosockets are unavailable in log phase. Logs are telemetry
only.

## TLS

SINKS_AF_TLS_VERIFY and SINKS_OS_TLS_VERIFY explicitly default to false. Override
them for HTTPS certificate verification and optionally mount PEM CA files using
SINKS_AF_TLS_CA_FILE / SINKS_OS_TLS_CA_FILE. These HTTP lab mocks do not use TLS.

## Tests

The unified suite in `labs/tests/altprobe_lab` covers the proxy plugin and its
OpenSearch output. Run from `labs/tests` with the lab running:

    cd ../tests
    LAB_BASE=http://localhost:9080 python3 run_tests.py

See the [shared test guide](../tests/README.md).

Implementation references: [OpenResty Lua API](https://github.com/openresty/lua-nginx-module), [Docker image](https://github.com/openresty/docker-openresty).
