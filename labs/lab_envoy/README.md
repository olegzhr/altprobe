# Altprobe Lab - Envoy

This lab shows the quickest way to run Altprobe behind Envoy and inspect the
traffic it collects. It uses only local demo services:

- Envoy receives HTTP traffic on `http://localhost:9080`.
- The mock service provides safe `/mcp`, `/test-api`, `/inventory`, and
  `/traces` endpoints.
- Envoy writes a JSON access log to a shared volume, and Altprobe reads it.
- OpenSearch stores normalized OCSF events.

No external model provider or collector is contacted by default.

## Start

```bash
cd labs/lab_envoy
docker compose build --no-cache altprobe
docker compose up -d --build --wait
docker compose ps
```

Check the demo service directly:

```bash
curl -s http://localhost:8000/health
```

Send harmless traffic through Envoy:

```bash
curl -s -X POST http://localhost:9080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
```

## Demo Requests

MCP tool call:

```bash
curl -s -X POST http://localhost:9080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hello","arguments":{"name":"Demo","language":"en"}}}'
```

REST API with demo credentials:

```bash
TOKEN=$(curl -s -X POST http://localhost:9080/test-api/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo_user&password=pwd12345" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:9080/test-api/users/me/ \
  -H "Authorization: Bearer $TOKEN"
```

AI Gateway demo route:

```bash
curl -s -X POST http://localhost:9080/ai-gateway/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"demo-model","messages":[{"role":"user","content":"hello"}]}'
```

## Observe Altprobe

```bash
docker compose logs -f altprobe
```

OpenSearch is available at `http://localhost:9200`, and OpenSearch Dashboards
is available at `http://localhost:5601`.

Query indexed OCSF events:

```bash
curl -s "http://localhost:9200/ocsf-1.1.0-4002-http_activity*/_count"
curl -s "http://localhost:9200/ocsf-1.1.0-6003-api_activity*/_count"
```

Inspect the raw Envoy access log:

```bash
docker run --rm -v lab_envoy_envoy-logs:/logs busybox tail -n 5 /logs/access.log
```

## Tests

Run the unified Python test suites (smoke, function, security, e2e, sbom)
from the shared test directory:

```bash
cd ../tests
python3 -m pip install -r requirements.txt   # once: installs pytest
LAB_BASE=http://localhost:9080 python3 run_tests.py
```

Run a single suite:

```bash
LAB_BASE=http://localhost:9080 python3 run_tests.py sbom
```

The tests only use harmless demo traffic: MCP methods, REST demo endpoints, the
local AI Gateway mock and a bundled CycloneDX SBOM fixture. Requires Python
3.8+. Artifacts (JUnit XML report and the Altprobe debug log) are written to
`labs/tests/logs/`.

## Ports

| Port | Service | Purpose |
|------|---------|---------|
| 9080 | Envoy | Gateway entry point |
| 9901 | Envoy admin API | Local admin API |
| 8000 | Mock | Direct demo service access |
| 9200 | OpenSearch | OCSF event API |
| 5601 | OpenSearch Dashboards | Event dashboards |

## Stop

```bash
docker compose down
docker compose down -v
```

`docker compose down -v` also removes indexed lab data.

## Policy on the proxy side

- `envoy/envoy.yaml` has a separate `policy_listener` on **9443** with downstream
  mTLS (client certificates from `envoy/certs`, generated at startup). Its
  `/policy-check` route uses `envoy.filters.http.ext_authz` (gRPC) and forwards
  decisions to the `altprobe_policy` cluster (`127.0.0.1:9191`).
- The main listener on **9080** (`/mcp`, `/test-api`, AI Gateway) has no
  `ext_authz`; Policy applies only to the mTLS listener.
- Altprobe: `POLICY_ENABLED=true`, `POLICY_TYPE_AGENT=envoy`,
  `POLICY_SIDECAR_GRPC_ENABLED=true` (loopback 9191).
- The single URI SAN of the client certificate is the identity
  (`auth:envoy:<principal>`). Requests without an authenticated principal, and
  all traffic on the main listener, fall back to the observed source address
  (`ip:<host>:<remote_addr>`). Client-supplied identity headers are ignored.

### Run without policy

1. Set `POLICY_ENABLED=false` in `docker-compose.yaml`.
2. Remove the `policy_listener` (9443) or its `ext_authz` filter from
   `envoy/envoy.yaml`. The main 9080 listener is unaffected.

## Policy and Incident update

Runtime Docker builds install the SHA-256-pinned Altprobe `1.0.2` package.
For other packages, set both version and digest as described in the
[package guide](../README.md#collector-package). See the
[shared test guide](../tests/README.md) for all ports and the lab test suite.

GET https://localhost:9443/policy-check uses standard ext_authz v3 over gRPC.
Clients must present a lab CA-signed certificate with exactly one URI SAN.
The certificate init service generates active/blocked/unknown identities in the
envoy-certs volume. The Policy regression tests were removed; the retained
suite covers the proxy plugin and its OpenSearch output. The ordinary detector
listener is http://localhost:9080.

Mock console changes use
PATCH http://localhost:8000/lab/policy/agents/policy-active with blockStatus
blocked or active; Altprobe consumes the status through inventory polling.
[Envoy ext_authz protocol](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto.html).

Incident delivery uses POLICY_INCIDENT_ENABLED / POLICY_* settings; gateway
Policy enforces access decisions. See the [shared guide](../tests/README.md).

## TLS verification

SINKS_AF_TLS_VERIFY and SINKS_OS_TLS_VERIFY default to false in this lab. Set
them to true to verify HTTPS certificates. Optional SINKS_AF_TLS_CA_FILE and
SINKS_OS_TLS_CA_FILE refer to PEM CA files inside Altprobe; mount the files read-only.
Alertflex verification also applies to inventory, logs, traces and incidents.
SINKS_AF_TLS_CA_FILE / SINKS_OS_TLS_CA_FILE point to PEM CA files inside
Altprobe. The default HTTP lab
services do not perform a TLS handshake.
