# Altprobe Lab - APISIX

This lab shows the quickest way to run Altprobe behind APISIX and inspect the
traffic it collects. It uses only local demo services:

- APISIX receives HTTP traffic on `http://localhost:9080`.
- The mock service provides safe `/mcp`, `/test-api`, `/inventory`, and
  `/traces` endpoints.
- Redis carries gateway logs from APISIX to Altprobe.
- OpenSearch stores normalized OCSF events.

No external model provider or collector is contacted by default.

Altprobe is installed from the published `1.0.2` package and checked against its
pinned SHA-256. No collector source checkout is required. CRS is pinned to
`4.29.0`. SBOM tests use the bundled fixture; set `LAB_INSTALL_TRIVY=true` for
optional Trivy installation. See the [package guide](../README.md#collector-package).
The shared [session pytest suite](../tests/README.md) covers all six labs.

## Start

```bash
cd labs/lab_apisix
docker compose build --no-cache altprobe
docker compose up -d --build --wait
docker compose ps
```

Check the demo service directly:

```bash
curl -s http://localhost:8000/health
```

Send harmless traffic through APISIX:

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
| 9080 | APISIX | Gateway entry point |
| 9180 | APISIX admin API | Local admin API |
| 9000 | APISIX dashboard | Local dashboard |
| 2379 | etcd | APISIX configuration storage |
| 16379 | Redis | Gateway log queue |
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

The gateway enforces Policy; Altprobe only evaluates its local inventory snapshot.

- `apisix/entrypoint.sh` creates the `/policy-check` route with the built-in
  `key-auth` + `opa` plugins (`opa.host=http://127.0.0.1:8181`,
  `policy=altprobe/allow`, `with_consumer=true`) and registers the consumers
  `policy-active`, `policy-blocked`, `policy-unknown` with the `apikey` values
  `lab-policy-active-key`, `lab-policy-blocked-key`, `lab-policy-unknown-key`.
- Altprobe (`docker-compose.yaml`): `POLICY_ENABLED=true`,
  `POLICY_TYPE_AGENT=apisix`, `POLICY_SIDECAR_HTTP_ENABLED=true` (loopback 8181).
- The authenticated consumer is the identity (`auth:apisix:<consumer>`); requests
  without a consumer fall back to the observed source address
  (`ip:<host>:<remote_addr>`). Client-supplied identity headers are ignored.
- `/mcp*`, `/test-api*` and the AI Gateway alias are **not** policy-gated.

### Run without policy

Disable it on **both** sides:

1. Set `POLICY_ENABLED=false` in `docker-compose.yaml` (stops the Altprobe sidecar).
2. Remove the `key-auth` + `opa` plugins from the `/policy-check` route in
   `apisix/entrypoint.sh` (or delete that route). Otherwise the gateway keeps
   calling the stopped sidecar and requests fail closed with 503.

All other routes already run without Policy.

## Policy and Incident update

Runtime Docker builds install the SHA-256-pinned Altprobe `1.0.2` package.
For other packages, set both version and digest as described in the
[package guide](../README.md#collector-package). See the
[shared test guide](../tests/README.md) for all ports and the lab test suite.

GET /policy-check uses the standard key-auth and opa plugins, with authenticated
consumer identity passed to the loopback Altprobe HTTP listener. For example:

    curl -i http://localhost:9080/policy-check -H 'apikey: lab-policy-active-key'
    curl -i http://localhost:9080/policy-check -H 'apikey: lab-policy-blocked-key'
    curl -X PATCH http://localhost:8000/lab/policy/agents/policy-active -H 'Content-Type: application/json' -d '{"blockStatus":"blocked"}'
    curl -X PATCH http://localhost:8000/lab/policy/agents/policy-active -H 'Content-Type: application/json' -d '{"blockStatus":"active"}'

The last command models console unblock. Allow up to the next 60-second inventory
poll before expecting enforcement to change. Existing /mcp and /test-api routes
remain detector demos and do not require Policy credentials.
[APISIX OPA protocol](https://apisix.apache.org/docs/apisix/plugins/opa/).

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
