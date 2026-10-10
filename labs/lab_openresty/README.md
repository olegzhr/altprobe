# Altprobe Lab - OpenResty

This lab shows how to run Altprobe behind OpenResty (nginx + Lua) and inspect
the HTTP traffic it collects. It is telemetry-only: OpenResty does not make
policy/OPA decisions here, it just logs each request to Redis. It uses only
local demo services:

- OpenResty receives HTTP traffic on `http://localhost:9080`.
- The mock service provides safe `/mcp`, `/test-api`, `/inventory`, and
  `/traces` endpoints.
- Redis carries gateway logs from OpenResty to Altprobe (key `log_proxy`).
- OpenSearch stores normalized OCSF events.

No external model provider or collector is contacted by default.

## Start

```bash
cd labs/lab_openresty
docker compose build
docker compose up -d
docker compose ps
```

Check the demo service directly:

```bash
curl -s http://localhost:8000/health
```

Send harmless traffic through OpenResty:

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

## How OpenResty feeds Altprobe

`openresty/lua/access.lua` stages the request body, request headers and the
JSON-RPC method in the access phase (the same capture the APISIX `redis-logger`
plugin does), `openresty/lua/log.lua` runs in the log phase and pushes one JSON
record per request to the Redis list `log_proxy`, and `openresty/lua/capture.lua`
caps the response body. The record uses the APISIX gateway field set
(`host_name`, `time_local`, `duration`, `status`, `request_uri`,
`request_body`/`response_body`, `req_headers`/`resp_headers`, `mcp_method`,
`mcp_session_id`, agent headers) that Altprobe's proxy parser expects and that
the APISIX lab tests exercise. Altprobe reads that list through its standard
proxy (Redis) source, normalizes the traffic into OCSF, and writes it to
OpenSearch. The `/ai-gateway/` route is rewritten to the mock's
OpenAI-compatible endpoint, matching the APISIX and Envoy labs. No policy/OPA
sidecar and no Alertflex incident delivery are configured.

## Tests

Run the public Python test suites (smoke, function, security, e2e, geo, sbom):

```bash
cd tests
python3 -m pip install -r requirements.txt   # once: installs pytest
LAB_BASE=http://localhost:9080 python3 run_tests.py
```

Run a single suite:

```bash
LAB_BASE=http://localhost:9080 python3 run_tests.py sbom
```

The tests only use harmless demo traffic: MCP methods, REST demo endpoints, the
local AI Gateway mock, emulated Suricata events in Redis, and a bundled
CycloneDX SBOM fixture. Requires Python 3.8+. Artifacts (JUnit XML report and
the Altprobe debug log) are written to `tests/logs/`.

## Ports

| Port | Service | Purpose |
|------|---------|---------|
| 9080 | OpenResty | Gateway entry point |
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
