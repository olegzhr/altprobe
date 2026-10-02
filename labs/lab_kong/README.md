# Altprobe Lab - Kong

This lab shows the quickest way to run Altprobe behind Kong and inspect the
traffic it collects. It uses only local demo services:

- Kong receives HTTP traffic on `http://localhost:8010`.
- The mock service provides safe `/mcp`, `/test-api`, `/inventory`, and
  `/traces` endpoints.
- Redis carries gateway logs from Kong to Altprobe.
- OpenSearch stores normalized OCSF events.

No external model provider or collector is contacted by default.

## Start

```bash
cd labs/lab_kong
docker compose build
docker compose up -d
docker compose ps
```

Check the demo service directly:

```bash
curl -s http://localhost:8000/health
```

Send harmless traffic through Kong:

```bash
curl -s -X POST http://localhost:8010/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
```

## Demo Requests

MCP tool call:

```bash
curl -s -X POST http://localhost:8010/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hello","arguments":{"name":"Demo","language":"en"}}}'
```

REST API with demo credentials:

```bash
TOKEN=$(curl -s -X POST http://localhost:8010/test-api/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo_user&password=pwd12345" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:8010/test-api/users/me/ \
  -H "Authorization: Bearer $TOKEN"
```

AI Gateway demo route:

```bash
curl -s -X POST http://localhost:8010/ai-gateway/v1/chat/completions \
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

Run the public Python test suites (smoke, function, security, e2e, geo, sbom):

```bash
cd tests
python3 -m pip install -r requirements.txt   # once: installs pytest
LAB_BASE=http://localhost:8010 python3 run_tests.py
```

Run a single suite:

```bash
LAB_BASE=http://localhost:8010 python3 run_tests.py sbom
```

The tests only use harmless demo traffic: MCP methods, REST demo endpoints, the
local AI Gateway mock, emulated Suricata events in Redis, and a bundled
CycloneDX SBOM fixture. Requires Python 3.8+. Artifacts (JUnit XML report and
the Altprobe debug log) are written to `tests/logs/`.

## Ports

| Port | Service | Purpose |
|------|---------|---------|
| 8010 | Kong | Gateway entry point |
| 8011 | Kong admin API | Local admin API |
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
