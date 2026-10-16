# Traefik Proxy OSS: local demo lab

Full stack modelled on the APISIX lab: its own `mock/`, `opensearch/`,
`altprobe/` and `traefik/`, plus Redis, OpenSearch 2.19.1, Dashboards and init
jobs that load index templates / saved objects. GeoIP and SBOM use local
fixtures. The plugin captures request/response and pushes events to Redis
`log_proxy`; the real Altprobe normalises them into OCSF and indexes them in
OpenSearch.

Altprobe is installed from the published `1.0.2` Linux package. The build
verifies its pinned SHA-256 before installation. No collector source checkout
or particular repository directory name is required. Gateway plugins are built
from the sources included in this repository.

See the [release and rebuild instructions](../README.md#collector-package).

## Configuration

| Parameter | Value |
|---|---|
| Gateway | `traefik` |
| Asset / identity | `auth:traefik:<consumer>` |
| Mock | MCP, REST, OpenAI-compatible, inventory, traces, incidents, echo/SSE |
| Telemetry | bounded copies of both bodies, Redis -> Altprobe -> OpenSearch |
| Policy | OPA HTTP envelope, localhost:8181 in the gateway network namespace |
| Storage | dedicated named volumes for OpenSearch and the incident spool |

The demo runs without cloud credentials or a real AI provider. MCP `/mcp` and
`/test-api/*` are open for functional/detector tests. Policy applies only to
`/policy-check`, `/policy-other`, `/policy-unknown`.

```powershell
docker compose up -d --build --wait
```

The inventory/trace/incident sink defaults to `http://mock:8000`.
`policy-active` is active, `policy-blocked` is blocked, `policy-unknown` is
absent from inventory. Changes via `/lab/policy/agents/{name}` and
`/lab/policy/targets/endpoint` take effect after the next inventory poll (~60 s).

Tests are shared with the other demo labs: `../tests`. For a running stand:

```powershell
$env:LAB_GATEWAY="traefik"
$env:LAB_PROFILE="demo"
$env:LAB_LOCAL_COLLECTOR="1"
python ../tests/run_tests.py
```

## Requests and tests

Demo credentials: `apikey: lab-policy-active-key`, `lab-policy-blocked-key`,
`lab-policy-unknown-key`. The consumer identity comes from the key check, not
from client identity headers. The AI path `/ai-gateway/v1/chat/completions` is
rewritten to the local mock `/test-api/v1/chat/completions`.

The shared tests check MCP/REST/AI, auth failures and containment, OCSF
HTTP/API/Suricata/GeoIP/SBOM, provisioned Dashboards, Redis capture of both
bodies, truncation of the copied body while forwarding the full message, SSE and
real Policy. The optional slow policy case is marked `slow_policy`; exclude it
with `-m "not slow_policy"`.

| localhost port | Service |
|---|---|
| 9080 | Gateway |
| 8000 | Mock |
| 16379 | Redis |
| 9200 | OpenSearch |
| 5601 | OpenSearch Dashboards |

Run the stands sequentially: host ports are shared. Container/project names and
volumes differ by gateway. `docker compose down` keeps the data in volumes. Test
artifacts are written to `../tests/logs/`.

Headers carrying credentials are redacted; body content can be sensitive.
Telemetry is best effort, without durable retry. Policy is synchronous and fails
closed on an invalid/unavailable listener. The labs use API keys and HTTP on
localhost; this is a demonstration configuration.
