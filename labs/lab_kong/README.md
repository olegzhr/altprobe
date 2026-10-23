# Kong OSS: local demo lab

Full stack modelled on the APISIX lab: its own `mock/`, `opensearch/`,
`altprobe/` and `kong/`, plus Redis, OpenSearch 2.19.1, Dashboards and init jobs
that load index templates / saved objects. The SBOM regression uses a bundled
CycloneDX fixture. The plugin captures request/response and pushes events to
Redis `log_proxy`; the real Altprobe normalises them into OCSF and indexes them
in OpenSearch.

Identity is the gateway-authenticated auth key (`auth:kong:<consumer>`) first
and the observed source address (`ip:<host>:<remote_addr>`) otherwise. MCP
session id and JSON-RPC method are protocol metadata, not identity.

Altprobe is installed from the published `1.0.2` Linux package. The build
verifies its pinned SHA-256 before installation. No collector source checkout
or particular repository directory name is required. Gateway plugins are built
from the sources included in this repository.

See the [release and rebuild instructions](../README.md#collector-package).

## Configuration

| Parameter | Value |
|---|---|
| Gateway | `kong` |
| Asset / identity | `auth:kong:<consumer>`, else `ip:<host>:<remote_addr>` |
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
$env:LAB_GATEWAY="kong"
$env:LAB_PROFILE="demo"
$env:LAB_LOCAL_COLLECTOR="1"
python ../tests/run_tests.py
```

## Policy on the proxy side

- `kong/kong.yaml`: the `policy` route (`/policy-check`, `/policy-other`,
  `/policy-unknown`) uses the built-in `key-auth` plugin (`apikey` header) and the
  `altprobe` plugin with `policy_enabled: true`; the plugin calls the Altprobe
  sidecar at `127.0.0.1:8181/v1/data/altprobe/allow`.
- Consumers `policy-active`, `policy-blocked`, `policy-unknown` map to the API
  keys `lab-policy-active-key`, `lab-policy-blocked-key`,
  `lab-policy-unknown-key`; identity comes from `kong.client.get_consumer()`.
- Altprobe: `POLICY_ENABLED=true`, `POLICY_TYPE_AGENT=kong`,
  `POLICY_SIDECAR_HTTP_ENABLED=true` (loopback 8181).
- The `/` and AI Gateway routes use the telemetry-only `altprobe` plugin.

### Run without policy

1. Set `POLICY_ENABLED=false` in `docker-compose.yaml`.
2. In `kong/kong.yaml` remove `policy_enabled: true` (or the route-scoped
   `altprobe` plugin) from the `policy` route so the gateway stops calling the
   sidecar; remove `key-auth` as well if those paths should be open.

## Requests and tests

Demo credentials: `apikey: lab-policy-active-key`, `lab-policy-blocked-key`,
`lab-policy-unknown-key`. The consumer identity comes from the key check;
client-supplied identity headers are ignored. Without an authenticated
consumer, events are keyed by `ip:<host>:<remote_addr>`. The AI path `/ai-gateway/v1/chat/completions` is
rewritten to the local mock `/test-api/v1/chat/completions`.

The shared tests check MCP/REST/AI, auth failures and containment, OCSF
4002/2004/6003, SBOM 2002, provisioned Dashboards, Redis capture of both
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

Run the stands sequentially: host ports are shared. Compose project names and
volumes differ by gateway. `docker compose down` keeps the data in volumes. Test
artifacts are written to `../tests/logs/`.

Headers carrying credentials are redacted; body content can be sensitive.
Telemetry is best effort, without durable retry. Policy is synchronous and fails
closed on an invalid/unavailable listener. The labs use API keys and HTTP on
localhost; this is a demonstration configuration.
