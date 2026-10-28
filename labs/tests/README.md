# Lab tests

Shared pytest suite for the six gateways, Altprobe and OpenSearch.

| Category | Coverage |
|---|---|
| `smoke` | Gateway, MCP, REST, AI gateway and OCSF ingestion |
| `function` | MCP tools/resources/prompts, REST and AI gateway |
| `security` | Authentication, input rejection and MCP containment |
| `e2e` | Traffic reaches OpenSearch through the collector |
| `sbom` | SBOM components and fixture CVEs in OCSF 2002 |
| `traces` | Internal/native spans, W3C IDs and ingest mappings |
| `gateway` | Redis capture, SSE and body limits on Kong/Traefik/Higress |

```bash
python3 -m pip install -r requirements.txt
LAB_GATEWAY=apisix LAB_INDEX_WAIT=60 python3 run_tests.py
LAB_GATEWAY=apisix python3 run_tests.py traces
```

`LAB_GATEWAY` is `apisix`, `envoy`, `openresty`, `kong`, `traefik` or `higress`.
The other settings are `LAB_BASE` (gateway), `LAB_OS_BASE`, `LAB_INDEX_WAIT`
and optional `LAB_ALTPROBE_CONTAINER`.

Tests use real gateway traffic and never insert synthetic OpenSearch documents.
OpenResty skips the native OTLP trace case; the internal span case still runs.
Results are written to `logs/junit-<category>.xml` and `logs/altprobe.log`.
