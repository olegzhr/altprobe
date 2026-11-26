# Lab tests

Shared pytest suite for the five gateway labs, Altprobe and OpenSearch.

| Category | Coverage |
|---|---|
| `smoke` | Gateway, MCP, REST, AI gateway and OCSF ingestion |
| `function` | MCP tools/resources/prompts, REST and AI gateway |
| `security` | Authentication, input rejection and MCP containment |
| `e2e` | Traffic reaches OpenSearch through the collector |
| `sbom` | SBOM components and fixture CVEs in OCSF 2002 |
| `traces` | Internal/native spans, W3C IDs and ingest mappings |
| `gateway` | Request/response capture, truncation, SSE and MCP profile on all five gateway labs |

```bash
python3 -m pip install -r requirements.txt
LAB_GATEWAY=apisix LAB_INDEX_WAIT=60 python3 run_tests.py
LAB_GATEWAY=apisix python3 run_tests.py traces
```

`LAB_GATEWAY` is `apisix`, `envoy`, `kong`, `traefik` or `higress`.
The other settings are `LAB_BASE` (gateway), `LAB_OS_BASE`, `LAB_INDEX_WAIT`
and optional `LAB_ALTPROBE_CONTAINER`.

Tests use real gateway traffic and never insert synthetic OpenSearch documents.
The native OTLP trace case is skipped for gateways that do not expose native
OTLP; the internal span case still runs.
Results are written to `logs/junit-<category>.xml` and `logs/altprobe.log`.

## Source-lab verification

This gateway pytest suite is separate from the source-lab runner. From the
repository root, use `python3 labs/run_source_lab.py nemo start|test|stop`
(replace `nemo` with `sbom` or `suricata`). The source tests require current run
receipts, validate source/config/image/binary provenance and reject historical
events. The NeMo test also checks actual agent/refusal and mock audit evidence.
See the [lab catalog](../README.md) for OpenShell's external CLI workflow.

Offline regressions:

```bash
python3 labs/tests/test_source_runs.py
python3 connectors/shipper_altprobe/test_shipper.py
```

`test_connector_records.lua` runs actual APISIX/Kong Lua handlers with
isolated adapters. Invoke `luajit labs/tests/test_connector_records.lua .` from
the repository root with `cjson.safe` installed on `LUA_CPATH`. No gateway,
Redis or OpenSearch is contacted.
