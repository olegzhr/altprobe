# Altprobe lab tests

Unified pytest suite for the Altprobe proxy plugin and its OpenSearch (OCSF)
output. The same, environment-driven suite runs against any lab gateway
(APISIX, OpenResty, Envoy, Kong OSS, Traefik or Higress); select the target with
`LAB_BASE`. Only harmless demo traffic is used: MCP methods, REST demo
endpoints, the local AI Gateway mock and a bundled CycloneDX SBOM fixture.

Kong OSS, Traefik and Higress also use this shared suite. Set `LAB_GATEWAY` to the
selected gateway and `LAB_PROFILE=demo`; the added `gateway` category checks real
Redis capture, Altprobe -> OCSF indexing, Dashboards, body limits, SSE and Policy.
Set `LAB_LOCAL_COLLECTOR=1` to enable the mutable mock block/unblock scenario.
Start the chosen lab with `docker compose up -d --build --wait` and run the suite
from this directory (see Run below).

## Layout

| Path | Purpose |
|------|---------|
| `run_tests.py` | Runner (`gateway`, `smoke`, `function`, `security`, `e2e`, `sbom`) |
| `pytest.ini`, `requirements.txt` | pytest configuration and dependency |
| `logs/` | Test artifacts: JUnit XML report and the Altprobe container log |
| `altprobe_lab/common.py` | `requests`-based HTTP and OpenSearch helpers |
| `altprobe_lab/test_smoke.py` | Gateway/mock smoke and OpenSearch ingestion |
| `altprobe_lab/test_function.py` | MCP, REST and AI Gateway behavior |
| `altprobe_lab/test_security.py` | Auth enforcement, input rejection, MCP containment |
| `altprobe_lab/test_e2e.py` | Representative traffic end to end |
| `altprobe_lab/test_sbom.py` | OCSF 2002 findings from the SBOM fixture |
| `altprobe_lab/test_gateway.py` | Extended gateway checks (Kong/Traefik/Higress): Redis capture, body limits, SSE, Policy |

## Run

From this directory, with the target lab running:

```bash
python -m pip install -r requirements.txt   # once: installs pytest and requests
python run_tests.py                          # all categories
python run_tests.py smoke                    # one category
python run_tests.py smoke -k mcp             # extra args are passed to pytest
```

Or invoke pytest directly:

```bash
python -m pytest -q altprobe_lab
```

Requires Python 3.8+ and pytest. The runner writes both artifacts to `logs/`:

- `logs/junit-<category>.xml` - pytest JUnit XML report;
- `logs/altprobe.log` - full Altprobe container log (debug output). Container
  auto-detection uses `docker ps`; set `LAB_ALTPROBE_CONTAINER` to override.

## Environment variables

- `LAB_BASE` - gateway URL (default `http://localhost:9080`).
- `LAB_OS_BASE` - OpenSearch URL (default `http://localhost:9200`).
- `LAB_INDEX_WAIT` - seconds to wait for indexing (default 10).
- `LAB_GATEWAY` - selected gateway for the extended `gateway` category (`kong`, `traefik`, `higress`).
- `LAB_PROFILE` - `demo` for the local demo labs.
- `LAB_LOCAL_COLLECTOR` - set to `1` to enable the mutable mock Policy block/unblock scenario.

All labs expose the gateway on `9080`, the mock on `8000`, OpenSearch on
`9200` and Dashboards on `5601`. Labs whose gateway plugin buffers events in
Redis (APISIX, OpenResty, Kong OSS, Traefik, Higress) also expose Redis on
`16379`; the Envoy lab reads its access-log file directly.

## SBOM fixture

The labs ship one test-only asset in `altprobe/` and load it into the Altprobe
image:

- `sbom-fixture.cdx.json` + `sbom-test.yaml` - a CycloneDX SBOM with five known
  CVEs, consumed by the SBOM scanner and emitted as OCSF 2002. If trivy and its
  vulnerability DB are available, the pipeline runs `trivy sbom`; otherwise it
  falls back to the bundled fixture.

The expected OCSF output is proxy/API telemetry plus detection findings: 4002
HTTP activity, 2004 detection findings (ModSecurity/CRS and correlator), 6003 API
activity and 2002 SBOM vulnerability findings.
