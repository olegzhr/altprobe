# Altprobe lab tests

Unified pytest suite for the Altprobe proxy plugin and its OpenSearch (OCSF)
output. The same, environment-driven suite runs against any lab gateway
(APISIX, OpenResty or Envoy); select the target with `LAB_BASE`. Only harmless
demo traffic is used: MCP methods, REST demo endpoints, the local AI Gateway
mock, emulated Suricata events pushed to Redis, and a bundled CycloneDX SBOM
fixture.

## Layout

| Path | Purpose |
|------|---------|
| `run_tests.py` | Runner (`smoke`, `function`, `security`, `e2e`, `geo`, `sbom`) |
| `pytest.ini`, `requirements.txt` | pytest configuration and dependency |
| `logs/` | Test artifacts: JUnit XML report and the Altprobe container log |
| `altprobe_lab/common.py` | `requests`-based HTTP, OpenSearch and Redis helpers |
| `altprobe_lab/suricata_events.py` | Suricata eve.json emulation (private IPs from the test GeoIP DB) |
| `altprobe_lab/test_smoke.py` | Gateway/mock smoke, OpenSearch ingestion, Suricata OCSF classes |
| `altprobe_lab/test_function.py` | MCP, REST and AI Gateway behavior |
| `altprobe_lab/test_security.py` | Auth enforcement, input rejection, MCP containment |
| `altprobe_lab/test_e2e.py` | Representative traffic end to end |
| `altprobe_lab/test_geo.py` | Netflow GeoIP enrichment (test MaxMind DB) |
| `altprobe_lab/test_sbom.py` | OCSF 2002 findings from the SBOM fixture |

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

- `logs/junit-<category>.xml` — pytest JUnit XML report;
- `logs/altprobe.log` — full Altprobe container log (debug output). Container
  auto-detection uses `docker ps`; set `LAB_ALTPROBE_CONTAINER` to override.

## Environment variables

- `LAB_BASE` — gateway URL (default `http://localhost:9080`).
- `LAB_OS_BASE` — OpenSearch URL (default `http://localhost:9200`).
- `LAB_INDEX_WAIT` — seconds to wait for indexing (default 10).
- `LAB_REDIS_HOST` / `LAB_REDIS_PORT` / `LAB_REDIS_KEY` — Redis used for the
  Suricata emulation (defaults `localhost`, `16379`, `log_suricata`).

All labs expose the gateway on `9080`, the mock on `8000`, OpenSearch on `9200`,
Dashboards on `5601` and Redis on `16379`.

## Geo and SBOM fixtures

The labs ship two test-only assets in `altprobe/` and load them into the
Altprobe image:

- `GeoLite2-City-test.mmdb` — a small MaxMind-compatible database generated for
  the private lab addresses used by `suricata_events.py`. No license or
  download is required.
- `sbom-fixture.cdx.json` + `sbom-test.yaml` — a CycloneDX SBOM with five known
  CVEs, consumed by the SBOM scanner and emitted as OCSF 2002. If trivy and its
  vulnerability DB are available, the pipeline runs `trivy sbom`; otherwise it
  falls back to the bundled fixture.
