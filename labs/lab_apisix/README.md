# Altprobe lab - APISIX

Self-contained APISIX lab with local MCP, REST and OpenAI-compatible demo traffic.
No external LLM provider is contacted.

Altprobe collects gateway logs, native APISIX OTEL spans and SBOM findings, and
writes OCSF events and OTLP/JSON traces to OpenSearch.

## Start

```bash
cd labs/lab_apisix
docker compose up -d --build --wait --wait-timeout 600
```

The image installs the Altprobe package from GitHub Releases; no local source
checkout is required. Run one lab at a
time; all labs share host ports.

## Open

- Gateway: `http://localhost:9080`
- OpenSearch: `http://localhost:9200`
- Dashboards: `http://localhost:5601/app/dashboards`

## Test

```bash
cd ../tests
python3 -m pip install -r requirements.txt
LAB_GATEWAY=apisix LAB_INDEX_WAIT=60 python3 run_tests.py
```

## Stop

```bash
docker compose down
```

Add `-v` only to delete the lab's indexed data.
