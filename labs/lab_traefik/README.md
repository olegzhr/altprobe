# Altprobe lab - Traefik

Self-contained Traefik lab with local MCP, REST and OpenAI-compatible demo traffic.
No external LLM provider is contacted.

Altprobe collects Traefik middleware logs and native Traefik OTEL spans, and
writes OCSF events and OTLP/JSON traces to OpenSearch.

## Start

```bash
cd labs/lab_traefik
docker compose up -d --build --wait --wait-timeout 600
```

The image installs the Altprobe package from GitHub Releases. Run one lab
at a time; all labs share host ports.

## Open

- Gateway: `http://localhost:9080`
- OpenSearch: `http://localhost:9200`
- Dashboards: `http://localhost:5601/app/dashboards`

## Test

```bash
cd ../tests
python3 -m pip install -r requirements.txt
LAB_GATEWAY=traefik LAB_INDEX_WAIT=60 python3 run_tests.py
```

## Stop

```bash
docker compose down
```

Add `-v` only to delete the lab's indexed data.
