# Altprobe lab - Envoy

Self-contained Envoy lab with local MCP, REST and OpenAI-compatible demo traffic.
No external LLM provider is contacted.

Altprobe collects Envoy access logs and native Envoy OTEL spans, and writes OCSF
events and OTLP/JSON traces to OpenSearch.

## Start

```bash
cd labs/lab_envoy
docker compose up -d --build --wait --wait-timeout 600
```

The image installs the published Altprobe release package (`altprobe_1.0.2_amd64.deb`) using the shared [`labs/common/altprobe/Dockerfile`](../common/altprobe/Dockerfile) and verifies it against the release `SHA256SUMS`. Run one lab at a time; all gateway labs share host ports.

## Open

- Gateway: `http://localhost:9080`
- OpenSearch: `http://localhost:9200`
- Dashboards: `http://localhost:5601/app/dashboards`

## Test

```bash
cd ../tests
python3 -m pip install -r requirements.txt
LAB_GATEWAY=envoy LAB_INDEX_WAIT=60 python3 run_tests.py
```

## Stop

```bash
docker compose down
```

Plain `down` preserves indexed data and spool volumes.

## Integration scope

This stack exercises Envoy access-log JSON and native gRPC OTLP. Altprobe performs asynchronous collection;
request authorization remains a separate gateway/ctrlprobe concern.
Optional Ollama/NeMo content inspection uses `LLM_GUARD_*` on the collector.

For dedicated integrations use [NeMo](../lab_nemo/README.md),
[Trivy SBOM](../lab_sbom/README.md), [Suricata](../lab_suricata/README.md) or
[OpenShell](../lab_openshell/README.md). Their test entry points differ from
the shared gateway suite; see the [lab catalog](../README.md).
The common Altprobe image contains `/usr/local/share/altprobe/release-receipt.json` with the release package and installed binary hashes. A previous PASS does not verify a newly built image.
