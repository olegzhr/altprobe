# Labs

Six self-contained gateway labs for Altprobe and OpenSearch, plus an outbound
runtime lab:

| Gateway | Lab | Native OTEL |
|---|---|---|
| APISIX | [`lab_apisix`](lab_apisix/README.md) | HTTP/protobuf |
| Envoy | [`lab_envoy`](lab_envoy/README.md) | gRPC |
| OpenResty | [`lab_openresty`](lab_openresty/README.md) | No; internal spans |
| Kong OSS | [`lab_kong`](lab_kong/README.md) | HTTP |
| Traefik | [`lab_traefik`](lab_traefik/README.md) | HTTP |
| Higress | [`lab_higress`](lab_higress/README.md) | gRPC |

The outbound lab is not a gateway: it runs Claude Code + Prempti, Falco,
Suricata and Altprobe to exercise the runtime → network and agent → runtime
correlation path without OTLP ([`lab_outbound`](lab_outbound/README-RU.md)).

Each lab includes a real gateway, local mock services, Altprobe, OpenSearch,
dashboards, safe demo traffic, an SBOM fixture and an optional Falco/Suricata
overlay. **Run one lab at a time**; all labs share host ports.

Altprobe is installed from the GitHub Releases package; no local source
checkout is required.

## Start

```bash
cd labs/lab_apisix
docker compose up -d --build --wait --wait-timeout 600
```

- Gateway: `http://localhost:9080`
- OpenSearch: `http://localhost:9200`
- Dashboards: `http://localhost:5601/app/dashboards`
- OTEL traces: `http://localhost:5601/app/dashboards#/view/altprobe-otel-traces`

## Test

```bash
cd labs/tests
python3 -m pip install -r requirements.txt
LAB_GATEWAY=apisix LAB_INDEX_WAIT=60 python3 run_tests.py
```

Use the lab's gateway name for `LAB_GATEWAY`: `apisix`, `envoy`, `openresty`,
`kong`, `traefik` or `higress`. See [`tests/README.md`](tests/README.md) for
categories and settings.

Native gateways use a separate `altprobe-otel` container because
`TRACE_MODE=internal` and `TRACE_MODE=external` are mutually exclusive. Its
receiver listens on loopback and preserves native trace, span and parent IDs.

## Refresh assets

```bash
docker compose run --rm opensearch-init
docker compose run --rm opensearch-dashboards-init
```

See [`ids/README.md`](ids/README.md) for the optional Falco/Suricata overlay.
