# OpenSearch assets

Initialization registers OCSF index templates, the OTLP ingest pipeline and
saved objects:

```bash
docker compose run --rm opensearch-init
docker compose run --rm opensearch-dashboards-init
```

Open `http://localhost:5601/app/dashboards`.

Dashboards cover AI/MCP signals, HTTP/API/DNS/TLS, network flows, MITRE
ATT&CK/ATLAS, direct AI egress and vulnerability findings. The Network Flows
panel is a source-to-destination IP Sankey using `src_endpoint.ip` and
`dst_endpoint.ip`; no MaxMind or geographic data is used.

`otel-v1-traces*` stores OTLP/JSON spans with searchable `span.*` fields and a
derived `@timestamp`. It is separate from OCSF findings.

The `dashboard-ui` service on port 5601 serves the website palette, Manrope fonts
and panel styling. `ui/theme.css` and `ui/default.conf` are mirrored in every lab.

For older raw-OTLP indices, update the template/pipeline and reindex to populate
the `span.*` projection.
