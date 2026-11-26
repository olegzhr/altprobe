# OpenSearch assets for lab_suricata

From the parent lab directory, the Compose init services install the templates,
OTLP projection pipeline and saved objects in this directory:

```bash
docker compose run --rm opensearch-init
docker compose run --rm opensearch-dashboards-init
```

Open Dashboards at `http://127.0.0.1:5601/app/dashboards`.
Altprobe exports Suricata DNS (4001), network flow (4005) and TLS (4007)
observations directly to OpenSearch. HTTP observations attached to IDS alerts
can enter the HTTP inspection pipeline.

Canonical assets are `templates/`, `pipelines/`, `dashboards/index_patterns/`
and `dashboards/saved_objects/`. Setup resolves paths relative to each script;
files in legacy top-level export folders are not the installer input.
Native OTLP, when configured, is projected into `otel-v1-traces*` with `span.*`
fields and `@timestamp`, separately from OCSF findings. Network-flow panels use
source/destination IP fields and do not require geographic databases.

See the [parent lab](../README.md) for the workload, ports and verification.
The Suricata verifier uses the current run receipt to check fresh source and
OpenSearch records.

Provisioning overwrites bundled templates/saved objects and removes a fixed
list of obsolete objects. Preserve user edits before refreshing assets.
Templates affect new indices; migrate older mappings into a new index and
verify before switching aliases. Data volumes and local PKI must be preserved.
For standalone deployments and TLS/auth settings use the
[OpenSearch connector guide](../../../connectors/opensearch/README.md).
