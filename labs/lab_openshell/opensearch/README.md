# OpenSearch assets for lab_openshell

From the parent lab directory, the Compose init services install the templates,
OTLP projection pipeline and saved objects in this directory:

```bash
docker compose run --rm opensearch-init
docker compose run --rm opensearch-dashboards-init
```

Open Dashboards at `http://127.0.0.1:15601/app/dashboards`.
Altprobe exports OpenShell sandbox events directly to OpenSearch using their
native OCSF classes. The lab verifies process, authentication and lifecycle
events as well as allowed and denied network actions.

Canonical assets are `templates/`, `pipelines/`, `dashboards/index_patterns/`
and `dashboards/saved_objects/`. Setup resolves paths relative to each script;
files in legacy top-level export folders are not the installer input.
Native OTLP, when configured, is projected into `otel-v1-traces*` with `span.*`
fields and `@timestamp`, separately from OCSF findings. Network-flow panels use
source/destination IP fields and do not require geographic databases.

See the [parent lab](../README.md) for the workload, ports and verification.
The OpenShell verifier checks the sandbox records indexed in OpenSearch.

Provisioning overwrites bundled templates/saved objects and removes a fixed
list of obsolete objects. Preserve user edits before refreshing assets.
Templates affect new indices; migrate older mappings into a new index and
verify before switching aliases. Data volumes and local PKI must be preserved.
For standalone deployments and TLS/auth settings use the
[OpenSearch connector guide](../../../connectors/opensearch/README.md).
