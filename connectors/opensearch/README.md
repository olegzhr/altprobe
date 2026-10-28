# OpenSearch assets

Install these assets on an existing OpenSearch 2.x + OpenSearch Dashboards 2.x
deployment. The scripts are POSIX `sh` and require `curl`; they do not use Docker
Compose or lab hostnames.

Contents:

- `templates/` — OCSF and OTLP index templates.
- `pipelines/` — OTLP span projection pipeline.
- `dashboards/index_patterns/` — index patterns.
- `dashboards/saved_objects/` — dashboards, visualizations and saved searches.
- `setup_templates.sh`, `setup_dashboards.sh` — idempotent installers.

## Configure

```bash
export OS_URL="https://opensearch.example.com:9200"
export OS_USER="altprobe-installer"
export OS_PWD="<password>"
export OS_INSECURE="false"          # true only for a self-signed test endpoint

export OSD_URL="https://dashboards.example.com"
export OSD_USER="altprobe-installer"
export OSD_PWD="<password>"
export OSD_INSECURE="false"
```

Use HTTPS and an account allowed to create index templates, ingest pipelines,
indices, index patterns and Dashboards saved objects. Do not use an admin
account for normal operation.

## Install templates and pipeline

From this directory:

```bash
./setup_templates.sh
```

The script creates the OCSF templates, the `altprobe-otel-spans` pipeline and
empty class indices so Dashboards do not report missing patterns. It is
idempotent; re-running overwrites the templates.

## Install dashboards

```bash
./setup_dashboards.sh
```

The script imports index patterns, visualizations and dashboards with
`overwrite=true` and removes a fixed list of legacy geo/policy objects from
older bundles. Back up saved objects first if you have local edits.

Open `OSD_URL/app/dashboards` and verify the Altprobe dashboards. The Network
Flows panel uses `src_endpoint.ip` and `dst_endpoint.ip`; no MaxMind or
geographic data is used.

## Existing indices

Templates affect new indices. If you already have OCSF or `otel-v1-traces*`
indices created without these mappings, reindex them after applying the
templates and pipeline. Reindex into a new index, verify documents and
dashboards, then switch the alias or index pattern. Keep a backup until the
migration is verified.

`refresh_index_pattern_fields.sh` is an optional helper for refreshing field
lists from the current mapping.

## Security Analytics

The OCSF templates provide mapped fields for OpenSearch Security Analytics.
Create detectors and rules in Security Analytics after the templates are
installed. The collector sends OCSF events; detector policy remains an
OpenSearch configuration.

## Optional UI theme

`ui/` contains the lab dashboard theme and nginx proxy used by the labs. It is
optional and does not modify indexed data.
