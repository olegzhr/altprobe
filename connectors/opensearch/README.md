# OpenSearch sink connector for Altprobe

OCSF index templates, Dashboards saved objects and provisioning scripts for the
OpenSearch sink Altprobe writes to (`SINKS_OS_URL`).

## Files

| Path | Purpose |
|------|---------|
| `templates/*.json` | OCSF index templates (mappings: epoch_millis `time`, nested correlation timelines). |
| `dashboards/index_patterns/*.json` | Dashboard index patterns. |
| `dashboards/saved_objects/*.json` | Dashboards, saved searches and visualizations. |
| `setup_templates.sh` | Registers the index templates (run before Altprobe writes). |
| `setup_dashboards.sh` | Imports index patterns / searches / visualizations / dashboards. |
| `recover_stale_kibana.sh` | Clears an empty `.kibana_1` left by OpenSearch Dashboards racing OpenSearch. |
| `refresh_index_pattern_fields.sh` | Refreshes index-pattern fields from the current mappings. |

## Install

The scripts talk to OpenSearch / Dashboards over HTTP and expect `OS_URL` (e.g.
`http://opensearch:9200`) and `OSD_URL` (e.g. `http://opensearch-dashboards:5601`).
Run them from this directory (the scripts resolve `templates/` and `dashboards/`
relative to themselves; override with `DATA_DIR`):

```bash
OS_URL=http://localhost:9200 sh setup_templates.sh
OSD_URL=http://localhost:5601 sh setup_dashboards.sh
# after an unclean Dashboards start:
OS_URL=http://localhost:9200 sh recover_stale_kibana.sh
```

## Security-enabled OpenSearch

When the OpenSearch security plugin is enabled (user/password authentication),
pass Basic-auth credentials; the scripts add them (and optional TLS skipping) to
every request. Leaving `OS_USER` empty keeps anonymous access for a
security-disabled cluster.

| Variable | Applies to | Meaning |
|----------|-----------|---------|
| `OS_USER` / `OS_PWD` | OpenSearch API | Basic-auth user/password |
| `OSD_USER` / `OSD_PWD` | Dashboards API | Basic-auth user/password (defaults to `OS_USER`/`OS_PWD`) |
| `OS_INSECURE` | OpenSearch API | `true` = skip TLS certificate verification (self-signed cert) |
| `OSD_INSECURE` | Dashboards API | `true` = skip TLS verification (defaults to `OS_INSECURE`) |

```bash
OS_URL=https://localhost:9200 OS_USER=admin OS_PWD=MySecret OS_INSECURE=true \
  sh setup_templates.sh
OSD_URL=https://localhost:5601 OSD_USER=admin OSD_PWD=MySecret OSD_INSECURE=true \
  sh setup_dashboards.sh
OS_URL=https://localhost:9200 OS_USER=admin OS_PWD=MySecret OS_INSECURE=true \
  sh recover_stale_kibana.sh
```

For a trusted CA you can keep `OS_INSECURE=false` (default) and rely on the
system trust store.

Run `setup_templates.sh` before Altprobe starts writing so the daily
`ocsf-1.1.0-*` indices are created with the expected mappings.

## Altprobe side

- Set `SINKS_OS_URL`, `SINKS_OS_USER` and `SINKS_OS_PWD` to the OpenSearch
  endpoint. `SINKS_OS_TLS_VERIFY` / `SINKS_OS_TLS_CA_FILE` control HTTPS
  verification.
- Leave `SINKS_LOKI_URL` empty unless a Loki sink is also used.

## Notes

- All scripts are idempotent and safe to rerun.
- The saved-object import uses `overwrite=true`, so re-running updates existing
  dashboards rather than duplicating them.
