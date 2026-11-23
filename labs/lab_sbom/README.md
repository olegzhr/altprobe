# lab_sbom: Trivy -> Altprobe -> OpenSearch

Self-contained SBOM lab. Trivy scans a pinned npm project with known-vulnerable
dependencies; Altprobe converts every CycloneDX vulnerability into an OCSF 2002
finding and writes it to OpenSearch and OpenSearch Dashboards.

```text
target/package-lock.json (axios 0.21.1, lodash 4.17.4, minimist 1.2.0)
        │
        ▼
Altprobe scanner: trivy fs --scanners vuln --format cyclonedx
        │
        ├─ CycloneDX document in /var/lib/altprobe/sbom.cdx.json
        └─ OCSF 2002 per vulnerability -> OpenSearch
```

## Components

| Service | Role |
|---|---|
| `altprobe` | Collector image with Trivy 0.75.0; scanner runs the pipeline at startup |
| `opensearch` | `ocsf-1.8.0-2002-vulnerability_finding-*` documents |
| `opensearch-dashboards` | Vulnerability dashboards and index patterns |
| `opensearch-init` | OCSF templates and the OTLP pipeline |
| `opensearch-dashboards-init` | Saved objects |

The target is intentionally synthetic: `package-lock.json` pins known vulnerable
versions, so no application is executed. Exact finding counts depend on the current Trivy database.

## Start

```bash
# From the repository root
python3 labs/run_source_lab.py sbom start
```

The first scan downloads the Trivy vulnerability database (about 134 MiB) into
the `trivy-cache` volume. This requires network access. Later runs reuse the
database until Trivy refreshes it.

`scan_interval: 60` minutes: the scanner runs once at container start and then
waits interruptibly, so shutdown does not wait for the hour-long interval.
Set `scan_timeout_sec` in the SBOM configuration to bound each scan. The
collector stops the scan's process group when the deadline expires or the
collector shuts down.

## Open

- OpenSearch: `http://127.0.0.1:19200`
- Dashboards: `http://127.0.0.1:5601/app/dashboards`
- Vulnerability dashboard: `OCSF Vulnerability Findings (2002)`

## Test

```bash
python3 labs/run_source_lab.py sbom test
```

The test waits up to `SBOM_WAIT` seconds (default 600) and checks:

- OCSF 2002 findings exist with `metadata.log_name=altprobe_sbom`;
- `CVE-2021-23337` is reported for `lodash@4.17.4`;
- `CVE-2021-3749` is reported for `axios@0.21.1`;
- `CVE-2021-44906` is reported for `minimist@1.2.0`.

Expected: `status=PASS checks=3`.

## Manual checks

```bash
# Trivy ran and produced the CycloneDX report
docker compose exec altprobe ls -l /var/lib/altprobe/sbom.cdx.json

# Altprobe scanner log
docker compose logs altprobe | grep -E 'Scanner|trivy'

# OCSF 2002 count
curl -s 'http://127.0.0.1:19200/ocsf-1.8.0-2002-vulnerability_finding*/_count'
```

## Stop

```bash
python3 labs/run_source_lab.py sbom stop
```


## Notes

- Trivy is installed only when the Altprobe image is built with
  `TRIVY=true`; the SBOM lab passes that build argument.
- The scanner uses `/etc/altprobe/sbom.yaml` from this lab (mounted read-only).
- `SINKS_OS_TYPES=OCSF` is enough: the scanner writes class 2002 directly to
  OpenSearch; no Alertflex instance is required.
- The synthetic CVEs come from the pinned versions, not from a live application
  or a real registry.

## Run evidence

Each runner start assigns `ALTPROBE_ASSET_NAME=sbom-target-<run-id>`. Tests accept
only findings whose timestamp belongs to that run and whose metadata UID starts
with that asset. The release package digest, lab config digest, image ID, container start time and
actual binary SHA256 must match `.local/current-run.json` before and after the
check. The wait loop requires all expected CVEs, not merely three arbitrary findings.
Existing OpenSearch data and the downloaded Trivy database remain in their volumes.

Receipts expire after 24 hours. Lab config changes, container restarts or
binary drift require a new runner `start`; direct manual Compose starts do not
create a valid verification receipt. Run one lab at a time because ports overlap.
