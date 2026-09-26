# Public Lab Tests

These scripts run harmless smoke checks against a running lab. They only verify
that demo routes respond and Altprobe events reach OpenSearch.

```bash
cd tests
LAB_BASE=http://localhost:9080 bash 01_smoke.sh
LAB_BASE=http://localhost:9080 bash 02_opensearch_smoke.sh
```

Set `LAB_OS_BASE` if OpenSearch is exposed on a different host or port.
