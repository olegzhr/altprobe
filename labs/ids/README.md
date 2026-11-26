# Suricata replay overlay

The five gateway labs ship `docker-compose.ids.yaml`. It enables the shared
`log_suri` Redis list and adds a replay container that pushes synthetic Suricata
records and verifies what Altprobe stores:

- TLS records become OCSF `4007` documents with `tls.sni`;
- DNS answers become OCSF `4001` documents with `dns_query.hostname`;
- flows become OCSF `4005` documents with source/destination buckets and bytes.

For a real sensor run use [lab_suricata](../lab_suricata/README.md); this overlay
is a fixture-based storage regression, not proof of a live capture.

```bash
cd labs/lab_apisix  # or another gateway lab
docker compose -f docker-compose.yaml build altprobe
docker compose -f docker-compose.yaml -f docker-compose.ids.yaml up -d --no-build
docker compose -f docker-compose.yaml -f docker-compose.ids.yaml run --rm ids-replay
docker compose -f docker-compose.yaml -f docker-compose.ids.yaml down
```

Open the lab's TLS, DNS and Network Flows dashboards after the replay. See
[`ids-rules/README.md`](../../ids-rules/README.md) for rule deployment.

## Related source integrations

[Suricata](../lab_suricata/README.md) runs a real sensor and
[OpenShell](../lab_openshell/README.md) ingests native OCSF from its sandbox.
Both write to the SIEM; judgements such as "this workload contacted a provider
outside the approved gateway" are made from that evidence in the SIEM. The NeMo
and SBOM labs exercise different pipelines:
[NeMo content assessment](../lab_nemo/README.md) and
[Trivy vulnerability findings](../lab_sbom/README.md).
