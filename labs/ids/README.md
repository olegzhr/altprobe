# Falco + Suricata IDS overlay

Every lab has `docker-compose.ids.yaml`. It enables `log_falco` and `log_suri` in
Redis, configures AI workload selectors and adds a replay verifier.

The lab image installs the IDS-capable Altprobe package from GitHub Releases;
no bind-mounted binary is required.

```bash
cd labs/lab_apisix  # or any other lab
docker compose -f docker-compose.yaml build altprobe
docker compose -f docker-compose.yaml -f docker-compose.ids.yaml up -d --no-build
docker compose -f docker-compose.yaml -f docker-compose.ids.yaml run --rm ids-replay
```

The replay emits TLS, DNS and IPv4/IPv6 flow records and checks:

- direct TLS, reversed event order, DNS answer + connect and IPv6 matches;
- no bypass finding for proxied, DNS-only, wrong-port, accept, failed, stale or
  wrong-node cases;
- non-empty 4005 source/destination flow buckets in OpenSearch.

Open the lab's `Altprobe - Direct AI Connections (Proxy Bypass)` dashboard after
the replay. See [`ids-rules/README.md`](../../ids-rules/README.md) for rule
deployment.
