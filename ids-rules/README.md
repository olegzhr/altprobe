# IDS rules

One Suricata rule file, no lab or Docker dependency.

| File | Purpose |
|---|---|
| `suricata.rules` | 76 Suricata 7+ signatures: provider TLS/DNS/HTTP observations and MCP/A2A/REST HTTP inspection. |

These rules collect evidence. Altprobe correlates Suricata network evidence with
agent-sidecar evidence; a signature alone is not a bypass verdict.

## Suricata

Install the rule file:

```bash
sudo install -m 0644 suricata.rules /etc/suricata/rules/altprobe.rules
```

Add it to `rule-files` in `/etc/suricata/suricata.yaml`:

```yaml
rule-files:
  - altprobe.rules
```

Enable EVE output for `alert`, `tls`, `dns`, `flow` and `http`. Body-based rules
also need HTTP body logging enabled in the EVE configuration. Validate and
restart:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl restart suricata
```

Point Altprobe at the EVE file, or at the Redis list used by your shipper:

```yaml
sources:
  suricata_log: /var/log/suricata/eve.json
  # suricata_redis: log_suri
```

Ensure the Altprobe user can read `eve.json`; file input follows rotation and
starts at EOF. Empty values disable the source.

## Correlation requirements

- Keep node clocks synchronized; start with the default 2-second window.
- Do not use one node identity across unrelated NAT or sensor scopes.
- Keep EVE `tls`, `dns`, `flow` and `http` enabled.
- No GeoIP or MaxMind data is used.

## Labs and agent context

The [Suricata lab](../labs/lab_suricata/README.md) exercises TLS/DNS/flow through
the shared shipper. OpenShell supplies its own native OCSF rather than these rule
files. NeMo and Trivy/SBOM have dedicated [integration labs](../labs/README.md);
their assessments and vulnerability findings are independent of an IDS bypass
verdict.
