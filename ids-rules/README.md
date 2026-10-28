# IDS rules

Two files, no lab or Docker dependency:

| File | Purpose |
|---|---|
| `suricata.rules` | 76 Suricata 7+ signatures: provider TLS/DNS/HTTP observations and MCP/A2A/REST HTTP inspection. |
| `falco_rules.yaml` | Falco rules for successful AI workload connects with process, pod and container context. |

These rules collect evidence. Altprobe's Falco + Suricata correlation decides
whether a direct AI connection bypassed the gateway; a signature alone is not a
bypass verdict.

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

## Falco

Install the rules file:

```bash
sudo install -m 0644 falco_rules.yaml /etc/falco/rules.d/altprobe_rules.yaml
```

Load `/etc/falco/rules.d` in `falco.yaml` and enable JSON output:

```yaml
rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/rules.d
json_output: true
json_include_output_property: true
```

Edit the lists at the top of `falco_rules.yaml` for your environment:
`altprobe_ai_namespaces`, `altprobe_ai_containers`,
`altprobe_host_ai_processes`, `altprobe_proxy_namespaces` and
`altprobe_proxy_containers`. Keep them aligned with
`correlator.outbound.ai_namespaces`, `ai_containers`, `ai_processes` and the
proxy exclusions.

Validate and restart:

```bash
sudo falco --validate /etc/falco/falco.yaml
sudo systemctl restart falco
```

Point Altprobe at Falco JSON output, or at the Redis list used by your shipper:

```yaml
sources:
  falco_log: /var/log/falco/falco.json
  # falco_redis: log_falco
```

## Correlation requirements

- Use the same `hostname` in Falco and `host_name` in Suricata for one node.
- Keep node clocks synchronized; start with the default 2-second window.
- Do not use one node identity across unrelated NAT or sensor scopes.
- Keep EVE `tls`, `dns`, `flow` and `http` enabled.
- No GeoIP or MaxMind data is used.
