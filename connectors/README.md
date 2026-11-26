# Connectors

Reusable gateway and sink integrations for Altprobe. Each connector contains
the telemetry integration source. The matching labs live in [`labs/`](../labs/README.md)
and the shared tests in [`labs/tests/`](../labs/tests/README.md). Synchronous PEP
adapters belong to ctrlprobe.

| Connector | Transport | Altprobe source |
|---|---|---|
| [`apisix`](apisix/README.md) | APISIX `redis-logger` → Redis | `SOURCES_PROXY_REDIS` |
| [`envoy`](envoy/README.md) | Envoy access log → JSON-lines file | `SOURCES_PROXY_LOG` |
| [`kong`](kong/README.md) | Kong Lua plugin → Redis | `SOURCES_PROXY_REDIS` |
| [traefik](traefik/README.md) | Traefik Yaegi middleware → Redis | `SOURCES_PROXY_REDIS` |
| [higress](higress/README.md) | Higress WASM → private HTTP collector → Redis | `SOURCES_PROXY_REDIS` |
| [`shipper_altprobe`](shipper_altprobe/README.md) | Suricata/OpenShell JSONL → Redis | Per-source `SOURCES_*_REDIS` |
| [`opensearch`](opensearch/README.md) | OCSF templates, dashboards, provisioning | `SINKS_OS_URL` |

Altprobe normalizes gateway and IDS records to OCSF. The in-band correlator
processes HTTP, MCP and API activity. Altprobe exports Suricata network
observations and native OpenShell sandbox events directly to the configured
log destinations. For gateway events, identity comes from the authenticated
consumer when available, otherwise from the observed source address.
Client identity headers are not trusted.

Discovery records also carry `gateway_origin_id` and a stable per-request
`request_id`. Configure a unique origin for each gateway instance; keep it
unchanged while replaying/retrying that instance's telemetry. Use
`gateway_origin_id` in APISIX/Kong/Higress, `GatewayOriginID` in Traefik, and
the literal access-log field in Envoy. Lua/Traefik default to a local
hostname-based identity; Higress requires an explicit origin or Envoy `node.id`.
The origin is deployment configuration, never a client header. Higress and
Traefik generate observation IDs locally, so repeated client `X-Request-ID`
values cannot collapse discovery counters.

Envoy's `node.id` property follows the [Wasm attribute API](https://www.envoyproxy.io/docs/envoy/v1.30.6/intro/arch_overview/advanced/attributes).
Keep [request ID generation](https://www.envoyproxy.io/docs/envoy/v1.28.3/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto)
enabled in the Envoy HTTP connection manager.

Go regressions: `go test ./...` in each Traefik/Higress connector. The gateway
labs exercise the connectors end to end; see [`labs/tests`](../labs/tests/README.md).

## Guard and source integrations

Configure Ollama or NeMo through `altprobe.llm_guard` / `LLM_GUARD_*`.
Altprobe submits captured LLM bodies asynchronously and records the verdict
as OCSF 6003 detection evidence. In [lab_nemo](../labs/lab_nemo/README.md),
NeMo's input rail makes the decision for live requests routed to it.
A `Safe` assessment requires evidence from NeMo that its input rail completed.
Missing evidence produces `invalid_verdict`.

The shared shipper feeds [Suricata](../labs/lab_suricata/README.md) and
[OpenShell](../labs/lab_openshell/README.md). [SBOM](../labs/lab_sbom/README.md)
uses the native Trivy/CycloneDX scanner and does not need a gateway connector.
See the [lab catalog](../labs/README.md) for run receipts and verification commands.
