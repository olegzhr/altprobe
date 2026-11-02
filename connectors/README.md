# Connectors

Reusable gateway and sink integrations for Altprobe. Each connector contains
the files needed for deployment; the runnable demos live in
[`labs/`](../labs/README.md).

| Connector | Transport | Altprobe source |
|---|---|---|
| [`apisix`](apisix/README.md) | APISIX `redis-logger` → Redis | `SOURCES_PROXY_REDIS` |
| [`envoy`](envoy/README.md) | Envoy access log → JSON-lines file | `SOURCES_PROXY_LOG` |
| [`openresty`](openresty/README.md) | OpenResty Lua → Redis | `SOURCES_PROXY_REDIS` |
| [`kong`](kong/README.md) | Kong Lua plugin → Redis | `SOURCES_PROXY_REDIS` |
| [`traefik`](traefik/README.md) | Traefik Yaegi middleware → Redis | `SOURCES_PROXY_REDIS` |
| [`higress`](higress/README.md) | Higress Wasm filter → Redis | `SOURCES_PROXY_REDIS` |
| [`opensearch`](opensearch/README.md) | OCSF templates, dashboards, provisioning | `SINKS_OS_URL` |

Altprobe normalizes every record to OCSF. Identity comes from the authenticated
gateway consumer when available, otherwise from the observed source address.
Client identity headers are not trusted.

Discovery records also carry `gateway_origin_id` and a stable per-request
`request_id`. Configure a unique origin for each gateway instance; keep it
unchanged while replaying/retrying that instance's telemetry. Use
`gateway_origin_id` in APISIX/Kong/Higress, `GatewayOriginID` in Traefik,
`ALTPROBE_GATEWAY_ORIGIN_ID` in OpenResty, and the literal access-log field in
Envoy. Lua/Traefik default to a local hostname-based identity; Higress requires
an explicit origin or Envoy `node.id`. The origin is deployment configuration,
never a client header. Higress and Traefik generate observation IDs locally,
so repeated client `X-Request-ID` values cannot collapse discovery counters.

Envoy's `node.id` property follows the [Wasm attribute API](https://www.envoyproxy.io/docs/envoy/v1.30.6/intro/arch_overview/advanced/attributes).
Keep [request ID generation](https://www.envoyproxy.io/docs/envoy/v1.28.3/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto)
enabled in the Envoy HTTP connection manager.

Lua contract regression: `ALTPROBE_GATEWAY_ORIGIN_ID=trusted-origin lua5.1
labs/tests/test_connector_records.lua .` (from the repository root; requires
lua-cjson). Go regressions: `go test ./...` in each Traefik/Higress connector.
