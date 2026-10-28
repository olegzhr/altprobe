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
