# connectors

Reusable integration code that connects gateways and sinks to **Altprobe**,
extracted from the quick-start labs and presented without lab-specific setup
(no docker-compose, mock services, lab ports or asset names).

| Connector | What it does | Where Altprobe reads it |
|-----------|--------------|-------------------------|
| `apisix/` | APISIX `redis-logger` plugin ships proxy logs to Redis | `SOURCES_PROXY_REDIS` (Redis list, default `log_proxy`) |
| `envoy/` | Envoy Lua filter + file access logger writes proxy logs to a file | `SOURCES_PROXY_LOG` (log file) |
| `openresty/` | OpenResty nginx + Lua ships proxy logs to Redis | `SOURCES_PROXY_REDIS` (Redis list, default `log_proxy`) |
| `kong/` | Kong OSS Lua plugin ships proxy logs to Redis | `SOURCES_PROXY_REDIS` (Redis list, default `log_proxy`) |
| `traefik/` | Traefik Yaegi middleware ships proxy logs to Redis | `SOURCES_PROXY_REDIS` (Redis list, default `log_proxy`) |
| `higress/` | Higress Go/Wasm filter ships proxy logs to Redis | `SOURCES_PROXY_REDIS` (Redis list, default `log_proxy`) |
| `opensearch/` | OCSF index templates, Dashboards saved objects and provisioning scripts | `SINKS_OS_URL` (Altprobe native OpenSearch sink) |

Each gateway record is normalized by Altprobe into OCSF and written to the
configured sink. The gateway integrations collect telemetry and, when enabled
on protected routes, enforce access decisions from Altprobe Policy or a
compatible OPA endpoint. Altprobe delivers incidents; the gateway plugins do not.
See each connector's README for its supported authorization mechanism.
