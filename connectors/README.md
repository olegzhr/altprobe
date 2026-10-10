# connectors

Reusable integration code that connects gateways and sinks to **Altprobe**,
extracted from the quick-start labs and presented without lab-specific setup
(no docker-compose, mock services, lab ports or asset names).

| Connector | What it does | Where Altprobe reads it |
|-----------|--------------|-------------------------|
| `apisix/` | APISIX `redis-logger` plugin ships proxy logs to Redis | `SOURCES_PROXY_REDIS` (Redis list, default `log_proxy`) |
| `envoy/` | Envoy Lua filter + file access logger writes proxy logs to a file | `SOURCES_PROXY_LOG` (log file) |
| `openresty/` | OpenResty nginx + Lua ships proxy logs to Redis | `SOURCES_PROXY_REDIS` (Redis list, default `log_proxy`) |
| `opensearch/` | OCSF index templates, Dashboards saved objects and provisioning scripts | `SINKS_OS_URL` (Altprobe native OpenSearch sink) |

Each gateway record is normalized by Altprobe into OCSF and written to the
configured sink. The gateway connectors only ship telemetry; they do not make
policy/OPA decisions or deliver Alertflex incidents.
