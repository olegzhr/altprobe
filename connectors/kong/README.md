# Kong OSS → Altprobe

Lua plugin for Kong OSS 3.9.1. It captures request/response bodies and sends the
APISIX-compatible JSON record to Redis from the `log` phase.

## Install

Copy `altprobe/` to
`/usr/local/share/lua/5.1/kong/plugins/altprobe/` and set:

```bash
KONG_PLUGINS=bundled,altprobe
```

Enable the plugin globally for telemetry:

```yaml
plugins:
- name: altprobe
  config:
    redis_host: redis
    redis_port: 6379
    redis_key: log_proxy
    host_name: my-kong
    gateway_origin_id: kong-gateway-1
    max_body_size: 5000
```

## Altprobe

Set `SOURCES_PROXY_REDIS=log_proxy` and the matching Redis host/port.
Authorization, cookie and API-key headers are redacted; body capture is bounded.

## Lab and content inspection

Use the [Kong lab](../../labs/lab_kong/README.md) and the
[integration catalog](../README.md). The logger runs asynchronously; authentication/enforcement is configured separately in the gateway.
Optional Ollama/NeMo inspection is configured on Altprobe through `LLM_GUARD_*`;
it consumes the captured request/response bodies and writes OCSF assessments.
Capture limits remain significant: incomplete or oversized bodies must not be
interpreted as a successful content check.
