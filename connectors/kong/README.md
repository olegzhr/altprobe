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
