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
    max_body_size: 5000
```

## Policy

On protected routes, enable `key-auth` before this plugin and add
`policy_enabled: true` plus `policy_url` to the route plugin config. Policy uses
the APISIX envelope and returns `result.allow`; missing/invalid Policy returns
503. Identity is `auth:kong:<consumer>` or the observed source IP.

## Altprobe

Set `SOURCES_PROXY_REDIS=log_proxy` and the matching Redis host/port.
Authorization, cookie and API-key headers are redacted; body capture is bounded.
