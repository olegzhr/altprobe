# OpenResty → Altprobe

OpenResty stages request/response data in the access, body and log phases;
`log.lua` pushes one JSON record per request to a Redis list. Altprobe reads it
through `SOURCES_PROXY_REDIS` and parses it as the APISIX field set.

## Files

- `nginx.conf` — OpenResty server and Lua phase wiring.
- `lua/access.lua`, `lua/capture.lua`, `lua/log.lua` — request capture, response
  capture and Redis delivery.

## Install

1. Copy `nginx.conf` into the OpenResty configuration.
2. Copy `lua/` to `/etc/openresty/lua`.
3. Set `proxy_pass` to your upstream.
4. Set `REDIS_HOST`, `REDIS_PORT`, `REDIS_KEY` and `HOST_NAME` in `lua/log.lua`.

## Altprobe

```yaml
sources:
  proxy_redis: log_proxy
  redis_host: redis
  redis_port: 6379
```

This connector is telemetry-only; it does not authenticate requests or make
policy decisions. Identity is the observed source IP.
