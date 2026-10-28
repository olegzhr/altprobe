# APISIX lab gateway

APISIX with a custom `redis-logger` plugin that writes one JSON record per
proxied request to Redis or a JSON-lines file.

## Routes

| URI | Upstream |
|---|---|
| `/mcp*` | `UPSTREAM_HOST:8000` |
| `/test-api*` | `UPSTREAM_HOST:8000` |
| `/ai-gateway/v1/chat/completions` | `UPSTREAM_HOST:8000/test-api/v1/chat/completions` |

## Ports

| Port | Purpose |
|---|---|
| 9080 | Proxy |
| 9180 | Admin API |
| 2379 | etcd |
| 9000 | Admin UI |

## Logger

The plugin records request body and redacted headers in `access`, response
headers in `header_filter`, a bounded response body in `body_filter`, and sends
the JSON record from `log` through `ngx.timer.at(0, ...)`.

```yaml
plugin_attr:
  redis-logger:
    output_type: redis
    redis_host: REDIS_HOST
    redis_port: 6379
    redis_key: log_proxy
    log_file_path: /usr/local/apisix/logs/proxy-json.log
```

Settings: `output_type`, `redis_host`, `redis_port`, `redis_password`,
`redis_database`, `redis_key`, `log_file_path`, `host_name`, `timeout`,
`max_body_size`.

Notes:

- keep `plugins` at the top YAML level in APISIX 3.9+;
- plugin methods use dot notation (`_M.log`);
- Redis writes must run outside the log phase via `ngx.timer.at`.
