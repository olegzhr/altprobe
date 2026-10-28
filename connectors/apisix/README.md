# APISIX → Altprobe

The APISIX `redis-logger` plugin writes one JSON record per proxied request to a
Redis list or JSON-lines file. Altprobe reads it through its proxy Redis or file
source and normalizes it to OCSF.

## Files

- `redis-logger.lua` — APISIX plugin.
- `config.example.yaml` — plugin and `plugin_attr` settings.

## Install

1. Copy `redis-logger.lua` to `/usr/local/apisix/apisix/plugins/`.
2. Merge `config.example.yaml` into `conf/config.yaml`; keep `plugins` at the
   top YAML level.
3. Attach the plugin to the routes you want to observe, for example:

```bash
curl -X PUT http://127.0.0.1:9180/apisix/admin/routes/my-route \
  -H "X-API-KEY: <admin-key>" -H "Content-Type: application/json" \
  -d '{"uri":"/api/*","upstream":{"type":"roundrobin","nodes":{"app:8000":1}},"plugins":{"redis-logger":{"output_type":"redis"}}}'
```

## Altprobe

```yaml
sources:
  proxy_redis: log_proxy
  redis_host: redis
  redis_port: 6379
```

For file output, set `SOURCES_PROXY_LOG` to the plugin's `log_file_path` instead.
`max_body_size` bounds captured bodies. Authorization, cookie and API-key
headers are redacted.
