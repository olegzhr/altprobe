# APISIX Gateway — Redis/File Logger Plugin

APISIX API gateway with a custom `redis-logger` plugin that asynchronously logs proxied HTTP requests to Redis or a JSON Lines log file.

## Quick Start

```bash
git clone <repo-url>
cd <repo-name>

# Build APISIX image
docker compose build apisix

# Start all services
docker compose up -d

# View logs
docker compose logs -f apisix

# Stop
docker compose down
```

## Routes

| URI | Upstream |
|-----|----------|
| `/mcp*` | `UPSTREAM_HOST:8000` |
| `/test-api*` | `UPSTREAM_HOST:8000` |
| `/ai-gateway/v1/chat/completions` | `UPSTREAM_HOST:8000/test-api/v1/chat/completions` |

`UPSTREAM_HOST` and the redis connection are resolved from the environment
(`UPSTREAM_HOST`, `REDIS_HOST`, `REDIS_PORT`, `REDIS_KEY`) — see `entrypoint.sh`.

## Ports

| Port | Purpose |
|------|---------|
| `9080` | **Proxy** — entry point for all routes |
| `9180` | Admin API for route management |
| `2379` | etcd (configuration storage) |
| `9000` | Admin UI |

### Example Requests

```bash
curl http://localhost:9080/test-api/status
curl -X POST http://localhost:9080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
```

## Logger Output

The `redis-logger` plugin asynchronously writes a full JSON log of each proxied request to the configured output. `output_type: redis` sends records to Redis (`RPUSH`), and `output_type: file` appends one JSON object per line to `log_file_path`. Phases:

| Phase | What it collects |
|-------|-----------------|
| `access` | request body (`request_body`), request headers (`req_headers`) |
| `header_filter` | response headers (`resp_headers`) |
| `body_filter` | response body (`response_body`, truncated to `max_body_size`) |
| `log` | all request variables, builds JSON, sends via `ngx.timer.at(0, publish_log)` |

Log fields: `host_name`, `request_uri`, `request_id`, `request_method`, `http_version`, `remote_addr`, `remote_user`, `server_port`, `time_local`, `duration`, `status`, `body_bytes_sent`, `http_referer`, `http_x_forwarded_for`, `http_x_real_ip`, `http_host`, `http_user_agent`, `http_authorization`, `http_accept_language`, `http_accept_encoding`, `http_connection`, `http_cookie`, `request_body`, `response_body`, `req_headers`, `resp_headers`.

Connection is configured in `plugin_attr.redis-logger` in `conf/config.yaml`. The plugin can also be configured per-route — `entrypoint.sh` attaches it during route creation.

```yaml
plugin_attr:
  redis-logger:
    output_type: redis
    redis_host: REDIS_HOST
    redis_port: 6379
    redis_key: log_proxy
    log_file_path: /usr/local/apisix/logs/proxy-json.log
```

Schema fields: `output_type`, `redis_host`, `redis_port`, `redis_key`, `redis_password`, `redis_database`, `log_file_path`, `host_name`, `timeout`, `max_body_size`.

### Important Notes

1. **`plugins` at root level** — in APISIX 3.9.0, the plugin list must be at the top YAML level, not inside `apisix:`.
2. **Plugin methods use `.` notation** — methods (`check_schema`, `access`, `log`) must use dot notation (`.log`) not colon (`:log`), because APISIX calls them without self.
3. **Redis is not directly available in `log_by_lua`** — `resty.redis` requires yielding, which is forbidden in this phase. Solution: delegate the call via `ngx.timer.at(0, ...)`.
4. **`resp_headers` via `ngx.resp.get_headers()`** — in `header_filter`, `core.response.headers(ctx)` cannot be used. `ngx.resp.get_headers()` works instead.

## Structure

```
├── conf/config.yaml           # APISIX configuration
├── docker-compose.yml         # services (etcd, apisix, dashboard)
├── Dockerfile                 # image build with plugins
├── entrypoint.sh              # route initialization on startup
├── plugins/redis-logger.lua   # custom logging plugin
└── dashboard_conf/conf.yaml   # dashboard config
```
