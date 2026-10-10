# APISIX -> Altprobe connector

The APISIX `redis-logger` plugin asynchronously logs every proxied request as a
JSON record to Redis (or a JSON-Lines file). Altprobe reads that Redis list
through its proxy (Redis) source and normalizes the traffic into OCSF.

## Files

| File | Purpose |
|------|---------|
| `redis-logger.lua` | The APISIX plugin (access/header_filter/body_filter/log phases). |
| `config.example.yaml` | The `plugins` / `plugin_attr` keys to merge into APISIX `conf/config.yaml`. |

## Install

1. Copy `redis-logger.lua` into the APISIX plugins directory
   (`/usr/local/apisix/apisix/plugins/redis-logger.lua`).
2. Enable the plugin and configure the Redis target in `conf/config.yaml`
   (see `config.example.yaml`). Redis settings can also be set per route.
3. Attach the plugin to the routes you want to observe. Example Admin API call:

   ```bash
   curl -s -X PUT http://127.0.0.1:9180/apisix/admin/routes/my-route \
     -H "X-API-KEY: <admin-key>" -H "Content-Type: application/json" \
     -d '{
       "uri": "/your-api/*",
       "upstream": {"type": "roundrobin", "nodes": {"your-app:8000": 1}},
       "plugins": {"redis-logger": {"output_type": "redis"}}
     }'
   ```

## Altprobe side

- Redis mode: set `SOURCES_PROXY_REDIS=log_proxy` (must match `redis_key`) and
  `SOURCES_REDIS_HOST` / `SOURCES_REDIS_PORT` to the same Redis.
- File mode (`output_type: file`): set `SOURCES_PROXY_LOG` to `log_file_path`.

## Log fields

`host_name`, `mcp_session_id`, `mcp_method`, `http_x_claude_code_agent_id`,
`http_x_claude_code_session_id`, `http_session_id`, `http_x_agent_id`,
`request_uri`, `request_id`, `request_method`, `http_version`, `remote_addr`,
`remote_user`, `server_port`, `time_local`, `duration`, `status`,
`body_bytes_sent`, `http_referer`, `http_x_forwarded_for`, `http_x_real_ip`,
`http_host`, `http_user_agent`, `http_authorization`, `http_accept_language`,
`http_accept_encoding`, `http_connection`, `http_content_type`,
`http_content_length`, `http_cookie`, `request_body`, `response_body`,
`req_headers`, `resp_headers`.

Configuration keys (per route or in `plugin_attr`): `output_type`,
`redis_host`, `redis_port`, `redis_password`, `redis_database`, `redis_key`,
`log_file_path`, `host_name`, `timeout`, `max_body_size`.

## Notes

- The plugin list must be at the top YAML level in APISIX 3.9+.
- Plugin methods use `.` notation (`_M.log`), because APISIX calls them without
  `self`.
- Redis is not usable directly in the log phase (yielding is forbidden), so the
  plugin dispatches the write via `ngx.timer.at(0, ...)`.
