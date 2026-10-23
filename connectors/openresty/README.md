# OpenResty -> Altprobe connector

OpenResty (nginx + Lua) stages request/response data in the access, body and log
phases, and `log.lua` pushes one JSON record per request to a Redis list that
Altprobe reads through its proxy (Redis) source. Records follow the APISIX
connector field set (without a consumer, since this connector does not
authenticate), so Altprobe's proxy parser handles them unchanged.

## Files

| File | Purpose |
|------|---------|
| `nginx.conf` | nginx config wiring the Lua phases into a proxying `server`. |
| `lua/access.lua` | Access phase: read the request body, headers and JSON-RPC method. |
| `lua/capture.lua` | Body phase: cap and stash the response body. |
| `lua/log.lua` | Log phase: assemble the record and push it to Redis. |

## Install

1. Copy `nginx.conf` to `/usr/local/openresty/nginx/conf/nginx.conf`.
2. Copy the `lua/` directory to `/etc/openresty/lua`.
3. Set `proxy_pass` in `nginx.conf` to your application upstream.
4. Set the Redis target and host name at the top of `lua/log.lua`
   (`REDIS_HOST`, `REDIS_PORT`, `REDIS_KEY`, `HOST_NAME`).

## Altprobe side

- Set `SOURCES_PROXY_REDIS=log_proxy` (must match `REDIS_KEY`) and
  `SOURCES_REDIS_HOST` / `SOURCES_REDIS_PORT` to the same Redis.

## Log fields

`host_name`, `mcp_session_id`, `mcp_method`, `request_uri`, `request_id`,
`request_method`, `http_version`, `remote_addr`, `remote_user`, `server_port`,
`time_local`, `duration`, `status`, `body_bytes_sent`, `http_referer`,
`http_host`, `http_user_agent`, `http_accept_language`, `http_accept_encoding`,
`http_connection`, `http_content_type`, `http_content_length`, `request_body`,
`response_body`, `req_headers`, `resp_headers`.

Identity: this telemetry-only connector does not authenticate requests, so
Altprobe identifies entities by the observed source IP
(`ip:<host>:<remote_addr>`). When the gateway is fronted by an authenticating
tier that supplies a consumer, Altprobe uses that auth key instead.
`mcp_session_id` is MCP protocol metadata, not identity. Client identity headers
are not read or forwarded, and credentials in the header dumps are redacted.

## Notes

- cosockets are unavailable in the log phase, so the Redis write happens in a
  zero-delay `ngx.timer.at` callback.
- This connector is telemetry-only: it makes no policy/OPA decision. For route
  namespacing (e.g. `/ai-gateway/...` rewritten to the upstream endpoint) add a
  dedicated `location`.
