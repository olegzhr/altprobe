# Envoy -> Altprobe connector

Envoy captures request/response bodies and agent/session headers with a Lua HTTP
filter into dynamic metadata, and the file access logger writes one JSON object
per request to a log file. Altprobe reads that file through its proxy (file)
source and normalizes the traffic into OCSF.

## Files

| File | Purpose |
|------|---------|
| `envoy.yaml` | Envoy bootstrap config with the Lua filter, JSON file access log and a placeholder `app` cluster. |

## Install

1. Merge `envoy.yaml` into your Envoy bootstrap config (or mount it as the
   bootstrap file).
2. Point the cluster `app` (`address: BACKEND`, port `8000`) at your
   application upstream.
3. Ensure the access-log directory exists and is writable, e.g.
   `mkdir -p /var/log/envoy && touch /var/log/envoy/access.log`.
4. Namespace routes as needed: you can expose an `/ai-gateway/...` path that is
   prefix-rewritten to the upstream's real endpoint so `api_guard` matches the
   AI-gateway context. Add such a route when you want that behavior.

## Altprobe side

- Set `SOURCES_PROXY_LOG=/var/log/envoy/access.log` (must match `path` in the
  access logger) and leave `SOURCES_PROXY_REDIS` empty.

## Log fields

Populated by the access logger: `host_name`, `request_id`, `server_port`,
`request_uri`, `request_method`, `http_version`, `remote_addr`, `remote_user`,
`time_local`, `duration`, `status`, `body_bytes_sent`, `http_referer`,
`http_x_forwarded_for`, `http_x_real_ip`, `http_host`, `http_user_agent`,
`http_authorization`, `http_accept_language`, `http_accept_encoding`,
`http_connection`, `http_cookie`.

Populated by the Lua filter (via dynamic metadata): `request_body`,
`response_body`, `mcp_session_id`, `mcp_method`, `http_x_claude_code_agent_id`,
`http_x_claude_code_session_id`, `http_session_id`, `http_x_agent_id`,
`http_content_type`, `http_content_length`.

## Notes

- Bodies are capped (`max_body` 4096 request / 8192 response) so a single JSON
  log line stays within Altprobe's line buffer.
- Header values are read into plain strings before iterating body chunks: the
  header map handle must not be used after body iteration.
