-- OpenResty gateway telemetry for Altprobe.
--
-- Emits the same field set as the APISIX redis-logger plugin, so the standard
-- Altprobe proxy (Redis) source normalizes it into OCSF without code changes.
-- Telemetry only: no policy/OPA decision is involved.
local json = require "cjson.safe"

local function field(name)
    return ngx.var[name] or "-"
end

local function encode_headers(getter)
    local ok, headers = pcall(getter)
    if not ok or type(headers) ~= "table" then return "{}" end
    local eok, res = pcall(json.encode, headers)
    if not eok then return "{}" end
    return res
end

local ctx = ngx.ctx

-- Altprobe reads these top-level fields to keep MCP events tied to a stable
-- session/agent id (same priority order the APISIX plugin uses).
local agent_session_id = ngx.var.http_mcp_session_id or ngx.var.http_x_agent_id or "-"

local record = {
    host_name = "altprobe-openresty-lab",
    mcp_session_id = agent_session_id,
    mcp_method = ctx.mcp_method or "-",
    http_x_claude_code_agent_id = field("http_x_claude_code_agent_id"),
    http_x_claude_code_session_id = field("http_x_claude_code_session_id"),
    http_session_id = field("http_session_id"),
    http_x_agent_id = field("http_x_agent_id"),
    request_uri = field("request_uri"),
    request_id = field("request_id"),
    request_method = field("request_method"),
    http_version = field("server_protocol"),
    remote_addr = field("remote_addr"),
    remote_user = field("remote_user"),
    server_port = tonumber(ngx.var.server_port) or 0,
    time_local = field("time_local"),
    duration = tonumber(ngx.var.request_time) or 0,
    status = ngx.status or 0,
    body_bytes_sent = tonumber(ngx.var.body_bytes_sent) or 0,
    http_referer = field("http_referer"),
    http_x_forwarded_for = field("http_x_forwarded_for"),
    http_x_real_ip = field("http_x_real_ip"),
    http_host = field("http_host"),
    http_user_agent = field("http_user_agent"),
    http_authorization = ngx.var.http_authorization and "[REDACTED]" or "-",
    http_accept_language = field("http_accept_language"),
    http_accept_encoding = field("http_accept_encoding"),
    http_connection = field("http_connection"),
    http_content_type = field("http_content_type"),
    http_content_length = field("http_content_length"),
    http_cookie = field("http_cookie"),
    request_body = ctx.request_body or "",
    response_body = ctx.response_body or "",
    req_headers = ctx.req_headers or "{}",
    resp_headers = encode_headers(ngx.resp.get_headers),
}

local payload = json.encode(record)
if not payload then
    ngx.log(ngx.ERR, "cannot encode proxy event")
    return
end

-- Cosockets are unavailable in the log phase; send from a zero-delay timer.
local ok, err = ngx.timer.at(0, function(premature, event)
    if premature then return end
    local redis = require "resty.redis"
    local client = redis:new()
    client:set_timeout(1000)
    local connected, connect_err = client:connect("redis", 6379)
    if not connected then ngx.log(ngx.ERR, "redis connect: ", connect_err); return end
    local sent, send_err = client:rpush("log_proxy", event)
    if not sent then client:close(); ngx.log(ngx.ERR, "redis log: ", send_err); return end
    client:set_keepalive(10000, 100)
end, payload)
if not ok then ngx.log(ngx.ERR, "redis timer: ", err) end
