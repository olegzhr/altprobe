-- OpenResty (nginx + Lua) -> Altprobe gateway log connector.
--
-- Runs in the log phase and pushes one JSON record per request to a Redis list
-- that Altprobe reads through its proxy (Redis) source (SOURCES_PROXY_REDIS).
-- The record follows the APISIX redis-logger field set, so the same Altprobe
-- proxy parser handles it; OpenResty does not authenticate, so no consumer_name
-- is emitted. Telemetry only: no policy/OPA decision is made.
--
-- Wire-up (see nginx.conf): access.lua stages request_body/req_headers/mcp_method
-- and capture.lua stages response_body; this handler assembles the record.
local json = require "cjson.safe"

-- Deployment settings ---------------------------------------------------------
local REDIS_HOST = "127.0.0.1"    -- Redis host Altprobe reads from
local REDIS_PORT = 6379
local REDIS_KEY  = "log_proxy"    -- altprobe SOURCES_PROXY_REDIS
local HOST_NAME  = "openresty-gateway"
local MAX_BODY   = 65536          -- bytes kept per request/response body
--------------------------------------------------------------------------------

local function field(name)
    return ngx.var[name] or "-"
end

local function encode_headers(getter)
    local ok, headers = pcall(getter)
    if not ok or type(headers) ~= "table" then return "{}" end
    local clean = {}
    for k, v in pairs(headers) do
        local key = type(k) == "string" and k:lower() or ""
        if key == "authorization" or key == "proxy-authorization"
            or key == "apikey" or key == "cookie" or key == "set-cookie" then
            clean[k] = "[REDACTED]"
        else
            clean[k] = v
        end
    end
    local eok, res = pcall(json.encode, clean)
    if not eok then return "{}" end
    return res
end

local ctx = ngx.ctx

-- Identity is the authenticated gateway consumer when present, otherwise the
-- observed source IP. mcp_session_id is protocol metadata, not identity.
local record = {
    gateway_origin_id = os.getenv("ALTPROBE_GATEWAY_ORIGIN_ID") or ("openresty:" .. ngx.var.hostname),
    host_name = HOST_NAME,
    mcp_session_id = field("http_mcp_session_id"),
    mcp_method = ctx.mcp_method or "-",
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
    http_host = field("http_host"),
    http_user_agent = field("http_user_agent"),
    http_accept_language = field("http_accept_language"),
    http_accept_encoding = field("http_accept_encoding"),
    http_connection = field("http_connection"),
    http_content_type = field("http_content_type"),
    http_content_length = field("http_content_length"),
    request_body = (ctx.request_body or ""):sub(1, MAX_BODY),
    response_body = (ctx.response_body or ""):sub(1, MAX_BODY),
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
    local connected, connect_err = client:connect(REDIS_HOST, REDIS_PORT)
    if not connected then ngx.log(ngx.ERR, "redis connect: ", connect_err); return end
    local sent, send_err = client:rpush(REDIS_KEY, event)
    if not sent then client:close(); ngx.log(ngx.ERR, "redis log: ", send_err); return end
    client:set_keepalive(10000, 100)
end, payload)
if not ok then ngx.log(ngx.ERR, "redis timer: ", err) end
