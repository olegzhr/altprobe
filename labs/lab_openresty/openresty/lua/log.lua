local json = require "cjson.safe"
local ctx = ngx.ctx
local function field(name) return ngx.var[name] or "" end
local record = {
    gateway_origin_id = os.getenv("ALTPROBE_GATEWAY_ORIGIN_ID") or ("openresty:" .. ngx.var.hostname),
    host_name = "altprobe-openresty-lab", consumer_name = ctx.consumer_name or "",
    request_uri = field("request_uri"), request_method = field("request_method"),
    request_id = field("request_id"), remote_addr = field("remote_addr"),
    timestamp_ms = math.floor(ngx.now() * 1000), server_port = tonumber(ngx.var.server_port),
    status = ngx.status, request_time = field("request_time"), http_host = field("host"),
    http_user_agent = field("http_user_agent"), http_version = field("server_protocol"),
    http_content_type = field("http_content_type"), http_content_length = field("content_length"),
    mcp_session_id = field("http_mcp_session_id"),
    request_body = (ctx.request_body or ""):sub(1, 65536), response_body = ctx.response_body or "",
    request_body_original_size = ctx.request_size or 0, response_body_original_size = ctx.response_size or 0,
    request_body_missing = ctx.request_missing or false,
    request_body_truncated = (ctx.request_size or 0) > 65536 or ctx.request_missing or false,
    response_body_truncated = (ctx.response_size or 0) > 65536
}
local payload = json.encode(record)
if not payload then ngx.log(ngx.ERR, "cannot encode proxy event"); return end
-- Cosockets are unavailable in log phase; send from a zero-delay timer.
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
