local core = require("apisix.core")
local redis = require("resty.redis")
local cjson = require("cjson")

local plugin_name = "redis-logger"

local schema = {
    type = "object",
    properties = {
        output_type = { type = "string", default = "redis", enum = { "redis", "file" } },
        redis_host = { type = "string", default = "127.0.0.1" },
        redis_port = { type = "integer", default = 6379 },
        redis_password = { type = "string", default = "" },
        redis_database = { type = "integer", default = 0 },
        redis_key = { type = "string", default = "log_proxy" },
        log_file_path = { type = "string", default = "/usr/local/apisix/logs/proxy-json.log" },
        host_name = { type = "string", default = "127.0.0.1" },
        timeout = { type = "integer", default = 1000 },
        max_body_size = { type = "integer", default = 5000 }
    }
}

local _M = {
    version = 1.0,
    priority = 399,
    name = plugin_name,
    schema = schema
}

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return true
    end
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end
    return true
end

local function safe_encode(obj)
    local ok, res = pcall(cjson.encode, obj)
    if not ok then
        return nil
    end
    return res
end

-- Credentials never reach the collector in clear text. Identity is the
-- authenticated consumer, never a client-supplied identity header.
local function redacted_headers(headers)
    local out = {}
    for name, value in pairs(headers or {}) do
        local lower = string.lower(name)
        if lower == "authorization" or lower == "proxy-authorization"
            or lower == "cookie" or lower == "set-cookie" or lower == "apikey" then
            out[name] = "[REDACTED]"
        else
            out[name] = value
        end
    end
    return out
end

function _M.access(conf, ctx)
    ngx.req.read_body()
    ctx.request_body = ngx.req.get_body_data() or ""
    ctx.req_headers = safe_encode(redacted_headers(core.request.headers(ctx))) or "{}"
    ctx.resp_body = ""

    -- Trace support: Altprobe's proxy.cpp reads a top-level "mcp_method"
    -- field (JSON-RPC method) and matches trace-pattern conditions on it.
    -- Extract it here so altprobe does not have to re-parse the body.
    -- Only decode when the body looks like JSON-RPC and is within a bounded
    -- size, so the access phase never parses arbitrary (large/binary/non-JSON)
    -- request bodies on the hot path.
    ctx.mcp_method = "-"
    local body = ctx.request_body or ""
    local content_type = ngx.var.http_content_type or ""
    local method_parse_limit = 32768
    if #body > 0 and #body <= method_parse_limit
        and content_type:find("application/json", 1, true)
        and body:find('"method"', 1, true) then
        local ok, decoded = pcall(cjson.decode, body)
        if ok and type(decoded) == "table" and type(decoded.method) == "string" then
            ctx.mcp_method = decoded.method
        end
    end
end

function _M.header_filter(conf, ctx)
    ctx.resp_headers = safe_encode({ redacted_headers(ngx.resp.get_headers()) }) or "{}"
end

function _M.body_filter(conf, ctx)
    local chunk = ngx.arg[1]
    if chunk then
        local prev = ctx.resp_body or ""
        local max_body_size = conf.max_body_size or 5000
        if #prev < max_body_size then
            ctx.resp_body = prev .. string.sub(chunk, 1, max_body_size - #prev)
        end
    end
end

local function send_to_redis(premature, conf, payload)
    if premature then
        return
    end

    local red = redis:new()
    red:set_timeout(conf.timeout)

    local ok, err = red:connect(conf.redis_host, conf.redis_port)
    if not ok then
        return
    end

    if conf.redis_password and conf.redis_password ~= "" then
        red:auth(conf.redis_password)
    end

    if conf.redis_database then
        red:select(conf.redis_database)
    end

    red:rpush(conf.redis_key, payload)
    red:set_keepalive(10000, 100)
end

local function send_to_file(premature, conf, payload)
    if premature then
        return
    end

    local file, err = io.open(conf.log_file_path, "a")
    if not file then
        core.log.error("redis-logger: log file open failed: ", err)
        return
    end

    local ok, write_err = file:write(payload, "\n")
    file:close()

    if not ok then
        core.log.error("redis-logger: log file write failed: ", write_err)
    end
end

local function publish_log(premature, conf, payload)
    if conf.output_type == "file" then
        return send_to_file(premature, conf, payload)
    end

    return send_to_redis(premature, conf, payload)
end

function _M.log(conf, ctx)
    -- MCP session id and method are protocol metadata only. Identity is the
    -- gateway-authenticated consumer below; Altprobe falls back to the observed
    -- source address when no consumer authenticated the request.
    local mcp_session_id = ngx.var.http_mcp_session_id or "-"

    local log_data = {
        host_name = conf.host_name,
        mcp_session_id = mcp_session_id,
        mcp_method = ctx.mcp_method or "-",
        consumer_name = ctx.consumer and ctx.consumer.username or "-",
        request_uri = ngx.var.request_uri or "-",
        request_id = ngx.var.request_id or "-",
        request_method = ngx.req.get_method() or "-",
        http_version = ngx.var.server_protocol or "-",
        remote_addr = ngx.var.remote_addr or "-",
        remote_user = ngx.var.remote_user or "-",
        server_port = tonumber(ngx.var.server_port) or 0,
        time_local = ngx.var.time_local or "-",
        duration = tonumber(ngx.var.request_time) or 0,
        status = ngx.status or 0,
        body_bytes_sent = tonumber(ngx.var.body_bytes_sent) or 0,
        http_referer = ngx.var.http_referer or "-",
        http_host = ngx.var.http_host or "-",
        http_user_agent = ngx.var.http_user_agent or "-",
        http_accept_language = ngx.var.http_accept_language or "-",
        http_accept_encoding = ngx.var.http_accept_encoding or "-",
        http_connection = ngx.var.http_connection or "-",
        http_content_type = ngx.var.http_content_type or "-",
        http_content_length = ngx.var.http_content_length or "-",
        request_body = ctx.request_body or "",
        response_body = ctx.resp_body or "",
        req_headers = ctx.req_headers or "{}",
        resp_headers = ctx.resp_headers or "{}"
    }

    local payload = safe_encode(log_data)
    if not payload then
        return
    end

    local ok, err = ngx.timer.at(0, publish_log, conf, payload)
    if not ok then
        core.log.error("redis-logger: async log dispatch failed: ", err)
    end
end

return _M
