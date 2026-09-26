local redis = require "resty.redis"
local cjson = require "cjson.safe"

local CustomLogRedisHandler = {
    VERSION = "1.0.0",
    PRIORITY = 1000,
}

function CustomLogRedisHandler:access(conf)
    ngx.req.read_body()

    local body = ngx.req.get_body_data()
    if not body then
        body = ""
    end

    ngx.ctx.request_body = body

    -- Trace support: Altprobe's proxy.cpp reads a top-level "mcp_method"
    -- field (JSON-RPC method) and trace-pattern conditions can match on it.
    -- Extract it in the access phase so altprobe does not have to re-parse
    -- the body. Only decode when the body looks like JSON-RPC and is within a
    -- bounded size, so arbitrary (large/binary/non-JSON) bodies are never
    -- parsed on the hot path. cjson.safe returns nil on invalid JSON.
    local mcp_method = "-"
    local content_type = ngx.var.http_content_type or ""
    local method_parse_limit = 32768
    if #body > 0 and #body <= method_parse_limit
        and content_type:find("application/json", 1, true)
        and body:find('"method"', 1, true) then
        local decoded = cjson.decode(body)
        if type(decoded) == "table" and type(decoded.method) == "string" then
            mcp_method = decoded.method
        end
    end
    ngx.ctx.mcp_method = mcp_method

    local req_headers = ngx.req.get_headers()
    ngx.ctx.req_headers = cjson.encode(req_headers)
end

function CustomLogRedisHandler:header_filter(conf)
    ngx.ctx.resp_body = ""

    local headers = ngx.resp.get_headers()
    ngx.ctx.resp_headers = cjson.encode(headers)
end

function CustomLogRedisHandler:body_filter(conf)
    local chunk = ngx.arg[1]

    if chunk and #chunk > 0 then
        ngx.ctx.resp_body = (ngx.ctx.resp_body or "") .. chunk
    end

    if ngx.arg[2] then
        if ngx.ctx.resp_body then
            ngx.ctx.resp_body = string.sub(ngx.ctx.resp_body, 1, 5000)
        end
    end
end

local function send_to_redis(conf, log_data)
    local json = cjson.encode(log_data)

    if not json then
        kong.log.err("custom-log-redis: JSON encode failed")
        return
    end

    local red = redis:new()
    red:set_timeout(1000)

    local ok, err = red:connect(conf.redis_host, conf.redis_port)

    if not ok then
        kong.log.err("Redis connect failed: ", err)
        return
    end

    if conf.redis_password ~= nil and conf.redis_password ~= "" then
        local ok, err = red:auth(conf.redis_password)

        if not ok then
            kong.log.err("Redis auth failed: ", err)
            return
        end
    end

    if conf.redis_database then
        local ok, err = red:select(conf.redis_database)

        if not ok then
            kong.log.err("Redis select failed: ", err)
            return
        end
    end

    local ok, err = red:rpush(conf.redis_key, json)

    if not ok then
        kong.log.err("Redis RPUSH failed: ", err)
        return
    end

    red:set_keepalive(10000, 100)
end

function CustomLogRedisHandler:log(conf)
    kong.log.info("custom-log-redis: LOG phase start")
    kong.log.info("URI: ", ngx.var.request_uri)
    kong.log.info("STATUS: ", ngx.status)

    -- Altprobe reads this top-level field from the gateway log envelope to
    -- keep MCP events associated with a stable session or agent id.
    local agent_session_id = ngx.var.http_mcp_session_id or ngx.var.http_x_agent_id or "-"

    -- Trace support: Altprobe's computeAgentKey() (trace.cpp) resolves the
    -- agent identity from the P1 headers below, in priority order:
    --   X-Claude-Code-Agent-Id > X-Claude-Code-Session-Id > Session-Id >
    --   X-Agent-Id > Mcp-Session-Id, then falls back to source IP + window.
    -- Forward each as its own top-level field so a request carrying any one
    -- of them is still traceable as a distinct agent.
    local log_data = {
        host_name = conf.host_name or "UPSTREAM_HOST",
        mcp_session_id = agent_session_id,
        mcp_method = ngx.ctx.mcp_method or "-",
        http_x_claude_code_agent_id = ngx.var.http_x_claude_code_agent_id or "-",
        http_x_claude_code_session_id = ngx.var.http_x_claude_code_session_id or "-",
        http_session_id = ngx.var.http_session_id or "-",
        http_x_agent_id = ngx.var.http_x_agent_id or "-",
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
        http_x_forwarded_for = ngx.var.http_x_forwarded_for or "-",
        http_x_real_ip = ngx.var.http_x_real_ip or "-",
        http_host = ngx.var.http_host or "-",
        http_user_agent = ngx.var.http_user_agent or "-",
        http_authorization = ngx.var.http_authorization and "[REDACTED]" or "-",
        http_accept_language = ngx.var.http_accept_language or "-",
        http_accept_encoding = ngx.var.http_accept_encoding or "-",
        http_connection = ngx.var.http_connection or "-",
        http_cookie = ngx.var.http_cookie or "-",
        request_body = ngx.ctx.request_body or "",
        response_body = ngx.ctx.resp_body or "",
        req_headers = ngx.ctx.req_headers or "",
        resp_headers = ngx.ctx.resp_headers or "",
    }

    ngx.timer.at(0, function()
        send_to_redis(conf, log_data)
    end)

    kong.log.info("custom-log-redis: LOG phase end")
    kong.log.info("==============================")
end

return CustomLogRedisHandler
