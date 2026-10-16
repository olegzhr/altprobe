local json = require "cjson.safe"
local redis = require "resty.redis"
local http = require "resty.http"
local Handler = { VERSION = "1.0.0", PRIORITY = 700 }

local function scrub(headers)
  local out = {}
  for k, v in pairs(headers or {}) do
    local key = k:lower()
    if key == "authorization" or key == "proxy-authorization" or key == "apikey"
      or key == "cookie" or key == "set-cookie" then out[k] = "[REDACTED]"
    else out[k] = v end
  end
  return out
end

function Handler:access(conf)
  local ctx = kong.ctx.plugin
  ngx.req.read_body()
  local body = ngx.req.get_body_data()
  ctx.request_body = (body or ""):sub(1, conf.max_body_size)
  ctx.request_missing = ngx.req.get_body_file() ~= nil
  ctx.request_size = tonumber(ngx.var.content_length) or #(body or "")
  ctx.request_truncated = ctx.request_missing or ctx.request_size > #ctx.request_body
  ctx.headers = scrub(kong.request.get_headers())
  -- Strip gateway credentials even on telemetry-only routes.
  kong.service.request.clear_header("apikey")
  local consumer = kong.client.get_consumer()
  ctx.consumer = consumer and consumer.username or "-"
  -- key-auth runs first (priority 1250). Identity is never taken from agent headers.
  if not conf.policy_enabled then return end
  if ctx.consumer == "-" then
    return kong.response.exit(401, {reason = "authentication_required"})
  end
  local envelope = json.encode({input = {
    type = "http", consumer = {username = ctx.consumer},
    request = {method = kong.request.get_method(), path = ngx.var.request_uri, headers = ctx.headers},
    var = {remote_addr = ngx.var.remote_addr},
  }})
  local client = http.new()
  client:set_timeout(conf.timeout)
  local response = client:request_uri(conf.policy_url, {
    method = "POST", body = envelope, headers = {["Content-Type"] = "application/json"},
    ssl_verify = true, keepalive = true,
  })
  local doc = response and response.status == 200 and json.decode(response.body)
  local result = type(doc) == "table" and doc.result
  if type(result) ~= "table" or type(result.allow) ~= "boolean" then
    return kong.response.exit(503, {reason = "policy_unavailable"})
  end
  if not result.allow then
    local status = tonumber(result.status_code) or 403
    if status < 400 or status > 599 then status = 403 end
    return kong.response.exit(status, {reason = result.reason, inventory_version = result.inventory_version})
  end
end

function Handler:header_filter(conf)
  kong.ctx.plugin.response_headers = scrub(kong.response.get_headers())
end

function Handler:body_filter(conf)
  local ctx, chunk = kong.ctx.plugin, ngx.arg[1] or ""
  ctx.response_size = (ctx.response_size or 0) + #chunk
  ctx.response_body = (ctx.response_body or "") .. chunk:sub(1, math.max(0, conf.max_body_size - #(ctx.response_body or "")))
  -- Leave ngx.arg unchanged: SSE chunks continue immediately.
end

local function publish(premature, conf, payload)
  if premature then return end
  local red = redis:new()
  red:set_timeout(conf.timeout)
  local ok, err = red:connect(conf.redis_host, conf.redis_port)
  if ok then ok, err = red:rpush(conf.redis_key, payload) end
  if not ok then kong.log.err("altprobe telemetry delivery failed: ", err); red:close(); return end
  red:set_keepalive(10000, 100)
end

function Handler:log(conf)
  local ctx = kong.ctx.plugin
  local function h(name) return ngx.var["http_" .. name] or "-" end
  local decoded = json.decode(ctx.request_body or "")
  local record = {
    host_name = conf.host_name, consumer_name = ctx.consumer or "-",
    request_uri = ngx.var.request_uri, request_method = ngx.req.get_method(),
    request_id = ngx.var.request_id, http_version = ngx.var.server_protocol,
    remote_addr = ngx.var.remote_addr, remote_user = ctx.consumer or "-",
    server_port = tonumber(ngx.var.server_port), time_local = ngx.var.time_local,
    duration = tonumber(ngx.var.request_time), status = ngx.status,
    body_bytes_sent = tonumber(ngx.var.body_bytes_sent),
    request_body = ctx.request_body or "", response_body = ctx.response_body or "",
    request_body_missing = ctx.request_missing or false, request_body_truncated = ctx.request_truncated or false,
    request_body_original_size = ctx.request_size or 0, response_body_original_size = ctx.response_size or 0,
    response_body_truncated = (ctx.response_size or 0) > #(ctx.response_body or ""),
    req_headers = json.encode(ctx.headers or {}), resp_headers = json.encode(ctx.response_headers or {}),
    mcp_method = type(decoded) == "table" and type(decoded.method) == "string" and decoded.method or "-",
    mcp_session_id = h("mcp_session_id"), http_x_agent_id = h("x_agent_id"),
    http_x_claude_code_agent_id = h("x_claude_code_agent_id"),
    http_x_claude_code_session_id = h("x_claude_code_session_id"),
    http_session_id = ngx.var.http_session_id or ngx.var.http_x_session_id or "-",
    http_host = h("host"), http_user_agent = h("user_agent"), http_referer = h("referer"),
    http_x_forwarded_for = h("x_forwarded_for"), http_x_real_ip = h("x_real_ip"),
    http_content_type = h("content_type"), http_content_length = h("content_length"),
    http_accept_language = h("accept_language"), http_accept_encoding = h("accept_encoding"),
    http_connection = h("connection"), http_authorization = "[REDACTED]", http_cookie = "[REDACTED]",
  }
  local payload, err = json.encode(record)
  if not payload then kong.log.err("altprobe encoding failed: ", err); return end
  local ok
  ok, err = ngx.timer.at(0, publish, conf, payload)
  if not ok then kong.log.err("altprobe dispatch failed: ", err) end
end
return Handler
