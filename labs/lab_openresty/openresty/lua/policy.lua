local json = require "cjson.safe"

-- Lab authentication only (demo keys). Production must derive the username from
-- its own verified gateway identity.
local keys = {
    ["lab-policy-active-key"] = "policy-active",
    ["lab-policy-blocked-key"] = "policy-blocked",
    ["lab-policy-unknown-key"] = "policy-unknown"
}

-- Telemetry body capture for the log pipeline. Kept inline (not via dofile):
-- ngx.req.read_body() may yield when the body has not fully arrived, and a yield
-- across dofile's C-call boundary aborts the request with HTTP 500.
ngx.req.read_body()
local body = ngx.req.get_body_data()
ngx.ctx.request_body = body or ""
ngx.ctx.request_missing = ngx.req.get_body_file() ~= nil
ngx.ctx.request_size = tonumber(ngx.var.content_length) or #(body or "")

local consumer = keys[ngx.req.get_headers()["apikey"] or ""]
if not consumer then
    ngx.status = 401
    ngx.header.content_type = "application/json"
    ngx.say('{"reason":"authentication_required"}')
    return ngx.exit(401)
end
ngx.ctx.consumer_name = consumer

-- Credentials and client-claimed principals are not part of the decision input.
local headers = ngx.req.get_headers()
for _, name in ipairs({"apikey", "authorization", "cookie", "x-consumer-username", "x-authenticated-principal"}) do
    headers[name] = nil
end

local payload = json.encode({input = {
    type = "http", consumer = {username = consumer},
    request = {method = ngx.req.get_method(), path = ngx.var.request_uri, headers = headers},
    var = {remote_addr = ngx.var.remote_addr}
}})
if not payload then
    ngx.status = 400
    ngx.header.content_type = "application/json"
    ngx.say('{"reason":"policy_input_invalid"}')
    return ngx.exit(400)
end

-- Loopback Altprobe sidecar (POLICY_SIDECAR_HTTP_* in docker-compose.yaml).
local sock = ngx.socket.tcp()
sock:settimeout(2000)
local ok = sock:connect("127.0.0.1", 8181)
if not ok then return ngx.exit(503) end
local sent = sock:send("POST /v1/data/altprobe/allow HTTP/1.0\r\nHost: localhost\r\n" ..
    "Content-Type: application/json\r\nContent-Length: " .. #payload ..
    "\r\nConnection: close\r\n\r\n" .. payload)
if not sent then
    sock:close()
    return ngx.exit(503)
end
local raw, err = sock:receive("*a")
sock:close()
if not raw or err then return ngx.exit(503) end

local status = tonumber(raw:match("^HTTP/%d%.%d (%d%d%d)"))
local response = raw:match("\r\n\r\n(.*)$")
local doc = response and json.decode(response)
local result = doc and doc.result
if status ~= 200 or type(result) ~= "table" or type(result.allow) ~= "boolean" then
    return ngx.exit(503)
end

if not result.allow then
    local code = tonumber(result.status_code)
    if not code or code < 400 or code > 599 then code = 403 end
    ngx.status = code
    ngx.header.content_type = "application/json"
    ngx.say(json.encode({reason = result.reason, inventory_version = result.inventory_version}))
    return ngx.exit(code)
end
