-- Telemetry-only request capture for the OpenResty log handler.
--
-- Mirrors the APISIX redis-logger plugin's access phase so log.lua can emit the
-- exact same field set (which the APISIX lab tests exercise). No policy/OPA
-- decision is made here: the lab does not authenticate or authorize callers.
local json = require "cjson.safe"

ngx.req.read_body()
local body = ngx.req.get_body_data() or ""
ngx.ctx.request_body = body

local ok, headers = pcall(ngx.req.get_headers)
if ok and type(headers) == "table" then
    local eok, encoded = pcall(json.encode, headers)
    ngx.ctx.req_headers = eok and encoded or "{}"
else
    ngx.ctx.req_headers = "{}"
end

-- Extract the JSON-RPC method so Altprobe's mcp_method trace conditions work.
ngx.ctx.mcp_method = "-"
local content_type = ngx.var.http_content_type or ""
if #body > 0 and #body <= 32768
    and content_type:find("application/json", 1, true)
    and body:find('"method"', 1, true) then
    local dok, decoded = pcall(json.decode, body)
    if dok and type(decoded) == "table" and type(decoded.method) == "string" then
        ngx.ctx.mcp_method = decoded.method
    end
end
