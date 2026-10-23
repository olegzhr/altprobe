-- Telemetry-only request capture for the OpenResty log handler.
--
-- Mirrors the APISIX redis-logger plugin's access phase so log.lua can emit a
-- matching field set (minus consumer identity: this connector does not
-- authenticate or authorize callers).
local json = require "cjson.safe"

ngx.req.read_body()
local body = ngx.req.get_body_data() or ""
ngx.ctx.request_body = body

-- Redact credentials in the header dump; entity identity is never derived from
-- client headers (Altprobe uses the authenticated gateway consumer or source IP).
local SENSITIVE = {
    authorization = true,
    ["proxy-authorization"] = true,
    apikey = true,
    cookie = true,
    ["set-cookie"] = true,
}
local ok, headers = pcall(ngx.req.get_headers)
if ok and type(headers) == "table" then
    local clean = {}
    for k, v in pairs(headers) do
        local key = type(k) == "string" and k:lower() or ""
        clean[k] = SENSITIVE[key] and "[REDACTED]" or v
    end
    local eok, encoded = pcall(json.encode, clean)
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
