-- Telemetry only: record the request body for the log pipeline. No access decision.
ngx.req.read_body()
local body = ngx.req.get_body_data()
ngx.ctx.request_body = body or ""
ngx.ctx.request_missing = ngx.req.get_body_file() ~= nil
ngx.ctx.request_size = tonumber(ngx.var.content_length) or #(body or "")
