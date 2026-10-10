-- Capture at most 64 KiB; preserve the original byte count and truncation flags.
local chunk = ngx.arg[1] or ""
ngx.ctx.response_size = (ngx.ctx.response_size or 0) + #chunk
local captured = ngx.ctx.response_body or ""
local remaining = 65536 - #captured
if remaining > 0 then ngx.ctx.response_body = captured .. chunk:sub(1, remaining) end
