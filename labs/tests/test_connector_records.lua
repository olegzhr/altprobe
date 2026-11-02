-- Execute the real Lua log handlers with isolated Redis/ngx/Kong adapters.
local json = require "cjson.safe"
local root = assert(arg[1], "repository root required")
local payload
local redis = {}
function redis:new()
    return {
        set_timeout=function() end, connect=function() return true end,
        auth=function() return true end, select=function() return true end,
        rpush=function(_,_,value) payload=value; return 1 end,
        set_keepalive=function() end, close=function() end,
    }
end
package.preload["resty.redis"] = function() return redis end
package.preload["resty.http"] = function() return {} end
package.preload["kong.db.schema.typedefs"] = function() return {protocols_http={}} end
package.preload["apisix.core"] = function() return {schema={},log={error=error}} end
local paths = {
    {"apisix","connectors/apisix/redis-logger.lua"},
    {"apisix","labs/lab_apisix/apisix/redis-logger/redis-logger.lua"},
    {"kong","connectors/kong/altprobe/handler.lua"},
    {"kong","labs/lab_kong/kong/altprobe/handler.lua"},
    {"openresty","connectors/openresty/lua/log.lua"},
    {"openresty","labs/lab_openresty/openresty/lua/log.lua"},
}
for _, entry in ipairs(paths) do
    local kind,path=entry[1],entry[2]
    local records={}
    for i=1,2 do
        payload=nil
        ngx={var={hostname="node-a",request_id="request-"..i,request_uri="/test-api/status",request_method="GET",
                  remote_addr="10.1.1.1",http_gateway_origin_id="client-spoof",server_port="9080",
                  time_local="01/Nov/2026:12:00:00 +0300"},
             ctx={},status=200,ERR=1,log=error,now=function() return 1793520000 end,
             req={get_method=function() return "GET" end},resp={get_headers=function() return {} end},
             timer={at=function(_,callback,...) callback(false,...); return true end}}
        kong={ctx={plugin={}},request={get_method=function() return "GET" end},log={err=error}}
        local conf={gateway_origin_id="trusted-origin",host_name="gateway",max_body_size=5000,redis_host="redis",
                    redis_port=6379,redis_key="log_proxy",timeout=1000}
        local module=assert(loadfile(root.."/"..path))()
        if kind=="apisix" then module.log(conf,{}) end
        if kind=="kong" then module:log(conf) end
        assert(payload,path)
        local record=assert(json.decode(payload))
        assert(record.gateway_origin_id=="trusted-origin",path..": untrusted or missing origin")
        assert(record.request_id=="request-"..i,path..": missing observation ID")
        records[i]=record
    end
    assert(records[1].gateway_origin_id==records[2].gateway_origin_id)
    assert(records[1].request_id~=records[2].request_id)
    print("PASS "..path)
end
