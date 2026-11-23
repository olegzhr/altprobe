-- Execute the real Lua log handlers with isolated Redis/ngx/Kong adapters.
local json = require "cjson.safe"
local root = assert(arg[1], "repository root required")
local payload
local calls, redis_error, logged
local redis = {}
function redis:new()
    return {
        set_timeout=function() end, connect=function() return true end,
        auth=function(_, username, password)
            assert(username=="fixture-user" and password=="fixture-password")
            calls[#calls+1]="auth"
            return redis_error~="auth"
        end,
        select=function(_, db)
            assert(db==2)
            calls[#calls+1]="select"
            return redis_error~="select"
        end,
        rpush=function(_,_,value) calls[#calls+1]="rpush"; payload=value; return 1 end,
        set_keepalive=function() calls[#calls+1]="keepalive" end,
        close=function() calls[#calls+1]="close" end,
    }
end
package.preload["resty.redis"] = function() return redis end
package.preload["resty.http"] = function() return {} end
package.preload["kong.db.schema.typedefs"] = function() return {protocols_http={}} end
package.preload["apisix.core"] = function()
    return {schema={},log={error=function(message) logged=message end}}
end
local paths = {
    {"apisix","connectors/apisix/redis-logger.lua"},
    {"apisix","labs/lab_apisix/apisix/redis-logger/redis-logger.lua"},
    {"kong","connectors/kong/altprobe/handler.lua"},
    {"kong","labs/lab_kong/kong/altprobe/handler.lua"},

}
for _, entry in ipairs(paths) do
    local kind,path=entry[1],entry[2]
    local records={}
    for i=1,2 do
        payload,calls,redis_error,logged=nil,{},nil,nil
        ngx={var={hostname="node-a",request_id="request-"..i,request_uri="/test-api/status",request_method="GET",
                  remote_addr="10.1.1.1",http_gateway_origin_id="client-spoof",server_port="9080",
                  time_local="01/Nov/2026:12:00:00 +0300"},
             ctx={},status=200,ERR=1,log=error,now=function() return 1793520000 end,
             req={get_method=function() return "GET" end},resp={get_headers=function() return {} end},
             timer={at=function(_,callback,...) callback(false,...); return true end}}
        kong={ctx={plugin={}},request={get_method=function() return "GET" end},log={err=error}}
        local conf={gateway_origin_id="trusted-origin",host_name="gateway",max_body_size=5000,redis_host="redis",
                    redis_port=6379,redis_key="log_proxy",timeout=1000}
        local getenv=os.getenv

        local module=assert(loadfile(root.."/"..path))()
        os.getenv=getenv
        if kind=="apisix" then
            if i==2 then
                conf.redis_username="fixture-user"
                conf.redis_password="fixture-password"
                conf.redis_database=2
                for _, failure in ipairs({"auth", "select"}) do
                    redis_error=failure
                    calls={}
                    module.log(conf,{})
                    assert(not payload and logged, path..": sent a record after Redis "..failure.." failed")
                    local expected=failure=="auth" and "auth,close" or "auth,select,close"
                    assert(table.concat(calls,",")==expected, path..": Redis failure sequence")
                end
                redis_error,calls,logged=nil,{},nil
            end
            module.log(conf,{})
            local expected=i==1 and "rpush,keepalive" or "auth,select,rpush,close"
            assert(table.concat(calls,",")==expected and not logged, path..": Redis success sequence")
        end
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
