FROM openresty/openresty:1.27.1.2-0-alpine-fat

# Telemetry-only gateway: nginx proxies to the demo mock and the Lua log
# handler pushes one JSON record per request to Redis ("log_proxy"), which
# Altprobe reads through its standard proxy (Redis) source.
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua /etc/openresty/lua
