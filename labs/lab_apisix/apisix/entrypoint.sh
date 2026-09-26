#!/bin/bash

echo "Waiting for etcd..." >&2
while true; do
  curl -s http://etcd:2379/health 2>/dev/null | grep -q '"health":"true"' && break
  sleep 2
done
echo "etcd ready" >&2

echo "Init APISIX..." >&2
apisix init >/dev/null 2>&1 || true
apisix init_etcd >/dev/null 2>&1 || true

# Clean stale runtime files from a previous unclean shutdown; otherwise nginx
# fails to bind() the worker_events.sock and the Admin API never comes up.
rm -f /usr/local/apisix/logs/worker_events.sock /usr/local/apisix/logs/nginx.pid 2>/dev/null

echo "Start APISIX..." >&2
apisix start >/dev/null 2>&1 &

sleep 10

echo "Waiting for Admin API (200)..." >&2
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "${ADMIN_AUTH[@]}" http://127.0.0.1:9180/apisix/admin/routes 2>/dev/null || echo "000")
  if [ "$code" = "200" ]; then echo "Admin API ready (HTTP $code)" >&2; break; fi
  sleep 2
done

API="http://127.0.0.1:9180/apisix/admin"
ADMIN_KEY="${ADMIN_KEY:-edd1c9f034335f136f87ad84b625c8f1}"
ADMIN_AUTH=(-H "X-API-KEY: ${ADMIN_KEY}")

# Upstream and Redis are resolved from the environment so the same image can be
# reused in the alertflex-lab demo. Defaults keep the standalone plugin working.
UPSTREAM_HOST="${UPSTREAM_HOST:-127.0.0.1}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_KEY="${REDIS_KEY:-log_proxy}"

PLUGINS='{"redis-logger":{"output_type":"redis","redis_host":"'$REDIS_HOST'","redis_port":'$REDIS_PORT',"redis_key":"'$REDIS_KEY'","log_file_path":"/usr/local/apisix/logs/proxy-json.log"}}'

create_route() {
  local id=$1 uri=$2 upstream=$3
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$API/routes/$id" \
    -H "Content-Type: application/json" \
    "${ADMIN_AUTH[@]}" \
    -d "{\"uri\":\"$uri\",\"upstream\":$upstream,\"plugins\":$PLUGINS}")
  echo "Route $id ($uri): HTTP $code" >&2
}

add_plugin_to_route() {
  local id=$1 uri=$2 upstream=$3
  code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$API/routes/$id" \
    -H "Content-Type: application/json" \
    "${ADMIN_AUTH[@]}" \
    -d "{\"uri\":\"$uri\",\"upstream\":$upstream,\"plugins\":$PLUGINS}")
  echo "Plugin added to route $id: HTTP $code" >&2
}

UPSTREAM_MCP='{"nodes":{"'$UPSTREAM_HOST':8000":1},"type":"roundrobin"}'

create_route 1 "/mcp*" "$UPSTREAM_MCP"
create_route 3 "/test-api*" "$UPSTREAM_MCP"

# AI Gateway route. APISIX forwards the request to the local mock's
# OpenAI-compatible endpoint; no external model provider is contacted.
AI_GATEWAY_PLUGINS='{
  "ai-proxy": {
    "provider": "openai-compatible",
    "override": {"endpoint": "http://'$UPSTREAM_HOST':8000/test-api/v1/chat/completions"},
    "auth": {"header": {"Authorization": "Bearer synthetic-ai-gateway-key"}}
  },
  "redis-logger": {"output_type":"redis","redis_host":"'$REDIS_HOST'","redis_port":'$REDIS_PORT',"redis_key":"'$REDIS_KEY'","log_file_path":"/usr/local/apisix/logs/proxy-json.log"}
}'

code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$API/routes/6" \
  -H "Content-Type: application/json" \
  "${ADMIN_AUTH[@]}" \
  -d "{\"uri\":\"/ai-gateway/v1/chat/completions\",\"methods\":[\"POST\"],\"upstream\":$UPSTREAM_MCP,\"plugins\":$AI_GATEWAY_PLUGINS}")
echo "Route 6 (/ai-gateway/v1/chat/completions, AI Gateway): HTTP $code" >&2

echo "Done" >&2

tail -f /usr/local/apisix/logs/error.log
