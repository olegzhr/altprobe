#!/bin/bash
# Verifies that harmless demo traffic reaches OpenSearch through Altprobe.
set -euo pipefail

BASE="${LAB_BASE:-http://localhost:${LAB_PORT:-9080}}"
OS="${LAB_OS_BASE:-http://localhost:9200}"
OUT="$(cd "$(dirname "$0")" && pwd)/out"
LOGFILE="$OUT/02_opensearch_smoke.out"
mkdir -p "$OUT"
: > "$LOGFILE"

say() {
  echo "$@" | tee -a "$LOGFILE"
}

post_json() {
  curl -s -X POST "$1" -H "Content-Type: application/json" -d "$2" >/dev/null
}

say "=== Altprobe OpenSearch smoke test ==="
say "Gateway: $BASE"
say "OpenSearch: $OS"

post_json "$BASE/mcp" '{"jsonrpc":"2.0","id":10,"method":"ping"}'
curl -s "$BASE/test-api/status" >/dev/null
post_json "$BASE/ai-gateway/v1/chat/completions" '{"model":"demo-model","messages":[{"role":"user","content":"hello"}]}'

say "--- waiting for Altprobe indexing ---"
sleep "${LAB_INDEX_WAIT:-10}"

say "--- OpenSearch cluster health ---"
curl -s "$OS/_cluster/health?pretty" | tee -a "$LOGFILE"

api_count=$(curl -s "$OS/ocsf-1.1.0-6003-api_activity*/_count" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)
http_count=$(curl -s "$OS/ocsf-1.1.0-4002-http_activity*/_count" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)

say "api_activity documents : $api_count"
say "http_activity documents: $http_count"

if [ "$api_count" -gt 0 ] || [ "$http_count" -gt 0 ]; then
  say "PASS: Altprobe events are indexed in OpenSearch."
else
  say "FAIL: no OCSF documents found yet."
  exit 1
fi
