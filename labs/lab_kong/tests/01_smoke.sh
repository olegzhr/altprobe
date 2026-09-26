#!/bin/bash
# Basic public-lab smoke test. It sends harmless demo traffic through the
# gateway and checks that the mock services answer as expected.
set -euo pipefail

BASE="${LAB_BASE:-http://localhost:${LAB_PORT:-9080}}"
OUT="$(cd "$(dirname "$0")" && pwd)/out"
LOGFILE="$OUT/01_smoke.out"
mkdir -p "$OUT"
: > "$LOGFILE"

say() {
  echo "$@" | tee -a "$LOGFILE"
}

post_json() {
  curl -s -X POST "$1" -H "Content-Type: application/json" -d "$2"
}

say "=== Altprobe public lab smoke test ==="
say "Gateway: $BASE"

say "--- MCP ping ---"
post_json "$BASE/mcp" '{"jsonrpc":"2.0","id":1,"method":"ping"}' \
  | tee -a "$LOGFILE" \
  | python3 -c "import sys,json; assert json.load(sys.stdin)['result'] == 'pong'"

say "--- MCP tool call ---"
post_json "$BASE/mcp" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hello","arguments":{"name":"Demo","language":"en"}}}' \
  | tee -a "$LOGFILE" \
  | python3 -c "import sys,json; data=json.load(sys.stdin); assert 'Hello, Demo!' in data['result']['content'][0]['text']"

say "--- REST status ---"
curl -s -o /dev/null -w "%{http_code}" "$BASE/test-api/status" \
  | tee -a "$LOGFILE" \
  | python3 -c "import sys; assert sys.stdin.read().strip() == '200'"

say "--- REST token and user profile ---"
TOKEN=$(curl -s -X POST "$BASE/test-api/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo_user&password=pwd12345" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s "$BASE/test-api/users/me/" -H "Authorization: Bearer $TOKEN" \
  | tee -a "$LOGFILE" \
  | python3 -c "import sys,json; assert json.load(sys.stdin)['username'] == 'demo_user'"

say "--- REST API-key endpoint ---"
curl -s "$BASE/test-api/hotels/api-key/" -H "X-API-Key: demo-api-key" \
  | tee -a "$LOGFILE" \
  | python3 -c "import sys,json; assert len(json.load(sys.stdin)) >= 1"

say "--- AI Gateway demo route ---"
post_json "$BASE/ai-gateway/v1/chat/completions" '{"model":"demo-model","messages":[{"role":"user","content":"hello"}]}' \
  | tee -a "$LOGFILE" \
  | python3 -c "import sys,json; assert json.load(sys.stdin)['choices'][0]['message']['content'] == 'demo response'"

say "PASS: public lab smoke checks completed."
