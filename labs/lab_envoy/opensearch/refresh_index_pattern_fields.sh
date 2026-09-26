#!/usr/bin/env bash
# =============================================================================
# Refresh the cached field metadata of every OCSF index pattern in OpenSearch
# Dashboards (Discover fix, same technique as before but covering all patterns
# provisioned by dashboards-init).
#
# When to run: after a fresh lab boot + test traffic (the init job provisions
# field-less patterns because it runs before any index has data) or whenever a
# Discover date-histogram crashes with FieldParamType/this.deserialize after a
# mapping change. Idempotent and safe to re-run.
#
# USAGE (from the repo root, on the host; requires curl + jq):
#   bash opensearch/refresh_index_pattern_fields.sh
#   OSD_URL=http://localhost:5601 bash opensearch/refresh_index_pattern_fields.sh
# =============================================================================
set -euo pipefail

OSD_URL="${OSD_URL:-http://localhost:5601}"

# pattern-id | wildcard
PATTERNS=(
  "ocsf-2004-detection-finding|ocsf-1.1.0-2004-detection_finding*"
  "ocsf-4001-dns-activity|ocsf-1.1.0-4001-dns_activity*"
  "ocsf-4002-http-activity|ocsf-1.1.0-4002-http_activity*"
  "ocsf-4005-network-activity|ocsf-1.1.0-4005-network_activity*"
  "ocsf-4007-tls-activity|ocsf-1.1.0-4007-tls_activity*"
  "ocsf-6003-api-activity|ocsf-1.1.0-6003-api_activity*"
  "ocsf-all|ocsf-1.1.0-*"
)
TIMEFIELD="time"

echo "[refresh] waiting for OpenSearch Dashboards at $OSD_URL ..."
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' "$OSD_URL/api/status")" = "200" ]; do
  i=$((i+1))
  if [ "$i" -gt 80 ]; then
    echo "[refresh] Dashboards not ready after $((i*3))s" >&2
    exit 1
  fi
  sleep 3
done
echo "[refresh] Dashboards ready."

for entry in "${PATTERNS[@]}"; do
  PATTERN_ID="${entry%%|*}"
  PATTERN_WILDCARD="${entry#*|}"

  echo "[refresh] fetching live field capabilities for '$PATTERN_WILDCARD' ..."
  fields_json=$(curl -s -X GET \
    "$OSD_URL/api/index_patterns/_fields_for_wildcard?pattern=$PATTERN_WILDCARD" \
    -H "osd-xsrf: true")
  fields=$(echo "$fields_json" | jq -c '.fields')
  count=$(echo "$fields_json" | jq '.fields | length')

  if [ "$count" = "0" ]; then
    echo "[refresh] WARN: no fields reported for '$PATTERN_WILDCARD' - no matching index with data/mapping exists yet. Skipping." >&2
    continue
  fi

  pattern=$(curl -s "$OSD_URL/api/saved_objects/index-pattern/$PATTERN_ID")
  version=$(echo "$pattern" | jq -r '.version')

  payload=$(jq -n \
    --arg fields "$fields" \
    --arg version "$version" \
    --arg title "$PATTERN_WILDCARD" \
    --arg time "$TIMEFIELD" \
    '{version: $version,
      attributes: {title: $title, timeFieldName: $time, fields: $fields}}')

  code=$(curl -s -o /tmp/refresh_resp.json -w "%{http_code}" \
    -X PUT "$OSD_URL/api/saved_objects/index-pattern/$PATTERN_ID" \
    -H "osd-xsrf: true" -H "Content-Type: application/json" -d "$payload")
  if [ "$code" = "409" ]; then
    echo "[refresh] version conflict on '$PATTERN_ID', re-reading and retrying once ..."
    version=$(curl -s "$OSD_URL/api/saved_objects/index-pattern/$PATTERN_ID" | jq -r '.version')
    payload=$(jq -n \
      --arg fields "$fields" \
      --arg version "$version" \
      --arg title "$PATTERN_WILDCARD" \
      --arg time "$TIMEFIELD" \
      '{version: $version,
        attributes: {title: $title, timeFieldName: $time, fields: $fields}}')
    code=$(curl -s -o /tmp/refresh_resp.json -w "%{http_code}" \
      -X PUT "$OSD_URL/api/saved_objects/index-pattern/$PATTERN_ID" \
      -H "osd-xsrf: true" -H "Content-Type: application/json" -d "$payload")
  fi
  echo "[refresh] PUT index-pattern/$PATTERN_ID: HTTP $code"
  cat /tmp/refresh_resp.json
  echo
  [ "$code" = "200" ] || { echo "[refresh] failed to update $PATTERN_ID" >&2; exit 1; }

  updated=$(curl -s "$OSD_URL/api/saved_objects/index-pattern/$PATTERN_ID")
  time_type=$(echo "$updated" | jq -r --arg f "$TIMEFIELD" \
    '.attributes.fields | fromjson | map(select(.name == $f))[0].type // "MISSING"')
  echo "[refresh] cached '$TIMEFIELD' type on '$PATTERN_ID' = $time_type"
done

echo "[refresh] done. Hard-refresh Discover / the dashboards in the browser (Ctrl/Cmd+Shift+R)."
