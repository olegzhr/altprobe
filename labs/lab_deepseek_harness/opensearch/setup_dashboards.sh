#!/bin/sh
# One-shot init: provisions the OpenSearch Dashboards saved objects from
# opensearch/dashboards/ so results are one click away after a fresh lab start.
# Idempotent: each call uses overwrite=true, so reruns overwrite the same
# objects rather than creating duplicates.
#
# Includes gateway/API findings plus Falco and Suricata DNS, TLS, IP flows
# and dedicated direct-AI correlation. No MaxMind or geographic maps.
set -e

# Resolve the data directory relative to this script so it works both when the
# directory is mounted at /setup (labs) and when run in place (connectors).
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DATA_DIR="${DATA_DIR:-$HERE}"

OSD_URL="${OSD_URL:-http://opensearch-dashboards:5601}"

# Authentication and TLS for a security-enabled OpenSearch Dashboards.
#   OSD_USER / OSD_PWD   - Basic-auth credentials (empty = security disabled)
#   OSD_INSECURE=true    - skip TLS certificate verification (self-signed cert)
# Defaults fall back to the OpenSearch credentials when unset.
OSD_USER="${OSD_USER:-${OS_USER:-}}"
OSD_PWD="${OSD_PWD:-${OS_PWD:-}}"
OSD_INSECURE="${OSD_INSECURE:-${OS_INSECURE:-false}}"

# Wrap curl so every call carries the configured auth/TLS settings.
curl() {
  if [ "$OSD_INSECURE" = "true" ]; then set -- -k "$@"; fi
  if [ -n "$OSD_USER" ]; then command curl -u "$OSD_USER:$OSD_PWD" "$@"; else command curl "$@"; fi
}

http_code() {
  # Numeric HTTP code only (000 on failure); never trips `set -e`.
  curl -s -o "$2" -w "%{http_code}" -m 10 "$1" 2>/dev/null || true
}

echo "[dashboards-init] waiting for OpenSearch Dashboards at $OSD_URL ..."
i=0
while [ "$(http_code "$OSD_URL/api/status" /dev/null)" != "200" ]; do
  i=$((i+1))
  if [ "$i" -gt 120 ]; then
    echo "[dashboards-init] Dashboards did not come up in time" >&2
    exit 1
  fi
  sleep 3
done
echo "[dashboards-init] Dashboards reachable."

put_object() {
  # $1 = type/id, $2 = json file. overwrite=true makes reruns idempotent
  # (a fresh POST to an existing id 409s otherwise). The saved-objects API can
  # still answer 503 right after /api/status comes up, so retry until ready.
  i=0
  while true; do
    code=$(curl -s -o /tmp/resp.json -w "%{http_code}" -m 30 \
      -X POST "$OSD_URL/api/saved_objects/$1?overwrite=true" \
      -H "Content-Type: application/json" -H "osd-xsrf: true" \
      --data-binary @"$2" 2>/dev/null || true)
    [ -z "$code" ] && code="000"
    if [ "$code" != "503" ] && [ "$code" != "000" ]; then
      break
    fi
    i=$((i+1))
    if [ "$i" -gt 120 ]; then
      echo "[dashboards-init] saved-objects API never became ready for $1" >&2
      break
    fi
    sleep 3
  done
  case "$code" in 200|201) ;; *) cat /tmp/resp.json >&2; exit 1;; esac
  echo "[dashboards-init] PUT $1: HTTP $code"
  echo
}

delete_object() {
  # $1 = type/id. Missing objects are fine: this keeps reruns idempotent and
  # removes dashboards from older lab bundles that are no longer shipped.
  code=$(curl -s -o /tmp/resp.json -w "%{http_code}" -m 30 \
    -X DELETE "$OSD_URL/api/saved_objects/$1" \
    -H "osd-xsrf: true" 2>/dev/null || true)
  [ -z "$code" ] && code="000"
  case "$code" in
    200|404)
      echo "[dashboards-init] DELETE stale $1: HTTP $code"
      ;;
    *)
      echo "[dashboards-init] DELETE stale $1: HTTP $code" >&2
      cat /tmp/resp.json >&2
      echo >&2
      ;;
  esac
}

echo "[dashboards-init] deleting dashboards and visualizations removed from this bundle ..."
for oid in \
  "dashboard/altprobe-agent-visibility" \
  "dashboard/ocsf-agents-services-flow" \
  "dashboard/ocsf-incidents-whowhatwhy" \
  "dashboard/e230ce50-6c32-11f1-a88c-61f8c15a044f" \
  "search/agent-data-handling-incidents" \
  "visualization/ocsf-agents-services-flow" \
  "visualization/ocsf-api-findings-incidents-600302" \
  "visualization/ocsf-incidents-whowhatwhy-avg-correlation-score" \
  "visualization/ocsf-incidents-whowhatwhy-distinct-agents-involved" \
  "visualization/ocsf-incidents-whowhatwhy-incidents-600302" \
  "visualization/ocsf-incidents-whowhatwhy-incidents-by-agent" \
  "visualization/ocsf-incidents-whowhatwhy-incidents-by-severity" \
  "visualization/ocsf-incidents-whowhatwhy-incidents-over-time" \
  "visualization/ocsf-incidents-whowhatwhy-services-touched" \
  "visualization/e230ce50-6c32-11f1-a88c-61f8c15a044f-distinct-dst-ips" \
  "visualization/e230ce50-6c32-11f1-a88c-61f8c15a044f-distinct-src-ips" \
  "visualization/e230ce50-6c32-11f1-a88c-61f8c15a044f-network-flows" \
  "visualization/e230ce50-6c32-11f1-a88c-61f8c15a044f-top-destinations-by-traffic-bytes" \
  "visualization/e230ce50-6c32-11f1-a88c-61f8c15a044f-top-source-countries-geoip" \
  "visualization/e230ce50-6c32-11f1-a88c-61f8c15a044f-traffic-volume-over-time" \
  "dashboard/ocsf-network-activity-flows-geo" \
  "visualization/ocsf-network-activity-flows-geo-network-flows" \
  "visualization/ocsf-network-activity-flows-geo-distinct-src-ips" \
  "visualization/ocsf-network-activity-flows-geo-distinct-dst-ips" \
  "visualization/ocsf-network-activity-flows-geo-world-map" \
  "visualization/ocsf-network-activity-flows-geo-ip-flows-sankey" \
  "visualization/ocsf-network-activity-flows-geo-top-destinations-by-traffic-bytes" \
  "visualization/ocsf-network-activity-flows-geo-top-source-countries-geoip" \
  "visualization/ocsf-network-activity-flows-geo-traffic-volume-over-time"
do
  delete_object "$oid"
done

echo "[dashboards-init] creating index patterns ..."
for f in "$DATA_DIR"/dashboards/index_patterns/*.json; do
  pid=$(basename "$f" .json)
  put_object "index-pattern/$pid" "$f"
done

echo "[dashboards-init] importing saved searches, then visualizations, then dashboards ..."
# Import in dependency order: the panels a dashboard references (searches and
# visualizations) are created before the dashboards themselves, so a dashboard
# opened mid-import never reports an unresolved panel reference.
for otype in search visualization dashboard; do
  for f in "$DATA_DIR"/dashboards/saved_objects/${otype}__*.json; do
    [ -e "$f" ] || continue
    base=$(basename "$f" .json)
    oid=${base#*__}
    put_object "$otype/$oid" "$f"
  done
done

echo "[dashboards-init] done. Open http://localhost:5601/app/dashboards (search for \"OCSF\" / \"Altprobe\")."
