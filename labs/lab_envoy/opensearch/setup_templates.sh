#!/bin/sh
# One-shot init: registers the OCSF index templates (opensearch/templates/)
# with OpenSearch so the daily ocsf-1.1.0-* indices get the correct mappings
# (epoch_millis `time`, keyword/enum fields, nested correlation timelines).
#
# The six OCSF class templates are reused from the previous lab iteration.
#
# Idempotent: PUT to a fixed template name overwrites, so reruns are safe.
set -e

OS_URL="${OS_URL:-http://opensearch:9200}"

http_code() {
  # Numeric HTTP code only (000 on failure); never trips `set -e`.
  curl -s -o "$2" -w "%{http_code}" -m 10 "$1" 2>/dev/null || true
}

echo "[os-templates] waiting for OpenSearch at $OS_URL ..."
i=0
while [ "$(http_code "$OS_URL/_cluster/health" /dev/null)" != "200" ]; do
  i=$((i+1))
  if [ "$i" -gt 120 ]; then
    echo "[os-templates] OpenSearch did not come up in time" >&2
    exit 1
  fi
  sleep 3
done
echo "[os-templates] OpenSearch reachable."

put_template() {
  # $1 = template name, $2 = json file. Retries transient 503/000 while the
  # cluster finishes starting.
  i=0
  while true; do
    code=$(curl -s -o /tmp/resp.json -w "%{http_code}" -m 10 \
      -X PUT "$OS_URL/_index_template/$1" \
      -H "Content-Type: application/json" \
      --data-binary @"$2" 2>/dev/null || true)
    # curl prints 000 on connect failure but exits non-zero; normalise so the
    # retry below actually treats a failed connection as retryable.
    [ -z "$code" ] && code="000"
    if [ "$code" != "503" ] && [ "$code" != "000" ]; then
      break
    fi
    i=$((i+1))
    if [ "$i" -gt 120 ]; then
      echo "[os-templates] OpenSearch API never became ready for $1" >&2
      break
    fi
    sleep 3
  done
  echo "[os-templates] PUT _index_template/$1: HTTP $code"
  [ -f /tmp/resp.json ] && cat /tmp/resp.json
  echo
}

for f in /setup/templates/*.json; do
  name=$(basename "$f" .json)
  put_template "$name" "$f"
done

# Ensure an index exists for every OCSF class pattern, so OpenSearch Dashboards
# does not log "No matching indices found" for classes this lab does not emit
# (e.g. DNS/network/TLS). Empty indices are harmless: the class template gives
# them the right mapping and altprobe still writes its own daily indices.
for idx in ocsf-1.1.0-2004-detection_finding-000001 \
           ocsf-1.1.0-4001-dns_activity-000001 \
           ocsf-1.1.0-4002-http_activity-000001 \
           ocsf-1.1.0-4005-network_activity-000001 \
           ocsf-1.1.0-4007-tls_activity-000001 \
           ocsf-1.1.0-6003-api_activity-000001; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X PUT "$OS_URL/$idx" 2>/dev/null || true)
  [ -z "$code" ] && code="000"
  echo "[os-templates] ensure index $idx: HTTP $code"
done

echo "[os-templates] done."
