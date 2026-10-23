#!/bin/sh
# One-shot init: registers the OCSF index templates (opensearch/templates/)
# with OpenSearch so the daily ocsf-1.1.0-* indices get the correct mappings
# (epoch_millis `time`, keyword/enum fields, nested correlation timelines).
#
# The four remaining OCSF class templates are reused from the previous lab
# iteration. DNS/network/TLS templates were retired with their producers.
#
# Idempotent: PUT to a fixed template name overwrites, so reruns are safe.
set -e

# Resolve the data directory relative to this script so it works both when the
# directory is mounted at /setup (labs) and when run in place (connectors).
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DATA_DIR="${DATA_DIR:-$HERE}"

OS_URL="${OS_URL:-http://opensearch:9200}"

# Authentication and TLS for a security-enabled OpenSearch.
#   OS_USER / OS_PWD     - Basic-auth credentials (leave empty when the
#                          security plugin is disabled / anonymous access)
#   OS_INSECURE=true     - skip TLS certificate verification (self-signed cert)
OS_USER="${OS_USER:-}"
OS_PWD="${OS_PWD:-}"
OS_INSECURE="${OS_INSECURE:-false}"

# Wrap curl so every call carries the configured auth/TLS settings.
curl() {
  if [ "$OS_INSECURE" = "true" ]; then set -- -k "$@"; fi
  if [ -n "$OS_USER" ]; then command curl -u "$OS_USER:$OS_PWD" "$@"; else command curl "$@"; fi
}

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

echo "[os-templates] deleting templates for retired OCSF classes ..."
for name in ocsf_dns_activity_template ocsf_network_activity_template ocsf_tls_activity_template; do
  code=$(curl -s -o /tmp/resp.json -w "%{http_code}" -m 10 \
    -X DELETE "$OS_URL/_index_template/$name" 2>/dev/null || true)
  [ -z "$code" ] && code="000"
  case "$code" in
    200|404)
      echo "[os-templates] DELETE stale _index_template/$name: HTTP $code"
      ;;
    *)
      echo "[os-templates] DELETE stale _index_template/$name: HTTP $code" >&2
      cat /tmp/resp.json >&2
      echo >&2
      ;;
  esac
done

for f in "$DATA_DIR"/templates/*.json; do
  name=$(basename "$f" .json)
  put_template "$name" "$f"
done

# Ensure an index exists for every remaining OCSF class pattern, so OpenSearch
# Dashboards does not log "No matching indices found" for classes that have not
# emitted data yet (e.g. vulnerability findings before the first SBOM scan).
# Empty indices are harmless: the class template gives them the right mapping
# and altprobe still writes its own daily indices.
for idx in ocsf-1.1.0-2002-vulnerability_finding-000001 \
           ocsf-1.1.0-2004-detection_finding-000001 \
           ocsf-1.1.0-4002-http_activity-000001 \
           ocsf-1.1.0-6003-api_activity-000001; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 -X PUT "$OS_URL/$idx" 2>/dev/null || true)
  [ -z "$code" ] && code="000"
  echo "[os-templates] ensure index $idx: HTTP $code"
done

echo "[os-templates] done."
