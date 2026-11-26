#!/bin/sh
# One-shot recovery for a stale OpenSearch Dashboards migration index.
#
# If OSD starts before OpenSearch is ready it can create an empty .kibana_1
# index whose saved-objects migration never completes. OSD then logs
# "Another OpenSearch Dashboards instance appears to be migrating the index"
# and answers 503 on /api/status forever, which stalls dashboards-init.
#
# Deleting that empty index lets OSD re-run the migration. A populated index
# (real saved objects / dashboards) is never deleted.
set -e

OS_URL="${OS_URL:-http://opensearch:9200}"
KIBANA_INDEX="${KIBANA_INDEX:-.kibana_1}"

# Authentication and TLS for a security-enabled OpenSearch.
#   OS_USER / OS_PWD     - Basic-auth credentials (empty = security plugin off)
#   OS_INSECURE=true     - skip TLS certificate verification (self-signed cert)
OS_USER="${OS_USER:-}"
OS_PWD="${OS_PWD:-}"
OS_INSECURE="${OS_INSECURE:-false}"

# Wrap curl so every call carries the configured auth/TLS settings.
curl() {
  if [ "$OS_INSECURE" = "true" ]; then set -- -k "$@"; fi
  if [ -n "$OS_USER" ]; then command curl -u "$OS_USER:$OS_PWD" "$@"; else command curl "$@"; fi
}

echo "[osd-recover] waiting for OpenSearch at $OS_URL ..."
i=0
while :; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$OS_URL/_cluster/health" 2>/dev/null || true)
  [ -z "$code" ] && code="000"
  [ "$code" = "200" ] && break
  i=$((i+1))
  if [ "$i" -gt 120 ]; then
    echo "[osd-recover] OpenSearch did not come up in time" >&2
    exit 1
  fi
  sleep 3
done
echo "[osd-recover] OpenSearch reachable."

count=$(curl -s -m 10 "$OS_URL/$KIBANA_INDEX/_count" 2>/dev/null \
  | sed -n 's/.*"count":\([0-9][0-9]*\).*/\1/p' || true)

if [ -n "$count" ] && [ "$count" -eq 0 ]; then
  echo "[osd-recover] $KIBANA_INDEX is empty (count=0) -> removing stale migration state."
  curl -s -m 10 -X DELETE "$OS_URL/$KIBANA_INDEX" || true
  echo
else
  echo "[osd-recover] $KIBANA_INDEX absent or populated (count=${count:-absent}); nothing to do."
fi
