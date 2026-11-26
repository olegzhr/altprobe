#!/bin/sh
set -eu

RUN_ID="${LAB_RUN_ID:-manual}"
QUERY="run-${RUN_ID}.api.anthropic.com"

# The capture side starts a few seconds after this container. Repeating the
# traffic keeps the Suricata healthcheck (a TLS event) satisfied regardless of
# start order and gives the dashboards a continuous stream of fresh records.
i=0
while [ "$i" -lt 30 ]; do
    if nslookup "$QUERY" dns >/dev/null 2>&1; then break; fi
    i=$((i+1))
    sleep 1
done

while true; do
    nslookup "$QUERY" dns >/dev/null 2>&1 || true
    nslookup api.anthropic.com dns >/dev/null 2>&1 || true
    nslookup example.org dns >/dev/null 2>&1 || true

    curl -k -sS --connect-to api.anthropic.com:443:tls:443 \
        https://api.anthropic.com/v1/models -o /dev/null >/dev/null 2>&1 || true

    printf '' | openssl s_client -connect tls:443 -servername example.org -brief \
        >/dev/null 2>&1 || true

    sleep 20
done
