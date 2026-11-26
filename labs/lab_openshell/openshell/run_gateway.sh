#!/usr/bin/env bash
# Start a real OpenShell gateway for the lab. Linux/WSL2 only.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_DIR="$LAB_DIR/.local"
TLS_DIR="$LOCAL_DIR/tls"
SUPERVISOR="$LOCAL_DIR/openshell-supervisor"
GATEWAY_IMAGE="${OPENSHELL_GATEWAY_IMAGE:-ghcr.io/nvidia/openshell/gateway:latest}"
SUPERVISOR_IMAGE="${OPENSHELL_SUPERVISOR_IMAGE:-ghcr.io/nvidia/openshell/supervisor:latest}"
PORT="${OPENSHELL_PORT:-8080}"

for command in docker curl openssl; do
  command -v "$command" >/dev/null || { echo "missing: $command" >&2; exit 1; }
done

mkdir -p "$LOCAL_DIR" "$TLS_DIR"
if [ ! -x "$SUPERVISOR" ]; then
  name="openshell-supervisor-extract-$$"
  docker create --name "$name" "$SUPERVISOR_IMAGE" >/dev/null
  docker cp "$name:/openshell-supervisor" "$SUPERVISOR"
  docker rm "$name" >/dev/null
  chmod 0755 "$SUPERVISOR"
fi
if [ ! -f "$TLS_DIR/ca.crt" ]; then
  docker run --rm --user 0 -v "$TLS_DIR:/tls" "$GATEWAY_IMAGE" \
    generate-certs --output-dir /tls --server-san 127.0.0.1
fi

docker rm -f openshell-gateway >/dev/null 2>&1 || true
docker run -d --name openshell-gateway \
  --user 0 --group-add 0 \
  -p "127.0.0.1:${PORT}:8080" \
  -v openshell-state:/var/openshell \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$SUPERVISOR:/opt/openshell-supervisor:ro" \
  -v "$TLS_DIR:/tls:ro" \
  -e OPENSHELL_COMPUTE_DRIVER=docker \
  -e OPENSHELL_GRPC_ENDPOINT="https://127.0.0.1:${PORT}" \
  -e OPENSHELL_DOCKER_SUPERVISOR_BIN=/opt/openshell-supervisor \
  -e OPENSHELL_DB_URL=sqlite:/var/openshell/openshell.db \
  -e OPENSHELL_LOCAL_TLS_DIR=/tls \
  -e OPENSHELL_TLS_CERT=/tls/server/tls.crt \
  -e OPENSHELL_TLS_KEY=/tls/server/tls.key \
  -e OPENSHELL_TLS_CLIENT_CA=/tls/ca.crt \
  -e OPENSHELL_ENABLE_MTLS_AUTH=true \
  "$GATEWAY_IMAGE"

sleep 4
docker ps --filter name=openshell-gateway --format '{{.Status}}'

if command -v openshell >/dev/null; then
  CERT_HOME="${HOME}/.config/openshell/gateways/local/mtls"
  mkdir -p "$CERT_HOME"
  cp "$TLS_DIR/ca.crt" "$TLS_DIR/client/tls.crt" "$TLS_DIR/client/tls.key" "$CERT_HOME/"
  openshell gateway remove local >/dev/null 2>&1 || true
  openshell gateway add "https://127.0.0.1:${PORT}" --local --name local
  openshell status
else
  echo "openshell CLI not found; install it, then run:"
  echo "  openshell gateway add https://127.0.0.1:${PORT} --local --name local"
fi
