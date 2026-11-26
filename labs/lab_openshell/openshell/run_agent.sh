#!/usr/bin/env bash
# Build the LangChain workload image and launch it in a real OpenShell sandbox.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${OPENSHELL_AGENT_IMAGE:-openshell-langchain:lab}"
NAME="${OPENSHELL_SANDBOX_NAME:-ai-client}"

command -v docker >/dev/null || { echo "missing: docker" >&2; exit 1; }
command -v openshell >/dev/null || { echo "missing: openshell CLI" >&2; exit 1; }

docker build -t "$IMAGE" "$HERE"
openshell sandbox delete "$NAME" >/dev/null 2>&1 || true
openshell sandbox create --name "$NAME" --from "$IMAGE" --detach -- python /app/client.py
sleep 3
openshell sandbox list | tail -5
echo
echo "OCSF log:"
echo "  openshell sandbox exec -n $NAME --no-login-shell -- cat /tmp/openshell-ocsf.jsonl"
