#!/usr/bin/env bash
set -u
export HOME=/home/codex
export CODEX_HOME=/home/codex/.codex
mkdir -p "$CODEX_HOME"
cp /opt/lab/config.toml "$CODEX_HOME/config.toml"
chown -R codex:codex "$HOME"

TASK="Use the shell to run: curl -k -s --connect-to api.openai.com:443:tls:443 https://api.openai.com/v1/models | head -c 80"

echo "[lab] running codex exec against the mock Responses API"
su -s /bin/bash codex -c "HOME=/home/codex CODEX_HOME=$CODEX_HOME OPENAI_API_KEY=mock codex exec --skip-git-repo-check '$TASK'" \
  2>&1 | tee "$HOME/codex-run.log"

exec sleep infinity
