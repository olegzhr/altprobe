#!/usr/bin/env bash
set -u
export HOME=/home/dsh
mkdir -p "$HOME"
chown -R dsh:dsh "$HOME"

TASK="Use the shell to run: curl -k -s --connect-to api.openai.com:443:tls:443 https://api.openai.com/v1/models | head -c 80"

echo "[lab] running dsh headless against the mock provider"
su -s /bin/bash dsh -c "HOME=/home/dsh DEEPSEEK_API_KEY=mock DEEPSEEK_BASE_URL=http://mock:4010 dsh --profile headless --json '$TASK'" \
  > "$HOME/dsh-events.jsonl" 2> "$HOME/dsh-run.log" || true
tail -5 "$HOME/dsh-run.log" || true
node /opt/lab/otel_push.js "$HOME/dsh-events.jsonl" "$HOME/dsh-run.log" || true

# Keep the container alive so the lab stays up for inspection.
exec sleep infinity
