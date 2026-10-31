#!/usr/bin/env bash
set -u
export HOME=/home/dsh
mkdir -p "$HOME"
chown -R dsh:dsh "$HOME"

TASK="Use the shell to run: curl -k -s --connect-to api.openai.com:443:tls:443 https://api.openai.com/v1/models | head -c 80"

echo "[lab] running dsh headless against the mock provider"
(
  echo $$ > "$HOME/agent.pid"
  exec su -s /bin/bash dsh -c "HOME=/home/dsh DEEPSEEK_API_KEY=mock DEEPSEEK_BASE_URL=http://mock:4010 dsh --profile headless '$TASK'"
) 2>&1 | tee "$HOME/dsh-run.log"

# Keep the container and netns alive for Suricata.
exec sleep infinity
