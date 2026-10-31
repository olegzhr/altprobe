#!/usr/bin/env bash
set -u
export HOME=/home/dsh
export DSH_HOME=/home/dsh/.dsh
mkdir -p "$HOME"
chown -R dsh:dsh "$HOME"

TASK="Use the shell to run: curl -k -s --connect-to api.openai.com:443:tls:443 https://api.openai.com/v1/models | head -c 80"

echo "[lab] preparing the headless profile and the LoongSuite OTel plugin"
su -s /bin/bash dsh -c "HOME=/home/dsh DSH_HOME=$DSH_HOME dsh --profile headless --from-default-profile headless" >/dev/null 2>&1 || true
su -s /bin/bash dsh -c "HOME=/home/dsh DSH_HOME=$DSH_HOME dsh plugin --profile headless add @loongsuite/dsh-plugin" \
  > "$HOME/otel-install.log" 2>&1 || true
tail -3 "$HOME/otel-install.log" 2>/dev/null || true

echo "[lab] running dsh headless: LoongSuite traces + --json logs"
su -s /bin/bash dsh -c "HOME=/home/dsh DSH_HOME=$DSH_HOME DEEPSEEK_API_KEY=mock DEEPSEEK_BASE_URL=http://mock:4010 OTEL_SERVICE_NAME=deepseek-harness OTEL_EXPORTER_OTLP_ENDPOINT=http://altprobe:4318 dsh --profile headless --json '$TASK'" \
  > "$HOME/dsh-events.jsonl" 2> "$HOME/dsh-run.log" || true
tail -5 "$HOME/dsh-run.log" 2>/dev/null || true
node /opt/lab/otel_push.js "$HOME/dsh-events.jsonl" "$HOME/dsh-run.log" || true

# Keep the container alive so the lab stays up for inspection.
exec sleep infinity
