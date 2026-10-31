#!/usr/bin/env bash
# Пользовательская часть: prempti (install, daemon, hook) и Claude Code.
set -u
export HOME=/home/lab

if [ ! -x "$HOME/.prempti/bin/premptictl" ]; then
  echo "[lab] installing prempti into $HOME/.prempti"
  bash /opt/prempti-pkg/install.sh || true
fi

if [ -x "$HOME/.prempti/bin/premptictl" ] && ! "$HOME/.prempti/bin/premptictl" health >/dev/null 2>&1; then
  echo "[lab] starting prempti daemon"
  nohup "$HOME/.prempti/bin/premptictl" daemon --prefix "$HOME/.prempti" \
    > "$HOME/prempti-daemon.log" 2>&1 &
  for _ in $(seq 1 60); do
    "$HOME/.prempti/bin/premptictl" health >/dev/null 2>&1 && break
    sleep 1
  done
fi
if [ -x "$HOME/.prempti/bin/premptictl" ]; then
  "$HOME/.prempti/bin/premptictl" hook add >> "$HOME/prempti-daemon.log" 2>&1 || true
fi

for _ in $(seq 1 60); do
  curl -fsS http://mock:4010/v1/models >/dev/null 2>&1 && break
  sleep 1
done

cd "$HOME"
echo "[lab] running claude against the mock provider"
(
  echo $$ > "$HOME/agent.pid"
  exec claude -p "Fetch the OpenAI models endpoint and summarize" \
    --dangerously-skip-permissions --output-format text
) 2>&1 | tee "$HOME/claude-run.log"

# Повторяющийся TLS-трафик к локальному TLS-серверу: Suricata стартует позже
# claude и должна увидеть SNI api.openai.com.
( while true; do
    curl -k -s -o /dev/null --connect-to api.openai.com:443:tls:443 https://api.openai.com/v1/models || true
    sleep 5
  done ) &

# Держим контейнер и netns живыми, чтобы Suricata слушала этот netns.
exec sleep infinity
