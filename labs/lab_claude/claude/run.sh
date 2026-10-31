#!/usr/bin/env bash
# root-часть: готовим HOME и уходим в непривилегированного пользователя
set -eu
export HOME=/home/lab
mkdir -p "$HOME"
chown -R lab:lab "$HOME"
exec su -s /bin/bash lab -c 'HOME=/home/lab exec bash /opt/lab/agent.sh'
