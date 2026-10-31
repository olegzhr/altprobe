#!/bin/sh
set -u
echo "--- falco rules check ---"
timeout 12 falco -o engine.kind=modern_ebpf -o log_stderr=true -o file_output.enabled=false \
  -o stdout_output.enabled=false -c /etc/falco/falco.yaml 2>&1 \
  | grep -Ei 'Loading rules|rules.local|error|Runtime error' | head -12
