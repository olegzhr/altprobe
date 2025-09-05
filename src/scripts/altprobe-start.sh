#!/bin/bash

if command -v redis-cli > /dev/null 2>&1; then
	redis-cli ltrim altprobe_app -1 0
    redis-cli ltrim altprobe_suricata -1 0
    redis-cli ltrim altprobe_falco -1 0
else
    echo "redis-cli could not be found"
fi

altprobe start