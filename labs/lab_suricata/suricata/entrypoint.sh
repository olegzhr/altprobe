#!/bin/sh
set -eu

IFACE=""
for _ in $(seq 1 60); do
    for dev in /sys/class/net/br-*; do
        [ -e "$dev" ] || continue
        name=$(basename "$dev")
        if ip -4 addr show dev "$name" 2>/dev/null | grep -q '172\.28\.0\.1/'; then
            IFACE="$name"
            break
        fi
    done
    [ -n "$IFACE" ] && break
    sleep 1
done

if [ -z "$IFACE" ]; then
    echo "lab bridge for 172.28.0.0/24 not found" >&2
    exit 1
fi

echo "capturing on $IFACE"
exec suricata -i "$IFACE" -v
