#!/usr/bin/env python3
"""Generate LLM DNS/TLS traffic from inside the Suricata container."""
import os
import socket
import struct
import subprocess
import time

RUN_ID = os.environ.get("LAB_RUN_ID", "manual")


def dns_query(name: str) -> None:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.rstrip(".").split("."))
    packet = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(packet, ("127.0.0.1", 53))
        sock.recvfrom(512)
    except OSError:
        pass
    finally:
        sock.close()


def tls(name: str) -> None:
    for _ in range(10):
        result = subprocess.run(
            ["curl", "-k", "-sS", "--connect-to", f"{name}:443:127.0.0.1:443",
             f"https://{name}/", "-o", "/dev/null"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        if result.returncode == 0:
            return
        time.sleep(1)


def main() -> None:
    time.sleep(10)
    run_name = f"run-{RUN_ID}.api.anthropic.com"
    dns_query(run_name)
    dns_query("api.anthropic.com")
    dns_query("example.org")
    tls("api.anthropic.com")
    tls("example.org")


if __name__ == "__main__":
    main()
