#!/usr/bin/env python3
"""Ship Suricata/OpenShell JSONL files to Altprobe Redis lists.

The shipper is deliberately generic: a JSON config lists files, target Redis
keys and optional event-type filters. It does not run any sensor process.
"""
from __future__ import annotations
import argparse
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import redis


@dataclass
class Source:
    name: str
    path: Path
    key: str
    consumer_id: str = ""
    consumer_name: str = ""
    host_name: str = ""
    normalize: str = ""
    event_types: set[str] = field(default_factory=set)
    offset: int = 0
    inode: int | None = None


def load_config(path: Path) -> tuple[dict, list[Source]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    sources = []
    for name, item in document.get("sources", {}).items():
        if not item.get("path"):
            continue
        sources.append(Source(
            name=name,
            path=Path(item["path"]),
            key=item["redis_key"],
            consumer_id=str(item.get("consumer_id", "")),
            consumer_name=str(item.get("consumer_name", "")),
            host_name=str(item.get("host_name", "")),
            normalize=str(item.get("normalize", "")),
            event_types=set(item.get("event_types", [])),
        ))
    return document, sources


def normalize(source: Source, document: dict) -> dict:
    if source.host_name:
        document["hostname"] = source.host_name
        document["host_name"] = source.host_name
    if source.consumer_id:
        agent = document.get("agent")
        if not isinstance(agent, dict):
            agent = {}
        agent["id"] = source.consumer_id
        if source.consumer_name:
            agent["name"] = source.consumer_name
        document["agent"] = agent
    return document


def send(client: redis.Redis, source: Source, line: bytes) -> None:
    line = line.strip()
    if line:
        client.rpush(source.key, line)


def tail_once(client: redis.Redis, source: Source) -> bool:
    try:
        stat = source.path.stat()
    except FileNotFoundError:
        return False
    if source.inode != stat.st_ino or stat.st_size < source.offset:
        source.offset, source.inode = 0, stat.st_ino
    if stat.st_size == source.offset:
        return False
    initial_offset = source.offset
    with source.path.open("rb") as handle:
        handle.seek(source.offset)
        while True:
            line = handle.readline()
            if not line or not line.endswith(b"\n"):
                # The writer may still be appending this record. Retry from its
                # beginning; never commit the position inside a JSONL record.
                break
            try:
                document = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                source.offset = handle.tell()
                continue
            if not isinstance(document, dict):
                print(f"shipper: {source.name}: skipping non-object JSON", file=sys.stderr)
                source.offset = handle.tell()
                continue
            document = normalize(source, document)
            event_type = document.get("event_type")
            if source.event_types and (not isinstance(event_type, str) or event_type not in source.event_types):
                source.offset = handle.tell()
                continue
            send(client, source, json.dumps(document, separators=(",", ":")).encode())
            # Commit each acknowledged record separately. A later Redis error
            # must not replay the already acknowledged prefix of the file.
            source.offset = handle.tell()
    return source.offset != initial_offset


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=os.getenv("SHIPPER_CONFIG", "/etc/shipper/config.json"))
    parser.add_argument("--once", action="store_true", help="drain current files and exit")
    args = parser.parse_args()
    document, sources = load_config(Path(args.config))
    if not sources:
        print("shipper: no sources configured", file=sys.stderr)
        return 2
    client = redis.Redis(
        host=document.get("redis_host", os.getenv("REDIS_HOST", "redis")),
        port=int(document.get("redis_port", os.getenv("REDIS_PORT", "6379"))),
        decode_responses=False,
        socket_timeout=3,
        socket_connect_timeout=3,
    )
    client.ping()
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running:
        changed = False
        for source in sources:
            try:
                changed |= tail_once(client, source)
            except redis.RedisError as error:
                print(f"shipper: redis unavailable: {error}", file=sys.stderr)
                time.sleep(2)
                break
        if args.once:
            break
        if not changed:
            time.sleep(0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
