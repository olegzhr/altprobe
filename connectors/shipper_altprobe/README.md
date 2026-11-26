# shipper_altprobe

Reads line-oriented JSON/JSONL from Suricata and OpenShell and pushes each line
into a Redis list consumed by Altprobe (`SOURCES_<NAME>_REDIS`).

```json
{
  "redis_host": "redis",
  "redis_port": 6379,
  "sources": {
    "suricata": {
      "path": "/var/log/suricata/eve.json",
      "redis_key": "log_suri",
      "consumer_id": "42",
      "consumer_name": "claude-code-dev",
      "host_name": "lab-node",
      "event_types": ["tls", "dns", "flow", "http"]
    }
  }
}
```

Only configured sources are read. Files are tailed from the current offset;
rotation and truncation are detected by inode/size. `--once` drains the current
files and exits, which is useful in CI.

`consumer_id` is the Alertflex `agents.rec_id` (`id`/`consumerId`), not a hostname
or container name; `consumer_name` is the display `client_name`. `host_name` is an
optional network label. `event_types` is an optional allow-list, for example
Suricata EVE records.

Unit checks:

```bash
python3 -m unittest discover -s connectors/shipper_altprobe -p 'test_*.py'
```

## Delivery behavior

The shipper waits for the terminating newline before parsing a JSONL record.
Partial writes keep the offset at the record's beginning. Invalid JSON,
invalid UTF-8 and non-object JSON values are skipped; a malformed event type
cannot stop the other sources. Each successfully acknowledged Redis push
advances the in-memory offset, so a later failure retries the unacknowledged
suffix rather than replaying the acknowledged prefix.

Offsets are not persisted: restarting the shipper replays existing files.
An ambiguous Redis acknowledgement can also duplicate a record. This is not
an exactly-once or durable end-to-end queue. `--once` processes complete lines
currently available and leaves an unfinished tail for a later invocation.

See [OpenShell](../../labs/lab_openshell/README.md) and
[Suricata](../../labs/lab_suricata/README.md).
