#!/usr/bin/env python3
"""Unit checks for connectors/shipper_altprobe/normalisation."""
import importlib.util
import json
import sys
import tempfile
import unittest
from unittest.mock import Mock
from pathlib import Path

MODULE = Path(__file__).with_name("shipper.py")
spec = importlib.util.spec_from_file_location("shipper", MODULE)
shipper = importlib.util.module_from_spec(spec)
sys.modules["shipper"] = shipper
spec.loader.exec_module(shipper)


class ShipperTest(unittest.TestCase):
    def test_partial_record_and_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            source = shipper.Source("test", path, "events")
            client = Mock()
            path.write_bytes(b'{"a":')
            shipper.tail_once(client, source)
            self.assertEqual(source.offset, 0)
            client.rpush.assert_not_called()
            with path.open("ab") as handle:
                handle.write(b'1}\n{"a":2}\n{"a":')
            shipper.tail_once(client, source)
            self.assertEqual(client.rpush.call_count, 2)
            with path.open("ab") as handle:
                handle.write(b'3}\n')
            shipper.tail_once(client, source)
            self.assertEqual(client.rpush.call_count, 3)
            path.rename(path.with_suffix(".old"))
            path.write_bytes(b'{"new":1}\n')
            shipper.tail_once(client, source)
            self.assertEqual(client.rpush.call_count, 4)

    def test_bad_records_do_not_stop_next_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b'[]\nnull\n"text"\n42\n{bad}\n\xff\n'
                             b'{"output_fields":{"evt.type":[]}}\n'
                             b'{"event_type":[]}\n{"event_type":"tls"}\n')
            source = shipper.Source("test", path, "events", host_name="node", event_types={"tls"})
            client = Mock()
            shipper.tail_once(client, source)
            client.rpush.assert_called_once()
            self.assertEqual(json.loads(client.rpush.call_args.args[1])["event_type"], "tls")

    def test_redis_retry_starts_at_unacknowledged_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b'{"a":1}\n{"a":2}\n')
            source = shipper.Source("test", path, "events")
            client = Mock()
            client.rpush.side_effect = [1, shipper.redis.ConnectionError("offline")]
            with self.assertRaises(shipper.redis.ConnectionError):
                shipper.tail_once(client, source)
            self.assertEqual(source.offset, len(b'{"a":1}\n'))
            client.rpush.side_effect = None
            shipper.tail_once(client, source)
            self.assertEqual(json.loads(client.rpush.call_args.args[1]), {"a": 2})

    def test_agent_identity_is_stamped(self):
        source = shipper.Source("test", Path("/none"), "events", consumer_id="42", consumer_name="claude-code")
        document = shipper.normalize(source, {"event_type": "tls", "agent": {"id": "old"}})
        self.assertEqual(document["agent"], {"id": "42", "name": "claude-code"})

    def test_load_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"sources": {
                "suricata": {"path": "/tmp/eve.json", "redis_key": "log_suri",
                             "event_types": ["tls", "flow"]}}}), encoding="utf-8")
            document, sources = shipper.load_config(config)
            self.assertEqual(document["sources"]["suricata"]["redis_key"], "log_suri")
            self.assertEqual(sources[0].event_types, {"tls", "flow"})


if __name__ == "__main__":
    unittest.main()
