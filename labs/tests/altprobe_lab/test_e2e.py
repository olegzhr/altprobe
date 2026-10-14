import unittest

from . import common


def mcp(payload):
    return common.body_json(common.post_json(common.LAB_BASE + "/mcp", payload))


class EndToEndFlow(unittest.TestCase):
    def test_traffic_is_normalized_and_indexed(self):
        mcp({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "hello", "arguments": {"name": "E2E", "language": "en"}}})
        common.get(common.LAB_BASE + "/test-api/status")
        common.get(common.LAB_BASE + "/test-api/hotels/api-key/",
                   headers={"X-API-Key": "demo-api-key"})
        common.post_json(common.LAB_BASE + "/ai-gateway/v1/chat/completions",
                         {"model": "demo-model", "messages": [{"role": "user", "content": "hello"}]})

        observed = common.wait_for(
            lambda: (common.os_count(common.OSCF["http"]) > 0
                     or common.os_count(common.OSCF["api"]) > 0
                     or common.os_count(common.OSCF["detection"]) > 0),
            timeout=30)
        self.assertTrue(observed, "no OCSF documents reached OpenSearch")
