import unittest

from . import common


class GatewaySmoke(unittest.TestCase):
    def test_mcp_ping(self):
        response = common.body_json(common.post_json(
            common.LAB_BASE + "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        self.assertEqual(response["result"], "pong")

    def test_mcp_tool_call(self):
        response = common.body_json(common.post_json(common.LAB_BASE + "/mcp", {
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "hello", "arguments": {"name": "Demo", "language": "en"}},
        }))
        self.assertIn("Hello, Demo!", response["result"]["content"][0]["text"])

    def test_rest_status(self):
        self.assertEqual(common.status(common.LAB_BASE + "/test-api/status"), 200)

    def test_rest_token_and_profile(self):
        token = common.body_json(common.post_form(common.LAB_BASE + "/test-api/token", {
            "username": "demo_user", "password": "pwd12345",
        }))["access_token"]
        self.assertTrue(token)
        profile = common.body_json(common.get(
            common.LAB_BASE + "/test-api/users/me/",
            headers={"Authorization": "Bearer " + token}))
        self.assertEqual(profile["username"], "demo_user")

    def test_rest_api_key(self):
        hotels = common.body_json(common.get(
            common.LAB_BASE + "/test-api/hotels/api-key/",
            headers={"X-API-Key": "demo-api-key"}))
        self.assertGreaterEqual(len(hotels), 1)

    def test_ai_gateway(self):
        response = common.body_json(common.post_json(
            common.LAB_BASE + "/ai-gateway/v1/chat/completions",
            {"model": "demo-model", "messages": [{"role": "user", "content": "hello"}]}))
        self.assertEqual(response["choices"][0]["message"]["content"], "demo response")


class OpenSearchSmoke(unittest.TestCase):
    def test_events_reach_opensearch(self):
        common.post_json(common.LAB_BASE + "/mcp",
                         {"jsonrpc": "2.0", "id": 10, "method": "ping"})
        common.get(common.LAB_BASE + "/test-api/status")
        common.post_json(common.LAB_BASE + "/ai-gateway/v1/chat/completions",
                         {"model": "demo-model", "messages": [{"role": "user", "content": "hello"}]})
        indexed = common.wait_for(
            lambda: common.os_count(common.OSCF["http"]) > 0 or common.os_count(common.OSCF["api"]) > 0,
            timeout=30)
        self.assertTrue(indexed, "no OCSF HTTP/API documents reached OpenSearch")
