import unittest

from . import common


def mcp(payload):
    return common.body_json(common.post_json(common.LAB_BASE + "/mcp", payload))


class McpFunctions(unittest.TestCase):
    def test_initialize(self):
        result = mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18"}})["result"]
        self.assertEqual(result["serverInfo"]["name"], "hello-server")
        self.assertTrue(result["protocolVersion"])

    def test_tools_list(self):
        tools = mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]
        self.assertTrue({"hello", "time", "echo"} <= {t["name"] for t in tools})

    def test_tool_call_hello(self):
        text = mcp({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "hello", "arguments": {"name": "Ada", "language": "en"}}})["result"]["content"][0]["text"]
        self.assertIn("Hello, Ada!", text)

    def test_tool_call_echo_repeat(self):
        text = mcp({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "abc", "repeat": 2}}})["result"]["content"][0]["text"]
        self.assertEqual(text, "abc abc")

    def test_unknown_tool(self):
        error = mcp({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                     "params": {"name": "no_such_tool"}})["error"]
        self.assertEqual(error["code"], -32601)

    def test_resources(self):
        resources = mcp({"jsonrpc": "2.0", "id": 6, "method": "resources/list"})["result"]["resources"]
        self.assertTrue(any("data.json" in r["uri"] for r in resources))
        templates = mcp({"jsonrpc": "2.0", "id": 7, "method": "resources/templates/list"})["result"]["resourceTemplates"]
        self.assertTrue(templates)
        content = mcp({"jsonrpc": "2.0", "id": 8, "method": "resources/read",
                       "params": {"uri": "file://data.json"}})["result"]["contents"][0]["text"]
        self.assertIn("sample data", content)
        greeting = mcp({"jsonrpc": "2.0", "id": 9, "method": "resources/read",
                        "params": {"uri": "hello://Ada"}})["result"]["contents"][0]["text"]
        self.assertIn("Ada", greeting)

    def test_prompts(self):
        prompts = mcp({"jsonrpc": "2.0", "id": 10, "method": "prompts/list"})["result"]["prompts"]
        self.assertTrue(any(p["name"] == "demo_summary" for p in prompts))
        messages = mcp({"jsonrpc": "2.0", "id": 11, "method": "prompts/get",
                        "params": {"name": "demo_summary", "arguments": {"service": "demo"}}})["result"]["messages"]
        self.assertTrue(messages)

    def test_roots(self):
        roots = mcp({"jsonrpc": "2.0", "id": 12, "method": "roots/list"})["result"]["roots"]
        self.assertTrue(roots)


class RestFunctions(unittest.TestCase):
    def test_status(self):
        self.assertEqual(common.status(common.LAB_BASE + "/test-api/status"), 200)

    def test_token(self):
        token = common.body_json(common.post_form(common.LAB_BASE + "/test-api/token", {
            "username": "demo_user", "password": "pwd12345",
        }))
        self.assertEqual(token["token_type"], "bearer")
        self.assertTrue(token["access_token"])

    def test_hotels_api_key(self):
        hotels = common.body_json(common.get(
            common.LAB_BASE + "/test-api/hotels/api-key/",
            headers={"X-API-Key": "demo-api-key"}))
        self.assertGreaterEqual(len(hotels), 1)

    def test_hotels_basic(self):
        import base64
        auth = base64.b64encode(b"demo_user:pwd12345").decode()
        hotels = common.body_json(common.get(
            common.LAB_BASE + "/test-api/hotels/basic/",
            headers={"Authorization": "Basic " + auth}))
        self.assertGreaterEqual(len(hotels), 1)


class AiGatewayFunctions(unittest.TestCase):
    def test_chat_completions(self):
        response = common.body_json(common.post_json(
            common.LAB_BASE + "/ai-gateway/v1/chat/completions",
            {"model": "demo-model", "messages": [{"role": "user", "content": "hello"}]}))
        self.assertEqual(response["object"], "chat.completion")
        self.assertEqual(response["choices"][0]["message"]["content"], "demo response")

    def test_models(self):
        response = common.body_json(common.get(common.LAB_BASE + "/test-api/v1/models"))
        self.assertTrue(any(m["id"] == "demo-model" for m in response["data"]))
