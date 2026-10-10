from ..core.models import MCPRequest, MCPResponse
from ..core.emulator import ResourceEmulator
from .tools import ToolsHandlers
from .resources import ResourcesHandlers


class MCPServer:
    PROTOCOL_VERSION = "2025-06-18"

    def __init__(self, data_dir: str = "./data"):
        self.emulator = ResourceEmulator(data_dir)
        self.tools = ToolsHandlers(self.emulator)
        self.resources = ResourcesHandlers(self.emulator)
        self.server_info = {
            "name": "hello-server",
            "version": "1.3.0",
        }

    def handle_request(self, request: MCPRequest):
        method = request.method
        params = request.params
        req_id = request.id

        if method == "initialize":
            return MCPResponse(
                id=req_id,
                result={
                    "protocolVersion": params.get("protocolVersion", self.PROTOCOL_VERSION),
                    "capabilities": {
                        "tools": {},
                        "resources": {
                            "subscribe": False,
                            "listChanged": False,
                        },
                    },
                    "serverInfo": self.server_info,
                },
            )

        if method == "notifications/initialized":
            return None

        if method == "ping":
            return MCPResponse(id=req_id, result="pong")

        if method == "tools/list":
            return self.tools.handle_tools_list(params, req_id)

        if method == "tools/call":
            return self.tools.handle_tools_call(params, req_id)

        if method == "resources/list":
            return self.resources.handle_resources_list(params, req_id)

        if method == "resources/templates/list":
            return self.resources.handle_resource_templates(params, req_id)

        if method == "resources/read":
            return self.resources.handle_resources_read(params, req_id)

        if method == "prompts/list":
            return MCPResponse(
                id=req_id,
                result={
                    "prompts": [
                        {
                            "name": "demo_summary",
                            "description": "Demo prompt for a short service summary",
                            "arguments": [{"name": "service", "required": True}],
                        }
                    ]
                },
            )

        if method == "prompts/get":
            return MCPResponse(
                id=req_id,
                result={
                    "description": "Demo prompt content",
                    "messages": [
                        {
                            "role": "user",
                            "content": {
                                "type": "text",
                                "text": params.get("prompt", "Summarize service status"),
                            },
                        }
                    ],
                },
            )

        if method == "roots/list":
            return MCPResponse(
                id=req_id,
                result={
                    "roots": [
                        {
                            "uri": "file:///workspace",
                            "name": "Synthetic Workspace",
                        }
                    ]
                },
            )

        return MCPResponse(
            id=req_id,
            error={"code": -32601, "message": "Method not found"},
        )
