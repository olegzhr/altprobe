from ..core.models import MCPResponse, MCPRequest


TOOL_DEFINITIONS = [
    {
        "name": "hello",
        "description": "Say hello to someone",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "language": {
                    "type": "string",
                    "enum": ["en", "es", "fr"],
                    "default": "en",
                },
            },
            "required": ["name"],
        },
    },
    {
        "name": "time",
        "description": "Get current server time",
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["12h", "24h", "iso"],
                    "default": "24h",
                }
            },
        },
    },
    {
        "name": "echo",
        "description": "Echo back text",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "repeat": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 5,
                    "default": 1,
                },
            },
            "required": ["text"],
        },
    },
]


class ToolsHandlers:
    def __init__(self, emulator):
        self.emulator = emulator

    def handle_tools_list(self, params: dict, request_id) -> MCPResponse:
        return MCPResponse(
            id=request_id,
            result={"tools": TOOL_DEFINITIONS},
        )

    def _find_tool_def(self, name: str) -> dict | None:
        for t in TOOL_DEFINITIONS:
            if t["name"] == name:
                return t
        return None

    def handle_tools_call(self, params: dict, request_id) -> MCPResponse:
        name = params.get("name")
        args = params.get("arguments", {})

        if name == "hello":
            text = self.emulator.make_greeting(
                args.get("name", "Friend"),
                args.get("language", "en"),
            )
        elif name == "time":
            text = self.emulator.get_current_time(args.get("format", "24h"))
        elif name == "echo":
            text = self.emulator.echo_text(
                args.get("text", ""),
                args.get("repeat", 1),
            )
        else:
            return MCPResponse(
                id=request_id,
                error={"code": -32601, "message": "Tool not found"},
            )

        return MCPResponse(
            id=request_id,
            result={"content": [{"type": "text", "text": text}]},
        )
