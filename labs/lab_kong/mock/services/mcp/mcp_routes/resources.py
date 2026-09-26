from ..core.models import MCPResponse, MCPRequest


class ResourcesHandlers:
    def __init__(self, emulator):
        self.emulator = emulator

    def handle_resources_list(self, params: dict, request_id) -> MCPResponse:
        return MCPResponse(
            id=request_id,
            result={"resources": self.emulator.list_files()},
        )

    def handle_resource_templates(self, params: dict, request_id) -> MCPResponse:
        return MCPResponse(
            id=request_id,
            result={"resourceTemplates": self.emulator.get_templates()},
        )

    def handle_resources_read(self, params: dict, request_id) -> MCPResponse:
        uri = params.get("uri", "")
        try:
            content = self.emulator.read_resource(uri)
        except FileNotFoundError as e:
            return MCPResponse(
                id=request_id,
                error={"code": -32602, "message": str(e)},
            )
        except ValueError as e:
            return MCPResponse(
                id=request_id,
                error={"code": -32602, "message": str(e)},
            )

        return MCPResponse(
            id=request_id,
            result={"contents": [content]},
        )
