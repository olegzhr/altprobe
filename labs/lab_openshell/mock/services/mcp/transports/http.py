import os
import json
import asyncio
import sys

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from ..core.models import MCPRequest
from ..mcp_routes.server import MCPServer

_data_dir = os.environ.get("MCP_DATA_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"))
_server = MCPServer(data_dir=_data_dir)

mcp_router = APIRouter()


class MCPHttpRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict = {}


@mcp_router.get("/")
async def root():
    return {
        "status": "ok",
        "server": _server.server_info["name"],
        "version": _server.server_info["version"],
        "mcp_endpoint": "/mcp",
    }


@mcp_router.get("/health")
async def health():
    from datetime import datetime
    return {"status": "healthy", "time": datetime.now().isoformat()}


@mcp_router.post("/mcp")
async def mcp_handler(body: MCPHttpRequest):
    mcp_req = MCPRequest(
        jsonrpc=body.jsonrpc,
        id=body.id,
        method=body.method,
        params=body.params or {},
    )
    resp = _server.handle_request(mcp_req)
    if resp is None:
        return JSONResponse(content=None, status_code=202)
    return JSONResponse(content=resp.to_dict())


@mcp_router.get("/sse")
async def sse_handler(request: Request):
    async def event_generator():
        yield {"event": "endpoint", "data": "/mcp"}
        while True:
            try:
                await asyncio.sleep(30)
                yield {"event": "ping", "data": ""}
            except asyncio.CancelledError:
                break

    return EventSourceResponse(event_generator())
