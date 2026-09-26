"""Small stand-in for the collector endpoints used by the demo labs."""

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Path, Request

inventory_router = APIRouter()

TEST_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "demo-mcp-ping",
        "triggerId": "demo-mcp-ping",
        "name": "demo-mcp-ping",
        "pattern": "ping",
        "field": "body",
        "track": "HTTP",
        "timeWindow": 60,
        "severity": 1,
        "caseSensitive": False,
    },
]


@inventory_router.get("/inventory/{asset}")
async def get_inventory(asset: str = Path(...)):
    return {
        "asset": asset,
        "projectId": "demo-project",
        "assetKnown": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoints": [],
        "mcp_tools": [],
        "mcp_resources": [],
        "mcp_prompts": [],
        "patterns": TEST_PATTERNS,
        "stats": {
            "totalEndpoints": 0,
            "totalMcpTools": 0,
            "totalMcpResources": 0,
            "totalMcpPrompts": 0,
            "totalPatterns": len(TEST_PATTERNS),
        },
    }


_MAX_TRACES = 200
_traces: List[Dict[str, Any]] = []


@inventory_router.post("/traces/{asset}")
async def post_trace(request: Request, asset: str = Path(...)):
    try:
        payload = await request.json()
    except Exception:
        return {"status": "ignored", "reason": "invalid_json"}

    if not payload.get("patternId") or not payload.get("agentKey") or "events" not in payload:
        return {"status": "ignored", "reason": "not_a_trace_payload"}

    record = {
        "id": len(_traces) + 1,
        "asset": asset,
        "receivedAt": datetime.now(timezone.utc).isoformat(),
        "patternId": payload.get("patternId"),
        "agentKey": payload.get("agentKey"),
        "track": payload.get("track"),
        "eventCount": len(payload.get("events") or []),
        "trace": payload,
    }
    _traces.append(record)
    if len(_traces) > _MAX_TRACES:
        del _traces[: len(_traces) - _MAX_TRACES]

    return {"status": "stored", "id": record["id"]}


@inventory_router.get("/traces")
async def list_traces():
    return {"count": len(_traces), "traces": _traces}


_ocsf_batches: List[int] = []


@inventory_router.post("/logs/batch")
async def logs_batch(request: Request):
    body = await request.body()
    _ocsf_batches.append(len(body))
    return {"status": "ok", "receivedBytes": len(body), "batches": len(_ocsf_batches)}


@inventory_router.get("/logs/stats")
async def logs_stats():
    return {"batches": len(_ocsf_batches), "bytes": sum(_ocsf_batches)}


@inventory_router.post("/inventory/{asset}/counters")
async def inventory_counters(request: Request, asset: str = Path(...)):
    return {"status": "ok", "asset": asset}
