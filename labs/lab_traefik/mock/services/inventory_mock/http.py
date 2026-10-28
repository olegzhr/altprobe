"""Small stand-in for the collector endpoints used by the demo labs."""

import base64
import gzip
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Path, Request, HTTPException

inventory_router = APIRouter()

TEST_PATTERNS: List[Dict[str, Any]] = [{
    "id": "demo-mcp-ping", "name": "demo-mcp-ping", "source": "proxy", "track": "*",
    "window_sec": 60, "min_events": 2, "cooldown_sec": 30, "pattern_severity": 1,
    "order_strict": False, "conditions": [{"body_contains": "ping", "case_sensitive": False}],
}]


@inventory_router.get("/inventory/{asset}")
async def get_inventory(asset: str = Path(...)):
    return {
        "asset": asset, "projectId": "demo-project", "assetKnown": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoints": [], "agents": [], "a2a_agents": [],
        "mcp_tools": [], "mcp_resources": [], "mcp_prompts": [],
        "patterns": TEST_PATTERNS,
        "stats": {"totalEndpoints": 0, "totalAgents": 0, "totalPatterns": len(TEST_PATTERNS)},
    }


_MAX_TRACES = 200
_traces: List[Dict[str, Any]] = []


@inventory_router.post("/traces/{asset}")
async def post_trace(request: Request, asset: str = Path(...)):
    try:
        payload = await request.json()
    except Exception:
        return {"status": "ignored", "reason": "invalid_json"}

    if payload.get("resourceSpans"):
        spans = [span for resource in payload["resourceSpans"] for scope in resource.get("scopeSpans", []) for span in scope.get("spans", [])]
        attrs = {a["key"]: a.get("value", {}).get("stringValue", "") for span in spans for a in span.get("attributes", [])}
        payload = {"patternId": attrs.get("alertflex.trigger.id"), "agentKey": attrs.get("alertflex.agent.key"), "events": spans, "track": "HTTP", "otlp": payload}
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
# Test-only receipts are in memory. Production uses transactional MySQL receipts.
_log_receipts = {}


@inventory_router.post("/logs")
@inventory_router.post("/logs/batch")
async def logs_batch(request: Request):
    body = await request.body()
    _ocsf_batches.append(len(body))
    try:
        envelope = json.loads(body)
        compressed = base64.b64decode(envelope["text_sample"], validate=True)
        if len(compressed) > 5 * 1024 * 1024: raise ValueError("oversized compressed batch")
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            decoded = stream.read(25 * 1024 * 1024 + 1)
        if len(decoded) > 25 * 1024 * 1024: raise ValueError("oversized decoded batch")
        batch = json.loads(decoded)
        if batch.get("delivery_version") != 1: raise ValueError("delivery_version 1 required")
        records = batch["logs"]
        if not isinstance(records, list) or len(records) > 10000: raise ValueError("invalid records")
        seen = set()
        for record in records:
            identity = record["id"]
            if str(uuid.UUID(identity)) != identity or identity in seen: raise ValueError("invalid record ID")
            seen.add(identity)
    except (ValueError, KeyError, TypeError, OSError, EOFError) as error:
        raise HTTPException(400, "invalid log delivery envelope") from error
    acknowledgements = []
    for record in records:
        identity = record["id"]
        try:
            event = json.loads(record["event"]) if isinstance(record.get("event"), str) else record.get("event")
            request_data = event.get("http_request") if isinstance(event, dict) else None
            valid = isinstance(request_data, dict) and isinstance(request_data.get("url"), str) and isinstance(request_data.get("http_method"), str) and bool(request_data.get("http_method"))
        except (ValueError, TypeError):
            valid = False
        status = "rejected"
        if valid:
            digest = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            scope = (envelope.get("asset"), envelope.get("host"), identity)
            previous = _log_receipts.get(scope)
            if previous is None or previous == digest:
                _log_receipts[scope] = digest
                status = "accepted"
        acknowledgements.append({"id": identity, "status": status})
    return {"ack_version": 1, "records": acknowledgements}



@inventory_router.get("/logs/stats")
async def logs_stats():
    return {"batches": len(_ocsf_batches), "bytes": sum(_ocsf_batches)}


@inventory_router.post("/inventory/{asset}/counters")
async def inventory_counters(request: Request, asset: str = Path(...)):
    return {"status": "ok", "asset": asset}


@inventory_router.get("/health")
async def collector_health():
    return {"status": "ok"}
