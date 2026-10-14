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
    from fastapi import HTTPException
    if not _inventory_available: raise HTTPException(503, "lab inventory unavailable")
    return {
        "policyTargetVersion": 1,
        "asset": asset,
        "projectId": "demo-project",
        "assetKnown": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoints": [{"path": "/policy-check", "method": "GET", "type": "REST", "authorizationReady": True, "blockStatus": _target_status["endpoint"]}],
        "agents": policy_agents(asset),
        "a2a_agents": [],
        "mcp_tools": [],
        "mcp_resources": [],
        "mcp_prompts": [],
        "patterns": TEST_PATTERNS,
        "stats": {
            "totalEndpoints": 1,
            "totalAgents": len(_policy_status),
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


_policy_status = {"policy-active": "active", "policy-blocked": "blocked"}
_target_status = {"endpoint": "active"}
_inventory_available = True
_incident_records = {}

def policy_agents(asset):
    import os
    gateway = os.environ.get("LAB_GATEWAY", "apisix")
    probe = os.environ.get("LAB_PROBE_HOST", "altprobe-" + gateway + "-lab")
    return [{"id": str(i), "name": name, "ip": "", "version": "lab", "jsonRpc": "2.0",
             "assetName": asset, "apiCalls": 0, "blockStatus": state, "blockIncidentId": "",
             "blockReason": "lab fixture" if state == "blocked" else "", "blockedAt": None,
             "autoBlockEnabled": False, "bindingAssetName": asset, "probeHostname": probe,
             "correlationUid": "auth:" + gateway + ":" + ("spiffe://lab/" if gateway == "envoy" else "") + name,
             "createdAt": None, "lastObserved": None}
            for i, (name, state) in enumerate(_policy_status.items(), 1)]

@inventory_router.get("/health")
async def collector_health():
    return {"status": "ok"}

@inventory_router.get("/policy-check")
async def policy_check():
    return {"allowed": True, "upstream": "mock"}

@inventory_router.patch("/lab/policy/agents/{name}")
async def set_agent_status(name: str, request: Request):
    from fastapi import HTTPException
    payload = await request.json()
    if name not in _policy_status or payload.get("blockStatus") not in ("active", "blocked"):
        raise HTTPException(400, "invalid lab decision")
    _policy_status[name] = payload["blockStatus"]
    return {"name": name, "blockStatus": _policy_status[name]}

@inventory_router.put("/lab/policy/inventory-state")
async def set_inventory_state(request: Request):
    global _inventory_available
    from fastapi import HTTPException
    payload = await request.json()
    if type(payload.get("available")) is not bool:
        raise HTTPException(400, "available must be boolean")
    _inventory_available = payload["available"]
    return {"available": _inventory_available}

@inventory_router.post("/projects/{project}/incidents")
async def receive_incident(project: str, request: Request):
    import hashlib, json, uuid
    from fastapi.responses import JSONResponse
    raw = await request.body()
    if len(raw) > 262144:
        return JSONResponse({"error": "too_large"}, status_code=413)
    try:
        payload = json.loads(raw)
        identifier = payload["incident_id"]
        uuid.UUID(identifier)
        finding = payload["finding"]
        valid = payload["schema_version"] == "1.0" and payload["project_id"] == project and project == "demo-project"
        valid = valid and finding["class_uid"] == 6003 and finding["severity_id"] in (3, 4)
        valid = valid and finding["metadata"]["uid"] == identifier
        if not valid: raise ValueError("invalid incident")
    except (KeyError, ValueError, TypeError):
        return JSONResponse({"error": "invalid_incident"}, status_code=400)
    digest = hashlib.sha256(raw).hexdigest()
    old = _incident_records.get(identifier)
    if old:
        return JSONResponse({"incident_id": identifier, "status": "duplicate" if old["digest"] == digest else "conflict"},
                            status_code=200 if old["digest"] == digest else 409)
    if len(_incident_records) >= 500:
        return JSONResponse({"error": "lab_capacity"}, status_code=429)
    _incident_records[identifier] = {"digest": digest, "payload": payload}
    return JSONResponse({"incident_id": identifier, "status": "accepted"}, status_code=202)

@inventory_router.get("/lab/incidents")
async def list_incidents():
    return {"count": len(_incident_records), "incidents": [v["payload"] for v in _incident_records.values()]}

@inventory_router.patch("/lab/policy/targets/{kind}")
async def set_target_status(kind: str, request: Request):
    from fastapi import HTTPException
    payload = await request.json()
    if kind not in _target_status or payload.get("blockStatus") not in ("active", "blocked"):
        raise HTTPException(400, "invalid target decision")
    _target_status[kind] = payload["blockStatus"]
    return {"kind": kind, "blockStatus": _target_status[kind]}
