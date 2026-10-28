"""Deterministic transport fixtures in the full demo mock; never emulates a gateway."""
import asyncio
import os

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

gateway_lab_router = APIRouter()


@gateway_lab_router.get('/lab/profile')
async def profile():
    return {'gateway': os.environ['LAB_GATEWAY'], 'profile': os.environ['LAB_PROFILE']}


@gateway_lab_router.post('/lab/echo')
async def echo(request: Request):
    return {'payload': await request.json(), 'apikey_forwarded': bool(request.headers.get('apikey'))}


@gateway_lab_router.get('/lab/stream')
async def stream():
    async def chunks():
        for value in ('first', 'second', '[DONE]'):
            yield 'data: ' + value + '\n\n'
            await asyncio.sleep(0.35)
    return StreamingResponse(chunks(), media_type='text/event-stream')
