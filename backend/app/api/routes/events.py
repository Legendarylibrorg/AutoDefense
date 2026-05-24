from __future__ import annotations

import asyncio
import hmac
import json
import logging
import time

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse

from app.core.event_bus import EventBus
from app.core.redis_client import get_redis
from app.core.ws_auth import parse_ws_auth_protocol
from app.settings import settings

router = APIRouter()
logger = logging.getLogger("autodefense.events")

_active_ws: set[WebSocket] = set()
_active_sse: int = 0
_sse_lock = asyncio.Lock()


@router.get("/events")
async def get_events(redis=Depends(get_redis)) -> list[dict]:
    bus = EventBus(redis)
    events = await bus.consume_latest(count=200)
    return [e.model_dump(mode="json") for e in events]


@router.get("/events/stream")
async def stream_events(redis=Depends(get_redis)):
    async with _sse_lock:
        if _active_sse >= settings.max_sse_connections:
            return JSONResponse(
                status_code=503,
                content={"detail": "SSE connection limit reached"},
            )

    bus = EventBus(redis)
    timeout = settings.sse_timeout_seconds

    async def gen():
        global _active_sse
        async with _sse_lock:
            if _active_sse >= settings.max_sse_connections:
                yield 'data: {"detail":"SSE connection limit reached"}\n\n'
                return
            _active_sse += 1
        start = time.monotonic()
        try:
            async for e in bus.stream_events():
                yield f"data: {json.dumps(e.model_dump(mode='json'))}\n\n"
                if time.monotonic() - start > timeout:
                    yield 'data: {"event": "timeout"}\n\n'
                    break
        finally:
            async with _sse_lock:
                _active_sse -= 1

    return StreamingResponse(gen(), media_type="text/event-stream")


@router.websocket("/events/ws")
async def events_ws(ws: WebSocket, redis=Depends(get_redis)):
    if len(_active_ws) >= settings.max_ws_connections:
        await ws.close(code=1013, reason="Connection limit reached")
        return

    subprotocol, token = parse_ws_auth_protocol(ws.headers.get("sec-websocket-protocol"))
    if settings.api_key:
        if not token or not hmac.compare_digest(token, settings.api_key):
            await ws.close(code=1008, reason="Unauthorized")
            return

    await ws.accept(subprotocol=subprotocol)
    _active_ws.add(ws)
    bus = EventBus(redis)
    timeout = settings.sse_timeout_seconds
    start = time.monotonic()
    try:
        async for e in bus.stream_events():
            await ws.send_json(e.model_dump(mode="json"))
            if time.monotonic() - start > timeout:
                await ws.close(code=1000, reason="Session timeout")
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.debug("WebSocket disconnected", exc_info=True)
    finally:
        _active_ws.discard(ws)
