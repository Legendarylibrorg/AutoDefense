from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.event_bus import EventBus
from app.core.redis_client import get_redis

router = APIRouter()


@router.get("/alerts")
async def get_alerts(redis=Depends(get_redis)) -> list[dict]:
    bus = EventBus(redis)
    events = await bus.consume_latest(count=500)
    critical = [
        e.model_dump(mode="json")
        for e in events
        if e.type in ("decision.block_isolate", "decision.sanitize", "incident.detected")
    ]
    return critical[-200:]

