from __future__ import annotations

import logging
from typing import AsyncIterator

from redis.asyncio import Redis

from app.core.models import Event
from app.settings import settings

logger = logging.getLogger("autodefense.event_bus")


def _parse_event_field(fields: dict) -> Event | None:
    payload = fields.get(b"event") or fields.get("event")
    if not payload:
        return None
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", errors="replace")
    try:
        return Event.model_validate_json(payload)
    except Exception:  # noqa: BLE001
        logger.warning(
            "Failed to decode event",
            exc_info=True,
            extra={"event_type": "decode_error"},
        )
        return None


class EventBus:
    def __init__(self, redis: Redis):
        self.redis = redis
        self.stream_key = settings.redis_stream_key

    async def publish(self, event: Event) -> str:
        data = {"event": event.model_dump_json()}
        event_id = await self.redis.xadd(self.stream_key, data, maxlen=5000, approximate=True)
        return str(event_id)

    async def consume_latest(
        self,
        count: int = 50,
    ) -> list[Event]:
        raw = await self.redis.xrevrange(self.stream_key, max="+", min="-", count=count)
        events: list[Event] = []
        for _id, fields in raw:
            event = _parse_event_field(fields)
            if event is not None:
                events.append(event)
        events.reverse()
        return events

    async def stream_events(self, block_ms: int = 5000) -> AsyncIterator[Event]:
        last_id = "$"
        while True:
            results = await self.redis.xread({self.stream_key: last_id}, block=block_ms, count=100)
            if not results:
                continue
            for _stream, messages in results:
                for msg_id, fields in messages:
                    last_id = msg_id
                    event = _parse_event_field(fields)
                    if event is not None:
                        yield event
