from __future__ import annotations

import json
from typing import Any

from redis.asyncio import Redis

from app.core.crypto import CryptoManager
from app.core.event_bus import EventBus
from app.core.models import AnalyzeRequest, Event
from app.settings import settings


class ForensicsAgent:
    name = "forensics"
    KEY = "autodefense:forensics:events"

    def __init__(self, redis: Redis):
        self.redis = redis
        self.bus = EventBus(redis)
        self.crypto = CryptoManager(
            settings.data_key_b64 if settings.data_encryption_enabled else None
        )

    async def record(
        self,
        *,
        req: AnalyzeRequest,
        decision: dict[str, Any],
        sanitized_input: str | None = None,
    ) -> None:
        record = {
            "trace_id": req.trace_id,
            "session_id": req.session_id,
            "user_input": (sanitized_input or "")[:2000],
            "risk_score": decision.get("risk_score"),
            "action": decision.get("action"),
            "threat_types": decision.get("explain", {}).get("threat_types", []),
            "top_reasons": decision.get("explain", {}).get("top_reasons", [])[:10],
        }
        wrapped = self.crypto.encrypt_json(record, aad=b"forensics_record")
        await self.redis.lpush(self.KEY, json.dumps(wrapped, ensure_ascii=False))
        await self.redis.ltrim(self.KEY, 0, 1000)

        await self.bus.publish(
            Event(
                type="forensics.recorded",
                trace_id=req.trace_id,
                session_id=req.session_id,
                payload={
                    "risk_score": decision.get("risk_score"),
                    "action": decision.get("action"),
                },
            )
        )
