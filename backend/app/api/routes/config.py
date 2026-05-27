from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.config_store import ConfigStore, RuntimeConfig
from app.core.event_bus import EventBus
from app.core.models import Event
from app.core.redis_client import get_redis

router = APIRouter()


class ConfigDTO(BaseModel):
    version: int = 1
    risk_allow_max: int = Field(ge=0, le=100)
    risk_monitor_max: int = Field(ge=0, le=100)
    risk_sanitize_max: int = Field(ge=0, le=100)
    self_heal_enabled: bool
    blocked_input_regexes: list[str] = Field(default_factory=list)
    sanitize_input_regexes: list[str] = Field(default_factory=list)


@router.get("/config", response_model=ConfigDTO)
async def get_config(redis=Depends(get_redis)) -> Any:
    store = ConfigStore(redis)
    try:
        cfg = await store.load()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail="Stored configuration could not be decrypted (check AUTODEFENSE_DATA_KEY_B64).",
        ) from exc
    return ConfigDTO(**cfg.__dict__)


@router.put("/config", response_model=ConfigDTO)
async def put_config(body: ConfigDTO, redis=Depends(get_redis)) -> Any:
    store = ConfigStore(redis)
    incoming = RuntimeConfig(**body.model_dump())

    errs = store.validate(incoming)
    if errs:
        raise HTTPException(status_code=400, detail={"errors": errs})

    # bump version deterministically
    try:
        current = await store.load()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail="Stored configuration could not be decrypted (check AUTODEFENSE_DATA_KEY_B64).",
        ) from exc
    incoming.version = max(current.version + 1, incoming.version)
    await store.save(incoming)

    bus = EventBus(redis)
    await bus.publish(
        Event(
            type="config.updated",
            trace_id="config",
            session_id="config",
            payload={"version": incoming.version},
        )
    )

    return ConfigDTO(**incoming.__dict__)
