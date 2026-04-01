from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.agents.artifact import ArtifactAgent
from app.core.event_bus import EventBus
from app.core.models import Event, ScanRequest, ScanResponse
from app.core.redis_client import get_redis
from app.core.risk import aggregate_risk
from app.core.response_engine import ResponseEngine
from app.core.config_store import ConfigStore
from app.core.sealed import unseal_to_dict

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest, redis=Depends(get_redis)) -> ScanResponse:
    bus = EventBus(redis)
    cfg = await ConfigStore(redis).load()
    thresholds = {
        "risk_allow_max": cfg.risk_allow_max,
        "risk_monitor_max": cfg.risk_monitor_max,
        "risk_sanitize_max": cfg.risk_sanitize_max,
    }

    await bus.publish(
        Event(
            type="scan.received",
            trace_id=req.trace_id,
            session_id=req.session_id,
            payload={"artifacts": len(req.artifacts)},
        )
    )

    agent = ArtifactAgent()
    out = await agent.analyze(req.artifacts)
    signals = out["signals"]
    risk, explain = aggregate_risk(signals)
    explain["artifact_summary"] = out.get("artifact_summary", [])

    engine = ResponseEngine()
    action = engine.decide_action(
        risk,
        risk_allow_max=int(thresholds["risk_allow_max"]),
        risk_monitor_max=int(thresholds["risk_monitor_max"]),
        risk_sanitize_max=int(thresholds["risk_sanitize_max"]),
    )

    await bus.publish(
        Event(
            type=f"scan.decision.{action.value}",
            trace_id=req.trace_id,
            session_id=req.session_id,
            payload={"risk_score": risk},
        )
    )

    return ScanResponse(
        session_id=req.session_id,
        trace_id=req.trace_id,
        risk_score=risk,
        action=action,
        explain=explain,
        signals=signals,
    )


class SealedScanRequest(BaseModel):
    sealed: dict


@router.post("/scan/sealed", response_model=ScanResponse)
async def scan_sealed(body: SealedScanRequest, redis=Depends(get_redis)) -> ScanResponse:
    raw = unseal_to_dict(body.sealed, aad=b"scan")
    if not raw:
        raise HTTPException(status_code=400, detail="Unable to unseal payload (check transport key/flag).")
    req = ScanRequest.model_validate(raw)
    return await scan(req=req, redis=redis)

