from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from app.agents.kernel import KernelAgent
from app.core.crypto import STORE_ENVELOPE_ALGS, CryptoManager
from app.core.event_bus import EventBus
from app.core.models import (
    DecisionAction,
    Event,
    KernelScanPayload,
    KernelScanResponse,
)
from app.core.redis_client import get_redis
from app.core.risk import aggregate_risk
from app.core.response_engine import ResponseEngine
from app.core.config_store import ConfigStore
from app.settings import settings

router = APIRouter()
logger = logging.getLogger("autodefense.kernel")

KERNEL_STATUS_KEY = "autodefense:kernel_status:v1"


def _verify_hmac(body_bytes: bytes, signature: str | None) -> None:
    """Verify HMAC-SHA256 signature from scanner. Skips if HMAC key is not configured."""
    if not settings.scanner_hmac_key:
        return
    if not signature:
        raise HTTPException(status_code=401, detail="Missing X-Scanner-Signature header")
    expected = hmac.new(
        settings.scanner_hmac_key.encode("utf-8"), body_bytes, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        logger.warning("Scanner HMAC verification failed", extra={"event_type": "security"})
        raise HTTPException(status_code=403, detail="Invalid scanner signature")


@router.post("/scan/kernel", response_model=KernelScanResponse)
async def scan_kernel(
    request: Request,
    redis=Depends(get_redis),
    x_scanner_signature: str | None = Header(default=None),
):
    raw_body = await request.body()
    payload = KernelScanPayload.model_validate_json(raw_body)

    if settings.scanner_hmac_key:
        _verify_hmac(raw_body, x_scanner_signature)

    bus = EventBus(redis)
    cfg = await ConfigStore(redis).load()
    thresholds = {
        "risk_allow_max": cfg.risk_allow_max,
        "risk_monitor_max": cfg.risk_monitor_max,
        "risk_sanitize_max": cfg.risk_sanitize_max,
    }

    await bus.publish(
        Event(
            type="kernel.scan_received",
            trace_id="kernel",
            session_id="kernel",
            payload={
                "platform": payload.platform,
                "hostname": payload.hostname,
                "findings": len(payload.findings),
            },
        )
    )

    agent = KernelAgent()
    result = agent.analyze(payload.findings)
    signals = result["signals"]

    risk = 0
    action = DecisionAction.allow
    if signals:
        risk, _explain = aggregate_risk(signals)
        engine = ResponseEngine()
        action = engine.decide_action(
            risk,
            risk_allow_max=int(thresholds["risk_allow_max"]),
            risk_monitor_max=int(thresholds["risk_monitor_max"]),
            risk_sanitize_max=int(thresholds["risk_sanitize_max"]),
        )

    await bus.publish(
        Event(
            type=f"kernel.decision.{action.value}",
            trace_id="kernel",
            session_id="kernel",
            payload={
                "risk_score": risk,
                "findings_count": len(payload.findings),
                "hostname": payload.hostname,
            },
        )
    )

    status: dict[str, Any] = {
        "platform": payload.platform,
        "kernel_version": payload.kernel_version,
        "hostname": payload.hostname,
        "timestamp": payload.timestamp,
        "in_container": payload.in_container,
        "findings_count": len(payload.findings),
        "risk_score": risk,
        "action": action.value,
        "hardening": payload.hardening,
        "findings": [f.model_dump(mode="json") for f in payload.findings],
    }
    crypto = CryptoManager(settings.data_key_b64 if settings.data_encryption_enabled else None)
    wrapped = crypto.encrypt_json(status, aad=b"kernel_status")
    await redis.set(KERNEL_STATUS_KEY, json.dumps(wrapped, ensure_ascii=False))

    return KernelScanResponse(
        accepted=True,
        findings_count=len(payload.findings),
        risk_score=risk,
        action=action,
        signals=signals,
    )


@router.get("/kernel/status")
async def kernel_status(redis=Depends(get_redis)) -> dict:
    raw = await redis.get(KERNEL_STATUS_KEY)
    if not raw:
        return {"scanned": False}
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    data = json.loads(raw)
    if isinstance(data, dict) and data.get("alg") in STORE_ENVELOPE_ALGS:
        crypto = CryptoManager(settings.data_key_b64 if settings.data_encryption_enabled else None)
        data = crypto.decrypt_json(data, aad=b"kernel_status")
    data["scanned"] = True
    return data
