from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.sealed import SealedBody, unsealed_dict
from app.core.models import ScanRequest, ScanResponse
from app.core.redis_client import get_redis
from app.services.pipeline import DefensePipeline

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest, redis=Depends(get_redis)) -> ScanResponse:
    return await DefensePipeline(redis).scan(req)


@router.post("/scan/sealed", response_model=ScanResponse)
async def scan_sealed(body: SealedBody, redis=Depends(get_redis)) -> ScanResponse:
    req = ScanRequest.model_validate(unsealed_dict(body, b"scan"))
    return await DefensePipeline(redis).scan(req)
