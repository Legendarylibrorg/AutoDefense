from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.sealed import SealedBody, unsealed_dict
from app.core.models import AnalyzeRequest, AnalyzeResponse
from app.core.redis_client import get_redis
from app.services.pipeline import DefensePipeline

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest, redis=Depends(get_redis)) -> AnalyzeResponse:
    return await DefensePipeline(redis).run(req)


@router.post("/analyze/sealed", response_model=AnalyzeResponse)
async def analyze_sealed(body: SealedBody, redis=Depends(get_redis)) -> AnalyzeResponse:
    req = AnalyzeRequest.model_validate(unsealed_dict(body, b"analyze"))
    return await DefensePipeline(redis).run(req)
