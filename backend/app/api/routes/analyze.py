from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.models import AnalyzeRequest, AnalyzeResponse
from app.core.sealed import unseal_to_dict
from app.core.redis_client import get_redis
from app.services.pipeline import DefensePipeline

router = APIRouter()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest, redis=Depends(get_redis)) -> AnalyzeResponse:
    pipeline = DefensePipeline(redis)
    return await pipeline.run(req)


class SealedAnalyzeRequest(BaseModel):
    sealed: dict


@router.post("/analyze/sealed", response_model=AnalyzeResponse)
async def analyze_sealed(body: SealedAnalyzeRequest, redis=Depends(get_redis)) -> AnalyzeResponse:
    raw = unseal_to_dict(body.sealed, aad=b"analyze")
    if not raw:
        raise HTTPException(status_code=400, detail="Unable to unseal payload (check transport key/flag).")
    req = AnalyzeRequest.model_validate(raw)
    pipeline = DefensePipeline(redis)
    return await pipeline.run(req)

