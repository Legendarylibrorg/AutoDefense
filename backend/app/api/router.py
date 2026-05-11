from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import alerts, analyze, config, events, kernel, metrics, scan

api_router = APIRouter()
api_router.include_router(analyze.router, tags=["analyze"])
api_router.include_router(events.router, tags=["events"])
api_router.include_router(alerts.router, tags=["alerts"])
api_router.include_router(metrics.router, tags=["metrics"])
api_router.include_router(config.router, tags=["config"])
api_router.include_router(scan.router, tags=["scan"])
api_router.include_router(kernel.router, tags=["kernel"])
