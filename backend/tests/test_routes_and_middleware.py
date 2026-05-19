"""Coverage for alerts/metrics routes, middleware hardening, and platform cache."""

from __future__ import annotations

import pytest
from fakeredis.aioredis import FakeRedis
from httpx import ASGITransport, AsyncClient

from app.api.routes import metrics as metrics_route
from app.core.event_bus import EventBus
from app.core.models import Event
from app.core.redis_client import get_redis
from app.main import MAX_BODY_BYTES, create_app
from app.settings import settings

TEST_API_KEY = "test-api-key-routes"


@pytest.fixture
def authed_app(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "api_key", TEST_API_KEY)
    monkeypatch.setattr(settings, "scanner_hmac_key", None)
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    monkeypatch.setattr(settings, "environment", "local")
    app = create_app()
    fake = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    return app, fake


async def test_alerts_returns_only_critical_types(authed_app):
    app, fake = authed_app
    bus = EventBus(fake)
    await bus.publish(
        Event(
            type="decision.block_isolate",
            trace_id="t1",
            session_id="s1",
            payload={"risk": 0.9},
        )
    )
    await bus.publish(Event(type="request.received", trace_id="t2", session_id="s1", payload={}))

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as client:
        res = await client.get("/alerts")
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 1
    assert body[0]["type"] == "decision.block_isolate"


async def test_metrics_counts_event_types(authed_app):
    app, fake = authed_app
    bus = EventBus(fake)
    await bus.publish(Event(type="request.received", trace_id="t1", session_id="s1", payload={}))
    await bus.publish(Event(type="request.received", trace_id="t2", session_id="s1", payload={}))

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as client:
        res = await client.get("/metrics")
    assert res.status_code == 200
    data = res.json()
    assert data["events_total_recent"] >= 2
    assert data["events_by_type_recent"].get("request.received", 0) >= 2


async def test_security_headers_on_api_response(authed_app):
    app, _ = authed_app
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as client:
        res = await client.get("/health")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'none'" in res.headers.get("Content-Security-Policy", "")


async def test_body_too_large_returns_413(authed_app):
    app, _ = authed_app
    transport = ASGITransport(app=app)
    huge = b"x" * (MAX_BODY_BYTES + 1)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={
            "Authorization": f"Bearer {TEST_API_KEY}",
            "Content-Type": "application/json",
        },
    ) as client:
        res = await client.post("/analyze", content=huge)
    assert res.status_code == 413


async def test_sse_connection_limit_returns_503(authed_app, monkeypatch: pytest.MonkeyPatch):
    from app.api.routes import events as events_route

    monkeypatch.setattr(settings, "max_ws_connections", 1)
    events_route._active_sse = 1  # at limit for max_ws_connections=1
    app, _ = authed_app
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as client:
        res = await client.get("/events/stream")
    assert res.status_code == 503
    assert res.json()["detail"] == "SSE connection limit reached"
    events_route._active_sse = 0


def test_platform_cache_separate_for_local_vs_staging(monkeypatch: pytest.MonkeyPatch):
    metrics_route._platform_cache.clear()
    monkeypatch.setattr(settings, "environment", "local")
    local_info = metrics_route._platform_info()
    assert local_info["hostname"] != "redacted"

    monkeypatch.setattr(settings, "environment", "staging")
    staging_info = metrics_route._platform_info()
    assert staging_info["hostname"] == "redacted"
    assert local_info is not staging_info
