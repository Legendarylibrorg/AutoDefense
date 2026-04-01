from __future__ import annotations

import pytest
from fakeredis.aioredis import FakeRedis
from httpx import ASGITransport, AsyncClient

from app.core.redis_client import get_redis
from app.main import create_app
from app.settings import settings

TEST_API_KEY = "test-api-key-auth"


@pytest.fixture
def authed_app():
    settings.api_key = TEST_API_KEY
    settings.scanner_hmac_key = None
    settings.data_encryption_enabled = False
    app = create_app()
    fake = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    return app


async def test_no_auth_header_returns_401(authed_app):
    transport = ASGITransport(app=authed_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        res = await c.get("/events")
    assert res.status_code == 401
    assert res.json()["detail"] == "Unauthorized"


async def test_wrong_api_key_returns_401(authed_app):
    transport = ASGITransport(app=authed_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": "Bearer wrong-key"},
    ) as c:
        res = await c.get("/events")
    assert res.status_code == 401


async def test_malformed_bearer_returns_401(authed_app):
    transport = ASGITransport(app=authed_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": "Token " + TEST_API_KEY},
    ) as c:
        res = await c.get("/events")
    assert res.status_code == 401


async def test_valid_api_key_passes(authed_app):
    transport = ASGITransport(app=authed_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as c:
        res = await c.get("/health")
    assert res.status_code == 200


async def test_health_is_public(authed_app):
    transport = ASGITransport(app=authed_app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        res = await c.get("/health")
    assert res.status_code == 200


async def test_no_api_key_configured_allows_all():
    settings.api_key = None
    settings.scanner_hmac_key = None
    settings.data_encryption_enabled = False
    app = create_app()
    fake = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        res = await c.get("/events")
    assert res.status_code == 200
