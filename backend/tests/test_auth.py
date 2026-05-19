from __future__ import annotations

import pytest
import httpx
from fakeredis.aioredis import FakeRedis

from app.core.redis_client import get_redis
from app.main import create_app
from app.settings import settings

TEST_API_KEY = "test-api-key-auth"


@pytest.fixture
def authed_app(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "api_key", TEST_API_KEY)
    monkeypatch.setattr(settings, "scanner_hmac_key", None)
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    app = create_app()
    fake = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    return app


async def test_no_auth_header_returns_401(authed_app):
    transport = httpx.ASGITransport(app=authed_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        res = await c.get("/events")
    assert res.status_code == 401
    assert res.json()["detail"] == "Unauthorized"


async def test_wrong_api_key_returns_401(authed_app):
    transport = httpx.ASGITransport(app=authed_app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": "Bearer wrong-key"},
    ) as c:
        res = await c.get("/events")
    assert res.status_code == 401


async def test_malformed_bearer_returns_401(authed_app):
    transport = httpx.ASGITransport(app=authed_app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": "Token " + TEST_API_KEY},
    ) as c:
        res = await c.get("/events")
    assert res.status_code == 401


async def test_valid_api_key_passes(authed_app):
    transport = httpx.ASGITransport(app=authed_app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as c:
        res = await c.get("/health")
    assert res.status_code == 200


async def test_health_is_public(authed_app):
    transport = httpx.ASGITransport(app=authed_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        res = await c.get("/health")
    assert res.status_code == 200


def test_production_requires_api_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "scanner_hmac_key", "scanner-secret")
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    with pytest.raises(RuntimeError, match="AUTODEFENSE_API_KEY"):
        create_app()


def test_production_requires_scanner_hmac(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "api_key", "api-secret")
    monkeypatch.setattr(settings, "scanner_hmac_key", None)
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    with pytest.raises(RuntimeError, match="AUTODEFENSE_SCANNER_HMAC_KEY"):
        create_app()


def test_development_requires_api_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "scanner_hmac_key", "scanner-secret")
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    with pytest.raises(RuntimeError, match="AUTODEFENSE_API_KEY"):
        create_app()


def test_staging_requires_data_key_when_encryption_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "api_key", "api-secret")
    monkeypatch.setattr(settings, "scanner_hmac_key", "scanner-secret")
    monkeypatch.setattr(settings, "data_encryption_enabled", True)
    monkeypatch.setattr(settings, "data_key_b64", None)
    with pytest.raises(RuntimeError, match="AUTODEFENSE_DATA_KEY_B64"):
        create_app()


async def test_openapi_not_exposed_outside_local(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "api_key", TEST_API_KEY)
    monkeypatch.setattr(settings, "scanner_hmac_key", "scanner-secret")
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    app = create_app()
    fake = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as c:
        assert (await c.get("/openapi.json")).status_code == 404
        assert (await c.get("/docs")).status_code == 404


async def test_health_minimal_outside_local(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "staging")
    monkeypatch.setattr(settings, "api_key", TEST_API_KEY)
    monkeypatch.setattr(settings, "scanner_hmac_key", "scanner-secret")
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    app = create_app()
    fake = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        body = (await c.get("/health")).json()
    assert body == {"status": "ok"}
    assert "platform" not in body
    assert "redis" not in body


async def test_no_api_key_configured_allows_all(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "local")
    monkeypatch.setattr(settings, "api_key", None)
    monkeypatch.setattr(settings, "scanner_hmac_key", None)
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    app = create_app()
    fake = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        res = await c.get("/events")
    assert res.status_code == 200
