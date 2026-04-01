from __future__ import annotations

import pytest
from fakeredis.aioredis import FakeRedis
from httpx import ASGITransport, AsyncClient

from app.core.redis_client import get_redis
from app.main import create_app
from app.settings import settings


TEST_API_KEY = "test-api-key-for-unit-tests"


@pytest.fixture
def app():
    # Disable auth complexity in tests by using a known key.
    settings.api_key = TEST_API_KEY
    settings.scanner_hmac_key = None
    app_ = create_app()
    fake = FakeRedis()

    def _get():
        return fake

    app_.dependency_overrides[get_redis] = _get
    settings.data_encryption_enabled = False
    settings.transport_seal_enabled = True
    settings.transport_key_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="  # 32 zero bytes
    return app_


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as c:
        yield c

