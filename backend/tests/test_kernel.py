from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

import httpx
import pytest
from fakeredis.aioredis import FakeRedis

from app.api.routes.kernel import KERNEL_STATUS_KEY
from app.core.redis_client import get_redis
from app.main import create_app
from app.settings import settings

TEST_API_KEY = "test-api-key-kernel"
TEST_HMAC_KEY = "test-hmac-key-for-scanner"


@pytest.fixture
def hmac_app(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "api_key", TEST_API_KEY)
    monkeypatch.setattr(settings, "scanner_hmac_key", TEST_HMAC_KEY)
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    monkeypatch.setattr(settings, "transport_seal_enabled", False)
    app = create_app()
    fake = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    return app


@pytest.fixture
async def hmac_client(hmac_app):
    transport = httpx.ASGITransport(app=hmac_app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as c:
        yield c


def _sign(payload_bytes: bytes) -> str:
    return hmac.new(TEST_HMAC_KEY.encode(), payload_bytes, hashlib.sha256).hexdigest()


def _kernel_payload(**overrides):
    base = {
        "platform": "linux",
        "kernel_version": "6.1.0",
        "hostname": "test-host",
        "timestamp": "2026-01-01T00:00:00Z",
        "in_container": False,
        "findings": [],
        "hardening": {},
    }
    base.update(overrides)
    return base


async def test_kernel_scan_valid_hmac(hmac_client):
    payload = _kernel_payload()
    body = json.dumps(payload).encode()
    sig = _sign(body)
    res = await hmac_client.post(
        "/scan/kernel",
        content=body,
        headers={"Content-Type": "application/json", "X-Scanner-Signature": sig},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["accepted"] is True
    assert data["risk_score"] == 0


async def test_kernel_scan_missing_hmac_rejected(hmac_client):
    payload = _kernel_payload()
    body = json.dumps(payload).encode()
    res = await hmac_client.post(
        "/scan/kernel",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert res.status_code == 401


async def test_kernel_scan_invalid_hmac_rejected(hmac_client):
    payload = _kernel_payload()
    body = json.dumps(payload).encode()
    res = await hmac_client.post(
        "/scan/kernel",
        content=body,
        headers={"Content-Type": "application/json", "X-Scanner-Signature": "badhex"},
    )
    assert res.status_code == 403


async def test_kernel_scan_hmac_checked_before_json_parse(hmac_client):
    """Invalid JSON must not be parsed before HMAC rejects a wrong signature."""
    body = b"not-json-at-all"
    res = await hmac_client.post(
        "/scan/kernel",
        content=body,
        headers={"Content-Type": "application/json", "X-Scanner-Signature": "deadbeef"},
    )
    assert res.status_code == 403


async def test_kernel_scan_invalid_json_after_valid_hmac(hmac_client):
    body = b"not-json-at-all"
    sig = _sign(body)
    res = await hmac_client.post(
        "/scan/kernel",
        content=body,
        headers={"Content-Type": "application/json", "X-Scanner-Signature": sig},
    )
    assert res.status_code == 422


async def test_kernel_scan_critical_findings_raise_risk(hmac_client):
    payload = _kernel_payload(
        findings=[
            {
                "category": "rootkit",
                "severity": "critical",
                "title": "Known rootkit module loaded: diamorphine",
                "detail": "The module 'diamorphine' matches a known rootkit LKM.",
                "evidence": {"module": "diamorphine"},
            }
        ]
    )
    body = json.dumps(payload).encode()
    sig = _sign(body)
    res = await hmac_client.post(
        "/scan/kernel",
        content=body,
        headers={"Content-Type": "application/json", "X-Scanner-Signature": sig},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] >= 50
    assert data["action"] in ("sanitize", "block_isolate")


async def test_kernel_status_empty(hmac_client):
    res = await hmac_client.get("/kernel/status")
    assert res.status_code == 200
    assert res.json()["scanned"] is False


@pytest.fixture
def hmac_encrypted_app(monkeypatch: pytest.MonkeyPatch):
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    monkeypatch.setattr(settings, "api_key", TEST_API_KEY)
    monkeypatch.setattr(settings, "scanner_hmac_key", TEST_HMAC_KEY)
    monkeypatch.setattr(settings, "data_encryption_enabled", True)
    monkeypatch.setattr(settings, "data_key_b64", key_b64)
    monkeypatch.setattr(settings, "transport_seal_enabled", False)
    app = create_app()
    fake = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: fake
    return app


@pytest.fixture
async def hmac_encrypted_client(hmac_encrypted_app):
    transport = httpx.ASGITransport(app=hmac_encrypted_app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {TEST_API_KEY}"},
    ) as c:
        yield c


async def test_kernel_status_decrypt_failure_not_marked_scanned(
    hmac_encrypted_client, hmac_encrypted_app
):
    payload = _kernel_payload()
    body = json.dumps(payload).encode()
    sig = _sign(body)
    res = await hmac_encrypted_client.post(
        "/scan/kernel",
        content=body,
        headers={"Content-Type": "application/json", "X-Scanner-Signature": sig},
    )
    assert res.status_code == 200

    fake: FakeRedis = hmac_encrypted_app.dependency_overrides[get_redis]()
    raw = await fake.get(KERNEL_STATUS_KEY)
    assert raw
    envelope = json.loads(raw)
    envelope["ct_b64"] = base64.b64encode(b"tampered").decode("ascii")
    await fake.set(KERNEL_STATUS_KEY, json.dumps(envelope, ensure_ascii=False))

    res2 = await hmac_encrypted_client.get("/kernel/status")
    assert res2.status_code == 200
    data = res2.json()
    assert data["scanned"] is False
    assert data.get("kernel_status_unavailable") is True
