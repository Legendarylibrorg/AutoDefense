from __future__ import annotations

import base64
import os

import pytest
from fakeredis.aioredis import FakeRedis

import json

from app.core.config_store import ConfigStore
from app.settings import settings


async def test_runtime_config_survives_v3_encrypted_roundtrip(monkeypatch: pytest.MonkeyPatch):
    key_b64 = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(settings, "data_encryption_enabled", True)
    monkeypatch.setattr(settings, "data_key_b64", key_b64)

    redis = FakeRedis()
    store = ConfigStore(redis)
    cfg = store.defaults()
    cfg.risk_allow_max = 77
    await store.save(cfg)

    loaded = await store.load()
    assert loaded.risk_allow_max == 77


async def test_runtime_config_decrypt_failure_raises(monkeypatch: pytest.MonkeyPatch):
    key_b64 = base64.b64encode(os.urandom(32)).decode()
    wrong_b64 = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(settings, "data_encryption_enabled", True)
    monkeypatch.setattr(settings, "data_key_b64", key_b64)

    redis = FakeRedis()
    store = ConfigStore(redis)
    cfg = store.defaults()
    await store.save(cfg)

    monkeypatch.setattr(settings, "data_key_b64", wrong_b64)
    store2 = ConfigStore(redis)
    with pytest.raises(RuntimeError, match="decrypt"):
        await store2.load()


async def test_runtime_config_rejects_plaintext_when_encryption_enabled(
    monkeypatch: pytest.MonkeyPatch,
):
    key_b64 = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(settings, "data_encryption_enabled", True)
    monkeypatch.setattr(settings, "data_key_b64", key_b64)

    redis = FakeRedis()
    await redis.set(
        ConfigStore.KEY,
        json.dumps({"v": 1, "alg": "none", "pt": {"version": 1}}),
    )
    store = ConfigStore(redis)
    with pytest.raises(RuntimeError, match="decrypt"):
        await store.load()


async def test_get_config(client):
    res = await client.get("/config")
    assert res.status_code == 200
    body = res.json()
    assert "risk_allow_max" in body
    assert "blocked_input_regexes" in body


async def test_put_config_rejects_bad_thresholds(client):
    cfg = (await client.get("/config")).json()
    cfg["risk_allow_max"] = 90
    cfg["risk_monitor_max"] = 40
    cfg["risk_sanitize_max"] = 80
    res = await client.put("/config", json=cfg)
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert "errors" in detail


async def test_put_config_accepts_and_versions(client):
    cfg = (await client.get("/config")).json()
    old_v = cfg["version"]
    cfg["risk_allow_max"] = 10
    cfg["risk_monitor_max"] = 20
    cfg["risk_sanitize_max"] = 30
    res = await client.put("/config", json=cfg)
    assert res.status_code == 200
    body = res.json()
    assert body["version"] >= old_v + 1
    assert body["risk_allow_max"] == 10


def test_settings_is_local_normalizes_environment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "  LOCAL  ")
    assert settings.is_local is True
    monkeypatch.setattr(settings, "environment", "development")
    assert settings.is_local is False
