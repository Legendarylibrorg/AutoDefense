from __future__ import annotations

import base64
import os

import pytest

from app.main import create_app
from app.settings import settings


def test_create_app_rejects_invalid_data_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "local")
    monkeypatch.setattr(settings, "api_key", "test-key")
    monkeypatch.setattr(settings, "data_encryption_enabled", True)
    monkeypatch.setattr(settings, "data_key_b64", "not-valid-key")
    with pytest.raises(RuntimeError, match="base64"):
        create_app()


def test_create_app_rejects_short_scanner_hmac_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "local")
    monkeypatch.setattr(settings, "api_key", "test-key")
    monkeypatch.setattr(settings, "scanner_hmac_key", "tiny")
    with pytest.raises(RuntimeError, match="SCANNER_HMAC"):
        create_app()


def test_create_app_accepts_valid_keys(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "environment", "local")
    monkeypatch.setattr(settings, "api_key", "test-key")
    monkeypatch.setattr(settings, "data_encryption_enabled", False)
    monkeypatch.setattr(settings, "data_key_b64", None)
    monkeypatch.setattr(settings, "transport_key_b64", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setattr(settings, "scanner_hmac_key", "x" * 16)
    app = create_app()
    assert app.title
