"""Rate-limit fallback and trusted proxy client IP extraction."""
from __future__ import annotations

import time

import pytest
from starlette.requests import Request

from app import main as main_mod
from app.main import _client_host_for_rate_limit, _memory_rate_limit_allow
from app.settings import settings


@pytest.fixture(autouse=True)
def _clear_memory_rate_state():
    main_mod._mem_counts.clear()
    yield
    main_mod._mem_counts.clear()


def test_memory_rate_limit_blocks_after_threshold():
    bucket = int(time.time()) // 60
    assert _memory_rate_limit_allow("1.2.3.4", bucket, 2) is True
    assert _memory_rate_limit_allow("1.2.3.4", bucket, 2) is True
    assert _memory_rate_limit_allow("1.2.3.4", bucket, 2) is False


def test_client_host_without_trust_uses_direct_tcp_ip(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "trusted_proxy_hops", 0)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "client": ("10.0.0.2", 12345),
        "headers": [(b"x-forwarded-for", b"203.0.113.9, 192.0.2.1")],
    }
    req = Request(scope)
    assert _client_host_for_rate_limit(req) == "10.0.0.2"


def test_client_host_with_trust_uses_xff_leftmost(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "trusted_proxy_hops", 1)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "client": ("10.0.0.2", 12345),
        "headers": [(b"x-forwarded-for", b"203.0.113.9, 192.0.2.1")],
    }
    req = Request(scope)
    assert _client_host_for_rate_limit(req) == "203.0.113.9"


def test_client_host_invalid_xff_falls_back_to_direct(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "trusted_proxy_hops", 1)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "client": ("10.0.0.2", 12345),
        "headers": [(b"x-forwarded-for", b"not-an-ip")],
    }
    req = Request(scope)
    assert _client_host_for_rate_limit(req) == "10.0.0.2"
