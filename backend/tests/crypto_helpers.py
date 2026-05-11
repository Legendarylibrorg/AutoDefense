"""Shared crypto helpers for HTTP integration tests.

Uses :class:`~app.core.crypto.CryptoManager` with the patched
``settings.transport_key_b64`` from ``conftest`` — same v2 envelope as
``/analyze/sealed`` and ``/scan/sealed`` in production and the dashboard.
"""

from __future__ import annotations

from typing import Any

from app.core.crypto import CryptoManager
from app.settings import settings

_V2_REQUIRED = frozenset(
    {"v", "alg", "inner_nonce_b64", "outer_nonce_b64", "ct_b64", "sha256", "hmac"}
)


def transport_seal_v2(obj: dict[str, Any], *, aad: bytes) -> dict[str, Any]:
    """Return a v2 double-layer envelope suitable for ``{"sealed": ...}`` POST bodies."""
    env = CryptoManager(settings.transport_key_b64).encrypt_json(obj, aad=aad)
    assert env.get("v") == 2 and env.get("alg") == "AES-256-GCM-DOUBLE"
    assert _V2_REQUIRED <= env.keys()
    return env
