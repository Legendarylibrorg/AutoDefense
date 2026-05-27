"""Shared crypto helpers for HTTP integration tests.

Uses :class:`~app.core.crypto.CryptoManager` with the patched
``settings.transport_key_b64`` from ``conftest`` — same v3 envelope as
``/analyze/sealed`` and ``/scan/sealed`` in production and the dashboard.
"""

from __future__ import annotations

from typing import Any

from app.core.crypto import CryptoManager
from app.settings import settings

_V3_REQUIRED = frozenset({"v", "alg", "nonce_b64", "ct_b64"})


def transport_seal(obj: dict[str, Any], *, aad: bytes) -> dict[str, Any]:
    """Return a v3 AES-GCM envelope suitable for ``{"sealed": ...}`` POST bodies."""
    env = CryptoManager(settings.transport_key_b64).encrypt_json(obj, aad=aad)
    assert env.get("v") == 3 and env.get("alg") == "AES-256-GCM"
    assert _V3_REQUIRED <= env.keys()
    return env


def transport_seal_v2(obj: dict[str, Any], *, aad: bytes) -> dict[str, Any]:
    """Build a legacy v2 envelope for backward-compat decrypt tests."""
    import base64
    import hashlib
    import hmac as _hmac
    import json
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    key = CryptoManager(settings.transport_key_b64)._key  # type: ignore[arg-type]
    assert key is not None

    def _derive(info: bytes) -> bytes:
        return HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(key)

    key_inner = _derive(b"autodefense-inner-v2")
    key_outer = _derive(b"autodefense-outer-v2")
    key_hmac = _derive(b"autodefense-hmac-v2")

    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    mac = _hmac.new(key_hmac, raw, hashlib.sha256).hexdigest()
    inner_nonce = os.urandom(12)
    inner_ct = AESGCM(key_inner).encrypt(inner_nonce, raw, aad)
    outer_nonce = os.urandom(12)
    outer_ct = AESGCM(key_outer).encrypt(outer_nonce, inner_ct, aad)
    return {
        "v": 2,
        "alg": "AES-256-GCM-DOUBLE",
        "inner_nonce_b64": base64.b64encode(inner_nonce).decode("ascii"),
        "outer_nonce_b64": base64.b64encode(outer_nonce).decode("ascii"),
        "ct_b64": base64.b64encode(outer_ct).decode("ascii"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "hmac": mac,
    }
