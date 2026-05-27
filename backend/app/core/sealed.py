from __future__ import annotations

from typing import Any

from app.core.crypto import CryptoManager
from app.settings import settings


def transport_crypto() -> CryptoManager:
    if not settings.transport_seal_enabled:
        return CryptoManager(None)
    return CryptoManager(
        settings.transport_key_b64,
        require_key=bool(settings.transport_key_b64),
    )


def unseal_to_dict(env: dict[str, Any], *, aad: bytes) -> dict[str, Any]:
    c = transport_crypto()
    if not c.enabled:
        return {}
    return c.decrypt_json(env, aad=aad)
