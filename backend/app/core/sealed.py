from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.core.crypto import CryptoManager
from app.settings import settings


class SealedEnvelopeV1(BaseModel):
    v: int = 1
    alg: str = "AES-256-GCM"
    nonce_b64: str
    ct_b64: str
    sha256: str


class SealedEnvelopeV2(BaseModel):
    v: int = 2
    alg: str = "AES-256-GCM-DOUBLE"
    inner_nonce_b64: str
    outer_nonce_b64: str
    ct_b64: str
    sha256: str
    hmac: str


def transport_crypto() -> CryptoManager:
    if not settings.transport_seal_enabled:
        return CryptoManager(None)
    return CryptoManager(settings.transport_key_b64)


def unseal_to_dict(env: dict[str, Any], *, aad: bytes) -> dict[str, Any]:
    c = transport_crypto()
    if not c.enabled:
        return {}
    return c.decrypt_json(env, aad=aad)
