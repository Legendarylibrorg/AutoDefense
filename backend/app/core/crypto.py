from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


@dataclass(frozen=True)
class EncryptedEnvelope:
    v: int
    alg: str
    nonce_b64: str
    ct_b64: str
    sha256: str


class CryptoManager:
    """
    Deterministic UX goal: encryption is transparent to callers.
    Security goal: encrypt persisted payloads (at-rest in Redis) with AES-256-GCM (AEAD).

    Key management:
    - Provide a 32-byte key via AUTODEFENSE_DATA_KEY_B64 (base64).
    - If missing, encryption is disabled (still hashes for observability).
    """

    def __init__(self, key_b64: str | None):
        self._key = None
        if key_b64:
            try:
                key = _b64d(key_b64)
                if len(key) == 32:
                    self._key = key
            except Exception:
                self._key = None

    @property
    def enabled(self) -> bool:
        return self._key is not None

    def encrypt_json(self, obj: dict[str, Any], *, aad: bytes = b"") -> dict[str, Any]:
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        digest = sha256_hex(raw)
        if not self.enabled:
            return {"v": 1, "alg": "none", "sha256": digest, "pt": obj}

        nonce = os.urandom(12)
        aes = AESGCM(self._key)
        ct = aes.encrypt(nonce, raw, aad)
        env = EncryptedEnvelope(v=1, alg="AES-256-GCM", nonce_b64=_b64e(nonce), ct_b64=_b64e(ct), sha256=digest)
        return env.__dict__

    def decrypt_json(self, payload: dict[str, Any], *, aad: bytes = b"") -> dict[str, Any]:
        alg = payload.get("alg")
        if alg == "none":
            if self.enabled:
                # Reject alg:none when encryption is active (prevents JWT-style downgrade)
                return {}
            pt = payload.get("pt")
            if isinstance(pt, dict):
                return pt
            return {}

        if not self.enabled:
            return {}

        nonce = _b64d(str(payload["nonce_b64"]))
        ct = _b64d(str(payload["ct_b64"]))
        aes = AESGCM(self._key)
        try:
            raw = aes.decrypt(nonce, ct, aad)
        except InvalidTag:
            return {}
        # integrity check: hash of plaintext
        expected = str(payload.get("sha256", ""))
        if expected and sha256_hex(raw) != expected:
            return {}
        obj = json.loads(raw.decode("utf-8"))
        return obj if isinstance(obj, dict) else {}

