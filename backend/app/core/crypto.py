from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _derive_subkey(master: bytes, info: bytes) -> bytes:
    """Deterministic subkey derivation via HKDF-SHA256 (RFC 5869)."""
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(master)


# `alg` values that indicate a Redis-stored payload should pass through decrypt_json.
STORE_ENVELOPE_ALGS = frozenset({"AES-256-GCM", "AES-256-GCM-DOUBLE", "none"})


class CryptoManager:
    """
    Double-layer AES-256-GCM encryption with HMAC-SHA256 integrity binding.

    From a single 32-byte master key, three independent subkeys are derived
    via HKDF-SHA256:

        key_inner  = HKDF(master, info="autodefense-inner-v2")   → inner AES-256-GCM
        key_outer  = HKDF(master, info="autodefense-outer-v2")   → outer AES-256-GCM
        key_hmac   = HKDF(master, info="autodefense-hmac-v2")    → HMAC-SHA256

    Encrypt path:
        1. SHA-256 hash of canonical JSON plaintext
        2. HMAC-SHA256(key_hmac, plaintext)
        3. inner_ct = AES-256-GCM(key_inner, nonce1, plaintext, aad)
        4. outer_ct = AES-256-GCM(key_outer, nonce2, inner_ct, aad)

    Decrypt path reverses all four checks.  Any single failure → empty dict.

    v1 single-layer envelopes are still accepted for backward compatibility.
    """

    def __init__(self, key_b64: str | None):
        self._key: bytes | None = None
        self._key_inner: bytes | None = None
        self._key_outer: bytes | None = None
        self._key_hmac: bytes | None = None
        if key_b64:
            try:
                key = _b64d(key_b64)
                if len(key) == 32:
                    self._key = key
                    self._key_inner = _derive_subkey(key, b"autodefense-inner-v2")
                    self._key_outer = _derive_subkey(key, b"autodefense-outer-v2")
                    self._key_hmac = _derive_subkey(key, b"autodefense-hmac-v2")
            except Exception:
                self._key = None

    @property
    def enabled(self) -> bool:
        return self._key is not None

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def encrypt_json(self, obj: dict[str, Any], *, aad: bytes = b"") -> dict[str, Any]:
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        digest = sha256_hex(raw)

        if not self.enabled:
            return {"v": 1, "alg": "none", "sha256": digest, "pt": obj}

        assert self._key_inner and self._key_outer and self._key_hmac

        mac = _hmac.new(self._key_hmac, raw, hashlib.sha256).hexdigest()

        inner_nonce = os.urandom(12)
        inner_ct = AESGCM(self._key_inner).encrypt(inner_nonce, raw, aad)

        outer_nonce = os.urandom(12)
        outer_ct = AESGCM(self._key_outer).encrypt(outer_nonce, inner_ct, aad)

        return {
            "v": 2,
            "alg": "AES-256-GCM-DOUBLE",
            "inner_nonce_b64": _b64e(inner_nonce),
            "outer_nonce_b64": _b64e(outer_nonce),
            "ct_b64": _b64e(outer_ct),
            "sha256": digest,
            "hmac": mac,
        }

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def decrypt_json(self, payload: dict[str, Any], *, aad: bytes = b"") -> dict[str, Any]:
        alg = payload.get("alg")

        if alg == "none":
            if self.enabled:
                return {}
            pt = payload.get("pt")
            return pt if isinstance(pt, dict) else {}

        if not self.enabled:
            return {}

        if alg == "AES-256-GCM-DOUBLE":
            return self._decrypt_v2(payload, aad=aad)

        return self._decrypt_v1(payload, aad=aad)

    def _decrypt_v2(self, payload: dict[str, Any], *, aad: bytes) -> dict[str, Any]:
        assert self._key_inner and self._key_outer and self._key_hmac

        try:
            outer_nonce = _b64d(str(payload["outer_nonce_b64"]))
            ct = _b64d(str(payload["ct_b64"]))
        except Exception:
            return {}

        try:
            inner_ct = AESGCM(self._key_outer).decrypt(outer_nonce, ct, aad)
        except InvalidTag:
            return {}

        try:
            inner_nonce = _b64d(str(payload["inner_nonce_b64"]))
        except Exception:
            return {}

        try:
            raw = AESGCM(self._key_inner).decrypt(inner_nonce, inner_ct, aad)
        except InvalidTag:
            return {}

        expected_hmac = str(payload.get("hmac", ""))
        if not expected_hmac:
            return {}
        actual = _hmac.new(self._key_hmac, raw, hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(actual, expected_hmac):
            return {}

        expected_sha = str(payload.get("sha256", ""))
        if not expected_sha:
            return {}
        if sha256_hex(raw) != expected_sha:
            return {}

        try:
            text = raw.decode("utf-8")
            obj = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return obj if isinstance(obj, dict) else {}

    def _decrypt_v1(self, payload: dict[str, Any], *, aad: bytes) -> dict[str, Any]:
        """Backward-compatible single-layer decrypt for pre-existing v1 envelopes."""
        assert self._key
        try:
            nonce = _b64d(str(payload["nonce_b64"]))
            ct = _b64d(str(payload["ct_b64"]))
        except Exception:
            return {}

        try:
            raw = AESGCM(self._key).decrypt(nonce, ct, aad)
        except InvalidTag:
            return {}

        expected = str(payload.get("sha256", ""))
        if not expected or sha256_hex(raw) != expected:
            return {}

        try:
            text = raw.decode("utf-8")
            obj = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return obj if isinstance(obj, dict) else {}
