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

MASTER_KEY_BYTES = 32
HKDF_AES_V3_INFO = b"autodefense-aes-v3"
MIN_SCANNER_HMAC_KEY_LEN = 16

# Legacy v2 derivation labels (decrypt-only).
_HKDF_INNER_V2 = b"autodefense-inner-v2"
_HKDF_OUTER_V2 = b"autodefense-outer-v2"
_HKDF_HMAC_V2 = b"autodefense-hmac-v2"


class CryptoKeyError(ValueError):
    """Raised when a configured base64 master key is missing or malformed."""


class DecryptionError(RuntimeError):
    """Raised when an encrypted envelope cannot be decrypted or verified."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def decode_master_key(key_b64: str) -> bytes:
    """Decode and validate a 32-byte base64 master key."""
    try:
        key = _b64d(key_b64.strip())
    except Exception as exc:
        raise CryptoKeyError("Master key must be valid base64") from exc
    if len(key) != MASTER_KEY_BYTES:
        raise CryptoKeyError(f"Master key must be {MASTER_KEY_BYTES} bytes after base64 decode")
    return key


def _derive_subkey(master: bytes, info: bytes) -> bytes:
    """Deterministic subkey derivation via HKDF-SHA256 (RFC 5869)."""
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=info).derive(master)


def validate_scanner_hmac_key(key: str | None) -> None:
    """Require a non-trivial scanner HMAC secret when one is configured."""
    if key is None:
        return
    trimmed = key.strip()
    if not trimmed:
        raise CryptoKeyError("AUTODEFENSE_SCANNER_HMAC_KEY must not be empty when set")
    if len(trimmed) < MIN_SCANNER_HMAC_KEY_LEN:
        raise CryptoKeyError(
            f"AUTODEFENSE_SCANNER_HMAC_KEY must be at least {MIN_SCANNER_HMAC_KEY_LEN} characters"
        )


# `alg` values that indicate a Redis-stored payload should pass through decrypt_json.
STORE_ENVELOPE_ALGS = frozenset({"AES-256-GCM", "AES-256-GCM-DOUBLE", "none"})


class CryptoManager:
    """
    At-rest and transport encryption using AES-256-GCM (v3).

    New writes use a single HKDF-derived AES key (``autodefense-aes-v3``). v2
    double-layer and v1 single-layer envelopes remain decryptable for migration.
    """

    def __init__(self, key_b64: str | None, *, require_key: bool = False):
        self._key: bytes | None = None
        self._key_aes: bytes | None = None
        self._key_inner: bytes | None = None
        self._key_outer: bytes | None = None
        self._key_hmac: bytes | None = None

        if not key_b64:
            if require_key:
                raise CryptoKeyError("Encryption key is required but not configured")
            return

        key = decode_master_key(key_b64)
        self._key = key
        self._key_aes = _derive_subkey(key, HKDF_AES_V3_INFO)
        self._key_inner = _derive_subkey(key, _HKDF_INNER_V2)
        self._key_outer = _derive_subkey(key, _HKDF_OUTER_V2)
        self._key_hmac = _derive_subkey(key, _HKDF_HMAC_V2)

    @property
    def enabled(self) -> bool:
        return self._key is not None

    # ------------------------------------------------------------------
    # Encrypt (v3)
    # ------------------------------------------------------------------

    def encrypt_json(self, obj: dict[str, Any], *, aad: bytes = b"") -> dict[str, Any]:
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )

        if not self.enabled:
            return {"v": 1, "alg": "none", "sha256": sha256_hex(raw), "pt": obj}

        assert self._key_aes is not None
        nonce = os.urandom(12)
        ct = AESGCM(self._key_aes).encrypt(nonce, raw, aad)
        return {
            "v": 3,
            "alg": "AES-256-GCM",
            "nonce_b64": _b64e(nonce),
            "ct_b64": _b64e(ct),
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

        version = payload.get("v")
        if alg == "AES-256-GCM-DOUBLE" or version == 2:
            return self._decrypt_v2(payload, aad=aad)
        if version == 3:
            return self._decrypt_v3(payload, aad=aad)
        return self._decrypt_v1(payload, aad=aad)

    def decrypt_json_required(self, payload: dict[str, Any], *, aad: bytes = b"") -> dict[str, Any]:
        """Like decrypt_json but raises DecryptionError when verification fails."""
        alg = payload.get("alg")
        if alg == "none":
            if self.enabled:
                raise DecryptionError("Plaintext envelope rejected while encryption is enabled")
            pt = payload.get("pt")
            if isinstance(pt, dict):
                return pt
            raise DecryptionError("Invalid plaintext envelope")
        obj = self.decrypt_json(payload, aad=aad)
        if not obj:
            raise DecryptionError(f"Unable to decrypt envelope (alg={alg!r}, v={payload.get('v')})")
        return obj

    def _decrypt_v3(self, payload: dict[str, Any], *, aad: bytes) -> dict[str, Any]:
        assert self._key_aes is not None
        try:
            nonce = _b64d(str(payload["nonce_b64"]))
            ct = _b64d(str(payload["ct_b64"]))
        except Exception:
            return {}
        try:
            raw = AESGCM(self._key_aes).decrypt(nonce, ct, aad)
        except InvalidTag:
            return {}
        return self._parse_json_dict(raw)

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

        return self._parse_json_dict(raw)

    def _decrypt_v1(self, payload: dict[str, Any], *, aad: bytes) -> dict[str, Any]:
        """Backward-compatible single-layer decrypt (raw master key, pre-v3)."""
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

        return self._parse_json_dict(raw)

    @staticmethod
    def _parse_json_dict(raw: bytes) -> dict[str, Any]:
        try:
            text = raw.decode("utf-8")
            obj = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return obj if isinstance(obj, dict) else {}
