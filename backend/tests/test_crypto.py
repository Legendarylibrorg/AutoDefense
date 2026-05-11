from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.crypto import CryptoManager


def test_crypto_encrypt_decrypt_roundtrip():
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    assert c.enabled
    obj = {"a": 1, "b": "x", "nested": {"k": True}}
    env = c.encrypt_json(obj, aad=b"test")
    out = c.decrypt_json(env, aad=b"test")
    assert out == obj


def test_crypto_aad_mismatch_fails_closed():
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    env = c.encrypt_json({"a": 1}, aad=b"a")
    out = c.decrypt_json(env, aad=b"b")
    assert out == {}


def test_crypto_v2_requires_hmac():
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    env = c.encrypt_json({"a": 1}, aad=b"t")
    del env["hmac"]
    assert c.decrypt_json(env, aad=b"t") == {}


def test_crypto_v2_requires_sha256():
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    env = c.encrypt_json({"a": 1}, aad=b"t")
    del env["sha256"]
    assert c.decrypt_json(env, aad=b"t") == {}


def test_crypto_decrypt_rejects_malformed_json_utf8():
    """Invalid UTF-8 after successful AEAD should not raise."""
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    raw = b"\xff\xfe invalid utf8"
    inner_nonce = os.urandom(12)
    inner_ct = AESGCM(c._key_inner).encrypt(inner_nonce, raw, b"x")  # type: ignore[attr-defined]
    outer_nonce = os.urandom(12)
    outer_ct = AESGCM(c._key_outer).encrypt(outer_nonce, inner_ct, b"x")  # type: ignore[attr-defined]
    mac = _hmac.new(c._key_hmac, raw, hashlib.sha256).hexdigest()  # type: ignore[attr-defined]
    env = {
        "v": 2,
        "alg": "AES-256-GCM-DOUBLE",
        "inner_nonce_b64": base64.b64encode(inner_nonce).decode("ascii"),
        "outer_nonce_b64": base64.b64encode(outer_nonce).decode("ascii"),
        "ct_b64": base64.b64encode(outer_ct).decode("ascii"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "hmac": mac,
    }
    assert c.decrypt_json(env, aad=b"x") == {}


def test_crypto_v1_rejects_missing_sha256():
    key = os.urandom(32)
    key_b64 = base64.b64encode(key).decode("ascii")
    c = CryptoManager(key_b64)
    raw = json.dumps({"a": 1}, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, raw, b"ctx")
    env = {
        "v": 1,
        "alg": "AES-256-GCM",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ct_b64": base64.b64encode(ct).decode("ascii"),
    }
    assert c.decrypt_json(env, aad=b"ctx") == {}

