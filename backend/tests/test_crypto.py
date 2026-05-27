from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.crypto import (
    CryptoKeyError,
    CryptoManager,
    DecryptionError,
    decode_master_key,
    validate_scanner_hmac_key,
)


def test_crypto_v3_encrypt_decrypt_roundtrip():
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    assert c.enabled
    obj = {"a": 1, "b": "x", "nested": {"k": True}}
    env = c.encrypt_json(obj, aad=b"test")
    assert env["v"] == 3
    assert env["alg"] == "AES-256-GCM"
    assert "nonce_b64" in env
    assert "hmac" not in env
    out = c.decrypt_json(env, aad=b"test")
    assert out == obj


def test_crypto_aad_mismatch_fails_closed():
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    env = c.encrypt_json({"a": 1}, aad=b"a")
    out = c.decrypt_json(env, aad=b"b")
    assert out == {}


def test_crypto_v2_decrypt_backward_compat():
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    raw = json.dumps({"legacy": True}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    assert c._key_inner and c._key_outer and c._key_hmac
    inner_nonce = os.urandom(12)
    inner_ct = AESGCM(c._key_inner).encrypt(inner_nonce, raw, b"ctx")
    outer_nonce = os.urandom(12)
    outer_ct = AESGCM(c._key_outer).encrypt(outer_nonce, inner_ct, b"ctx")
    mac = _hmac.new(c._key_hmac, raw, hashlib.sha256).hexdigest()
    env = {
        "v": 2,
        "alg": "AES-256-GCM-DOUBLE",
        "inner_nonce_b64": base64.b64encode(inner_nonce).decode("ascii"),
        "outer_nonce_b64": base64.b64encode(outer_nonce).decode("ascii"),
        "ct_b64": base64.b64encode(outer_ct).decode("ascii"),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "hmac": mac,
    }
    assert c.decrypt_json(env, aad=b"ctx") == {"legacy": True}


def test_crypto_decrypt_required_raises_on_failure():
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    env = c.encrypt_json({"a": 1}, aad=b"t")
    with pytest.raises(DecryptionError):
        c.decrypt_json_required(env, aad=b"wrong")


def test_crypto_invalid_master_key_raises():
    with pytest.raises(CryptoKeyError):
        CryptoManager("not-valid-base64!!!")
    short = base64.b64encode(b"short").decode("ascii")
    with pytest.raises(CryptoKeyError):
        decode_master_key(short)


def test_crypto_decrypt_rejects_malformed_json_utf8():
    key_b64 = base64.b64encode(os.urandom(32)).decode("ascii")
    c = CryptoManager(key_b64)
    raw = b"\xff\xfe invalid utf8"
    assert c._key_aes is not None
    nonce = os.urandom(12)
    ct = AESGCM(c._key_aes).encrypt(nonce, raw, b"x")
    env = {
        "v": 3,
        "alg": "AES-256-GCM",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ct_b64": base64.b64encode(ct).decode("ascii"),
    }
    assert c.decrypt_json(env, aad=b"x") == {}


def test_crypto_v1_rejects_missing_sha256():
    key = os.urandom(32)
    key_b64 = base64.b64encode(key).decode("ascii")
    c = CryptoManager(key_b64)
    raw = json.dumps({"a": 1}, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, raw, b"ctx")
    env = {
        "v": 1,
        "alg": "AES-256-GCM",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ct_b64": base64.b64encode(ct).decode("ascii"),
    }
    assert c.decrypt_json(env, aad=b"ctx") == {}


def test_validate_scanner_hmac_key_min_length():
    validate_scanner_hmac_key("a" * 16)
    with pytest.raises(CryptoKeyError):
        validate_scanner_hmac_key("short")
