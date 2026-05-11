from __future__ import annotations

import base64
import os

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

