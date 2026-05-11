from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def seal(obj: dict, *, aad: bytes) -> dict:
    key = b"\x00" * 32
    nonce = b"\x01" * 12
    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode(
        "utf-8"
    )
    sha256 = hashlib.sha256(raw).hexdigest()
    ct = AESGCM(key).encrypt(nonce, raw, aad)
    return {
        "v": 1,
        "alg": "AES-256-GCM",
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ct_b64": base64.b64encode(ct).decode("ascii"),
        "sha256": sha256,
    }


async def test_scan_sealed_roundtrip(client):
    env = seal({"artifacts": [{"kind": "url", "content_text": "file:///etc/passwd"}]}, aad=b"scan")
    res = await client.post("/scan/sealed", json={"sealed": env})
    assert res.status_code == 200
    body = res.json()
    assert "risk_score" in body


async def test_analyze_sealed_roundtrip(client):
    env = seal({"user_input": "hello", "model_output": "ok"}, aad=b"analyze")
    res = await client.post("/analyze/sealed", json={"sealed": env})
    assert res.status_code == 200
    body = res.json()
    assert "risk_score" in body
