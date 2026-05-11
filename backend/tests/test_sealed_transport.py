from __future__ import annotations

import base64
from typing import Any

import pytest
from httpx import Response

from crypto_helpers import transport_seal_v2


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _assert_unseal_rejected(res: Response) -> None:
    assert res.status_code == 400
    assert "unseal" in res.json()["detail"].lower()


@pytest.mark.parametrize(
    ("path", "aad", "payload"),
    (
        (
            "/scan/sealed",
            b"scan",
            {"artifacts": [{"kind": "url", "content_text": "file:///etc/passwd"}]},
        ),
        (
            "/analyze/sealed",
            b"analyze",
            {"user_input": "hello", "model_output": "ok"},
        ),
    ),
)
async def test_sealed_v2_roundtrip(client, path: str, aad: bytes, payload: dict[str, Any]) -> None:
    env = transport_seal_v2(payload, aad=aad)
    res = await client.post(path, json={"sealed": env})
    assert res.status_code == 200
    data = res.json()

    for key in ("session_id", "trace_id", "risk_score", "action", "explain", "signals"):
        assert key in data
    assert isinstance(data["risk_score"], int)
    assert 0 <= data["risk_score"] <= 100
    assert data["action"] in ("allow", "log_monitor", "sanitize", "block_isolate")

    if path == "/scan/sealed":
        assert data["risk_score"] >= 1
        assert any(s.get("threat_type") == "anomaly" for s in data["signals"])
    else:
        assert "sanitized_input" in data
        assert "sanitized_output" in data
        assert "patches" in data


async def test_sealed_v2_wrong_aad_rejected(client) -> None:
    env = transport_seal_v2({"user_input": "hello"}, aad=b"scan")
    _assert_unseal_rejected(await client.post("/analyze/sealed", json={"sealed": env}))


async def test_sealed_v2_tampered_outer_ciphertext_rejected(client) -> None:
    env = transport_seal_v2({"user_input": "hello"}, aad=b"analyze")
    ct = bytearray(base64.b64decode(env["ct_b64"]))
    ct[0] ^= 0xFF
    env["ct_b64"] = _b64(bytes(ct))
    _assert_unseal_rejected(await client.post("/analyze/sealed", json={"sealed": env}))


async def test_sealed_v2_tampered_hmac_rejected(client) -> None:
    env = transport_seal_v2({"user_input": "hello"}, aad=b"analyze")
    h = env["hmac"]
    env["hmac"] = h[:-1] + ("0" if h[-1] != "0" else "1")
    _assert_unseal_rejected(await client.post("/analyze/sealed", json={"sealed": env}))
