from __future__ import annotations

import base64


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


async def test_scan_blocks_dangerous_download_extension(client):
    res = await client.post(
        "/scan",
        json={
            "artifacts": [
                {
                    "kind": "file",
                    "name": "invoice.exe",
                    "content_base64": b64(b"MZ" + b"\x00" * 64),
                    "content_type": "application/octet-stream",
                    "size_bytes": 66,
                }
            ]
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["action"] in ("sanitize", "block_isolate")
    assert body["risk_score"] >= 50
    assert any(s["threat_type"] in ("policy_violation", "malware_in_file") for s in body["signals"])


async def test_scan_blocks_invalid_image_magic(client):
    res = await client.post(
        "/scan",
        json={
            "artifacts": [
                {
                    "kind": "image",
                    "name": "pic.png",
                    "content_base64": b64(b"NOTANIMAGE" * 50),
                    "content_type": "image/png",
                    "size_bytes": 500,
                }
            ]
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["risk_score"] >= 1
    assert any("magic bytes" in " ".join(s.get("reasons", [])).lower() for s in body["signals"])


async def test_scan_warns_non_http_url(client):
    res = await client.post(
        "/scan", json={"artifacts": [{"kind": "url", "content_text": "file:///etc/passwd"}]}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["risk_score"] >= 1
    assert any(s["threat_type"] == "anomaly" for s in body["signals"])
