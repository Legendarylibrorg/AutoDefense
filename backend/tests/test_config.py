from __future__ import annotations


async def test_get_config(client):
    res = await client.get("/config")
    assert res.status_code == 200
    body = res.json()
    assert "risk_allow_max" in body
    assert "blocked_input_regexes" in body


async def test_put_config_rejects_bad_thresholds(client):
    cfg = (await client.get("/config")).json()
    cfg["risk_allow_max"] = 90
    cfg["risk_monitor_max"] = 40
    cfg["risk_sanitize_max"] = 80
    res = await client.put("/config", json=cfg)
    assert res.status_code == 400
    detail = res.json()["detail"]
    assert "errors" in detail


async def test_put_config_accepts_and_versions(client):
    cfg = (await client.get("/config")).json()
    old_v = cfg["version"]
    cfg["risk_allow_max"] = 10
    cfg["risk_monitor_max"] = 20
    cfg["risk_sanitize_max"] = 30
    res = await client.put("/config", json=cfg)
    assert res.status_code == 200
    body = res.json()
    assert body["version"] >= old_v + 1
    assert body["risk_allow_max"] == 10

