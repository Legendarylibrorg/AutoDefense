from __future__ import annotations

import json
import logging
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from redis.asyncio import Redis

from app.core.crypto import STORE_ENVELOPE_ALGS, CryptoManager
from app.settings import settings

logger = logging.getLogger("autodefense.config_store")

_RE_PROBE = "a" * 50 + "!" + "a" * 50


def _regex_probe_timed(pattern: str) -> bool:
    """Return True if ``re.search`` on a worst-case probe finishes within ~0.5s."""
    ok: list[bool] = [True]

    def _run() -> None:
        try:
            re.search(pattern, _RE_PROBE, flags=re.IGNORECASE)
        except Exception:
            ok[0] = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=0.5)
    if t.is_alive():
        return False
    return ok[0]


def _is_safe_regex(pattern: str) -> bool:
    """Compilable, no nested quantifiers, and no ReDoS on probe."""
    if not isinstance(pattern, str) or len(pattern) > 300:
        return False
    try:
        compiled = re.compile(pattern)
    except re.error:
        return False
    if re.search(r"\([^)]*[+*][^)]*\)[+*]", compiled.pattern):
        return False
    return _regex_probe_timed(pattern)


def _filter_safe_regexes(patterns: list) -> list[str]:
    safe: list[str] = []
    for p in patterns:
        if _is_safe_regex(p):
            safe.append(p)
        else:
            logger.warning("Dropping unsafe/invalid config regex on load: %s", str(p)[:80])
    return safe


def _load_baseline_policy() -> dict[str, Any]:
    p = Path(__file__).resolve().parents[1] / "policies" / "default_policy.json"
    return json.loads(p.read_text(encoding="utf-8"))


_BASELINE_POLICY_CACHE: dict[str, Any] | None = None


def _get_baseline_policy() -> dict[str, Any]:
    global _BASELINE_POLICY_CACHE
    if _BASELINE_POLICY_CACHE is None:
        _BASELINE_POLICY_CACHE = _load_baseline_policy()
    return _BASELINE_POLICY_CACHE


@dataclass
class RuntimeConfig:
    version: int
    risk_allow_max: int
    risk_monitor_max: int
    risk_sanitize_max: int
    self_heal_enabled: bool
    blocked_input_regexes: list[str]
    sanitize_input_regexes: list[str]


def risk_thresholds(cfg: RuntimeConfig) -> dict[str, int]:
    """Shared shape for coordinator / ResponseEngine / scan path."""
    return {
        "risk_allow_max": cfg.risk_allow_max,
        "risk_monitor_max": cfg.risk_monitor_max,
        "risk_sanitize_max": cfg.risk_sanitize_max,
    }


def runtime_policy_for_agents(cfg: RuntimeConfig) -> dict[str, Any]:
    """PolicyAgent input: runtime regex lists from stored config."""
    return {
        "blocked_input_regexes": cfg.blocked_input_regexes,
        "sanitize_input_regexes": cfg.sanitize_input_regexes,
    }


class ConfigStore:
    KEY = "autodefense:runtime_config:v1"

    def __init__(self, redis: Redis):
        self.redis = redis
        self._baseline = _get_baseline_policy()
        self.crypto = CryptoManager(
            settings.data_key_b64 if settings.data_encryption_enabled else None
        )

    def defaults(self) -> RuntimeConfig:
        return RuntimeConfig(
            version=1,
            risk_allow_max=settings.risk_allow_max,
            risk_monitor_max=settings.risk_monitor_max,
            risk_sanitize_max=settings.risk_sanitize_max,
            self_heal_enabled=settings.self_heal_enabled,
            blocked_input_regexes=list(self._baseline.get("blocked_input_regexes", [])),
            sanitize_input_regexes=list(self._baseline.get("sanitize_input_regexes", [])),
        )

    async def load(self) -> RuntimeConfig:
        raw = await self.redis.get(self.KEY)
        if not raw:
            return self.defaults()
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="replace")
        data = json.loads(raw)
        # encrypted envelope support
        if isinstance(data, dict) and data.get("alg") in STORE_ENVELOPE_ALGS:
            data = self.crypto.decrypt_json(data, aad=b"runtime_config")
        d = self.defaults()
        return RuntimeConfig(
            version=int(data.get("version", d.version)),
            risk_allow_max=int(data.get("risk_allow_max", d.risk_allow_max)),
            risk_monitor_max=int(data.get("risk_monitor_max", d.risk_monitor_max)),
            risk_sanitize_max=int(data.get("risk_sanitize_max", d.risk_sanitize_max)),
            self_heal_enabled=bool(data.get("self_heal_enabled", d.self_heal_enabled)),
            blocked_input_regexes=_filter_safe_regexes(
                data.get("blocked_input_regexes", d.blocked_input_regexes)
            ),
            sanitize_input_regexes=_filter_safe_regexes(
                data.get("sanitize_input_regexes", d.sanitize_input_regexes)
            ),
        )

    def validate(self, cfg: RuntimeConfig) -> list[str]:
        errs: list[str] = []
        if not (0 <= cfg.risk_allow_max <= cfg.risk_monitor_max <= cfg.risk_sanitize_max <= 100):
            errs.append("Thresholds must satisfy 0 <= allow <= monitor <= sanitize <= 100")

        def _validate_regex_list(name: str, xs: list[str]):
            if len(xs) > 200:
                errs.append(f"{name} too large (max 200)")
                return
            for rx in xs:
                if not isinstance(rx, str) or len(rx) > 300:
                    errs.append(f"{name} contains invalid/too-long regex")
                    continue
                try:
                    compiled = re.compile(rx)
                except Exception:
                    errs.append(f"{name} contains invalid regex: {rx}")
                    continue
                # ReDoS guard: reject patterns with nested quantifiers / known
                # catastrophic backtracking constructs like (a+)+, (a*)*,
                # (a|b+)*, or (.+.+)+  which cause exponential runtime.
                raw = compiled.pattern
                if re.search(r"\([^)]*[+*][^)]*\)[+*]", raw):
                    errs.append(f"{name} contains unsafe regex (nested quantifiers): {rx[:80]}")
                    continue
                # Reject excessive use of alternation with overlapping quantifiers
                if raw.count("|") > 20:
                    errs.append(f"{name} regex has excessive alternation (>20 branches): {rx[:80]}")
                    continue
                if not _regex_probe_timed(rx):
                    errs.append(
                        f"{name} regex causes excessive backtracking (ReDoS risk): {rx[:80]}"
                    )

        _validate_regex_list("blocked_input_regexes", cfg.blocked_input_regexes)
        _validate_regex_list("sanitize_input_regexes", cfg.sanitize_input_regexes)
        return errs

    async def save(self, cfg: RuntimeConfig) -> None:
        payload: dict[str, Any] = {
            "version": cfg.version,
            "risk_allow_max": cfg.risk_allow_max,
            "risk_monitor_max": cfg.risk_monitor_max,
            "risk_sanitize_max": cfg.risk_sanitize_max,
            "self_heal_enabled": cfg.self_heal_enabled,
            "blocked_input_regexes": cfg.blocked_input_regexes,
            "sanitize_input_regexes": cfg.sanitize_input_regexes,
        }
        wrapped = self.crypto.encrypt_json(payload, aad=b"runtime_config")
        await self.redis.set(self.KEY, json.dumps(wrapped, ensure_ascii=False))
