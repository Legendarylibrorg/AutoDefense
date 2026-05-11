from __future__ import annotations

import json
import logging
import re
import threading
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from app.core.crypto import STORE_ENVELOPE_ALGS, CryptoManager
from app.settings import settings

logger = logging.getLogger("autodefense.rules_store")


def _is_safe_regex(pattern: str) -> bool:
    """Reject regexes with nested quantifiers or that hang on a test string."""
    if not isinstance(pattern, str) or len(pattern) > 300:
        return False
    try:
        compiled = re.compile(pattern)
    except re.error:
        return False
    if re.search(r"\([^)]*[+*][^)]*\)[+*]", compiled.pattern):
        return False
    result = [True]

    def _run():
        try:
            re.search(pattern, "a" * 50 + "!" + "a" * 50, flags=re.IGNORECASE)
        except Exception:
            result[0] = False

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=0.5)
    if t.is_alive():
        return False
    return result[0]


def _filter_safe_regexes(patterns: list) -> list[str]:
    """Return only regexes that compile and pass ReDoS checks."""
    safe: list[str] = []
    for p in patterns:
        if _is_safe_regex(p):
            safe.append(p)
        else:
            logger.warning("Dropping unsafe/invalid dynamic regex: %s", str(p)[:80])
    return safe


@dataclass
class DynamicRules:
    version: int
    injection_regex_append: list[str]
    exfil_regex_append: list[str]


class RulesStore:
    KEY = "autodefense:dynamic_rules:v1"

    def __init__(self, redis: Redis):
        self.redis = redis
        self.crypto = CryptoManager(settings.data_key_b64 if settings.data_encryption_enabled else None)

    async def load(self) -> DynamicRules:
        raw = await self.redis.get(self.KEY)
        if not raw:
            return DynamicRules(version=1, injection_regex_append=[], exfil_regex_append=[])
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="replace")
        data = json.loads(raw)
        if isinstance(data, dict) and data.get("alg") in STORE_ENVELOPE_ALGS:
            data = self.crypto.decrypt_json(data, aad=b"dynamic_rules")
        return DynamicRules(
            version=int(data.get("version", 1)),
            injection_regex_append=_filter_safe_regexes(data.get("injection_regex_append", [])),
            exfil_regex_append=_filter_safe_regexes(data.get("exfil_regex_append", [])),
        )

    async def save(self, rules: DynamicRules) -> None:
        payload: dict[str, Any] = {
            "version": rules.version,
            "injection_regex_append": rules.injection_regex_append,
            "exfil_regex_append": rules.exfil_regex_append,
        }
        wrapped = self.crypto.encrypt_json(payload, aad=b"dynamic_rules")
        await self.redis.set(self.KEY, json.dumps(wrapped, ensure_ascii=False))

