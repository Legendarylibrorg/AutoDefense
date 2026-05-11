from __future__ import annotations

import re
import unicodedata
from typing import Any

from app.core.models import AgentSignal, AnalyzeRequest, ThreatType


def _normalize(text: str) -> str:
    out = unicodedata.normalize("NFKC", text)
    out = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]", "", out)
    out = re.sub(r"\s+", " ", out)
    return out


class PolicyAgent:
    name = "policy"

    def __init__(self):
        pass

    async def analyze(
        self,
        req: AnalyzeRequest,
        *,
        sentinel_sanitized_input: str,
        runtime_policy: dict[str, Any],
    ) -> dict[str, Any]:
        signals: list[AgentSignal] = []

        text = sentinel_sanitized_input
        check_text = _normalize(text)
        blocked: list[str] = []
        for rx in runtime_policy.get("blocked_input_regexes", []):
            if re.search(rx, check_text, flags=re.IGNORECASE):
                blocked.append(rx)

        if blocked:
            signals.append(
                AgentSignal(
                    agent=self.name,
                    threat_type=ThreatType.policy_violation,
                    score=90.0,
                    confidence=0.85,
                    reasons=[f"Policy blocked input regex: {r}" for r in blocked],
                    evidence={"blocked_regexes": blocked},
                )
            )

        sanitized = _normalize(text)
        for rx in runtime_policy.get("sanitize_input_regexes", []):
            sanitized = re.sub(rx, "[[POLICY_REDACTED]]", sanitized, flags=re.IGNORECASE)

        return {"signals": signals, "sanitized_input": sanitized}
