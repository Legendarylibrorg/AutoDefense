from __future__ import annotations

import re
from typing import Any

from app.core.models import AgentSignal, AnalyzeRequest, ThreatType
from app.core.text import normalize_for_matching


class PolicyAgent:
    name = "policy"

    async def analyze(
        self,
        req: AnalyzeRequest,  # noqa: ARG002 — kept for pipeline API symmetry
        *,
        sentinel_sanitized_input: str,
        runtime_policy: dict[str, Any],
    ) -> dict[str, Any]:
        signals: list[AgentSignal] = []

        text = sentinel_sanitized_input
        check_text = normalize_for_matching(text)
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

        sanitized = normalize_for_matching(text)
        for rx in runtime_policy.get("sanitize_input_regexes", []):
            sanitized = re.sub(rx, "[[POLICY_REDACTED]]", sanitized, flags=re.IGNORECASE)

        return {"signals": signals, "sanitized_input": sanitized}
