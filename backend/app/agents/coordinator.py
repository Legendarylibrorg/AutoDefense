from __future__ import annotations

from collections import Counter
from typing import Any

from app.core.models import AgentSignal, AnalyzeRequest
from app.core.response_engine import risk_score_to_decision_action
from app.core.risk import aggregate_risk


class CoordinatorAgent:
    name = "coordinator"

    async def decide(
        self,
        *,
        req: AnalyzeRequest,  # noqa: ARG002 — reserved for future request-aware routing
        signals: list[AgentSignal],
        sanitized_input: str,
        sanitized_output: str | None,
        thresholds: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        risk, explain = aggregate_risk(signals)

        threat_types = [s.threat_type.value for s in signals if s.score > 0]
        threat_counts = Counter(threat_types)

        top_reasons: list[str] = []
        for s in sorted(signals, key=lambda x: x.score * x.confidence, reverse=True)[:4]:
            top_reasons.extend([f"{s.agent}: {r}" for r in s.reasons[:3]])

        t = thresholds or {}
        allow_max = int(t.get("risk_allow_max", 30))
        monitor_max = int(t.get("risk_monitor_max", 60))
        sanitize_max = int(t.get("risk_sanitize_max", 80))

        action = risk_score_to_decision_action(
            risk,
            risk_allow_max=allow_max,
            risk_monitor_max=monitor_max,
            risk_sanitize_max=sanitize_max,
        ).value

        explain_out = {
            "risk": risk,
            "action": action,
            "threat_types": list(threat_counts.keys()),
            "threat_counts": dict(threat_counts),
            "top_reasons": top_reasons[:12],
            **explain,
        }

        return {
            "risk_score": risk,
            "action": action,
            "sanitized_input": sanitized_input,
            "sanitized_output": sanitized_output,
            "explain": explain_out,
        }
