from __future__ import annotations

from collections import Counter
from typing import Any

from app.core.models import AgentSignal, AnalyzeRequest
from app.core.risk import aggregate_risk


class CoordinatorAgent:
    name = "coordinator"

    async def decide(
        self,
        *,
        req: AnalyzeRequest,
        signals: list[AgentSignal],
        sanitized_input: str,
        sanitized_output: str | None,
        thresholds: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        risk, explain = aggregate_risk(signals)

        threat_types = [s.threat_type.value for s in signals if s.score > 0]
        threat_counts = Counter(threat_types)

        top_reasons: list[str] = []
        for s in sorted(signals, key=lambda x: (x.score * x.confidence), reverse=True)[:4]:
            top_reasons.extend([f"{s.agent}: {r}" for r in s.reasons[:3]])

        t = thresholds or {}
        allow_max = int(t.get("risk_allow_max", 30))
        monitor_max = int(t.get("risk_monitor_max", 60))
        sanitize_max = int(t.get("risk_sanitize_max", 80))

        if risk <= allow_max:
            action = "allow"
        elif risk <= monitor_max:
            action = "log_monitor"
        elif risk <= sanitize_max:
            action = "sanitize"
        else:
            action = "block_isolate"

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
 
