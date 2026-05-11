from __future__ import annotations

from typing import Any

from app.core.models import (
    AgentSignal,
    KernelFinding,
    KernelFindingCategory,
    KernelFindingSeverity,
    ThreatType,
)

SEVERITY_SCORE: dict[KernelFindingSeverity, tuple[float, float]] = {
    KernelFindingSeverity.critical: (95.0, 0.90),
    KernelFindingSeverity.high: (80.0, 0.80),
    KernelFindingSeverity.medium: (55.0, 0.70),
    KernelFindingSeverity.low: (30.0, 0.60),
    KernelFindingSeverity.info: (0.0, 0.50),
}

CATEGORY_THREAT: dict[KernelFindingCategory, ThreatType] = {
    KernelFindingCategory.rootkit: ThreatType.rootkit,
    KernelFindingCategory.zero_day: ThreatType.kernel_exploit,
    KernelFindingCategory.integrity: ThreatType.kernel_integrity,
    KernelFindingCategory.network: ThreatType.anomaly,
}


class KernelAgent:
    name = "kernel"

    def analyze(self, findings: list[KernelFinding]) -> dict[str, Any]:
        signals: list[AgentSignal] = []

        for f in findings:
            score, confidence = SEVERITY_SCORE.get(f.severity, (0.0, 0.5))
            if score == 0.0:
                continue

            threat = CATEGORY_THREAT.get(f.category, ThreatType.unknown)
            signals.append(
                AgentSignal(
                    agent=self.name,
                    threat_type=threat,
                    score=score,
                    confidence=confidence,
                    reasons=[f.title],
                    evidence={
                        "category": f.category.value,
                        "severity": f.severity.value,
                        "detail": f.detail,
                        **f.evidence,
                    },
                )
            )

        return {"signals": signals}
