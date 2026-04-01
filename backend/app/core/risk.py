from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.core.models import AgentSignal


@dataclass(frozen=True)
class WeightedSignal:
    agent: str
    weight: float


DEFAULT_WEIGHTS: dict[str, float] = {
    "sentinel": 0.35,
    "policy": 0.20,
    "behavior": 0.20,
    "artifact": 0.15,
    "kernel": 0.15,
    "forensics": 0.10,
}


def clamp_int(v: float, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(round(v))))


def aggregate_risk(
    signals: Iterable[AgentSignal], weights: dict[str, float] | None = None
) -> tuple[int, dict]:
    """
    Weighted aggregation that stays explainable.
    - Each agent contributes max(score * weight).
    - Confidence slightly attenuates contribution.
    """
    w = weights or DEFAULT_WEIGHTS
    contribs: list[dict] = []
    total = 0.0
    for s in signals:
        weight = float(w.get(s.agent, 0.15))
        contribution = float(s.score) * weight * (0.5 + 0.5 * float(s.confidence))
        total += contribution
        contribs.append(
            {
                "agent": s.agent,
                "threat_type": s.threat_type.value,
                "score": s.score,
                "confidence": s.confidence,
                "weight": weight,
                "contribution": round(contribution, 2),
                "reasons": s.reasons,
            }
        )

    strong = sum(1 for s in signals if s.score >= 70 and s.confidence >= 0.6)
    bump = 0.0
    if strong >= 2:
        bump = min(15.0, 5.0 * (strong - 1))
        total += bump

    # Deterministic floors for high-impact threat classes.
    # This prevents low-weight blends from incorrectly "allowing" clear threats.
    floors = 0.0
    for s in signals:
        tt = s.threat_type.value
        if tt in ("policy_violation", "malware_in_file", "rootkit"):
            floors = max(floors, 50.0)
        if tt in ("prompt_injection", "jailbreak", "kernel_exploit", "kernel_integrity",
                   "tool_abuse", "data_exfiltration"):
            floors = max(floors, 25.0)
    total += floors

    risk = clamp_int(total)
    explain = {"contributions": contribs, "strong_signal_bump": bump, "threat_floor_bump": floors}
    return risk, explain
 
