from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DecisionAction(str, Enum):
    allow = "allow"
    log_monitor = "log_monitor"
    sanitize = "sanitize"
    block_isolate = "block_isolate"


class ThreatType(str, Enum):
    prompt_injection = "prompt_injection"
    jailbreak = "jailbreak"
    data_exfiltration = "data_exfiltration"
    tool_abuse = "tool_abuse"
    anomaly = "anomaly"
    policy_violation = "policy_violation"
    malware_in_file = "malware_in_file"
    rootkit = "rootkit"
    kernel_exploit = "kernel_exploit"
    kernel_integrity = "kernel_integrity"
    unknown = "unknown"


class AgentSignal(BaseModel):
    agent: str
    threat_type: ThreatType = ThreatType.unknown
    score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    reasons: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ArtifactKind(str, Enum):
    text = "text"
    email = "email"
    url = "url"
    file = "file"
    image = "image"


class Artifact(BaseModel):
    """
    Optional content that should be scanned deterministically *before* use.
    - For files/images: provide base64 in content_base64 (no host mounts required).
    - For emails/text: provide content_text.
    """

    kind: ArtifactKind
    name: str | None = Field(default=None, max_length=500)
    content_text: str | None = Field(default=None, max_length=200_000)
    content_base64: str | None = Field(default=None, max_length=12_000_000)
    content_type: str | None = Field(default=None, max_length=200)
    size_bytes: int | None = Field(default=None, ge=0, le=50_000_000)


_ID_PATTERN = r"^[a-zA-Z0-9\-_.:]{1,128}$"


class AnalyzeRequest(BaseModel):
    session_id: str = Field(
        default_factory=lambda: str(uuid4()), max_length=128, pattern=_ID_PATTERN
    )
    trace_id: str = Field(default_factory=lambda: str(uuid4()), max_length=128, pattern=_ID_PATTERN)

    user_input: str = Field(max_length=50_000)
    model_output: str | None = Field(default=None, max_length=100_000)

    tool_calls: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[Artifact] = Field(default_factory=list, max_length=50)

    @field_validator("metadata", mode="before")
    @classmethod
    def _limit_metadata(cls, v: Any) -> Any:
        if isinstance(v, dict) and len(str(v)) > 50_000:
            raise ValueError("metadata too large")
        return v


class AnalyzeResponse(BaseModel):
    session_id: str
    trace_id: str

    sanitized_input: str
    sanitized_output: str | None

    risk_score: int = Field(ge=0, le=100)
    action: DecisionAction
    explain: dict[str, Any]

    signals: list[AgentSignal]
    patches: list[dict[str, Any]] = Field(default_factory=list)


class ScanRequest(BaseModel):
    session_id: str = Field(
        default_factory=lambda: str(uuid4()), max_length=128, pattern=_ID_PATTERN
    )
    trace_id: str = Field(default_factory=lambda: str(uuid4()), max_length=128, pattern=_ID_PATTERN)
    artifacts: list[Artifact] = Field(default_factory=list, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScanResponse(BaseModel):
    session_id: str
    trace_id: str
    risk_score: int = Field(ge=0, le=100)
    action: DecisionAction
    explain: dict[str, Any]
    signals: list[AgentSignal] = Field(default_factory=list)


class Event(BaseModel):
    ts: datetime = Field(default_factory=utcnow)
    type: str = Field(max_length=100)
    trace_id: str = Field(max_length=128)
    session_id: str = Field(max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Kernel scanning models
# ---------------------------------------------------------------------------


class KernelFindingSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class KernelFindingCategory(str, Enum):
    rootkit = "rootkit"
    zero_day = "zero_day"
    integrity = "integrity"
    network = "network"


class KernelFinding(BaseModel):
    category: KernelFindingCategory
    severity: KernelFindingSeverity
    title: str = Field(max_length=300)
    detail: str = Field(max_length=2000)
    evidence: dict[str, Any] = Field(default_factory=dict)


class KernelScanPayload(BaseModel):
    platform: str = Field(max_length=50)
    kernel_version: str = Field(default="", max_length=200)
    hostname: str = Field(default="unknown", min_length=1, max_length=300)
    timestamp: str = Field(default="")
    in_container: bool = False
    findings: list[KernelFinding] = Field(default_factory=list, max_length=500)
    hardening: dict[str, Any] = Field(default_factory=dict)


class KernelScanResponse(BaseModel):
    accepted: bool
    findings_count: int
    risk_score: int = Field(ge=0, le=100)
    action: DecisionAction
    signals: list[AgentSignal] = Field(default_factory=list)
