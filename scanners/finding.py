"""Shared finding dict shape for platform scanner scripts (kernel / macos / windows)."""

from __future__ import annotations

from typing import Any


def finding(
    category: str,
    severity: str,
    title: str,
    detail: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence or {},
    }
