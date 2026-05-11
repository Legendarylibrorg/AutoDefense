from __future__ import annotations

import re
from typing import Any

from redis.asyncio import Redis

from app.core.event_bus import EventBus
from app.core.models import AnalyzeRequest, Event, ThreatType
from app.core.rules_store import DynamicRules, RulesStore
from app.settings import settings


class SelfHealingEngine:
    def __init__(self, redis: Redis):
        self.redis = redis
        self.bus = EventBus(redis)
        self.store = RulesStore(redis)

    def _build_patches(
        self, dyn: DynamicRules, req: AnalyzeRequest, decision: dict[str, Any]
    ) -> list[dict[str, Any]]:
        patches: list[dict[str, Any]] = []
        threats = decision.get("explain", {}).get("threat_types", [])
        text = (req.user_input or "")[:2000]

        if ThreatType.prompt_injection.value in threats:
            suggested = self._suggest_injection_regex(text)
            if suggested and suggested not in dyn.injection_regex_append:
                dyn.injection_regex_append.append(suggested)
                patches.append(
                    {
                        "type": "guardrail_update",
                        "issue": "prompt injection",
                        "fix": "block instruction-override pattern",
                        "implementation": {"append_regex": suggested},
                    }
                )

        if ThreatType.jailbreak.value in threats:
            suggested = self._suggest_jailbreak_regex(text)
            if suggested and suggested not in dyn.injection_regex_append:
                dyn.injection_regex_append.append(suggested)
                patches.append(
                    {
                        "type": "guardrail_update",
                        "issue": "jailbreak",
                        "fix": "block jailbreak persona pattern",
                        "implementation": {"append_regex": suggested},
                    }
                )

        if ThreatType.data_exfiltration.value in threats:
            suggested = self._suggest_exfil_regex(text)
            if suggested and suggested not in dyn.exfil_regex_append:
                dyn.exfil_regex_append.append(suggested)
                patches.append(
                    {
                        "type": "guardrail_update",
                        "issue": "data exfiltration",
                        "fix": "block exfiltration prompt pattern",
                        "implementation": {"append_regex": suggested},
                    }
                )

        if ThreatType.tool_abuse.value in threats:
            suggested = self._suggest_tool_abuse_regex(text)
            if suggested and suggested not in dyn.injection_regex_append:
                dyn.injection_regex_append.append(suggested)
                patches.append(
                    {
                        "type": "guardrail_update",
                        "issue": "tool abuse / code execution",
                        "fix": "block dangerous command pattern",
                        "implementation": {"append_regex": suggested},
                    }
                )

        dyn.injection_regex_append = dyn.injection_regex_append[
            : settings.self_heal_max_rule_growth
        ]
        dyn.exfil_regex_append = dyn.exfil_regex_append[: settings.self_heal_max_rule_growth]
        return patches

    async def ingest_incident(
        self, *, req: AnalyzeRequest, decision: dict[str, Any]
    ) -> dict[str, Any]:
        if not settings.self_heal_enabled:
            return {"patches": []}

        await self.bus.publish(
            Event(
                type="incident.detected",
                trace_id=req.trace_id,
                session_id=req.session_id,
                payload={
                    "risk_score": decision.get("risk_score"),
                    "action": decision.get("action"),
                    "top_reasons": decision.get("explain", {}).get("top_reasons", []),
                },
            )
        )

        patches, new_version = await self.store.merge_update(
            lambda dyn: self._build_patches(dyn, req, decision)
        )

        if patches and new_version is not None:
            await self.bus.publish(
                Event(
                    type="self_heal.applied",
                    trace_id=req.trace_id,
                    session_id=req.session_id,
                    payload={"patches": patches, "rules_version": new_version},
                )
            )

        return {"patches": patches}

    def _suggest_injection_regex(self, text: str) -> str | None:
        patterns = [
            r"ignore (all|any) (previous|prior) (instructions|directions)",
            r"disregard (the )?(system|developer) message",
            r"reveal (the )?(system prompt|hidden instructions)",
            r"override (security|safety) (rules|policy)",
            r"bypass (the )?(filter|safety|content|restriction)",
            r"forget (everything|all) (above|previous|prior)",
            r"do not follow (the )?(rules|policies|guidelines)",
            r"(new|updated) (instructions|rules|policy):",
        ]
        for p in patterns:
            if re.search(p, text, flags=re.IGNORECASE):
                return p
        return None

    def _suggest_jailbreak_regex(self, text: str) -> str | None:
        patterns = [
            r"you are now (DAN|developer mode|unfiltered|unrestricted)",
            r"(enable|activate) (DAN|developer|jailbreak) mode",
            r"(pretend|act|imagine) (you are|to be) (evil|malicious|unfiltered)",
            r"from now on,? you (will|must|shall)",
            r"respond without (any )?(filter|safety|restriction)",
            r"(you are|you'?re) no longer (bound by|subject to|limited by)",
            r"stay in (DAN|developer|character) mode",
            r"(dual|split|two) (response|answer|output) mode",
        ]
        for p in patterns:
            if re.search(p, text, flags=re.IGNORECASE):
                return p
        return None

    def _suggest_exfil_regex(self, text: str) -> str | None:
        patterns = [
            r"(api|access|secret) key",
            r"dump (all )?(env|environment) variables",
            r"print .*password",
            r"(show|display|read) .{0,20}(credential|secret|token)",
            r"(cat|read) .{0,20}(/etc/passwd|/etc/shadow|\.env|\.ssh/)",
            r"(connection string|database url|db_password)",
            r"(send|post|upload) .{0,20}(to |via )?(http|external|server)",
        ]
        for p in patterns:
            if re.search(p, text, flags=re.IGNORECASE):
                return p
        return None

    def _suggest_tool_abuse_regex(self, text: str) -> str | None:
        patterns = [
            r"rm\s+-rf\s+/",
            r"format\s+c:",
            r"(reverse|bind)\s+shell",
            r"(sudo|su\s+root)",
            r"chmod\s+(777|\+s)",
            r"(drop|delete|truncate)\s+(table|database)",
            r"docker\s+run\s+--privileged",
            r"kubectl\s+delete",
            r"terraform\s+destroy",
        ]
        for p in patterns:
            if re.search(p, text, flags=re.IGNORECASE):
                return p
        return None
