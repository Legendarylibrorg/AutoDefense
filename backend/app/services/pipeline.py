from __future__ import annotations

import asyncio
import logging
from typing import Any

from redis.asyncio import Redis

from app.agents.artifact import ArtifactAgent
from app.agents.behavior import BehaviorAgent
from app.agents.coordinator import CoordinatorAgent
from app.agents.forensics import ForensicsAgent
from app.agents.policy import PolicyAgent
from app.agents.sentinel import SentinelAgent
from app.core.config_store import ConfigStore, risk_thresholds, runtime_policy_for_agents
from app.core.event_bus import EventBus
from app.core.models import AnalyzeRequest, AnalyzeResponse, Event, ScanRequest, ScanResponse
from app.core.response_engine import ResponseEngine, risk_score_to_decision_action
from app.core.risk import aggregate_risk
from app.core.rules_store import RulesStore
from app.core.self_heal import SelfHealingEngine

logger = logging.getLogger("autodefense.pipeline")


class DefensePipeline:
    def __init__(self, redis: Redis):
        self.redis = redis
        self.bus = EventBus(redis)

        self.sentinel = SentinelAgent()
        self.policy = PolicyAgent()
        self.behavior = BehaviorAgent()
        self.artifact = ArtifactAgent()
        self.forensics = ForensicsAgent(redis)
        self.coordinator = CoordinatorAgent()
        self.response_engine = ResponseEngine()
        self.self_heal = SelfHealingEngine(redis)

    async def run(self, req: AnalyzeRequest) -> AnalyzeResponse:
        cfg_store = ConfigStore(self.redis)
        cfg = await cfg_store.load()
        runtime_policy = runtime_policy_for_agents(cfg)
        thresholds = risk_thresholds(cfg)

        await self.bus.publish(
            Event(
                type="request.received",
                trace_id=req.trace_id,
                session_id=req.session_id,
                payload={
                    "has_output": req.model_output is not None,
                    "tool_calls": len(req.tool_calls),
                    "artifacts": len(req.artifacts),
                },
            )
        )

        dynamic_rules = await RulesStore(self.redis).load()

        artifact, sentinel, behavior = await asyncio.gather(
            self.artifact.analyze(req.artifacts),
            self.sentinel.analyze(req, dynamic=dynamic_rules),
            self.behavior.analyze(req),
        )
        policy = await self.policy.analyze(
            req,
            sentinel_sanitized_input=sentinel["sanitized_input"],
            runtime_policy=runtime_policy,
        )

        signals = (
            artifact["signals"] + policy["signals"] + sentinel["signals"] + behavior["signals"]
        )

        decision = await self.coordinator.decide(
            req=req,
            signals=signals,
            sanitized_input=policy["sanitized_input"],
            sanitized_output=behavior["sanitized_output"],
            thresholds=thresholds,
        )

        # Attach artifact summary to explain output deterministically (purely informational)
        decision["explain"]["artifact_summary"] = artifact.get("artifact_summary", [])

        await self.forensics.record(
            req=req,
            decision=decision,
            sanitized_input=decision.get("sanitized_input"),
        )

        patches: list[dict[str, Any]] = []
        if decision["action"] in ("sanitize", "block_isolate") and cfg.self_heal_enabled:
            incident = await self.self_heal.ingest_incident(req=req, decision=decision)
            patches = incident.get("patches", [])

        response = self.response_engine.apply(
            session_id=req.session_id,
            trace_id=req.trace_id,
            sanitized_input=decision["sanitized_input"],
            sanitized_output=decision["sanitized_output"],
            risk_score=decision["risk_score"],
            action=decision["action"],
            explain=decision["explain"],
            signals=signals,
            patches=patches,
            thresholds=thresholds,
        )

        await self.bus.publish(
            Event(
                type=f"decision.{response.action.value}",
                trace_id=req.trace_id,
                session_id=req.session_id,
                payload={
                    "risk_score": response.risk_score,
                    "signals": [s.model_dump(mode="json") for s in response.signals],
                },
            )
        )

        return response

    async def scan(self, req: ScanRequest) -> ScanResponse:
        cfg = await ConfigStore(self.redis).load()
        thresholds = risk_thresholds(cfg)

        await self.bus.publish(
            Event(
                type="scan.received",
                trace_id=req.trace_id,
                session_id=req.session_id,
                payload={"artifacts": len(req.artifacts)},
            )
        )

        out = await self.artifact.analyze(req.artifacts)
        signals = out["signals"]
        risk, explain = aggregate_risk(signals)
        explain["artifact_summary"] = out.get("artifact_summary", [])

        action = risk_score_to_decision_action(
            risk,
            risk_allow_max=int(thresholds["risk_allow_max"]),
            risk_monitor_max=int(thresholds["risk_monitor_max"]),
            risk_sanitize_max=int(thresholds["risk_sanitize_max"]),
        )

        await self.bus.publish(
            Event(
                type=f"scan.decision.{action.value}",
                trace_id=req.trace_id,
                session_id=req.session_id,
                payload={"risk_score": risk},
            )
        )

        return ScanResponse(
            session_id=req.session_id,
            trace_id=req.trace_id,
            risk_score=risk,
            action=action,
            explain=explain,
            signals=signals,
        )
