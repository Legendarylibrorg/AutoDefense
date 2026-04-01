from __future__ import annotations

from app.core.models import AgentSignal, AnalyzeResponse, DecisionAction


class ResponseEngine:
    def decide_action(
        self,
        risk_score: int,
        *,
        risk_allow_max: int,
        risk_monitor_max: int,
        risk_sanitize_max: int,
    ) -> DecisionAction:
        if risk_score <= risk_allow_max:
            return DecisionAction.allow
        if risk_score <= risk_monitor_max:
            return DecisionAction.log_monitor
        if risk_score <= risk_sanitize_max:
            return DecisionAction.sanitize
        return DecisionAction.block_isolate

    def apply(
        self,
        *,
        session_id: str,
        trace_id: str,
        sanitized_input: str,
        sanitized_output: str | None,
        risk_score: int,
        action: str,
        explain: dict,
        signals: list[AgentSignal],
        patches: list[dict],
        thresholds: dict,
    ) -> AnalyzeResponse:
        enforced = self.decide_action(
            risk_score,
            risk_allow_max=int(thresholds["risk_allow_max"]),
            risk_monitor_max=int(thresholds["risk_monitor_max"]),
            risk_sanitize_max=int(thresholds["risk_sanitize_max"]),
        )

        if action in (a.value for a in DecisionAction):
            requested = DecisionAction(action)
            order = [
                DecisionAction.allow,
                DecisionAction.log_monitor,
                DecisionAction.sanitize,
                DecisionAction.block_isolate,
            ]
            if order.index(requested) > order.index(enforced):
                enforced = requested

        out = sanitized_output
        if enforced == DecisionAction.block_isolate:
            out = None

        return AnalyzeResponse(
            session_id=session_id,
            trace_id=trace_id,
            sanitized_input=sanitized_input,
            sanitized_output=out,
            risk_score=risk_score,
            action=enforced,
            explain=explain,
            signals=signals,
            patches=patches,
        )

