import type { EventItem } from "./api";

const DECISION_ACTIONS = new Set(["allow", "log_monitor", "sanitize", "block_isolate"]);

export type DecisionAction = "allow" | "log_monitor" | "sanitize" | "block_isolate" | "unknown";

export function decisionFromEventType(type: string): DecisionAction {
  if (!type.startsWith("decision.")) return "unknown";
  const action = type.slice("decision.".length);
  return DECISION_ACTIONS.has(action) ? (action as DecisionAction) : "unknown";
}

export function countDecisions(events: EventItem[]): Partial<Record<DecisionAction, number>> {
  const counts: Partial<Record<DecisionAction, number>> = {};
  for (const e of events) {
    const action = decisionFromEventType(e.type);
    if (action === "unknown") continue;
    counts[action] = (counts[action] ?? 0) + 1;
  }
  return counts;
}
