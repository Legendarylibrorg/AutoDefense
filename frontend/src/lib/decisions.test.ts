import { describe, expect, it } from "vitest";
import { countDecisions, decisionFromEventType } from "./decisions";
import type { EventItem } from "./api";

describe("decisionFromEventType", () => {
  it("parses decision event types", () => {
    expect(decisionFromEventType("decision.allow")).toBe("allow");
    expect(decisionFromEventType("decision.block_isolate")).toBe("block_isolate");
    expect(decisionFromEventType("request.received")).toBe("unknown");
  });
});

describe("countDecisions", () => {
  it("counts decision events only", () => {
    const events: EventItem[] = [
      {
        ts: "2026-01-01T00:00:00Z",
        type: "decision.allow",
        trace_id: "a",
        session_id: "s",
        payload: {},
      },
      {
        ts: "2026-01-01T00:00:01Z",
        type: "decision.allow",
        trace_id: "b",
        session_id: "s",
        payload: {},
      },
      {
        ts: "2026-01-01T00:00:02Z",
        type: "request.received",
        trace_id: "c",
        session_id: "s",
        payload: {},
      },
    ];
    expect(countDecisions(events)).toEqual({ allow: 2 });
  });
});
