import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { API, type EventItem, type HealthInfo } from "../lib/api";
import { useEventStream } from "../lib/useEventStream";
import { AnalyzePanel } from "../components/AnalyzePanel";
import { ArtifactScanner } from "../components/ArtifactScanner";
import { ConfigPanel } from "../components/ConfigPanel";
import { EventFeed } from "../components/EventFeed";
import { KernelHealth } from "../components/KernelHealth";
import { StatCard } from "../components/StatCard";
import { ConnectionCredentials } from "../components/ConnectionCredentials";
import { osLabel } from "../lib/platform";

const RiskChart = lazy(() =>
  import("../components/RiskChart").then((m) => ({ default: m.RiskChart }))
);

function classifyAction(type: string): "allow" | "log_monitor" | "sanitize" | "block_isolate" | "unknown" {
  if (!type.startsWith("decision.")) return "unknown";
  const suffix = type.slice("decision.".length);
  if (
    suffix === "allow" ||
    suffix === "log_monitor" ||
    suffix === "sanitize" ||
    suffix === "block_isolate"
  ) {
    return suffix;
  }
  return "unknown";
}

function countDecisions(events: EventItem[]) {
  const counts: Record<string, number> = {};
  for (const e of events) {
    const a = classifyAction(e.type);
    if (a === "unknown") continue;
    counts[a] = (counts[a] ?? 0) + 1;
  }
  return counts;
}

export function App() {
  const { events, connected } = useEventStream(600);
  const [alerts, setAlerts] = useState<EventItem[]>([]);
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [thresholds, setThresholds] = useState<
    { risk_allow_max: number; risk_monitor_max: number; risk_sanitize_max: number } | undefined
  >(undefined);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const [a, m, h] = await Promise.all([API.fetchAlerts(), API.fetchMetrics(), API.fetchHealth()]);
        if (cancelled) return;
        setAlerts(a);
        setMetrics(m);
        setHealth(h);
      } catch {
        // ignore
      }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const decisions = useMemo(() => countDecisions(events), [events]);
  const critical = useMemo(
    () => alerts.filter((e) => e.type.includes("block_isolate") || e.type.includes("incident")).length,
    [alerts]
  );

  return (
    <div className="min-h-screen">
      <header className="mx-auto max-w-7xl px-6 py-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-xs tracking-widest text-muted">AUTO DEFENSE</div>
            <div className="text-2xl font-semibold">Autonomous AI Defense System</div>
            <div className="mt-1 text-sm text-muted">
              Backend: <span className="font-mono">{API.httpBase}</span>
              {health?.platform ? (
                <span>
                  {" · "}
                  {osLabel(health.platform.os)}
                  {" "}{health.platform.arch}
                  {health.platform.in_container ? " (container)" : ""}
                </span>
              ) : null}
            </div>
          </div>
          <div className="flex items-center gap-3">
            {health ? (
              <div className={`rounded-md border px-2 py-1 text-xs ${
                health.status === "ok"
                  ? "border-ok/40 text-ok"
                  : "border-warn/40 text-warn"
              }`}>
                {health.status === "ok" ? "Healthy" : "Degraded"}
              </div>
            ) : null}
            <div className="flex items-center gap-2">
              <div
                className={`h-2 w-2 rounded-full ${connected ? "bg-ok" : "bg-danger"} shadow`}
                aria-label={connected ? "connected" : "disconnected"}
              />
              <div className="text-sm text-muted">{connected ? "Live" : "Reconnecting…"}</div>
            </div>
            <ConnectionCredentials />
          </div>
        </div>
      </header>

      <main className="mx-auto grid max-w-7xl grid-cols-1 gap-6 px-6 pb-10 lg:grid-cols-12">
        <section className="grid grid-cols-1 gap-4 lg:col-span-12 lg:grid-cols-4">
          <StatCard title="Recent events" value={events.length} hint="Redis stream tail" />
          <StatCard title="Critical alerts" value={critical} tone={critical > 0 ? "danger" : "ok"} />
          <StatCard title="Decisions (allow)" value={decisions.allow ?? 0} tone="ok" />
          <StatCard title="Decisions (blocked)" value={decisions.block_isolate ?? 0} tone="danger" />
        </section>

        <section className="lg:col-span-7">
          <Suspense
            fallback={
              <div className="rounded-xl border border-white/10 bg-panel p-4 text-sm text-muted">
                Loading risk chart…
              </div>
            }
          >
            <RiskChart events={events} thresholds={thresholds} />
          </Suspense>
          <div className="mt-6">
            <AnalyzePanel />
          </div>
          <div className="mt-6">
            <ArtifactScanner />
          </div>
          <div className="mt-6">
            <ConfigPanel
              onConfig={(c) =>
                setThresholds({
                  risk_allow_max: c.risk_allow_max,
                  risk_monitor_max: c.risk_monitor_max,
                  risk_sanitize_max: c.risk_sanitize_max
                })
              }
            />
          </div>
          <div className="mt-6 rounded-xl border border-white/10 bg-panel p-4">
            <div className="text-sm font-semibold">System health</div>
            <pre className="mt-3 whitespace-pre-wrap break-words rounded-lg bg-black/20 p-3 text-xs text-muted">
              {JSON.stringify(metrics ?? { loading: true }, null, 2)}
            </pre>
          </div>
        </section>

        <section className="lg:col-span-5">
          <KernelHealth />
          <div className="mt-6">
            <EventFeed events={events} />
          </div>
        </section>
      </main>
    </div>
  );
}
