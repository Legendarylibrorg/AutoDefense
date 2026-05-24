import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { API, type EventItem, type HealthInfo } from "../lib/api";
import { countDecisions } from "../lib/decisions";
import { useEventStream } from "../lib/useEventStream";
import { AnalyzePanel } from "../components/AnalyzePanel";
import { ArtifactScanner } from "../components/ArtifactScanner";
import { ConfigPanel } from "../components/ConfigPanel";
import { EventFeed } from "../components/EventFeed";
import { KernelHealth } from "../components/KernelHealth";
import { StatCard } from "../components/StatCard";
import { ConnectionCredentials } from "../components/ConnectionCredentials";
import { SystemHealthPanel } from "../components/SystemHealthPanel";
import { osLabel } from "../lib/platform";

const RiskChart = lazy(() =>
  import("../components/RiskChart").then((m) => ({ default: m.RiskChart }))
);

export function App() {
  const { events, connected, authRequired } = useEventStream(600);
  const [alerts, setAlerts] = useState<EventItem[]>([]);
  const [metrics, setMetrics] = useState<Record<string, unknown> | null>(null);
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [thresholds, setThresholds] = useState<
    { risk_allow_max: number; risk_monitor_max: number; risk_sanitize_max: number } | undefined
  >(undefined);

  useEffect(() => {
    const controller = new AbortController();
    const tick = async () => {
      try {
        const opts = { signal: controller.signal };
        const [a, m, h] = await Promise.all([
          API.fetchAlerts(opts),
          API.fetchMetrics(opts),
          API.fetchHealth(opts),
        ]);
        setAlerts(a);
        setMetrics(m);
        setHealth(h);
      } catch (err) {
        if (err instanceof DOMException && err.name === "AbortError") return;
      }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => {
      controller.abort();
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

      {authRequired ? (
        <div className="mx-auto max-w-7xl px-6 pb-2">
          <div className="rounded-lg border border-warn/40 bg-warn/10 px-4 py-3 text-sm text-warn">
            Authentication required — paste your API key (and transport key if sealed transport is on) under{" "}
            <strong>API session keys</strong>, then save and reload.
          </div>
        </div>
      ) : null}

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
          <div className="mt-6">
            <SystemHealthPanel health={health} metrics={metrics} />
          </div>
        </section>

        <section className="lg:col-span-5">
          <KernelHealth health={health} />
          <div className="mt-6">
            <EventFeed events={events} />
          </div>
        </section>
      </main>
    </div>
  );
}
