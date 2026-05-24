import type { HealthInfo } from "../lib/api";

function redisLabel(health: HealthInfo | null): string {
  if (!health) return "checking…";
  if (!health.redis) return "unknown";
  return health.redis === "connected" ? "connected" : health.redis;
}

function redisTone(health: HealthInfo | null): string {
  if (!health?.redis) return "text-muted";
  return health.redis === "connected" ? "text-ok" : "text-warn";
}

export function SystemHealthPanel(props: {
  health: HealthInfo | null;
  metrics: Record<string, unknown> | null;
}) {
  const { health, metrics } = props;
  const eventTotal =
    typeof metrics?.events_total_recent === "number" ? metrics.events_total_recent : null;
  const byType =
    metrics?.events_by_type_recent && typeof metrics.events_by_type_recent === "object"
      ? (metrics.events_by_type_recent as Record<string, number>)
      : null;
  const topTypes = byType
    ? Object.entries(byType)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
    : [];

  return (
    <div className="rounded-xl border border-white/10 bg-panel p-4">
      <div className="text-sm font-semibold">System health</div>
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-white/10 bg-black/10 p-3">
          <div className="text-xs text-muted">Backend</div>
          <div
            className={`mt-1 text-sm font-semibold ${
              health?.status === "ok" ? "text-ok" : health ? "text-warn" : "text-muted"
            }`}
          >
            {health?.status ?? "loading…"}
          </div>
        </div>
        <div className="rounded-lg border border-white/10 bg-black/10 p-3">
          <div className="text-xs text-muted">Redis</div>
          <div className={`mt-1 text-sm font-semibold ${redisTone(health)}`}>{redisLabel(health)}</div>
        </div>
        <div className="rounded-lg border border-white/10 bg-black/10 p-3">
          <div className="text-xs text-muted">Recent events (stream tail)</div>
          <div className="mt-1 text-sm font-semibold text-text">{eventTotal ?? "—"}</div>
        </div>
      </div>

      {topTypes.length ? (
        <div className="mt-4">
          <div className="text-xs font-semibold text-muted">Events by type (recent)</div>
          <div className="mt-2 space-y-1">
            {topTypes.map(([type, count]) => (
              <div key={type} className="flex items-center justify-between text-xs">
                <span className="font-mono text-muted">{type}</span>
                <span className="font-mono text-text">{count}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="mt-4 text-xs text-muted">
          {metrics ? "No recent events in the stream tail." : "Loading metrics…"}
        </div>
      )}
    </div>
  );
}
