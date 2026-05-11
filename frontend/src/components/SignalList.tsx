import type { AgentSignal } from "../lib/api";

export function SignalList({ signals }: { signals: AgentSignal[] }) {
  const top = signals
    .slice()
    .sort((a, b) => b.score * b.confidence - a.score * a.confidence)
    .slice(0, 8);

  if (!top.length) {
    return <div className="text-sm text-muted">No signals (allow).</div>;
  }

  return (
    <>
      {top.map((s, idx) => (
        <div key={`${s.agent}-${idx}`} className="rounded-md border border-white/10 bg-black/10 p-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-xs font-mono text-text">
              {s.agent} · {s.threat_type}
            </div>
            <div className="text-xs text-muted">
              score {s.score} · conf {Math.round(s.confidence * 100)}%
            </div>
          </div>
          {s.reasons?.length ? (
            <ul className="mt-2 list-disc pl-5 text-[11px] text-muted">
              {s.reasons.slice(0, 5).map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ))}
    </>
  );
}
