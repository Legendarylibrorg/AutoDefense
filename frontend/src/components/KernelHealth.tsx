import { useEffect, useState } from "react";
import { API, type HealthInfo, type KernelStatus, type KernelFinding } from "../lib/api";

function severityColor(s: string) {
  if (s === "critical") return "text-danger";
  if (s === "high") return "text-warn";
  if (s === "medium") return "text-muted";
  return "text-text";
}

function overallTone(status: KernelStatus) {
  if (!status.scanned) return "border-white/10 bg-panel";
  const score = status.risk_score ?? 0;
  if (score >= 81) return "border-danger/30 bg-panel";
  if (score >= 31) return "border-warn/30 bg-panel";
  return "border-ok/30 bg-panel";
}

function hardeningPercent(status: KernelStatus): number | null {
  const h = status.hardening;
  if (!h || typeof h.percent !== "number") return null;
  return h.percent as number;
}

function severityRank(s: string): number {
  if (s === "critical") return 0;
  if (s === "high") return 1;
  if (s === "medium") return 2;
  if (s === "low") return 3;
  return 4;
}

function osLabel(os: string): string {
  if (os === "linux") return "Linux";
  if (os === "darwin") return "macOS";
  if (os === "windows") return "Windows";
  return os;
}

function scannerCommand(health: HealthInfo): string {
  const p = health.platform;
  if (p.in_container) {
    return "# Run on the Docker host (not inside a container):\n# Linux:   python3 kernel/scanner.py --post http://localhost:8000\n# macOS:   python3 macos/scanner.py --post http://localhost:8000\n# Windows: python windows\\scanner.py --post http://localhost:8000";
  }
  if (p.os === "linux") {
    return "python3 kernel/scanner.py --post http://localhost:8000";
  }
  if (p.os === "darwin") {
    return "python3 macos/scanner.py --post http://localhost:8000";
  }
  if (p.os === "windows") {
    return "python windows\\scanner.py --post http://localhost:8000";
  }
  return "# Pick your platform scanner:\n# Linux:   python3 kernel/scanner.py --post http://localhost:8000\n# macOS:   python3 macos/scanner.py --post http://localhost:8000\n# Windows: python windows\\scanner.py --post http://localhost:8000";
}

function NoScanView({ health }: { health: HealthInfo | null }) {
  const p = health?.platform;
  const available = p?.kernel_scanner_available ?? false;

  return (
    <div className="rounded-xl border border-white/10 bg-panel p-4">
      <div className="flex items-center justify-between">
        <div className="text-sm font-semibold">Kernel protection</div>
        {p ? (
          <div className="rounded-md border border-white/10 bg-black/20 px-2 py-0.5 text-[11px] text-muted">
            Backend: {osLabel(p.os)} {p.arch}
            {p.in_container ? " (container)" : ""}
          </div>
        ) : null}
      </div>

      {!health ? (
        <div className="mt-2 text-xs text-muted">Detecting platform…</div>
      ) : (
        <div className="mt-3">
          <div className="text-xs text-muted">{p!.scanner_hint}</div>
          <div className="mt-2 text-xs text-muted">No scan received yet. Run:</div>
          <pre className="mt-1.5 rounded-lg bg-black/20 p-2 text-[11px] text-muted whitespace-pre-wrap">
            {scannerCommand(health)}
          </pre>
          <div className="mt-2 text-[11px] text-muted">
            For continuous monitoring: add <code className="rounded bg-black/20 px-1 font-mono">--loop 120</code>
          </div>
        </div>
      )}
    </div>
  );
}

function ScanResultView({ status }: { status: KernelStatus }) {
  const [expanded, setExpanded] = useState(false);
  const findings = status.findings ?? [];
  const threats = findings.filter((f) => f.severity !== "info");
  const hPercent = hardeningPercent(status);

  return (
    <div className={`rounded-xl border ${overallTone(status)} p-4`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-sm font-semibold">Kernel protection</div>
          <div className="mt-1 text-xs text-muted">
            {status.hostname} · {osLabel(status.platform ?? "")} {status.kernel_version}
            {status.in_container ? " (container)" : ""}
          </div>
        </div>
        <div className="flex items-center gap-3">
          {hPercent !== null ? (
            <div className="text-xs text-muted">
              Hardening <span className="font-mono font-semibold text-text">{hPercent}%</span>
            </div>
          ) : null}
          <div className="text-xs text-muted">
            Risk <span className="font-mono font-semibold text-text">{status.risk_score ?? 0}/100</span>
          </div>
          <div className={`rounded-md border px-2 py-1 text-xs font-semibold ${
            (status.action === "allow") ? "border-ok/40 text-ok" :
            (status.action === "log_monitor") ? "border-white/20 text-muted" :
            (status.action === "sanitize") ? "border-warn/40 text-warn" :
            "border-danger/40 text-danger"
          }`}>
            {(status.action ?? "none").toUpperCase()}
          </div>
        </div>
      </div>

      {threats.length > 0 ? (
        <div className="mt-3">
          <button
            className="rounded-md border border-white/10 bg-black/10 px-2 py-1 text-xs text-text hover:bg-white/5"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? "Hide" : "Show"} {threats.length} finding{threats.length !== 1 ? "s" : ""}
          </button>

          {expanded ? (
            <div className="mt-2 max-h-64 space-y-2 overflow-auto">
              {threats
                .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
                .map((f, i) => (
                  <div key={i} className="rounded-md border border-white/10 bg-black/10 p-2">
                    <div className={`text-xs font-mono ${severityColor(f.severity)}`}>
                      [{f.severity.toUpperCase()}] {f.category}
                    </div>
                    <div className="mt-1 text-xs text-text">{f.title}</div>
                    <div className="mt-1 text-[11px] text-muted">{f.detail}</div>
                  </div>
                ))}
            </div>
          ) : null}
        </div>
      ) : (
        <div className="mt-3 text-xs text-ok">No threats detected.</div>
      )}

      <div className="mt-2 text-[11px] text-muted">
        Last scan: {status.timestamp ? new Date(status.timestamp).toLocaleString() : "unknown"}
      </div>
    </div>
  );
}

export function KernelHealth() {
  const [health, setHealth] = useState<HealthInfo | null>(null);
  const [status, setStatus] = useState<KernelStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const [h, s] = await Promise.all([API.fetchHealth(), API.fetchKernelStatus()]);
        if (!cancelled) {
          setHealth(h);
          setStatus(s);
        }
      } catch {
        // silent — will retry
      }
    };
    tick();
    const id = setInterval(tick, 10_000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  if (status?.scanned) {
    return <ScanResultView status={status} />;
  }

  return <NoScanView health={health} />;
}
