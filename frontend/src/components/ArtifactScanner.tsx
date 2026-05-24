import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { SignalList } from "./SignalList";
import { actionTone } from "../lib/actionTone";
import { API, errorMessage, type Artifact, type ArtifactKind, type ScanResponse } from "../lib/api";
import { bytesToBase64 } from "../lib/encoding";

async function fileToArtifact(file: File, kind: ArtifactKind): Promise<Artifact> {
  const buf = new Uint8Array(await file.arrayBuffer());
  return {
    kind,
    name: file.name,
    content_type: file.type || null,
    size_bytes: file.size,
    content_base64: bytesToBase64(buf)
  };
}

export function ArtifactScanner() {
  const [kind, setKind] = useState<ArtifactKind>("url");
  const [text, setText] = useState("");
  const [files, setFiles] = useState<FileList | null>(null);
  const [autoScan, setAutoScan] = useState(false);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [showDetails, setShowDetails] = useState(false);
  const debounceRef = useRef<number | null>(null);
  const lastSigRef = useRef<string>("");

  const canScan = useMemo(() => {
    if (kind === "file" || kind === "image") return (files?.length ?? 0) > 0;
    return text.trim().length > 0;
  }, [kind, text, files]);

  const scan = useCallback(async () => {
    const sig = JSON.stringify({
      kind,
      text: kind === "file" || kind === "image" ? "" : text,
      files:
        kind === "file" || kind === "image"
          ? Array.from(files ?? []).map((f) => `${f.name}:${f.size}`)
          : [],
    });
    if (sig === lastSigRef.current) return;

    setErr(null);
    setResult(null);
    setShowDetails(false);
    setRunning(true);
    try {
      let artifacts: Artifact[] = [];
      if (kind === "file" || kind === "image") {
        const list = files ? Array.from(files).slice(0, 5) : [];
        artifacts = await Promise.all(list.map((f) => fileToArtifact(f, kind)));
      } else {
        artifacts = [
          {
            kind,
            name: kind.toUpperCase(),
            content_text: text,
          },
        ];
      }
      lastSigRef.current = sig;
      const res = await API.scanArtifacts(artifacts);
      setResult(res);
    } catch (e: unknown) {
      setErr(errorMessage(e));
    } finally {
      setRunning(false);
    }
  }, [files, kind, text]);

  useEffect(() => {
    if (!autoScan) return;
    if (kind === "file" || kind === "image") return;
    if (!text.trim()) return;
    if (debounceRef.current) window.clearTimeout(debounceRef.current);
    debounceRef.current = window.setTimeout(() => {
      scan();
    }, 450);
    return () => {
      if (debounceRef.current) window.clearTimeout(debounceRef.current);
    };
  }, [autoScan, kind, scan, text]);

  return (
    <div className="rounded-xl border border-white/10 bg-panel p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold">Artifact scanner (preflight)</div>
          <div className="mt-1 text-xs text-muted">
            Deterministic scan to block exploit attempts before use (downloads, URLs, emails, images).
          </div>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-muted">
            <input type="checkbox" checked={autoScan} onChange={(e) => setAutoScan(e.target.checked)} />
            Auto-scan on input
          </label>
          <button
            className="rounded-lg border border-accent/40 bg-accent/20 px-3 py-2 text-xs text-text hover:bg-accent/30 disabled:opacity-50"
            onClick={scan}
            disabled={!canScan || running}
          >
            {running ? "Scanning…" : "Scan"}
          </button>
        </div>
      </div>

      <div className="mt-4 rounded-lg border border-white/10 bg-black/10 p-3">
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          <label className="block text-xs text-muted">
            Kind
            <select
              className="mt-1 w-full rounded-md border border-white/10 bg-black/20 px-2 py-2 text-sm text-text"
              value={kind}
              onChange={(e) => {
                setKind(e.target.value as ArtifactKind);
                setResult(null);
                setErr(null);
                setShowDetails(false);
                setText("");
                setFiles(null);
              }}
            >
              <option value="url">URL</option>
              <option value="email">Email text</option>
              <option value="text">Text</option>
              <option value="image">Image upload</option>
              <option value="file">File upload</option>
            </select>
          </label>

          {kind === "file" || kind === "image" ? (
            <label className="block text-xs text-muted lg:col-span-2">
              Upload (max 5)
              <input
                className="mt-1 block w-full text-sm text-muted file:mr-3 file:rounded-md file:border file:border-white/10 file:bg-black/20 file:px-3 file:py-2 file:text-xs file:text-text hover:file:bg-white/5"
                type="file"
                multiple
                accept={kind === "image" ? "image/*" : undefined}
                onChange={(e) => {
                  setFiles(e.target.files);
                  if (autoScan && (e.target.files?.length ?? 0) > 0) scan();
                }}
              />
            </label>
          ) : (
            <label className="block text-xs text-muted lg:col-span-2">
              Content
              <input
                className="mt-1 w-full rounded-md border border-white/10 bg-black/20 px-2 py-2 text-sm text-text"
                placeholder={kind === "url" ? "https://example.com/..." : "Paste suspicious email/text…"}
                value={text}
                onChange={(e) => setText(e.target.value)}
              />
              <div className="mt-1 text-[11px] text-muted">
                Tip: for long emails, paste into the box then scan.
              </div>
            </label>
          )}
        </div>
      </div>

      <div className="mt-3">
        {err ? (
          <div className="rounded-lg border border-danger/30 bg-danger/10 p-3 text-xs text-danger">
            {err}
          </div>
        ) : null}

        {result ? (
          <div className={`rounded-lg border p-3 ${actionTone(result.action)}`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <div className="text-sm font-semibold text-text">{result.action.toUpperCase()}</div>
                <div className="text-sm text-muted">Risk {result.risk_score}/100</div>
                <div className="text-xs text-muted font-mono">trace {result.trace_id.slice(0, 8)}</div>
              </div>
              <button
                className="rounded-md border border-white/10 bg-black/10 px-2 py-1 text-xs text-text hover:bg-white/5"
                onClick={() => setShowDetails((v) => !v)}
              >
                {showDetails ? "Hide details" : "Details"}
              </button>
            </div>

            {showDetails ? (
              <>
                <div className="mt-3 text-xs font-semibold text-muted">Signals</div>
                <div className="mt-2 space-y-2">
                  <SignalList signals={result.signals} />
                </div>

                <div className="mt-3 text-xs font-semibold text-muted">Explain</div>
                <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-black/20 p-2 text-[11px] text-muted">
                  {JSON.stringify(result.explain, null, 2)}
                </pre>
              </>
            ) : null}
          </div>
        ) : (
          <div className="text-sm text-muted">Ready. Add input and scan.</div>
        )}
      </div>
    </div>
  );
}

