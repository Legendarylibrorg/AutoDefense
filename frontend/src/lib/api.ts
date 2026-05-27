import { bytesFromBase64, bytesToBase64 } from "./encoding";

export type EventItem = {
  ts: string;
  type: string;
  trace_id: string;
  session_id: string;
  payload: Record<string, unknown>;
};

export type RuntimeConfig = {
  version: number;
  risk_allow_max: number;
  risk_monitor_max: number;
  risk_sanitize_max: number;
  self_heal_enabled: boolean;
  blocked_input_regexes: string[];
  sanitize_input_regexes: string[];
};

export type PlatformInfo = {
  os: string;
  os_pretty: string;
  arch: string;
  hostname: string;
  in_container: boolean;
  kernel_version: string;
  python_version: string;
  kernel_scanner_available: boolean;
  scanner_hint: string;
};

export type HealthInfo = {
  status: "ok" | "degraded";
  redis: string;
  platform: PlatformInfo;
};

export type ArtifactKind = "text" | "email" | "url" | "file" | "image";

export type Artifact = {
  kind: ArtifactKind;
  name?: string | null;
  content_text?: string | null;
  content_base64?: string | null;
  content_type?: string | null;
  size_bytes?: number | null;
};

export type AgentSignal = {
  agent: string;
  threat_type: string;
  score: number;
  confidence: number;
  reasons: string[];
  evidence: Record<string, unknown>;
};

export type ScanResponse = {
  session_id: string;
  trace_id: string;
  risk_score: number;
  action: "allow" | "log_monitor" | "sanitize" | "block_isolate";
  explain: Record<string, unknown>;
  signals: AgentSignal[];
};

export type KernelFinding = {
  category: "rootkit" | "zero_day" | "integrity" | "network";
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  evidence: Record<string, unknown>;
};

export type KernelStatus = {
  scanned: boolean;
  kernel_status_unavailable?: boolean;
  platform?: string;
  kernel_version?: string;
  hostname?: string;
  timestamp?: string;
  in_container?: boolean;
  findings_count?: number;
  risk_score?: number;
  action?: string;
  hardening?: Record<string, unknown>;
  findings?: KernelFinding[];
};

export type AnalyzeResponse = {
  session_id: string;
  trace_id: string;
  sanitized_input: string;
  sanitized_output: string | null;
  risk_score: number;
  action: "allow" | "log_monitor" | "sanitize" | "block_isolate";
  explain: Record<string, unknown>;
  signals: AgentSignal[];
  patches: Array<Record<string, unknown>>;
};

type SealedEnvelope = {
  v: 3;
  alg: "AES-256-GCM";
  nonce_b64: string;
  ct_b64: string;
};

export const SESSION_KEYS = {
  apiKey: "autodefense_api_key",
  transportKeyB64: "autodefense_transport_key_b64",
} as const;

function resolveHttpBase(): string {
  const fromEnv = import.meta.env.VITE_BACKEND_HTTP as string | undefined;
  if (fromEnv?.trim()) return fromEnv.trim().replace(/\/$/, "");
  if (import.meta.env.DEV) return "";
  return "http://localhost:8000";
}

function resolveWsBase(): string {
  const fromEnv = import.meta.env.VITE_BACKEND_WS as string | undefined;
  if (fromEnv?.trim()) return fromEnv.trim().replace(/\/$/, "");
  if (import.meta.env.DEV) {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}`;
  }
  return "ws://localhost:8000";
}

const httpBase = resolveHttpBase();
const wsBase = resolveWsBase();

function resolveStoredOrEnv(sessionKey: string, envValue: string | undefined): string | undefined {
  try {
    const stored = sessionStorage.getItem(sessionKey)?.trim();
    if (stored) return stored;
  } catch {
    /* ignore */
  }
  return envValue?.trim() || undefined;
}

export function getResolvedApiKey(): string | undefined {
  return resolveStoredOrEnv(SESSION_KEYS.apiKey, import.meta.env.VITE_API_KEY as string | undefined);
}

export function getResolvedTransportKeyB64(): string | undefined {
  return resolveStoredOrEnv(
    SESSION_KEYS.transportKeyB64,
    import.meta.env.VITE_TRANSPORT_KEY_B64 as string | undefined,
  );
}

/** True when the transport key is baked into the frontend build (avoid in production). */
export function transportKeyEmbeddedInBuild(): boolean {
  return !!(import.meta.env.VITE_TRANSPORT_KEY_B64 as string | undefined)?.trim();
}

export function transportSealEnabled(): boolean {
  return (
    (import.meta.env.VITE_TRANSPORT_SEAL_ENABLED ?? "false") === "true" &&
    !!getResolvedTransportKeyB64()
  );
}

export function credentialStatus() {
  const sealEnabled = (import.meta.env.VITE_TRANSPORT_SEAL_ENABLED ?? "false") === "true";
  const hasApiKey = !!getResolvedApiKey();
  const hasTransportKey = !!getResolvedTransportKeyB64();
  const transportKeyInBuild = transportKeyEmbeddedInBuild();
  return {
    hasApiKey,
    hasTransportKey,
    sealEnabled,
    transportKeyInBuild,
    transportKeyInBuildWarning:
      transportKeyInBuild && import.meta.env.PROD
        ? "Transport key is embedded in the frontend build; anyone with the bundle can forge sealed payloads. Prefer session-only entry over VITE_TRANSPORT_KEY_B64 in production."
        : undefined,
    needsApiKey: !hasApiKey,
    needsTransportKey: sealEnabled && !hasTransportKey,
  };
}

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const key = getResolvedApiKey();
  if (key) headers.Authorization = `Bearer ${key}`;
  return headers;
}

function authGet(): RequestInit | undefined {
  const key = getResolvedApiKey();
  if (!key) return undefined;
  return { headers: { Authorization: `Bearer ${key}` } };
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

export class HttpError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

export type FetchOptions = { signal?: AbortSignal };

function withSignal(init: RequestInit | undefined, opts?: FetchOptions): RequestInit {
  if (!opts?.signal) return init ?? {};
  return { ...init, signal: opts.signal };
}

export async function formatHttpError(res: Response, label: string): Promise<string> {
  let detail = `${label} failed (${res.status})`;
  try {
    const body = (await res.json()) as { detail?: unknown };
    const d = body.detail;
    if (typeof d === "string" && d.trim()) return d;
    if (Array.isArray(d)) {
      const parts = d
        .map((item) => {
          if (typeof item === "string") return item;
          if (item && typeof item === "object" && "message" in item) {
            const msg = (item as { message?: unknown }).message;
            const field = (item as { field?: unknown }).field;
            if (typeof msg === "string" && typeof field === "string") return `${field}: ${msg}`;
            if (typeof msg === "string") return msg;
          }
          return null;
        })
        .filter(Boolean);
      if (parts.length) return parts.join("; ");
    }
  } catch {
    /* ignore non-JSON error bodies */
  }
  return detail;
}

async function readJson<T>(res: Response, label: string): Promise<T> {
  if (!res.ok) throw new HttpError(await formatHttpError(res, label), res.status);
  return res.json() as Promise<T>;
}

async function fetchJson<T>(
  path: string,
  init: RequestInit | undefined,
  opts?: FetchOptions,
): Promise<T> {
  const res = await fetch(`${httpBase}${path}`, withSignal(init, opts));
  return readJson<T>(res, path);
}

async function getJson<T>(path: string, opts?: FetchOptions): Promise<T> {
  return fetchJson<T>(path, authGet(), opts);
}

async function getJsonPublic<T>(path: string, opts?: FetchOptions): Promise<T> {
  return fetchJson<T>(path, undefined, opts);
}

async function writeJson<T>(
  method: "POST" | "PUT",
  path: string,
  body: unknown,
  opts?: FetchOptions,
): Promise<T> {
  return fetchJson<T>(
    path,
    { method, headers: authHeaders(), body: JSON.stringify(body) },
    opts,
  );
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  const ab = u8.buffer;
  return ab.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

async function importHkdfBaseKey(): Promise<CryptoKey> {
  const transportKeyB64 = getResolvedTransportKeyB64();
  if (!transportKeyB64)
    throw new Error("Transport key missing (set in browser session or VITE_TRANSPORT_KEY_B64)");
  const raw = bytesFromBase64(transportKeyB64);
  if (raw.byteLength !== 32) throw new Error("Transport key must decode to 32 bytes");
  return crypto.subtle.importKey("raw", toArrayBuffer(raw), "HKDF", false, ["deriveKey"]);
}

async function deriveAesSubkey(base: CryptoKey, info: string): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
}

async function sealJson(obj: unknown, aad: string): Promise<SealedEnvelope> {
  const raw = new TextEncoder().encode(JSON.stringify(obj));
  const base = await importHkdfBaseKey();
  const aesKey = await deriveAesSubkey(base, "autodefense-aes-v3");
  const aadBytes = new TextEncoder().encode(aad);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: toArrayBuffer(aadBytes) },
    aesKey,
    toArrayBuffer(raw),
  );
  return {
    v: 3,
    alg: "AES-256-GCM",
    nonce_b64: bytesToBase64(nonce),
    ct_b64: bytesToBase64(new Uint8Array(ct)),
  };
}

async function postSealedOrPlain<T>(
  sealedPath: string,
  plainPath: string,
  payload: unknown,
  aad: string,
): Promise<T> {
  if (transportSealEnabled()) {
    return writeJson<T>("POST", sealedPath, { sealed: await sealJson(payload, aad) });
  }
  return writeJson<T>("POST", plainPath, payload);
}

export const API = {
  httpBase,
  get wsUrl() {
    return `${wsBase.replace(/\/$/, "")}/events/ws`;
  },
  get wsProtocols(): string[] | undefined {
    const k = getResolvedApiKey();
    return k ? [`auth.${k}`] : undefined;
  },
  fetchHealth: (opts?: FetchOptions) => getJsonPublic<HealthInfo>("/health", opts),
  fetchEvents: (opts?: FetchOptions) => getJson<EventItem[]>("/events", opts),
  fetchAlerts: (opts?: FetchOptions) => getJson<EventItem[]>("/alerts", opts),
  fetchMetrics: (opts?: FetchOptions) => getJson<Record<string, unknown>>("/metrics", opts),
  fetchConfig: (opts?: FetchOptions) => getJson<RuntimeConfig>("/config", opts),
  putConfig: (cfg: RuntimeConfig, opts?: FetchOptions) =>
    writeJson<RuntimeConfig>("PUT", "/config", cfg, opts),
  scanArtifacts: (artifacts: Artifact[]) =>
    postSealedOrPlain<ScanResponse>("/scan/sealed", "/scan", { artifacts }, "scan"),
  fetchKernelStatus: (opts?: FetchOptions) => getJson<KernelStatus>("/kernel/status", opts),
  analyzeInput: (req: {
    user_input: string;
    model_output?: string;
    tool_calls?: Array<Record<string, unknown>>;
  }) => postSealedOrPlain<AnalyzeResponse>("/analyze/sealed", "/analyze", req, "analyze"),
};
