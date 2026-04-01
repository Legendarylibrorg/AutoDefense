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
  v: number;
  alg: "AES-256-GCM";
  nonce_b64: string;
  ct_b64: string;
  sha256: string;
};

 const httpBase = import.meta.env.VITE_BACKEND_HTTP ?? "http://localhost:8000";
 const wsBase = import.meta.env.VITE_BACKEND_WS ?? "ws://localhost:8000";
const transportKeyB64 = import.meta.env.VITE_TRANSPORT_KEY_B64 as string | undefined;
const transportSealEnabled =
  (import.meta.env.VITE_TRANSPORT_SEAL_ENABLED ?? "false") === "true" && !!transportKeyB64;
const apiKey = import.meta.env.VITE_API_KEY as string | undefined;

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) h["Authorization"] = `Bearer ${apiKey}`;
  return h;
}

function authGet(): RequestInit | undefined {
  if (!apiKey) return undefined;
  return { headers: { Authorization: `Bearer ${apiKey}` } };
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
  // Ensure we pass a real ArrayBuffer with the correct slice.
  // (Avoids TS BufferSource issues on newer lib.dom types.)
  const ab = u8.buffer;
  return ab.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer;
}

function b64(bytes: Uint8Array): string {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function bytesFromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importAesKey(): Promise<CryptoKey> {
  if (!transportKeyB64) throw new Error("Missing VITE_TRANSPORT_KEY_B64");
  const raw = bytesFromB64(transportKeyB64);
  if (raw.byteLength !== 32) throw new Error("VITE_TRANSPORT_KEY_B64 must decode to 32 bytes");
  return crypto.subtle.importKey("raw", toArrayBuffer(raw), { name: "AES-GCM" }, false, ["encrypt"]);
}

async function sealJson(obj: unknown, aad: string): Promise<SealedEnvelope> {
  const raw = new TextEncoder().encode(JSON.stringify(obj));
  const sha256 = await sha256Hex(raw);
  const key = await importAesKey();
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: new TextEncoder().encode(aad) },
    key,
    toArrayBuffer(raw)
  );
  return {
    v: 1,
    alg: "AES-256-GCM",
    nonce_b64: b64(nonce),
    ct_b64: b64(new Uint8Array(ct)),
    sha256
  };
}
 
 export const API = {
   httpBase,
   wsUrl: `${wsBase.replace(/\/$/, "")}/events/ws`,
   wsProtocols: apiKey ? ["auth." + apiKey] : undefined as string[] | undefined,
   async fetchHealth(): Promise<HealthInfo> {
     const res = await fetch(`${httpBase.replace(/\/$/, "")}/health`);
     if (!res.ok) throw new Error(`GET /health failed: ${res.status}`);
     return (await res.json()) as HealthInfo;
   },
   async fetchEvents(): Promise<EventItem[]> {
     const res = await fetch(`${httpBase.replace(/\/$/, "")}/events`, authGet());
     if (!res.ok) throw new Error(`GET /events failed: ${res.status}`);
     return (await res.json()) as EventItem[];
   },
   async fetchAlerts(): Promise<EventItem[]> {
     const res = await fetch(`${httpBase.replace(/\/$/, "")}/alerts`, authGet());
     if (!res.ok) throw new Error(`GET /alerts failed: ${res.status}`);
     return (await res.json()) as EventItem[];
   },
   async fetchMetrics(): Promise<Record<string, unknown>> {
     const res = await fetch(`${httpBase.replace(/\/$/, "")}/metrics`, authGet());
     if (!res.ok) throw new Error(`GET /metrics failed: ${res.status}`);
     return (await res.json()) as Record<string, unknown>;
  },
  async fetchConfig(): Promise<RuntimeConfig> {
    const res = await fetch(`${httpBase.replace(/\/$/, "")}/config`, authGet());
    if (!res.ok) throw new Error(`GET /config failed: ${res.status}`);
    return (await res.json()) as RuntimeConfig;
  },
  async putConfig(cfg: RuntimeConfig): Promise<RuntimeConfig> {
    const res = await fetch(`${httpBase.replace(/\/$/, "")}/config`, {
      method: "PUT",
      headers: authHeaders(),
      body: JSON.stringify(cfg)
    });
    if (!res.ok) throw new Error(`PUT /config failed: ${res.status}`);
    return (await res.json()) as RuntimeConfig;
  },
  async scanArtifacts(artifacts: Artifact[]): Promise<ScanResponse> {
    const url = `${httpBase.replace(/\/$/, "")}${transportSealEnabled ? "/scan/sealed" : "/scan"}`;
    const body = transportSealEnabled ? { sealed: await sealJson({ artifacts }, "scan") } : { artifacts };
    const res = await fetch(url, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`POST /scan failed: ${res.status}`);
    return (await res.json()) as ScanResponse;
  },
  async fetchKernelStatus(): Promise<KernelStatus> {
    const res = await fetch(`${httpBase.replace(/\/$/, "")}/kernel/status`, authGet());
    if (!res.ok) throw new Error(`GET /kernel/status failed: ${res.status}`);
    return (await res.json()) as KernelStatus;
  },
  async analyzeInput(req: {
    user_input: string;
    model_output?: string;
    tool_calls?: Array<Record<string, unknown>>;
  }): Promise<AnalyzeResponse> {
    const url = `${httpBase.replace(/\/$/, "")}${transportSealEnabled ? "/analyze/sealed" : "/analyze"}`;
    const body = transportSealEnabled ? { sealed: await sealJson(req, "analyze") } : req;
    const res = await fetch(url, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`POST /analyze failed: ${res.status}`);
    return (await res.json()) as AnalyzeResponse;
  }
 };
 
