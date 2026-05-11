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
  v: 2;
  alg: "AES-256-GCM-DOUBLE";
  inner_nonce_b64: string;
  outer_nonce_b64: string;
  ct_b64: string;
  sha256: string;
  hmac: string;
};

/** Session keys take precedence over Vite env so secrets are not required in the built bundle. */
export const SESSION_KEYS = {
  apiKey: "autodefense_api_key",
  transportKeyB64: "autodefense_transport_key_b64",
} as const;

const httpBase = import.meta.env.VITE_BACKEND_HTTP ?? "http://localhost:8000";
const wsBase = import.meta.env.VITE_BACKEND_WS ?? "ws://localhost:8000";

export function getResolvedApiKey(): string | undefined {
  try {
    const s = sessionStorage.getItem(SESSION_KEYS.apiKey)?.trim();
    if (s) return s;
  } catch {
    /* ignore */
  }
  const fromEnv = (import.meta.env.VITE_API_KEY as string | undefined)?.trim();
  return fromEnv || undefined;
}

export function getResolvedTransportKeyB64(): string | undefined {
  try {
    const s = sessionStorage.getItem(SESSION_KEYS.transportKeyB64)?.trim();
    if (s) return s;
  } catch {
    /* ignore */
  }
  const fromEnv = (import.meta.env.VITE_TRANSPORT_KEY_B64 as string | undefined)?.trim();
  return fromEnv || undefined;
}

function transportSealEnabled(): boolean {
  return (
    (import.meta.env.VITE_TRANSPORT_SEAL_ENABLED ?? "false") === "true" &&
    !!getResolvedTransportKeyB64()
  );
}

function authHeaders(): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  const key = getResolvedApiKey();
  if (key) h["Authorization"] = `Bearer ${key}`;
  return h;
}

function authGet(): RequestInit | undefined {
  const key = getResolvedApiKey();
  if (!key) return undefined;
  return { headers: { Authorization: `Bearer ${key}` } };
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function toArrayBuffer(u8: Uint8Array): ArrayBuffer {
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

async function importHkdfBaseKey(): Promise<CryptoKey> {
  const transportKeyB64 = getResolvedTransportKeyB64();
  if (!transportKeyB64) throw new Error("Transport key missing (set in browser session or VITE_TRANSPORT_KEY_B64)");
  const raw = bytesFromB64(transportKeyB64);
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

async function deriveHmacSubkey(base: CryptoKey, info: string): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode(info) },
    base,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );
}

async function hmacSha256Hex(key: CryptoKey, data: Uint8Array): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", key, toArrayBuffer(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sealJson(obj: unknown, aad: string): Promise<SealedEnvelope> {
  const raw = new TextEncoder().encode(JSON.stringify(obj));
  const sha256 = await sha256Hex(raw);

  const base = await importHkdfBaseKey();
  const innerKey = await deriveAesSubkey(base, "autodefense-inner-v2");
  const outerKey = await deriveAesSubkey(base, "autodefense-outer-v2");
  const hmacKey = await deriveHmacSubkey(base, "autodefense-hmac-v2");

  const mac = await hmacSha256Hex(hmacKey, raw);
  const aadBytes = new TextEncoder().encode(aad);

  const innerNonce = crypto.getRandomValues(new Uint8Array(12));
  const innerCt = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: innerNonce, additionalData: toArrayBuffer(aadBytes) },
    innerKey,
    toArrayBuffer(raw),
  );

  const outerNonce = crypto.getRandomValues(new Uint8Array(12));
  const outerCt = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: outerNonce, additionalData: toArrayBuffer(aadBytes) },
    outerKey,
    innerCt,
  );

  return {
    v: 2,
    alg: "AES-256-GCM-DOUBLE",
    inner_nonce_b64: b64(innerNonce),
    outer_nonce_b64: b64(outerNonce),
    ct_b64: b64(new Uint8Array(outerCt)),
    sha256,
    hmac: mac,
  };
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
    const sealed = transportSealEnabled();
    const url = `${httpBase.replace(/\/$/, "")}${sealed ? "/scan/sealed" : "/scan"}`;
    const body = sealed ? { sealed: await sealJson({ artifacts }, "scan") } : { artifacts };
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
    const sealed = transportSealEnabled();
    const url = `${httpBase.replace(/\/$/, "")}${sealed ? "/analyze/sealed" : "/analyze"}`;
    const body = sealed ? { sealed: await sealJson(req, "analyze") } : req;
    const res = await fetch(url, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify(body)
    });
    if (!res.ok) throw new Error(`POST /analyze failed: ${res.status}`);
    return (await res.json()) as AnalyzeResponse;
  }
 };
 
