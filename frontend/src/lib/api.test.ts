import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  HttpError,
  SESSION_KEYS,
  credentialStatus,
  errorMessage,
  formatHttpError,
  getResolvedApiKey,
} from "./api";

describe("errorMessage", () => {
  it("returns Error.message", () => {
    expect(errorMessage(new Error("boom"))).toBe("boom");
  });

  it("stringifies non-Error values", () => {
    expect(errorMessage(42)).toBe("42");
  });
});

describe("HttpError", () => {
  it("stores status code", () => {
    const err = new HttpError("Unauthorized", 401);
    expect(err.status).toBe(401);
    expect(err.message).toBe("Unauthorized");
    expect(err.name).toBe("HttpError");
  });
});

describe("formatHttpError", () => {
  it("uses string detail from JSON body", async () => {
    const res = new Response(JSON.stringify({ detail: "Invalid API key" }), { status: 401 });
    await expect(formatHttpError(res, "/events")).resolves.toBe("Invalid API key");
  });

  it("joins validation error array", async () => {
    const res = new Response(
      JSON.stringify({
        detail: [{ field: "user_input", message: "field required" }],
      }),
      { status: 422 },
    );
    await expect(formatHttpError(res, "/analyze")).resolves.toBe("user_input: field required");
  });

  it("falls back to status when body is not JSON", async () => {
    const res = new Response("nope", { status: 500 });
    await expect(formatHttpError(res, "/metrics")).resolves.toBe("/metrics failed (500)");
  });
});

describe("credentialStatus", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.stubEnv("VITE_API_KEY", "");
    vi.stubEnv("VITE_TRANSPORT_KEY_B64", "");
    vi.stubEnv("VITE_TRANSPORT_SEAL_ENABLED", "true");
  });

  it("flags missing API key and transport key when seal is enabled", () => {
    const s = credentialStatus();
    expect(s.needsApiKey).toBe(true);
    expect(s.needsTransportKey).toBe(true);
    expect(s.sealEnabled).toBe(true);
  });

  it("reads API key from sessionStorage", () => {
    sessionStorage.setItem(SESSION_KEYS.apiKey, "test-key");
    vi.stubEnv("VITE_TRANSPORT_KEY_B64", "dGVzdA==");
    const s = credentialStatus();
    expect(s.hasApiKey).toBe(true);
    expect(s.needsApiKey).toBe(false);
  });
});

describe("getResolvedApiKey", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.stubEnv("VITE_API_KEY", "");
  });

  it("prefers sessionStorage over env", () => {
    sessionStorage.setItem(SESSION_KEYS.apiKey, "from-session");
    vi.stubEnv("VITE_API_KEY", "from-env");
    expect(getResolvedApiKey()).toBe("from-session");
  });
});
