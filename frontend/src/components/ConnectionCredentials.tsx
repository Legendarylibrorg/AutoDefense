import React, { useEffect, useState } from "react";
import { SESSION_KEYS } from "../lib/api";

export function ConnectionCredentials() {
  const [apiKey, setApiKey] = useState("");
  const [transportKey, setTransportKey] = useState("");
  const sealEnabled = (import.meta.env.VITE_TRANSPORT_SEAL_ENABLED ?? "false") === "true";

  useEffect(() => {
    try {
      setApiKey(sessionStorage.getItem(SESSION_KEYS.apiKey) ?? "");
      setTransportKey(sessionStorage.getItem(SESSION_KEYS.transportKeyB64) ?? "");
    } catch {
      // ignore
    }
  }, []);

  function persistAndReload() {
    try {
      const ak = apiKey.trim();
      const tk = transportKey.trim();
      if (ak) sessionStorage.setItem(SESSION_KEYS.apiKey, ak);
      else sessionStorage.removeItem(SESSION_KEYS.apiKey);
      if (tk) sessionStorage.setItem(SESSION_KEYS.transportKeyB64, tk);
      else sessionStorage.removeItem(SESSION_KEYS.transportKeyB64);
    } catch {
      // ignore
    }
    window.location.reload();
  }

  return (
    <details className="rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-xs">
      <summary className="cursor-pointer select-none font-medium text-muted">API session keys</summary>
      <p className="mt-2 max-w-sm text-muted">
        Stored only in this browser tab (sessionStorage). Leave blank to use build-time Vite env values for
        local development.
      </p>
      <label className="mt-2 block text-muted">
        API key
        <input
          type="password"
          autoComplete="off"
          className="mt-1 w-full max-w-sm rounded-md border border-white/10 bg-black/30 px-2 py-1 font-mono text-text"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder="AUTODEFENSE_API_KEY"
        />
      </label>
      {sealEnabled ? (
        <label className="mt-2 block text-muted">
          Transport key (base64, 32 bytes)
          <input
            type="password"
            autoComplete="off"
            className="mt-1 w-full max-w-sm rounded-md border border-white/10 bg-black/30 px-2 py-1 font-mono text-text"
            value={transportKey}
            onChange={(e) => setTransportKey(e.target.value)}
            placeholder="AUTODEFENSE_TRANSPORT_KEY_B64"
          />
        </label>
      ) : null}
      <button
        type="button"
        className="mt-3 rounded-md border border-accent/40 bg-accent/20 px-3 py-1.5 text-text hover:bg-accent/30"
        onClick={persistAndReload}
      >
        Save and reload
      </button>
    </details>
  );
}
