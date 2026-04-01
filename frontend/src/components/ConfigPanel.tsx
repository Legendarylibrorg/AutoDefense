 import React, { useEffect, useMemo, useState } from "react";
 import { API, type RuntimeConfig } from "../lib/api";
 
 function clampInt(v: number, lo: number, hi: number) {
   return Math.max(lo, Math.min(hi, Math.round(v)));
 }
 
 function validate(cfg: RuntimeConfig): string[] {
   const errs: string[] = [];
   if (!(0 <= cfg.risk_allow_max && cfg.risk_allow_max <= cfg.risk_monitor_max && cfg.risk_monitor_max <= cfg.risk_sanitize_max && cfg.risk_sanitize_max <= 100)) {
     errs.push("Thresholds must satisfy 0 <= allow <= monitor <= sanitize <= 100.");
   }
   const lists: Array<[string, string[]]> = [
     ["blocked_input_regexes", cfg.blocked_input_regexes],
     ["sanitize_input_regexes", cfg.sanitize_input_regexes]
   ];
   for (const [name, xs] of lists) {
     if (xs.length > 200) errs.push(`${name} too large (max 200).`);
     for (const rx of xs) {
       if (rx.length > 300) errs.push(`${name} contains too-long regex (max 300 chars).`);
     }
   }
   return errs;
 }
 
 export function ConfigPanel(props: { onConfig?: (cfg: RuntimeConfig) => void }) {
   const [loading, setLoading] = useState(true);
   const [cfg, setCfg] = useState<RuntimeConfig | null>(null);
   const [draft, setDraft] = useState<RuntimeConfig | null>(null);
   const [err, setErr] = useState<string | null>(null);
   const [saving, setSaving] = useState(false);
 
   const errs = useMemo(() => (draft ? validate(draft) : []), [draft]);
   const dirty = useMemo(() => JSON.stringify(cfg) !== JSON.stringify(draft), [cfg, draft]);
 
   useEffect(() => {
     let cancelled = false;
     (async () => {
       try {
         const c = await API.fetchConfig();
         if (cancelled) return;
         setCfg(c);
         setDraft(c);
         props.onConfig?.(c);
       } catch (e: any) {
         setErr(String(e?.message ?? e));
       } finally {
         setLoading(false);
       }
     })();
     return () => {
       cancelled = true;
     };
   }, []);
 
   async function save() {
     if (!draft) return;
     setErr(null);
     setSaving(true);
     try {
       const saved = await API.putConfig(draft);
       setCfg(saved);
       setDraft(saved);
       props.onConfig?.(saved);
     } catch (e: any) {
       setErr(String(e?.message ?? e));
     } finally {
       setSaving(false);
     }
   }
 
   if (loading) {
     return (
       <div className="rounded-xl border border-white/10 bg-panel p-4">
         <div className="text-sm font-semibold">Config</div>
         <div className="mt-2 text-sm text-muted">Loading…</div>
       </div>
     );
   }
 
   if (!draft) {
     return (
       <div className="rounded-xl border border-white/10 bg-panel p-4">
         <div className="text-sm font-semibold">Config</div>
         <div className="mt-2 text-sm text-danger">{err ?? "Failed to load config."}</div>
       </div>
     );
   }
 
   return (
     <div className="rounded-xl border border-white/10 bg-panel p-4">
       <div className="flex items-center justify-between gap-3">
         <div>
           <div className="text-sm font-semibold">Config</div>
           <div className="mt-1 text-xs text-muted">Version {draft.version}</div>
         </div>
         <div className="flex items-center gap-2">
           <button
             className="rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-xs text-text hover:bg-white/5 disabled:opacity-50"
             onClick={() => setDraft(cfg)}
             disabled={!dirty || saving}
           >
             Reset
           </button>
           <button
             className="rounded-lg border border-accent/40 bg-accent/20 px-3 py-2 text-xs text-text hover:bg-accent/30 disabled:opacity-50"
             onClick={save}
             disabled={saving || errs.length > 0 || !dirty}
             title={errs.length ? errs.join("\n") : undefined}
           >
             {saving ? "Saving…" : "Save"}
           </button>
         </div>
       </div>
 
       {err ? <div className="mt-3 rounded-lg border border-danger/30 bg-danger/10 p-3 text-xs text-danger">{err}</div> : null}
       {errs.length ? (
         <div className="mt-3 rounded-lg border border-warn/30 bg-warn/10 p-3 text-xs text-warn">
           {errs.map((e) => (
             <div key={e}>{e}</div>
           ))}
         </div>
       ) : null}
 
       <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
         <div className="rounded-lg border border-white/10 bg-black/10 p-3">
           <div className="text-xs font-semibold text-muted">Risk thresholds</div>
           <div className="mt-3 grid grid-cols-3 gap-2">
             <label className="text-xs text-muted">
               allow ≤
               <input
                 className="mt-1 w-full rounded-md border border-white/10 bg-black/20 px-2 py-1 text-sm text-text"
                 type="number"
                 value={draft.risk_allow_max}
                 onChange={(e) =>
                   setDraft({
                     ...draft,
                     risk_allow_max: clampInt(Number(e.target.value), 0, 100)
                   })
                 }
               />
             </label>
             <label className="text-xs text-muted">
               monitor ≤
               <input
                 className="mt-1 w-full rounded-md border border-white/10 bg-black/20 px-2 py-1 text-sm text-text"
                 type="number"
                 value={draft.risk_monitor_max}
                 onChange={(e) =>
                   setDraft({
                     ...draft,
                     risk_monitor_max: clampInt(Number(e.target.value), 0, 100)
                   })
                 }
               />
             </label>
             <label className="text-xs text-muted">
               sanitize ≤
               <input
                 className="mt-1 w-full rounded-md border border-white/10 bg-black/20 px-2 py-1 text-sm text-text"
                 type="number"
                 value={draft.risk_sanitize_max}
                 onChange={(e) =>
                   setDraft({
                     ...draft,
                     risk_sanitize_max: clampInt(Number(e.target.value), 0, 100)
                   })
                 }
               />
             </label>
           </div>
           <label className="mt-3 flex items-center gap-2 text-xs text-muted">
             <input
               type="checkbox"
               checked={draft.self_heal_enabled}
               onChange={(e) => setDraft({ ...draft, self_heal_enabled: e.target.checked })}
             />
             Self-healing enabled (incident-triggered guardrail updates)
           </label>
         </div>
 
         <div className="rounded-lg border border-white/10 bg-black/10 p-3">
           <div className="text-xs font-semibold text-muted">Policy visualization</div>
           <div className="mt-2 grid grid-cols-1 gap-3">
             <div>
               <div className="text-xs text-muted">Blocked input regexes ({draft.blocked_input_regexes.length})</div>
               <textarea
                 className="mt-1 h-28 w-full rounded-md border border-white/10 bg-black/20 p-2 font-mono text-[11px] text-text"
                 value={draft.blocked_input_regexes.join("\n")}
                 onChange={(e) =>
                   setDraft({
                     ...draft,
                     blocked_input_regexes: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean)
                   })
                 }
               />
             </div>
             <div>
               <div className="text-xs text-muted">Sanitize input regexes ({draft.sanitize_input_regexes.length})</div>
               <textarea
                 className="mt-1 h-28 w-full rounded-md border border-white/10 bg-black/20 p-2 font-mono text-[11px] text-text"
                 value={draft.sanitize_input_regexes.join("\n")}
                 onChange={(e) =>
                   setDraft({
                     ...draft,
                     sanitize_input_regexes: e.target.value.split("\n").map((s) => s.trim()).filter(Boolean)
                   })
                 }
               />
             </div>
           </div>
         </div>
       </div>
     </div>
   );
 }
 
