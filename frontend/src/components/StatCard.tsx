import type { ReactNode } from "react";

export function StatCard(props: {
  title: string;
  value: ReactNode;
  hint?: string;
  tone?: "ok" | "warn" | "danger";
}) {
  const tone =
     props.tone === "ok"
       ? "border-ok/30 bg-panel"
       : props.tone === "warn"
         ? "border-warn/30 bg-panel"
         : props.tone === "danger"
           ? "border-danger/30 bg-panel"
           : "border-white/10 bg-panel";
 
   return (
     <div className={`rounded-xl border ${tone} p-4`}>
       <div className="text-sm text-muted">{props.title}</div>
       <div className="mt-2 text-2xl font-semibold text-text">{props.value}</div>
       {props.hint ? <div className="mt-1 text-xs text-muted">{props.hint}</div> : null}
     </div>
   );
 }
 
