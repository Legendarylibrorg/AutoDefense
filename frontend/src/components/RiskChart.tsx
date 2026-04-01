import React, { useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
 import type { EventItem } from "../lib/api";
 
 type Point = { t: string; risk: number };
 
 function extractRisk(e: EventItem): number | null {
   if (!e.type.startsWith("decision.")) return null;
   const r = (e.payload as any)?.risk_score;
   const n = typeof r === "number" ? r : Number(r);
   return Number.isFinite(n) ? n : null;
 }
 
export function RiskChart(props: {
  events: EventItem[];
  thresholds?: { risk_allow_max: number; risk_monitor_max: number; risk_sanitize_max: number };
}) {
   const data = useMemo(() => {
     const pts: Point[] = [];
     for (const e of props.events) {
       const risk = extractRisk(e);
       if (risk === null) continue;
       pts.push({ t: new Date(e.ts).toLocaleTimeString(), risk });
     }
     return pts.slice(-50);
   }, [props.events]);
  const t = props.thresholds;
 
   return (
     <div className="rounded-xl border border-white/10 bg-panel p-4">
       <div className="mb-3 flex items-center justify-between">
         <div className="text-sm font-semibold">Risk score (recent decisions)</div>
         <div className="text-xs text-muted">{data.length} points</div>
       </div>
       <div className="h-[220px]">
         <ResponsiveContainer width="100%" height="100%">
           <AreaChart data={data} margin={{ left: 0, right: 10, top: 10, bottom: 0 }}>
             <defs>
               <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                 <stop offset="0%" stopColor="#7c5cff" stopOpacity={0.55} />
                 <stop offset="100%" stopColor="#7c5cff" stopOpacity={0.05} />
               </linearGradient>
             </defs>
             <CartesianGrid stroke="rgba(255,255,255,0.07)" strokeDasharray="3 3" />
             <XAxis dataKey="t" tick={{ fill: "rgba(230,233,242,0.7)", fontSize: 11 }} />
             <YAxis domain={[0, 100]} tick={{ fill: "rgba(230,233,242,0.7)", fontSize: 11 }} />
            {t ? (
              <>
                <ReferenceLine y={t.risk_allow_max} stroke="rgba(45,212,191,0.55)" strokeDasharray="4 4" />
                <ReferenceLine y={t.risk_monitor_max} stroke="rgba(255,176,32,0.55)" strokeDasharray="4 4" />
                <ReferenceLine y={t.risk_sanitize_max} stroke="rgba(255,77,109,0.55)" strokeDasharray="4 4" />
              </>
            ) : null}
             <Tooltip
               contentStyle={{
                 background: "rgba(17,26,51,0.98)",
                 border: "1px solid rgba(255,255,255,0.12)",
                 borderRadius: 12,
                 color: "#e6e9f2"
               }}
             />
             <Area type="monotone" dataKey="risk" stroke="#7c5cff" fill="url(#riskFill)" />
           </AreaChart>
         </ResponsiveContainer>
       </div>
     </div>
   );
 }
 
