import type { EventItem } from "../lib/api";

function tone(type: string) {
   if (type.includes("block_isolate")) return "text-danger";
   if (type.includes("sanitize")) return "text-warn";
   if (type.includes("incident")) return "text-warn";
   if (type.includes("forensics")) return "text-ok";
   return "text-text";
 }
 
 export function EventFeed(props: { events: EventItem[] }) {
   const events = props.events.slice().reverse();
   return (
     <div className="rounded-xl border border-white/10 bg-panel2">
       <div className="flex items-center justify-between border-b border-white/10 px-4 py-3">
         <div className="text-sm font-semibold">Live threat feed</div>
         <div className="text-xs text-muted">{events.length} events</div>
       </div>
       <div className="max-h-[520px] overflow-auto">
         {events.map((e, idx) => (
           <div
             key={`${e.trace_id}-${idx}`}
             className="border-b border-white/5 px-4 py-3 hover:bg-white/5"
           >
             <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
               <div className={`text-xs font-mono ${tone(e.type)}`}>{e.type}</div>
               <div className="text-xs text-muted">{new Date(e.ts).toLocaleTimeString()}</div>
               <div className="text-xs text-muted font-mono">session {e.session_id.slice(0, 8)}</div>
               <div className="text-xs text-muted font-mono">trace {e.trace_id.slice(0, 8)}</div>
             </div>
             <pre className="mt-2 whitespace-pre-wrap break-words rounded-lg bg-black/20 p-2 text-[11px] text-muted">
               {JSON.stringify(e.payload, null, 2)}
             </pre>
           </div>
         ))}
         {events.length === 0 ? (
           <div className="px-4 py-10 text-center text-sm text-muted">No events yet.</div>
         ) : null}
       </div>
     </div>
   );
 }
 
