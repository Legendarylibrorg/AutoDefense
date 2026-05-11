export function actionTone(action: string): string {
  if (action === "block_isolate") return "border-danger/40 bg-danger/10";
  if (action === "sanitize") return "border-warn/40 bg-warn/10";
  if (action === "log_monitor") return "border-white/15 bg-black/10";
  return "border-ok/40 bg-ok/10";
}
