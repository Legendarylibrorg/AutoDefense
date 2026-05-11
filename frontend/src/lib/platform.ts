export function osLabel(os: string): string {
  if (os === "linux") return "Linux";
  if (os === "darwin") return "macOS";
  if (os === "windows") return "Windows";
  return os;
}
