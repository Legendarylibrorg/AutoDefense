#!/usr/bin/env python3
"""
AUTO DEFENSE — Windows Security Scanner

Audits Windows security posture (Defender, firewall, UAC, persistence, etc.).
Requires this repository's ``scanners/`` package (run from repo root).

Posts findings to the AUTO DEFENSE backend then exits.

Usage:
    python scanner.py                          # scan + print JSON
    python scanner.py --post http://host:8000  # scan + POST to backend
    python scanner.py --loop 60 --post ...     # repeat every 60 s
"""

from __future__ import annotations

import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from scanners.finding import finding  # noqa: E402


def _ps(script: str, timeout: int = 15) -> str | None:
    """Run a PowerShell one-liner and return stdout."""
    try:
        return subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            text=True, stderr=subprocess.DEVNULL, timeout=timeout,
        ).strip()
    except Exception:
        return None


def _cmd(args: list[str], timeout: int = 10) -> str | None:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=timeout).strip()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Windows Defender
# ---------------------------------------------------------------------------

def check_defender() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _ps("Get-MpComputerStatus | Select-Object -Property "
              "AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated "
              "| ConvertTo-Json")
    if out is None:
        results.append(finding(
            "integrity", "medium",
            "Unable to query Windows Defender status",
            "Get-MpComputerStatus failed — Defender may not be installed.",
        ))
        return results
    try:
        data = json.loads(out)
        av = data.get("AntivirusEnabled", False)
        rtp = data.get("RealTimeProtectionEnabled", False)
        sig = data.get("AntivirusSignatureLastUpdated", "unknown")

        if not av:
            results.append(finding(
                "integrity", "critical",
                "Windows Defender antivirus is disabled",
                "No active antivirus protection.",
                {"antivirus_enabled": av},
            ))
        if not rtp:
            results.append(finding(
                "integrity", "high",
                "Real-time protection is disabled",
                "Defender real-time scanning is off — malware won't be caught on access.",
                {"realtime_protection": rtp},
            ))
        if av and rtp:
            results.append(finding("integrity", "info", "Windows Defender is active",
                                   f"AV={av}, RTP={rtp}, sigs={sig}",
                                   {"antivirus_enabled": av, "realtime_protection": rtp, "signatures": str(sig)}))
    except json.JSONDecodeError:
        pass
    return results


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

def check_firewall() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _ps("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json")
    if out is None:
        return results
    try:
        profiles = json.loads(out)
        if isinstance(profiles, dict):
            profiles = [profiles]
        for p in profiles:
            name = p.get("Name", "?")
            enabled = p.get("Enabled", False)
            if not enabled:
                results.append(finding(
                    "integrity", "high",
                    f"Firewall profile '{name}' is disabled",
                    f"The {name} firewall profile is off — inbound connections are unfiltered.",
                    {"profile": name, "enabled": enabled},
                ))
            else:
                results.append(finding("integrity", "info", f"Firewall '{name}' enabled",
                                       f"{name} profile is active.", {"profile": name}))
    except json.JSONDecodeError:
        pass
    return results


# ---------------------------------------------------------------------------
# UAC (User Account Control)
# ---------------------------------------------------------------------------

def check_uac() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        val, _ = winreg.QueryValueEx(key, "EnableLUA")
        winreg.CloseKey(key)
        if val == 0:
            results.append(finding(
                "integrity", "critical",
                "User Account Control (UAC) is disabled",
                "UAC is off — all programs run with admin privileges without prompting.",
                {"EnableLUA": val},
            ))
        else:
            results.append(finding("integrity", "info", "UAC is enabled", "EnableLUA=1"))
    except Exception:
        out = _ps('(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA')
        if out and out.strip() == "0":
            results.append(finding("integrity", "critical", "UAC is disabled",
                                   "EnableLUA=0 in registry.", {"EnableLUA": 0}))
    return results


# ---------------------------------------------------------------------------
# BitLocker
# ---------------------------------------------------------------------------

def check_bitlocker() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _cmd(["manage-bde", "-status", "C:"])
    if out is None:
        out = _ps("Get-BitLockerVolume -MountPoint C: | Select-Object ProtectionStatus | ConvertTo-Json")
    if out is None:
        return results
    if "Protection On" in out or '"ProtectionStatus":1' in out or '"On"' in out:
        results.append(finding("integrity", "info", "BitLocker is enabled on C:",
                               "Full disk encryption is active."))
    else:
        results.append(finding(
            "integrity", "high",
            "BitLocker is not enabled on C:",
            "Disk encryption protects data if the device is lost or stolen.",
            {"raw": out[:300]},
        ))
    return results


# ---------------------------------------------------------------------------
# RDP (Remote Desktop)
# ---------------------------------------------------------------------------

def check_rdp() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Control\Terminal Server")
        val, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
        winreg.CloseKey(key)
        if val == 0:
            results.append(finding(
                "network", "medium",
                "Remote Desktop (RDP) is enabled",
                "RDP allows remote access — ensure NLA is required and strong passwords are used.",
                {"fDenyTSConnections": val},
            ))
    except Exception:
        out = _ps('(Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server").fDenyTSConnections')
        if out and out.strip() == "0":
            results.append(finding("network", "medium", "Remote Desktop (RDP) is enabled",
                                   "fDenyTSConnections=0"))
    return results


# ---------------------------------------------------------------------------
# SMB v1 (WannaCry attack surface)
# ---------------------------------------------------------------------------

def check_smb_v1() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _ps("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json")
    if out is None:
        return results
    try:
        data = json.loads(out)
        if data.get("EnableSMB1Protocol"):
            results.append(finding(
                "integrity", "critical",
                "SMB v1 is enabled",
                "SMB v1 is vulnerable to WannaCry/EternalBlue. It should be disabled.",
                {"smb1": True},
            ))
    except json.JSONDecodeError:
        pass
    return results


# ---------------------------------------------------------------------------
# PowerShell execution policy
# ---------------------------------------------------------------------------

def check_execution_policy() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _ps("Get-ExecutionPolicy")
    if out is None:
        return results
    policy = out.strip().lower()
    if policy in ("unrestricted", "bypass"):
        results.append(finding(
            "integrity", "medium",
            f"PowerShell execution policy is '{out.strip()}'",
            "Unrestricted/Bypass allows any script to run without signing requirements.",
            {"policy": out.strip()},
        ))
    return results


# ---------------------------------------------------------------------------
# Open ports
# ---------------------------------------------------------------------------

EXPECTED_PORTS = {80, 135, 139, 443, 445, 3389, 5040, 5432, 6379, 8000, 8080}


def check_open_ports() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _cmd(["netstat", "-an"])
    if out is None:
        return results
    for line in out.splitlines():
        if "LISTENING" not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        addr = parts[1]
        match = re.search(r":(\d+)$", addr)
        if not match:
            continue
        port = int(match.group(1))
        if port not in EXPECTED_PORTS and port > 1024:
            results.append(finding(
                "network", "medium",
                f"Unexpected listener on port {port}",
                f"Listening on {addr} — not in expected port list.",
                {"port": port, "address": addr},
            ))
    return results


# ---------------------------------------------------------------------------
# Sniffer / MITM processes
# ---------------------------------------------------------------------------

SNIFFER_TOOLS = {
    "wireshark", "tshark", "dumpcap", "windump",
    "npcap", "rawcap", "smartsniff",
    "ngrep", "ettercap", "bettercap",
    "arpspoof", "cain",
    "mitmproxy", "mitmdump", "mitmweb",
    "responder", "fiddler",
    "sslstrip", "ssldump",
    "scapy", "hping", "p0f", "pktmon",
    "netsh trace", "microsoft network monitor",
}


def check_sniffer_processes() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _cmd(["tasklist", "/FO", "CSV", "/NH"])
    if out is None:
        return results
    for line in out.splitlines():
        lower = line.lower()
        for tool in SNIFFER_TOOLS:
            if tool in lower:
                results.append(finding(
                    "network", "high",
                    f"Sniffer/MITM process detected: {tool}",
                    f"Process matching '{tool}' found in task list.",
                    {"tool": tool, "raw": line.strip()[:200]},
                ))
                break
    return results


# ---------------------------------------------------------------------------
# Scheduled tasks (persistence)
# ---------------------------------------------------------------------------

KNOWN_TASK_PREFIXES = {"\\microsoft\\", "\\google\\", "\\apple\\", "\\mozilla\\"}


def check_scheduled_tasks() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _cmd(["schtasks", "/Query", "/FO", "CSV", "/NH"])
    if out is None:
        return results
    suspicious_count = 0
    for line in out.splitlines():
        lower = line.lower()
        if not lower.strip():
            continue
        is_known = any(p in lower for p in KNOWN_TASK_PREFIXES)
        if not is_known and suspicious_count < 20:
            parts = line.split(",")
            name = parts[0].strip('"') if parts else line[:80]
            if name and not name.startswith("\\Microsoft"):
                suspicious_count += 1
                results.append(finding(
                    "rootkit", "low",
                    f"Non-system scheduled task: {name[:80]}",
                    "Third-party scheduled task — may be legitimate or a persistence mechanism.",
                    {"task": name[:200]},
                ))
    return results


# ---------------------------------------------------------------------------
# Autorun registry entries
# ---------------------------------------------------------------------------

AUTORUN_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
]


def check_autorun() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for key in AUTORUN_KEYS:
        out = _cmd(["reg", "query", key])
        if out is None:
            continue
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("HKEY_") or "REG_" not in line:
                continue
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            name = parts[0]
            value = parts[2] if len(parts) > 2 else ""
            results.append(finding(
                "rootkit", "info",
                f"Autorun entry: {name}",
                f"Registry: {key}  Value: {value[:200]}",
                {"key": key, "name": name, "value": value[:300]},
            ))
    return results


# ---------------------------------------------------------------------------
# Secure Boot
# ---------------------------------------------------------------------------

def check_secure_boot() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _ps("Confirm-SecureBootUEFI")
    if out is None:
        return results
    if out.strip().lower() == "true":
        results.append(finding("integrity", "info", "Secure Boot is enabled",
                               "UEFI Secure Boot is active."))
    else:
        results.append(finding(
            "integrity", "high",
            "Secure Boot is not enabled",
            "UEFI Secure Boot is off — rootkits can load before the OS.",
            {"secure_boot": out.strip()},
        ))
    return results


# ---------------------------------------------------------------------------
# Windows version (EOL check)
# ---------------------------------------------------------------------------

def check_windows_version() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    ver = platform.version()
    release = platform.release()
    # Windows 7 = 6.1, 8 = 6.2, 8.1 = 6.3
    if release in ("7", "8", "8.1") or ver.startswith("6.1") or ver.startswith("6.2") or ver.startswith("6.3"):
        results.append(finding(
            "integrity", "critical",
            f"Windows {release} is end-of-life",
            "This Windows version no longer receives security patches.",
            {"version": ver, "release": release},
        ))
    return results


# ---------------------------------------------------------------------------
# Pcap files
# ---------------------------------------------------------------------------

PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".etl"}


def check_pcap_files() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    search_dirs = [
        os.path.expandvars(r"%TEMP%"),
        os.path.expandvars(r"%USERPROFILE%\Desktop"),
        os.path.expandvars(r"%USERPROFILE%\Downloads"),
        r"C:\Temp",
    ]
    for search_dir in search_dirs:
        p = Path(search_dir)
        if not p.exists():
            continue
        try:
            for f in p.rglob("*"):
                if f.is_file() and f.suffix.lower() in PCAP_EXTENSIONS:
                    try:
                        st = f.stat()
                        results.append(finding(
                            "network", "medium",
                            f"Capture file: {f.name}",
                            f"Packet capture file found at {f} ({st.st_size} bytes).",
                            {"path": str(f), "size": st.st_size},
                        ))
                    except OSError:
                        pass
        except (PermissionError, OSError):
            pass
    return results


# ---------------------------------------------------------------------------
# Credential Guard
# ---------------------------------------------------------------------------

def check_credential_guard() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _ps("(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard).SecurityServicesRunning")
    if out is None:
        return results
    if "1" in out:
        results.append(finding("integrity", "info", "Credential Guard is active",
                               "Virtualization-based credential protection is running."))
    else:
        results.append(finding(
            "integrity", "medium",
            "Credential Guard is not active",
            "Credential Guard uses virtualization to protect NTLM hashes from theft.",
            {"raw": out[:200]},
        ))
    return results


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class WindowsScanner:
    def scan_all(self) -> dict[str, Any]:
        plat = platform.system().lower()
        result: dict[str, Any] = {
            "platform": plat,
            "kernel_version": platform.version(),
            "hostname": socket.gethostname(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "in_container": False,
            "findings": [],
            "hardening": {},
        }

        if plat != "windows":
            print(f"[windows-scanner] This scanner is Windows-only (detected: {plat}).", file=sys.stderr)
            print("[windows-scanner] Use kernel/scanner.py for Linux or macos/scanner.py for macOS.", file=sys.stderr)
            return result

        # System integrity
        result["findings"].extend(check_defender())
        result["findings"].extend(check_firewall())
        result["findings"].extend(check_uac())
        result["findings"].extend(check_bitlocker())
        result["findings"].extend(check_smb_v1())
        result["findings"].extend(check_secure_boot())
        result["findings"].extend(check_execution_policy())
        result["findings"].extend(check_credential_guard())
        result["findings"].extend(check_windows_version())

        # Hardening summary
        h: dict[str, str] = {}
        checks = ["defender", "firewall", "uac", "bitlocker", "secure_boot"]
        for f in result["findings"]:
            if f["severity"] == "info":
                title = f["title"].lower()
                if "defender" in title:
                    h["defender"] = "active"
                elif "firewall" in title and "enabled" in title:
                    h.setdefault("firewall", "enabled")
                elif "uac" in title:
                    h["uac"] = "enabled"
                elif "bitlocker" in title:
                    h["bitlocker"] = "enabled"
                elif "secure boot" in title and "enabled" in title:
                    h["secure_boot"] = "enabled"
                elif "credential guard" in title:
                    h["credential_guard"] = "active"
        passed = sum(1 for c in checks if c in h)
        h["score"] = f"{passed}/{len(checks)}"
        h["percent"] = round(100 * passed / len(checks))
        result["hardening"] = h

        # Network
        result["findings"].extend(check_rdp())
        result["findings"].extend(check_open_ports())
        result["findings"].extend(check_sniffer_processes())
        result["findings"].extend(check_pcap_files())

        # Persistence
        result["findings"].extend(check_scheduled_tasks())
        result["findings"].extend(check_autorun())

        return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _compute_hmac(data: bytes, key: str) -> str:
    import hmac as _hmac
    return _hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest()


def post_results(
    base_url: str,
    payload: dict[str, Any],
    *,
    hmac_key: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/scan/kernel"
    data = json.dumps(payload).encode("utf-8")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if hmac_key:
        headers["X-Scanner-Signature"] = _compute_hmac(data, hmac_key)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = Request(url, data=data, headers=headers, method="POST")
    with urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="AUTO DEFENSE Windows scanner")
    parser.add_argument("--post", metavar="URL", help="POST results to backend")
    parser.add_argument("--loop", type=int, default=0, metavar="SECONDS", help="Repeat every N seconds")
    parser.add_argument("--json", action="store_true", help="Print raw JSON")
    parser.add_argument("--hmac-key", metavar="KEY", default=os.environ.get("SCANNER_HMAC_KEY", ""),
                        help="HMAC-SHA256 key for signing payloads (or set SCANNER_HMAC_KEY env var)")
    parser.add_argument("--api-key", metavar="KEY", default=os.environ.get("AUTODEFENSE_API_KEY", ""),
                        help="API key for backend auth (or set AUTODEFENSE_API_KEY env var)")
    args = parser.parse_args()

    scanner = WindowsScanner()

    while True:
        result = scanner.scan_all()
        n = len(result["findings"])
        info = sum(1 for f in result["findings"] if f["severity"] == "info")
        threats = n - info

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[windows-scanner] platform={result['platform']}  "
                  f"version={platform.version()}  "
                  f"host={result['hostname']}  "
                  f"findings={n} (threats={threats}, info={info})")
            if result.get("hardening", {}).get("percent") is not None:
                print(f"[windows-scanner] hardening={result['hardening']['percent']}%")
            for f in result["findings"]:
                if f["severity"] != "info":
                    print(f"  [{f['severity'].upper()}] {f['title']}")

        if args.post:
            try:
                resp = post_results(
                    args.post, result,
                    hmac_key=args.hmac_key or None,
                    api_key=args.api_key or None,
                )
                print(f"[windows-scanner] POST -> risk={resp.get('risk_score', '?')} "
                      f"action={resp.get('action', '?')}")
            except Exception as e:
                print(f"[windows-scanner] POST failed: {e}", file=sys.stderr)

        if args.loop <= 0:
            break
        time.sleep(args.loop)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
