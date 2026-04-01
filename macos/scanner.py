#!/usr/bin/env python3
"""
AUTO DEFENSE — macOS Security Scanner

Standalone zero-dependency script (stdlib only) that audits macOS security
posture: SIP, Gatekeeper, FileVault, firewall, XProtect, sniffer/MITM
processes, persistence mechanisms, open ports, and more.

Posts findings to the AUTO DEFENSE backend then exits.

Usage:
    python3 scanner.py                          # scan + print JSON
    python3 scanner.py --post http://host:8000  # scan + POST to backend
    python3 scanner.py --loop 60 --post ...     # repeat every 60 s
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


# ---------------------------------------------------------------------------
# Finding helper
# ---------------------------------------------------------------------------

def finding(
    category: str,
    severity: str,
    title: str,
    detail: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "evidence": evidence or {},
    }


def _run(cmd: list[str], timeout: int = 10) -> str | None:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=timeout).strip()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# System Integrity Protection (SIP)
# ---------------------------------------------------------------------------

def check_sip() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _run(["csrutil", "status"])
    if out is None:
        return results
    if "enabled" in out.lower():
        results.append(finding("integrity", "info", "SIP is enabled", out, {"sip": "enabled"}))
    else:
        results.append(finding(
            "integrity", "critical",
            "System Integrity Protection (SIP) is disabled",
            f"{out} — SIP prevents unauthorized modifications to protected system files and directories.",
            {"sip": "disabled"},
        ))
    return results


# ---------------------------------------------------------------------------
# Gatekeeper
# ---------------------------------------------------------------------------

def check_gatekeeper() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _run(["spctl", "--status"])
    if out is None:
        return results
    if "enabled" in out.lower():
        results.append(finding("integrity", "info", "Gatekeeper is enabled", out))
    else:
        results.append(finding(
            "integrity", "high",
            "Gatekeeper is disabled",
            f"{out} — Gatekeeper blocks unverified apps from running.",
            {"gatekeeper": "disabled"},
        ))
    return results


# ---------------------------------------------------------------------------
# FileVault (disk encryption)
# ---------------------------------------------------------------------------

def check_filevault() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _run(["fdesetup", "status"])
    if out is None:
        return results
    if "on" in out.lower():
        results.append(finding("integrity", "info", "FileVault is enabled", out))
    else:
        results.append(finding(
            "integrity", "high",
            "FileVault disk encryption is off",
            f"{out} — Full disk encryption protects data if the device is lost or stolen.",
            {"filevault": "off"},
        ))
    return results


# ---------------------------------------------------------------------------
# Application Firewall
# ---------------------------------------------------------------------------

def check_firewall() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    fw_tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    out = _run([fw_tool, "--getglobalstate"])
    if out is None:
        return results
    if "enabled" in out.lower():
        results.append(finding("integrity", "info", "Application firewall is enabled", out))
    else:
        results.append(finding(
            "integrity", "medium",
            "Application firewall is disabled",
            f"{out} — The macOS firewall controls incoming connections.",
            {"firewall": "disabled"},
        ))

    # Stealth mode
    stealth = _run([fw_tool, "--getstealthmode"])
    if stealth and "enabled" not in stealth.lower():
        results.append(finding(
            "integrity", "low",
            "Firewall stealth mode is disabled",
            "Stealth mode prevents the Mac from responding to probing requests (ICMP ping).",
            {"stealth_mode": "disabled"},
        ))
    return results


# ---------------------------------------------------------------------------
# macOS version (EOL check)
# ---------------------------------------------------------------------------

EOL_VERSIONS: dict[str, str] = {
    "10.13": "High Sierra (EOL)",
    "10.14": "Mojave (EOL)",
    "10.15": "Catalina (EOL)",
    "11": "Big Sur (EOL)",
    "12": "Monterey (EOL)",
}


def check_macos_version() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    ver = platform.mac_ver()[0]
    if not ver:
        return results
    major_minor = ".".join(ver.split(".")[:2])
    major = ver.split(".")[0]
    label = EOL_VERSIONS.get(major_minor) or EOL_VERSIONS.get(major)
    if label:
        results.append(finding(
            "integrity", "high",
            f"macOS version {ver} is end-of-life ({label})",
            "Running an EOL macOS version means no security patches are being delivered.",
            {"version": ver, "label": label},
        ))
    return results


# ---------------------------------------------------------------------------
# Remote Login (SSH)
# ---------------------------------------------------------------------------

def check_remote_login() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _run(["systemsetup", "-getremotelogin"])
    if out is None:
        return results
    if "on" in out.lower():
        results.append(finding(
            "network", "medium",
            "Remote Login (SSH) is enabled",
            f"{out} — SSH access is open. Ensure only authorized keys are configured.",
            {"remote_login": "on"},
        ))
    return results


# ---------------------------------------------------------------------------
# Open network ports
# ---------------------------------------------------------------------------

EXPECTED_PORTS = {22, 53, 80, 443, 631, 3000, 5000, 5432, 6379, 8000, 8080, 8443}


def check_open_ports() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _run(["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n"])
    if out is None:
        return results
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name = parts[0]
        addr_port = parts[8]
        match = re.search(r":(\d+)$", addr_port)
        if not match:
            continue
        port = int(match.group(1))
        if port not in EXPECTED_PORTS:
            results.append(finding(
                "network", "medium",
                f"Unexpected listener: {name} on port {port}",
                f"{name} is listening on {addr_port} — not in expected port list.",
                {"process": name, "port": port, "address": addr_port},
            ))
    return results


# ---------------------------------------------------------------------------
# Sniffer / MITM process detection
# ---------------------------------------------------------------------------

SNIFFER_TOOLS = {
    "tcpdump", "tshark", "wireshark", "dumpcap",
    "ngrep", "ettercap", "bettercap",
    "arpspoof", "arpscan", "arp-scan",
    "mitmproxy", "mitmdump", "mitmweb",
    "responder", "dsniff", "sslstrip", "sslsplit", "ssldump",
    "scapy", "hping", "hping3", "p0f",
    "airodump-ng", "aireplay-ng", "aircrack-ng", "kismet",
    "netsniff-ng", "sniffglue",
    "ncat", "socat",
}


def check_sniffer_processes() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _run(["ps", "axo", "pid,comm,args"])
    if out is None:
        return results
    for line in out.splitlines()[1:]:
        lower = line.lower()
        for tool in SNIFFER_TOOLS:
            if tool in lower:
                parts = line.split(None, 2)
                pid = parts[0] if parts else "?"
                cmd = parts[2] if len(parts) > 2 else line.strip()
                results.append(finding(
                    "network", "high",
                    f"Sniffer/MITM process: {tool} (PID {pid})",
                    f"Process matching '{tool}' detected — "
                    f"possible network sniffing or MITM. Command: {cmd[:200]}",
                    {"pid": pid, "tool": tool, "command": cmd[:300]},
                ))
                break
    return results


# ---------------------------------------------------------------------------
# Promiscuous interfaces (macOS via ifconfig)
# ---------------------------------------------------------------------------

def check_promiscuous() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _run(["ifconfig", "-a"])
    if out is None:
        return results
    current_iface = ""
    for line in out.splitlines():
        iface_match = re.match(r"^(\w+):", line)
        if iface_match:
            current_iface = iface_match.group(1)
        if "promisc" in line.lower():
            results.append(finding(
                "network", "high",
                f"Interface {current_iface} in promiscuous mode",
                "Promiscuous mode allows packet sniffing — may indicate a sniffer.",
                {"interface": current_iface},
            ))
    return results


# ---------------------------------------------------------------------------
# LaunchDaemons / LaunchAgents (persistence)
# ---------------------------------------------------------------------------

SYSTEM_LAUNCH_PREFIXES = {
    "com.apple.", "com.microsoft.", "com.google.",
    "com.docker.", "org.mozilla.", "org.chromium.",
}


def check_persistence() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    dirs = [
        Path("/Library/LaunchDaemons"),
        Path("/Library/LaunchAgents"),
        Path.home() / "Library" / "LaunchAgents",
    ]
    for d in dirs:
        if not d.exists():
            continue
        try:
            for f in d.iterdir():
                if not f.is_file() or not f.name.endswith(".plist"):
                    continue
                is_known = any(f.name.startswith(p) for p in SYSTEM_LAUNCH_PREFIXES)
                if not is_known:
                    severity = "medium" if "Daemons" in str(d) else "low"
                    results.append(finding(
                        "rootkit", severity,
                        f"Third-party persistence: {f.name}",
                        f"Non-system plist in {d} — may be legitimate software or a persistence mechanism.",
                        {"path": str(f), "directory": str(d)},
                    ))
        except PermissionError:
            pass
    return results


# ---------------------------------------------------------------------------
# Login Items
# ---------------------------------------------------------------------------

def check_login_items() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    out = _run(["osascript", "-e",
                'tell application "System Events" to get the name of every login item'])
    if out and out.strip():
        items = [i.strip() for i in out.split(",")]
        for item in items:
            results.append(finding(
                "integrity", "info",
                f"Login item: {item}",
                f"'{item}' runs at login.",
                {"item": item},
            ))
    return results


# ---------------------------------------------------------------------------
# XProtect version
# ---------------------------------------------------------------------------

def check_xprotect() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    plist = Path("/System/Library/CoreServices/XProtect.bundle/Contents/version.plist")
    if plist.exists():
        try:
            text = plist.read_text()
            match = re.search(r"<string>(\d+)</string>", text)
            ver = match.group(1) if match else "unknown"
            results.append(finding(
                "integrity", "info",
                f"XProtect version: {ver}",
                "XProtect provides built-in malware detection.",
                {"version": ver},
            ))
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Pcap files
# ---------------------------------------------------------------------------

PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".snoop", ".pkt"}
PCAP_SEARCH_DIRS = ["/tmp", "/var/tmp", str(Path.home() / "Desktop"), str(Path.home() / "Downloads")]


def check_pcap_files() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for search_dir in PCAP_SEARCH_DIRS:
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
                            f"Pcap file found at {f} ({st.st_size} bytes).",
                            {"path": str(f), "size": st.st_size},
                        ))
                    except OSError:
                        pass
        except (PermissionError, OSError):
            pass
    return results


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class MacScanner:
    def scan_all(self) -> dict[str, Any]:
        plat = platform.system().lower()
        result: dict[str, Any] = {
            "platform": plat,
            "kernel_version": platform.release(),
            "hostname": socket.gethostname(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "in_container": False,
            "findings": [],
            "hardening": {},
        }

        if plat != "darwin":
            print(f"[macos-scanner] This scanner is macOS-only (detected: {plat}).", file=sys.stderr)
            print("[macos-scanner] Use kernel/scanner.py for Linux or windows/scanner.py for Windows.", file=sys.stderr)
            return result

        # System integrity
        result["findings"].extend(check_sip())
        result["findings"].extend(check_gatekeeper())
        result["findings"].extend(check_filevault())
        result["findings"].extend(check_firewall())
        result["findings"].extend(check_macos_version())
        result["findings"].extend(check_xprotect())

        # Hardening summary
        h: dict[str, str] = {}
        for f in result["findings"]:
            if f["category"] == "integrity" and f["severity"] == "info":
                if "SIP" in f["title"]:
                    h["sip"] = "enabled"
                elif "Gatekeeper" in f["title"]:
                    h["gatekeeper"] = "enabled"
                elif "FileVault" in f["title"]:
                    h["filevault"] = "enabled"
                elif "firewall" in f["title"].lower():
                    h["firewall"] = "enabled"
                elif "XProtect" in f["title"]:
                    h["xprotect"] = f["evidence"].get("version", "present")
        checks = ["sip", "gatekeeper", "filevault", "firewall"]
        passed = sum(1 for c in checks if c in h)
        h["score"] = f"{passed}/{len(checks)}"
        h["percent"] = round(100 * passed / len(checks))
        result["hardening"] = h

        # Network
        result["findings"].extend(check_remote_login())
        result["findings"].extend(check_open_ports())
        result["findings"].extend(check_promiscuous())
        result["findings"].extend(check_sniffer_processes())
        result["findings"].extend(check_pcap_files())

        # Persistence
        result["findings"].extend(check_persistence())
        result["findings"].extend(check_login_items())

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

    parser = argparse.ArgumentParser(description="AUTO DEFENSE macOS scanner")
    parser.add_argument("--post", metavar="URL", help="POST results to backend")
    parser.add_argument("--loop", type=int, default=0, metavar="SECONDS", help="Repeat every N seconds")
    parser.add_argument("--json", action="store_true", help="Print raw JSON")
    parser.add_argument("--hmac-key", metavar="KEY", default=os.environ.get("SCANNER_HMAC_KEY", ""),
                        help="HMAC-SHA256 key for signing payloads (or set SCANNER_HMAC_KEY env var)")
    parser.add_argument("--api-key", metavar="KEY", default=os.environ.get("AUTODEFENSE_API_KEY", ""),
                        help="API key for backend auth (or set AUTODEFENSE_API_KEY env var)")
    args = parser.parse_args()

    scanner = MacScanner()

    while True:
        result = scanner.scan_all()
        n = len(result["findings"])
        info = sum(1 for f in result["findings"] if f["severity"] == "info")
        threats = n - info

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[macos-scanner] platform={result['platform']}  "
                  f"version={platform.mac_ver()[0]}  "
                  f"host={result['hostname']}  "
                  f"findings={n} (threats={threats}, info={info})")
            if result.get("hardening", {}).get("percent") is not None:
                print(f"[macos-scanner] hardening={result['hardening']['percent']}%")
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
                print(f"[macos-scanner] POST -> risk={resp.get('risk_score', '?')} "
                      f"action={resp.get('action', '?')}")
            except Exception as e:
                print(f"[macos-scanner] POST failed: {e}", file=sys.stderr)

        if args.loop <= 0:
            break
        time.sleep(args.loop)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
