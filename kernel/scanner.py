#!/usr/bin/env python3
"""
AUTO DEFENSE — Linux Kernel Scanner (Linux only)

Reads /proc, /sys, and the filesystem for rootkit and integrity indicators.
Requires this repository's ``scanners/`` package (run from repo root or keep
``scanners/`` next to this script). Posts findings to the AUTO DEFENSE backend.

For macOS use macos/scanner.py. For Windows use windows/scanner.py.

Usage:
    python3 scanner.py                          # scan + print JSON
    python3 scanner.py --post http://host:8000  # scan + POST to backend
    python3 scanner.py --loop 60 --post ...     # repeat every 60 s
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import socket
import stat
import struct
import sys
import time
from datetime import datetime, timezone
from collections import deque
from pathlib import Path
from typing import Any, Iterator
from urllib.request import Request, urlopen

# Cap filesystem walks so scans finish on large trees (e.g. CI runner /home caches).
_FS_WALK_MAX_DEPTH = 6
_FS_WALK_MAX_FILES = 25_000

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from scanners.finding import finding  # noqa: E402

# ---------------------------------------------------------------------------
# Rootkit detection
# ---------------------------------------------------------------------------

def _iter_files(
    root: Path,
    *,
    max_depth: int = _FS_WALK_MAX_DEPTH,
    max_files: int = _FS_WALK_MAX_FILES,
) -> Iterator[Path]:
    """Yield files under root with depth and count limits."""
    queue: deque[tuple[Path, int]] = deque([(root, 0)])
    seen = 0
    while queue:
        dir_path, depth = queue.popleft()
        if depth > max_depth:
            continue
        try:
            with os.scandir(dir_path) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            queue.append((Path(entry.path), depth + 1))
                        elif entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                            seen += 1
                            if seen >= max_files:
                                return
                    except OSError:
                        pass
        except (PermissionError, OSError):
            pass


def _file_sha256(path: Path, *, max_bytes: int = 64 * 1024 * 1024) -> str | None:
    """Return SHA-256 hex digest, or None if the file is unreadable or too large."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > max_bytes:
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1 << 20):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


KNOWN_ROOTKIT_PATHS = [
    "/dev/.udev.d", "/dev/.udevdb", "/dev/.udev", "/dev/.lp",
    "/dev/.ark", "/dev/.sf", "/dev/.pc", "/dev/.dm",
    "/usr/lib/.libx", "/usr/lib/.lso", "/usr/lib/.wormie",
    "/usr/sbin/.sniff", "/tmp/.scsi", "/tmp/.log",
    "/var/tmp/.private", "/var/tmp/.pipe",
    "/etc/ld.so.hash", "/lib/.ldd", "/lib/.so",
    "/usr/include/.h", "/usr/include/rpm",
    "/usr/share/.a", "/usr/share/.k",
    "/var/run/.pid", "/var/run/...pid",
    "/.hidden", "/.bagel", "/.cinik",
]


def check_hidden_processes() -> list[dict[str, Any]]:
    """Compare /proc PID enumeration with /proc/[pid]/status readability."""
    results: list[dict[str, Any]] = []
    proc = Path("/proc")
    if not proc.exists():
        return results

    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = entry.name
        status_file = entry / "status"
        try:
            status_file.read_text()
        except PermissionError:
            pass
        except FileNotFoundError:
            results.append(finding(
                "rootkit", "critical",
                f"Hidden process detected (PID {pid})",
                f"/proc/{pid} exists but /proc/{pid}/status is missing — "
                "classic rootkit process hiding technique.",
                {"pid": int(pid)},
            ))
        except Exception:
            pass
    return results


def check_ld_preload() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    env_val = os.environ.get("LD_PRELOAD", "")
    if env_val:
        results.append(finding(
            "rootkit", "high",
            "LD_PRELOAD environment variable set",
            f"LD_PRELOAD={env_val}  — may indicate library injection.",
            {"ld_preload": env_val},
        ))

    preload_file = Path("/etc/ld.so.preload")
    if preload_file.exists():
        try:
            content = preload_file.read_text().strip()
            if content:
                results.append(finding(
                    "rootkit", "high",
                    "/etc/ld.so.preload contains entries",
                    f"Contents: {content[:500]}  — may indicate userspace rootkit.",
                    {"file": "/etc/ld.so.preload", "content": content[:500]},
                ))
        except Exception:
            pass
    return results


def check_rootkit_files() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for p in KNOWN_ROOTKIT_PATHS:
        if os.path.exists(p):
            results.append(finding(
                "rootkit", "critical",
                f"Known rootkit artifact found: {p}",
                f"The path {p} matches a known rootkit drop location.",
                {"path": p},
            ))
    return results


def check_suspicious_dev() -> list[dict[str, Any]]:
    """Flag non-standard hidden files under /dev."""
    results: list[dict[str, Any]] = []
    dev = Path("/dev")
    if not dev.exists():
        return results
    try:
        for entry in dev.iterdir():
            if entry.name.startswith(".") and entry.name not in (
                ".", "..", ".udev",
            ):
                results.append(finding(
                    "rootkit", "high",
                    f"Suspicious hidden file in /dev: {entry.name}",
                    f"{entry} — hidden entries in /dev may indicate a rootkit.",
                    {"path": str(entry)},
                ))
    except PermissionError:
        pass
    return results


def check_kernel_modules() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    modules_path = Path("/proc/modules")
    if not modules_path.exists():
        return results

    KNOWN_SUSPICIOUS = {
        "diamorphine", "reptile", "suterusu", "adore",
        "knark", "modhide", "rkmod", "bdvl",
    }

    try:
        for line in modules_path.read_text().splitlines():
            parts = line.split()
            if not parts:
                continue
            mod_name = parts[0].lower()
            if mod_name in KNOWN_SUSPICIOUS:
                results.append(finding(
                    "rootkit", "critical",
                    f"Known rootkit kernel module loaded: {mod_name}",
                    f"The module '{mod_name}' matches a known rootkit LKM.",
                    {"module": mod_name, "raw": line.strip()},
                ))
            taint_field = parts[6] if len(parts) > 6 else ""
            if "O" in taint_field:
                results.append(finding(
                    "rootkit", "medium",
                    f"Out-of-tree kernel module: {parts[0]}",
                    f"Module '{parts[0]}' is out-of-tree (taint flag O).",
                    {"module": parts[0], "taint": taint_field},
                ))
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# Zero-day indicators
# ---------------------------------------------------------------------------

def check_deleted_exe_processes() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    proc = Path("/proc")
    if not proc.exists():
        return results

    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        exe_link = entry / "exe"
        try:
            target = os.readlink(str(exe_link))
            if "(deleted)" in target:
                results.append(finding(
                    "zero_day", "high",
                    f"Process {entry.name} running from deleted executable",
                    f"PID {entry.name} exe -> {target}  — common post-exploitation indicator.",
                    {"pid": int(entry.name), "exe": target},
                ))
        except (PermissionError, FileNotFoundError, OSError):
            pass
    return results


def check_tmp_executables() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for tmp_dir in ("/tmp", "/dev/shm", "/var/tmp"):
        p = Path(tmp_dir)
        if not p.exists():
            continue
        try:
            for f in _iter_files(p):
                try:
                    st = f.stat()
                    if st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                        results.append(finding(
                            "zero_day", "high",
                            f"Executable file in temp directory: {f}",
                            f"{f} has execute permission — possible payload staging.",
                            {"path": str(f), "size": st.st_size},
                        ))
                except (PermissionError, OSError):
                    pass
        except PermissionError:
            pass
    return results


def check_setuid_binaries() -> list[dict[str, Any]]:
    """Flag setuid binaries outside well-known system paths."""
    results: list[dict[str, Any]] = []
    EXPECTED_DIRS = {
        "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec",
        "/bin", "/sbin", "/snap",
    }

    for search_root in ("/usr/local", "/opt", "/tmp", "/home", "/var"):
        root = Path(search_root)
        if not root.exists():
            continue
        try:
            for f in _iter_files(root):
                try:
                    st = f.stat()
                    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        parent = str(f.parent)
                        if not any(parent.startswith(d) for d in EXPECTED_DIRS):
                            results.append(finding(
                                "zero_day", "high",
                                f"Unexpected setuid/setgid binary: {f}",
                                f"{f} has setuid/setgid bit in a non-standard location.",
                                {"path": str(f), "mode": oct(st.st_mode)},
                            ))
                except (PermissionError, OSError):
                    pass
        except PermissionError:
            pass
    return results


def check_raw_sockets() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for raw_path in ("/proc/net/raw", "/proc/net/raw6"):
        p = Path(raw_path)
        if not p.exists():
            continue
        try:
            lines = p.read_text().splitlines()[1:]  # skip header
            for line in lines:
                line = line.strip()
                if line:
                    results.append(finding(
                        "zero_day", "medium",
                        f"Raw socket detected ({os.path.basename(raw_path)})",
                        f"Active raw socket: {line[:120]}",
                        {"source": raw_path, "entry": line[:200]},
                    ))
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Kernel integrity
# ---------------------------------------------------------------------------

VULNERABLE_KERNEL_PATTERNS = [
    (r"^3\.", "Kernel 3.x is EOL — no security patches"),
    (r"^4\.[0-9]\.", "Kernel 4.0–4.9 branches are largely EOL"),
    (r"^4\.1[0-4]\.", "Kernel 4.10–4.14 may lack recent fixes"),
]


def check_kernel_version() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    ver = platform.release()
    for pattern, msg in VULNERABLE_KERNEL_PATTERNS:
        if re.match(pattern, ver):
            results.append(finding(
                "integrity", "high",
                f"Potentially vulnerable kernel version: {ver}",
                msg,
                {"kernel_version": ver},
            ))
            break
    return results


SYSCTL_HARDENING: list[tuple[str, str, str, str]] = [
    ("/proc/sys/kernel/randomize_va_space", "2", "ASLR not fully enabled", "high"),
    ("/proc/sys/kernel/kptr_restrict", "1", "Kernel pointer addresses exposed", "medium"),
    ("/proc/sys/kernel/dmesg_restrict", "1", "Kernel logs readable by unprivileged users", "low"),
    ("/proc/sys/kernel/yama/ptrace_scope", "1", "ptrace unrestricted (allows process injection)", "medium"),
    ("/proc/sys/kernel/unprivileged_bpf_disabled", "1", "Unprivileged BPF enabled (attack surface)", "medium"),
    ("/proc/sys/kernel/sysrq", "0", "Magic SysRq fully enabled", "low"),
]


def check_sysctl_hardening() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    results: list[dict[str, Any]] = []
    audit: dict[str, Any] = {}
    total = 0
    passed = 0

    for path, expected_min, issue, severity in SYSCTL_HARDENING:
        total += 1
        p = Path(path)
        key = os.path.basename(path)
        if not p.exists():
            audit[key] = "n/a"
            continue
        try:
            val = p.read_text().strip()
            audit[key] = val
            if int(val) >= int(expected_min):
                passed += 1
            else:
                results.append(finding(
                    "integrity", severity,
                    f"Kernel hardening gap: {key}={val} (expected >= {expected_min})",
                    issue,
                    {"sysctl": key, "value": val, "expected_min": expected_min},
                ))
        except Exception:
            audit[key] = "error"

    audit["score"] = f"{passed}/{total}"
    audit["percent"] = round(100 * passed / total) if total else 0
    return results, audit


def check_security_modules() -> tuple[list[dict[str, Any]], dict[str, Any]]:
    results: list[dict[str, Any]] = []
    info: dict[str, Any] = {"selinux": "absent", "apparmor": "absent"}

    se = Path("/sys/fs/selinux/enforce")
    if se.exists():
        try:
            val = se.read_text().strip()
            info["selinux"] = "enforcing" if val == "1" else "permissive"
            if val != "1":
                results.append(finding(
                    "integrity", "medium",
                    "SELinux is not enforcing",
                    f"SELinux enforce = {val}  — reduced mandatory access control.",
                    {"enforce": val},
                ))
        except Exception:
            info["selinux"] = "error"

    aa = Path("/sys/module/apparmor/parameters/enabled")
    if aa.exists():
        try:
            val = aa.read_text().strip()
            info["apparmor"] = "enabled" if val == "Y" else "disabled"
            if val != "Y":
                results.append(finding(
                    "integrity", "medium",
                    "AppArmor is not enabled",
                    "AppArmor parameter enabled != Y.",
                    {"enabled": val},
                ))
        except Exception:
            info["apparmor"] = "error"

    if info["selinux"] == "absent" and info["apparmor"] == "absent":
        results.append(finding(
            "integrity", "medium",
            "No mandatory access control (SELinux/AppArmor) detected",
            "Neither SELinux nor AppArmor appears active on this system.",
        ))

    return results, info


def check_boot_integrity() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    boot = Path("/boot")
    if not boot.exists():
        return results
    try:
        for f in boot.iterdir():
            if not f.is_file():
                continue
            if not any(f.name.startswith(p) for p in ("vmlinuz", "initrd", "initramfs", "System.map")):
                continue
            try:
                st = f.stat()
                digest = _file_sha256(f)
                if digest is None:
                    continue
                results.append(finding(
                    "integrity", "info",
                    f"Boot file hash: {f.name}",
                    f"SHA-256: {digest}",
                    {"file": str(f), "sha256": digest, "size": st.st_size},
                ))
            except (PermissionError, OSError):
                pass
    except PermissionError:
        pass
    return results


# ---------------------------------------------------------------------------
# Network anomalies
# ---------------------------------------------------------------------------

def _parse_proc_net_tcp(path: str) -> list[dict[str, Any]]:
    """Parse /proc/net/tcp or tcp6 for listening sockets."""
    entries: list[dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        return entries
    try:
        for line in p.read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            state = parts[3]
            if state != "0A":  # 0A = LISTEN
                continue
            local = parts[1]
            addr_hex, port_hex = local.rsplit(":", 1)
            port = int(port_hex, 16)
            if ":" in path and len(addr_hex) == 32:
                # IPv6
                addr = ":".join(
                    addr_hex[i : i + 4] for i in range(0, 32, 4)
                )
            else:
                octets = [str(int(addr_hex[i : i + 2], 16)) for i in range(0, 8, 2)]
                addr = ".".join(reversed(octets))
            entries.append({"addr": addr, "port": port, "raw": line.strip()[:120]})
    except Exception:
        pass
    return entries


EXPECTED_LISTEN_PORTS = {22, 53, 80, 443, 631, 8000, 3000, 6379, 5432, 3306, 8080, 8443}


def check_network_listeners() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for proto_path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for entry in _parse_proc_net_tcp(proto_path):
            if entry["port"] not in EXPECTED_LISTEN_PORTS:
                results.append(finding(
                    "network", "medium",
                    f"Unexpected listener on port {entry['port']}",
                    f"{entry['addr']}:{entry['port']} — not in expected port list.",
                    {"addr": entry["addr"], "port": entry["port"]},
                ))
    return results


def check_promiscuous_interfaces() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    net_dir = Path("/sys/class/net")
    if not net_dir.exists():
        return results
    for iface in net_dir.iterdir():
        flags_path = iface / "flags"
        if not flags_path.exists():
            continue
        try:
            flags = int(flags_path.read_text().strip(), 16)
            IFF_PROMISC = 0x100
            if flags & IFF_PROMISC:
                results.append(finding(
                    "network", "high",
                    f"Interface {iface.name} in promiscuous mode",
                    "Promiscuous mode allows packet sniffing — may indicate a sniffer.",
                    {"interface": iface.name, "flags": hex(flags)},
                ))
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Port sniffer / packet capture detection
# ---------------------------------------------------------------------------

SNIFFER_PROCESS_NAMES = {
    "tcpdump", "tshark", "wireshark", "dumpcap", "ngrep",
    "ettercap", "bettercap", "arpspoof", "arpscan", "arp-scan",
    "mitmproxy", "mitmdump", "mitmweb",
    "responder", "sniffglue", "netsniff-ng",
    "dsniff", "filesnarf", "mailsnarf", "urlsnarf", "msgsnarf",
    "ssldump", "sslstrip", "sslsplit",
    "p0f", "pktmon",
    "kismet", "aircrack-ng", "airodump-ng", "aireplay-ng",
    "scapy", "hping3",
}

SNIFFER_KERNEL_MODULES = {
    "af_packet",   # raw packet capture (used by tcpdump/wireshark)
    "nflog",       # netfilter logging
    "nf_log_all",
}

PCAP_SEARCH_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/root", "/home"]
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap", ".snoop", ".pkt"}


def check_sniffer_processes() -> list[dict[str, Any]]:
    """Detect running packet sniffer / MITM processes via /proc on Linux."""
    results: list[dict[str, Any]] = []
    proc = Path("/proc")
    if not proc.exists():
        return results

    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        comm_file = entry / "comm"
        cmdline_file = entry / "cmdline"
        try:
            comm = comm_file.read_text().strip().lower()
        except (PermissionError, FileNotFoundError, OSError):
            continue

        if comm in SNIFFER_PROCESS_NAMES:
            cmd = ""
            try:
                raw = cmdline_file.read_bytes()
                cmd = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            except Exception:
                pass
            results.append(finding(
                "network", "high",
                f"Packet sniffer running: {comm} (PID {entry.name})",
                f"The process '{comm}' is a known network sniffer or MITM tool. "
                f"Command: {cmd[:200]}",
                {"pid": int(entry.name), "comm": comm, "cmdline": cmd[:300]},
            ))
            continue

        # Also check the full cmdline for sniffer tool invocations
        try:
            raw = cmdline_file.read_bytes()
            cmdline_str = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip().lower()
            for tool in SNIFFER_PROCESS_NAMES:
                if tool in cmdline_str:
                    results.append(finding(
                        "network", "high",
                        f"Sniffer tool in process args: {tool} (PID {entry.name})",
                        f"Process {entry.name} cmdline contains '{tool}'. "
                        f"Command: {cmdline_str[:200]}",
                        {"pid": int(entry.name), "tool": tool, "cmdline": cmdline_str[:300]},
                    ))
                    break
        except (PermissionError, FileNotFoundError, OSError):
            pass

    return results


def check_pcap_files() -> list[dict[str, Any]]:
    """Detect pcap capture files in common writable directories."""
    results: list[dict[str, Any]] = []
    for search_dir in PCAP_SEARCH_DIRS:
        p = Path(search_dir)
        if not p.exists():
            continue
        try:
            for f in _iter_files(p):
                if f.suffix.lower() in PCAP_EXTENSIONS:
                    try:
                        st = f.stat()
                        results.append(finding(
                            "network", "medium",
                            f"Packet capture file found: {f}",
                            f"A .{f.suffix} file was found at {f} ({st.st_size} bytes). "
                            "This may indicate active or past network sniffing.",
                            {"path": str(f), "size": st.st_size},
                        ))
                    except (PermissionError, OSError):
                        pass
        except (PermissionError, OSError):
            pass
    return results


def check_arp_anomalies() -> list[dict[str, Any]]:
    """Check /proc/net/arp for duplicate MACs (ARP spoofing indicator)."""
    results: list[dict[str, Any]] = []
    arp_path = Path("/proc/net/arp")
    if not arp_path.exists():
        return results
    try:
        lines = arp_path.read_text().splitlines()[1:]  # skip header
        mac_to_ips: dict[str, list[str]] = {}
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            ip = parts[0]
            mac = parts[3].lower()
            if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                continue
            mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                results.append(finding(
                    "network", "critical",
                    f"ARP spoofing indicator: MAC {mac} maps to {len(ips)} IPs",
                    f"MAC address {mac} is associated with multiple IPs: "
                    f"{', '.join(ips[:10])}. This is a strong indicator of ARP spoofing / MITM.",
                    {"mac": mac, "ips": ips[:10]},
                ))
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# Container detection
# ---------------------------------------------------------------------------

def detect_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    cgroup = Path("/proc/1/cgroup")
    if cgroup.exists():
        try:
            text = cgroup.read_text()
            if "docker" in text or "kubepods" in text or "containerd" in text:
                return True
        except Exception:
            pass
    return False


# ---------------------------------------------------------------------------
# Main scanner class (Linux only)
# ---------------------------------------------------------------------------

class KernelScanner:
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

        if plat != "linux":
            print(f"[kernel-scanner] This scanner is Linux-only (detected: {plat}).", file=sys.stderr)
            print("[kernel-scanner] Use macos/scanner.py or windows/scanner.py for other platforms.", file=sys.stderr)
            return result

        result["in_container"] = detect_container()
        if result["in_container"]:
            result["findings"].append(finding(
                "integrity", "info",
                "Running inside a container",
                "Some checks have reduced visibility. "
                "For full host scanning, run directly on the host or with --pid host.",
            ))

        result["findings"].extend(check_hidden_processes())
        result["findings"].extend(check_ld_preload())
        result["findings"].extend(check_rootkit_files())
        result["findings"].extend(check_suspicious_dev())
        result["findings"].extend(check_kernel_modules())
        result["findings"].extend(check_deleted_exe_processes())
        result["findings"].extend(check_tmp_executables())
        result["findings"].extend(check_setuid_binaries())
        result["findings"].extend(check_raw_sockets())
        result["findings"].extend(check_kernel_version())

        sysctl_findings, hardening = check_sysctl_hardening()
        result["findings"].extend(sysctl_findings)
        result["hardening"] = hardening

        sec_findings, sec_info = check_security_modules()
        result["findings"].extend(sec_findings)
        result["hardening"]["security_modules"] = sec_info

        result["findings"].extend(check_boot_integrity())
        result["findings"].extend(check_network_listeners())
        result["findings"].extend(check_promiscuous_interfaces())
        result["findings"].extend(check_sniffer_processes())
        result["findings"].extend(check_pcap_files())
        result["findings"].extend(check_arp_anomalies())

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

    parser = argparse.ArgumentParser(description="AUTO DEFENSE kernel scanner")
    parser.add_argument("--post", metavar="URL", help="POST results to AUTO DEFENSE backend (e.g. http://localhost:8000)")
    parser.add_argument("--loop", type=int, default=0, metavar="SECONDS", help="Repeat scan every N seconds (0 = once)")
    parser.add_argument("--json", action="store_true", help="Print raw JSON to stdout")
    parser.add_argument("--hmac-key", metavar="KEY", default=os.environ.get("SCANNER_HMAC_KEY", ""),
                        help="HMAC-SHA256 key for signing payloads (or set SCANNER_HMAC_KEY env var)")
    parser.add_argument("--api-key", metavar="KEY", default=os.environ.get("AUTODEFENSE_API_KEY", ""),
                        help="API key for backend auth (or set AUTODEFENSE_API_KEY env var)")
    args = parser.parse_args()

    scanner = KernelScanner()

    while True:
        result = scanner.scan_all()
        n = len(result["findings"])
        info = sum(1 for f in result["findings"] if f["severity"] == "info")
        threats = n - info

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"[kernel-scanner] platform={result['platform']}  "
                  f"kernel={result['kernel_version']}  "
                  f"host={result['hostname']}  "
                  f"container={result['in_container']}  "
                  f"findings={n} (threats={threats}, info={info})")
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
                print(f"[kernel-scanner] POST -> risk={resp.get('risk_score', '?')} "
                      f"action={resp.get('action', '?')}")
            except Exception as e:
                print(f"[kernel-scanner] POST failed: {e}", file=sys.stderr)

        if args.loop <= 0:
            break
        time.sleep(args.loop)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
