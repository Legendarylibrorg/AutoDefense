from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import re
import socket
import struct
from email.parser import BytesParser
from email.policy import default as email_default
from typing import Any
from urllib.parse import urlparse

from app.core.models import AgentSignal, Artifact, ArtifactKind, ThreatType

# ---------------------------------------------------------------------------
# File extension policy
# ---------------------------------------------------------------------------

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".msi", ".scr", ".com", ".pif",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd",
    ".jar", ".class",
    ".iso", ".img", ".dmg",
    ".hta", ".cpl", ".inf", ".reg",
    ".lnk", ".url",
    ".appx", ".msix",
    ".elf", ".so", ".dylib",
}

# ---------------------------------------------------------------------------
# Phishing patterns (email artifacts)
# ---------------------------------------------------------------------------

PHISHING_REGEXES = [
    r"verify your account",
    r"urgent action required",
    r"password expires",
    r"payment failed",
    r"login (immediately|now)",
    r"suspended.*account",
    r"unusual (activity|sign.in|login)",
    r"confirm your (identity|payment|information)",
    r"click (here|below|this link) (to|and|immediately)",
    r"your account (will be|has been) (locked|suspended|closed|disabled)",
    r"wire transfer",
    r"bitcoin.*wallet",
    r"cryptocurrency.*send",
    r"gift card",
]

URL_REGEX = r"https?://[^\s)>\"]+"

# ---------------------------------------------------------------------------
# Script / malware markers in file headers
# ---------------------------------------------------------------------------

SCRIPT_MARKERS = [
    b"<script",
    b"javascript:",
    b"powershell",
    b"cmd.exe",
    b"#!/bin/sh",
    b"#!/bin/bash",
    b"#!/usr/bin/env python",
    b"#!/usr/bin/env perl",
    b"import os; os.system",
    b"eval(",
    b"exec(",
    b"WScript.Shell",
    b"CreateObject",
    b"ActiveXObject",
]

# ---------------------------------------------------------------------------
# SSRF / internal network patterns (URL artifacts)
# ---------------------------------------------------------------------------

SSRF_PATTERNS: list[str] = [
    r"^https?://127\.",
    r"^https?://0\.",
    r"^https?://localhost",
    r"^https?://10\.",
    r"^https?://172\.(1[6-9]|2[0-9]|3[01])\.",
    r"^https?://192\.168\.",
    r"^https?://169\.254\.",            # AWS metadata
    r"^https?://\[::1\]",              # IPv6 loopback
    r"^https?://\[fc",                  # IPv6 ULA
    r"^https?://\[fd",                  # IPv6 ULA
    r"^https?://metadata\.google",      # GCP metadata
    r"^https?://169\.254\.169\.254",    # Cloud metadata endpoint
    r"^https?://100\.100\.100\.200",    # Alibaba metadata
    r"^file://",
    r"^gopher://",
    r"^dict://",
    r"^ftp://127\.",
    r"^ftp://localhost",
]

# ---------------------------------------------------------------------------
# Polyglot / archive bomb detection
# ---------------------------------------------------------------------------

POLYGLOT_MAGIC_COMBOS: list[tuple[bytes, bytes, str]] = [
    (b"%PDF", b"<script", "PDF/HTML polyglot"),
    (b"%PDF", b"javascript:", "PDF/JS polyglot"),
    (b"\x89PNG", b"<script", "PNG/HTML polyglot"),
    (b"GIF89a", b"<script", "GIF/HTML polyglot"),
    (b"PK\x03\x04", b"<script", "ZIP/HTML polyglot"),
]

MAX_FILE_SIZE = 8_000_000  # 8 MB hard cap


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _looks_like_image(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif"
    if data.startswith(b"RIFF") and b"WEBP" in data[:16]:
        return "image/webp"
    return None


def _detect_archive_bomb(data: bytes) -> bool:
    """Heuristic: ZIP with extreme compression ratio, scanning ALL local file headers."""
    if not data.startswith(b"PK\x03\x04"):
        return False
    try:
        compressed_size = len(data)
        total_uncompressed = 0
        offset = 0
        entries_checked = 0
        while offset < len(data) - 30 and entries_checked < 1000:
            sig = data[offset : offset + 4]
            if sig != b"PK\x03\x04":
                break
            fname_len = struct.unpack_from("<H", data, offset + 26)[0]
            extra_len = struct.unpack_from("<H", data, offset + 28)[0]
            total_uncompressed += struct.unpack_from("<I", data, offset + 22)[0]
            comp_size = struct.unpack_from("<I", data, offset + 18)[0]
            offset += 30 + fname_len + extra_len + comp_size
            entries_checked += 1
        if total_uncompressed > 0 and compressed_size > 0:
            return total_uncompressed / compressed_size > 100
    except Exception:
        pass
    return False


_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _host_is_private_sync(hostname: str) -> bool:
    """Synchronous check — meant to be called via run_in_executor."""
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        pass
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _family, _type, _proto, _canonname, sockaddr in results:
            ip_str = sockaddr[0]
            try:
                addr = ipaddress.ip_address(ip_str)
                if any(addr in net for net in _PRIVATE_NETS):
                    return True
            except ValueError:
                continue
    except (socket.gaierror, OSError):
        pass
    return False


def _host_is_private(hostname: str) -> bool:
    """Non-blocking numeric IP check; DNS resolution deferred to async wrapper."""
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _check_ssrf_sync(url: str) -> list[str]:
    """Regex-only SSRF check (no DNS). Fast, safe for sync context."""
    reasons: list[str] = []
    for rx in SSRF_PATTERNS:
        try:
            if re.search(rx, url, flags=re.IGNORECASE):
                reasons.append(f"SSRF risk: URL matches internal/metadata pattern ({rx[:40]})")
                return reasons
        except re.error:
            pass
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip("[]")
        if host and _host_is_private(host):
            reasons.append(f"SSRF risk: hostname '{host}' resolves to a private/loopback address")
        if host and host.lower() in ("metadata.google.internal",):
            reasons.append(f"SSRF risk: cloud metadata hostname '{host}'")
    except Exception:
        pass
    return reasons


async def _check_ssrf_async(url: str) -> list[str]:
    """Full SSRF check including non-blocking DNS resolution for rebinding detection."""
    reasons = _check_ssrf_sync(url)
    if reasons:
        return reasons
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip("[]")
        if host:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                is_private = await asyncio.wait_for(
                    asyncio.get_running_loop().run_in_executor(None, _host_is_private_sync, host),
                    timeout=2.0,
                )
                if is_private:
                    reasons.append(f"SSRF risk: hostname '{host}' resolves to a private/loopback address")
    except (asyncio.TimeoutError, Exception):
        pass
    return reasons


class ArtifactAgent:
    name = "artifact"

    async def analyze(self, artifacts: list[Artifact]) -> dict[str, Any]:
        signals: list[AgentSignal] = []
        if not artifacts:
            return {"signals": signals, "artifact_summary": []}

        summary: list[dict[str, Any]] = []

        for a in artifacts[:50]:
            item: dict[str, Any] = {"kind": a.kind.value, "name": a.name, "blocked": False}

            if a.kind in (ArtifactKind.file, ArtifactKind.image):
                if not a.content_base64:
                    continue
                try:
                    data = base64.b64decode(a.content_base64, validate=True)
                except Exception:
                    signals.append(
                        AgentSignal(
                            agent=self.name,
                            threat_type=ThreatType.anomaly,
                            score=60,
                            confidence=0.8,
                            reasons=["Invalid base64 artifact payload"],
                            evidence={"name": a.name, "kind": a.kind.value},
                        )
                    )
                    continue

                item["sha256"] = _sha256(data)
                item["size_bytes"] = len(data)

                # Size cap (prevents zip bombs / huge payloads)
                if len(data) > MAX_FILE_SIZE:
                    item["blocked"] = True
                    signals.append(
                        AgentSignal(
                            agent=self.name,
                            threat_type=ThreatType.tool_abuse,
                            score=85,
                            confidence=0.9,
                            reasons=[f"Artifact too large (hard cap {MAX_FILE_SIZE // 1_000_000}MB)"],
                            evidence={"name": a.name, "size_bytes": len(data)},
                        )
                    )

                # Extension-based blocking
                if a.name:
                    low = a.name.lower()
                    ext = "." + low.split(".")[-1] if "." in low else ""
                    if ext in SUSPICIOUS_EXTENSIONS:
                        item["blocked"] = True
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.policy_violation,
                                score=95,
                                confidence=0.95,
                                reasons=[f"Blocked dangerous file extension: {ext}"],
                                evidence={"name": a.name, "sha256": item.get("sha256")},
                            )
                        )
                    # Double extension trick (e.g. invoice.pdf.exe)
                    parts = low.rsplit(".", 2)
                    if len(parts) >= 3:
                        outer = "." + parts[-1]
                        inner = "." + parts[-2]
                        if outer in SUSPICIOUS_EXTENSIONS or inner in SUSPICIOUS_EXTENSIONS:
                            item["blocked"] = True
                            signals.append(
                                AgentSignal(
                                    agent=self.name,
                                    threat_type=ThreatType.malware_in_file,
                                    score=90,
                                    confidence=0.9,
                                    reasons=[f"Double extension detected: {inner}{outer}"],
                                    evidence={"name": a.name},
                                )
                            )

                # Image validation
                detected = _looks_like_image(data)
                if a.kind == ArtifactKind.image:
                    if not detected:
                        item["blocked"] = True
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.anomaly,
                                score=75,
                                confidence=0.9,
                                reasons=["Image artifact does not match known image magic bytes"],
                                evidence={"name": a.name},
                            )
                        )
                    else:
                        item["detected_type"] = detected

                # Script marker scan
                head = data[:4096].lower()
                for m in SCRIPT_MARKERS:
                    if m in head:
                        item["blocked"] = True
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.malware_in_file,
                                score=90,
                                confidence=0.8,
                                reasons=["Embedded script marker detected in artifact header"],
                                evidence={"name": a.name, "marker": m.decode("utf-8", "ignore")},
                            )
                        )
                        break

                # Polyglot detection
                for magic_a, magic_b, label in POLYGLOT_MAGIC_COMBOS:
                    if data[:16].startswith(magic_a) and magic_b in data[:8192].lower():
                        item["blocked"] = True
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.malware_in_file,
                                score=92,
                                confidence=0.85,
                                reasons=[f"Polyglot file detected: {label}"],
                                evidence={"name": a.name, "type": label},
                            )
                        )
                        break

                # Archive bomb detection
                if _detect_archive_bomb(data):
                    item["blocked"] = True
                    signals.append(
                        AgentSignal(
                            agent=self.name,
                            threat_type=ThreatType.malware_in_file,
                            score=90,
                            confidence=0.85,
                            reasons=["Archive bomb detected (extreme compression ratio)"],
                            evidence={"name": a.name, "size": len(data)},
                        )
                    )

            elif a.kind == ArtifactKind.email:
                txt = a.content_text or ""
                if a.content_base64 and not txt:
                    try:
                        raw = base64.b64decode(a.content_base64, validate=True)
                        msg = BytesParser(policy=email_default).parsebytes(raw)
                        txt = (msg.get("subject", "") or "") + "\n" + (
                            msg.get_body(preferencelist=("plain",)) or ""
                        ).get_content()
                    except Exception:
                        txt = ""

                urls = re.findall(URL_REGEX, txt, flags=re.IGNORECASE)
                if urls:
                    item["urls"] = urls[:10]

                # SSRF check on URLs in emails
                for url in urls[:20]:
                    ssrf_reasons = await _check_ssrf_async(url)
                    if ssrf_reasons:
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.anomaly,
                                score=70,
                                confidence=0.8,
                                reasons=ssrf_reasons,
                                evidence={"url": url[:200]},
                            )
                        )

                phish_hits = [p for p in PHISHING_REGEXES if re.search(p, txt, flags=re.IGNORECASE)]
                if phish_hits or len(urls) >= 3:
                    signals.append(
                        AgentSignal(
                            agent=self.name,
                            threat_type=ThreatType.anomaly,
                            score=65 if phish_hits else 55,
                            confidence=0.7,
                            reasons=[
                                *(f"Phishing phrase: {p}" for p in phish_hits),
                                *(["High link density in email"] if len(urls) >= 3 else []),
                            ],
                            evidence={"url_count": len(urls)},
                        )
                    )

            elif a.kind == ArtifactKind.url:
                txt = (a.content_text or "").strip()
                if txt:
                    # Scheme validation
                    if not re.match(r"^https?://", txt, flags=re.IGNORECASE):
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.anomaly,
                                score=40,
                                confidence=0.8,
                                reasons=["URL artifact is not http/https"],
                                evidence={"value": txt[:200]},
                            )
                        )

                    # SSRF detection
                    ssrf_reasons = await _check_ssrf_async(txt)
                    if ssrf_reasons:
                        item["blocked"] = True
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.tool_abuse,
                                score=85,
                                confidence=0.9,
                                reasons=ssrf_reasons,
                                evidence={"url": txt[:200]},
                            )
                        )

                    # Open redirect / data URI
                    if re.search(r"^data:", txt, re.I) or re.search(r"^javascript:", txt, re.I):
                        item["blocked"] = True
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.malware_in_file,
                                score=80,
                                confidence=0.9,
                                reasons=["Dangerous URI scheme (data: or javascript:)"],
                                evidence={"url": txt[:200]},
                            )
                        )

            summary.append(item)

        # Aggregate blocked signal
        if any(s.get("blocked") for s in summary):
            signals.append(
                AgentSignal(
                    agent=self.name,
                    threat_type=ThreatType.policy_violation,
                    score=92,
                    confidence=0.95,
                    reasons=["One or more artifacts deterministically blocked by policy"],
                    evidence={"blocked_count": sum(1 for s in summary if s.get("blocked"))},
                )
            )

        return {"signals": signals, "artifact_summary": summary}
