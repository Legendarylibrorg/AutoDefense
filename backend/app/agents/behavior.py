from __future__ import annotations

import json
import re
from typing import Any

from app.core.models import AgentSignal, AnalyzeRequest, ThreatType

# ---------------------------------------------------------------------------
# Secret / credential patterns in model output (OWASP LLM02)
# ---------------------------------------------------------------------------

SENSITIVE_OUTPUT_REGEXES: list[str] = [
    # Cryptographic keys
    r"\bBEGIN (RSA|OPENSSH|DSA|EC|PGP|ENCRYPTED) PRIVATE KEY\b",
    r"\bBEGIN CERTIFICATE\b",
    # Cloud provider credentials
    r"\bAKIA[0-9A-Z]{16}\b",  # AWS access key
    r"\bASIA[0-9A-Z]{16}\b",  # AWS STS temp key
    r"\b[A-Za-z0-9/+=]{40}\b(?=.*aws)",  # AWS secret key context
    r"AIza[0-9A-Za-z_-]{35}",  # Google API key
    r"\bya29\.[0-9A-Za-z_-]+\b",  # Google OAuth token
    r"GOCSPX-[A-Za-z0-9_-]+",  # Google client secret
    # Version control / CI tokens
    r"\bghp_[A-Za-z0-9]{30,}\b",  # GitHub PAT
    r"\bghs_[A-Za-z0-9]{30,}\b",  # GitHub App token
    r"\bghr_[A-Za-z0-9]{30,}\b",  # GitHub refresh token
    r"\bglpat-[A-Za-z0-9_-]{20,}\b",  # GitLab PAT
    # Chat / messaging tokens
    r"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b",  # Slack token
    r"\bBot\s+[A-Za-z0-9_-]{50,}\b",  # Discord bot token
    # Database connection strings
    r"(mongodb|postgres|mysql|redis)://[^\s\"']+@[^\s\"']+",
    # Generic high-entropy secrets (API key = hex/base64)
    r"\b(sk-|pk_live_|sk_live_|rk_live_|pk_test_|sk_test_)[A-Za-z0-9]{20,}\b",
    r"\b[a-f0-9]{32,64}\b(?=.*(secret|key|token|password))",
]

# ---------------------------------------------------------------------------
# PII detection in output (OWASP LLM02 — Sensitive Information Disclosure)
# ---------------------------------------------------------------------------

PII_REGEXES: list[tuple[str, str]] = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN pattern (XXX-XX-XXXX)"),
    (r"\b\d{9}\b(?=.*ssn)", "SSN pattern (9 consecutive digits near 'ssn')"),
    (
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "Credit card number",
    ),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address"),
    (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "US phone number"),
    (r"\b\d{3}[-.\s]\d{3}[-.\s]\d{3}\b", "SIN/tax ID pattern"),
    (
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "IP address",
    ),
]

# ---------------------------------------------------------------------------
# System prompt leakage detection in output (OWASP LLM07)
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_LEAK_INDICATORS: list[str] = [
    r"(?i)(my|the) system prompt (is|says|reads|contains|states)",
    r"(?i)(here is|here'?s|the following is) (my|the) (system|initial|developer) (prompt|instructions|message)",
    r"(?i)i was (instructed|told|given|programmed) (to|that)",
    r"(?i)(my|the) (instructions|guidelines|rules) (are|state|say|read)",
    r"(?i)(system|developer|initial) (prompt|message|instructions)\s*[:=]\s*[\"']",
]

# ---------------------------------------------------------------------------
# Output injection detection (OWASP LLM05 — Improper Output Handling)
# ---------------------------------------------------------------------------

OUTPUT_INJECTION_REGEXES: list[str] = [
    r"<script[\s>]",
    r"javascript\s*:",
    r"on(error|load|click|mouseover|focus|blur|submit|change|input)\s*=",
    r"<iframe[\s>]",
    r"<object[\s>]",
    r"<embed[\s>]",
    r"<form\s+action\s*=",
    r"document\.(cookie|location|write|domain)",
    r"window\.(location|open|eval)",
    r"eval\s*\(",
    r"<img[^>]+onerror\s*=",
    r"data:text/html",
    # Markdown injection
    r"\[.*?\]\(javascript:",
    r"!\[.*?\]\(data:",
]

# ---------------------------------------------------------------------------
# Tool abuse / excessive agency patterns (OWASP LLM06 + Agentic Top 10)
# ---------------------------------------------------------------------------

TOOL_ABUSE_HINTS: list[str] = [
    # Destructive file operations
    "rm -rf",
    "rm -f",
    "rmdir",
    "del /f",
    "del /s",
    "format c:",
    "format d:",
    "shred",
    "wipe",
    # System commands
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "init 0",
    "init 6",
    "systemctl stop",
    "systemctl disable",
    "kill -9",
    "killall",
    "pkill",
    # Shell / code execution
    "powershell -enc",
    "powershell -e ",
    "cmd.exe /c",
    "cmd /c",
    "bash -c",
    "sh -c",
    "/bin/sh",
    "eval(",
    "exec(",
    "os.system(",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "__import__",
    "importlib.import_module",
    "compile(",
    "execfile(",
    # Network exfiltration
    "curl http",
    "wget http",
    "nc -e",
    "ncat -e",
    "netcat",
    "socat",
    "ssh -R",
    "ssh -L",
    "reverse shell",
    "bind shell",
    # Privilege escalation
    "sudo ",
    "su -",
    "su root",
    "chmod 777",
    "chmod +s",
    "chown root",
    "setuid",
    "setgid",
    # Credential access
    "cat /etc/passwd",
    "cat /etc/shadow",
    "mimikatz",
    "lazagne",
    "hashcat",
    "john ",
    "reg query",
    "cmdkey",
    # Container escape
    "docker exec",
    "docker run --privileged",
    "nsenter",
    "chroot",
    "mount /dev",
    "mount -o bind",
    # Database operations
    "drop table",
    "drop database",
    "truncate table",
    "delete from",
    "alter table",
    "; select ",
    "union select",
    "or 1=1",
    # Cloud / infra
    "aws iam",
    "aws s3 rm",
    "aws ec2 terminate",
    "gcloud compute instances delete",
    "az vm delete",
    "terraform destroy",
    "kubectl delete",
    # Network sniffing / packet capture / MITM
    "tcpdump",
    "tshark",
    "wireshark",
    "dumpcap",
    "ngrep",
    "ettercap",
    "bettercap",
    "arpspoof",
    "arpscan",
    "arp-scan",
    "mitmproxy",
    "mitmdump",
    "mitmweb",
    "responder",
    "dsniff",
    "sslstrip",
    "sslsplit",
    "ssldump",
    "scapy",
    "hping",
    "p0f",
    "pktmon",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
    "kismet",
    "netsniff-ng",
    "sniffglue",
    "pcap",
    "promiscuous",
]

# ---------------------------------------------------------------------------
# Code execution patterns (Agentic AI — Unexpected Code Execution)
# ---------------------------------------------------------------------------

CODE_EXECUTION_REGEXES: list[str] = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bsubprocess\.(call|run|Popen|check_output)\s*\(",
    r"\b__import__\s*\(",
    r"\bcompile\s*\(.*\bexec\b",
    r"\bglobals\s*\(\s*\)\s*\[",
    r"\bgetattr\s*\(",
    r"\bsetattr\s*\(",
    r"\b(Function|setTimeout|setInterval)\s*\(",
    r"\bnew\s+Function\s*\(",
    r"child_process\.(exec|spawn|fork)\s*\(",
    r"require\s*\(\s*['\"]child_process",
    r"Runtime\.getRuntime\(\)\.exec\s*\(",
    r"ProcessBuilder\s*\(",
]


def _redact_output(text: str) -> tuple[str, list[str]]:
    reasons: list[str] = []
    out = text
    for rx in SENSITIVE_OUTPUT_REGEXES:
        try:
            if re.search(rx, out, flags=re.IGNORECASE):
                out = re.sub(rx, "[[REDACTED_SECRET]]", out, flags=re.IGNORECASE)
                reasons.append(f"Redacted secret: {rx[:60]}")
        except re.error:
            pass
    return out, reasons


def _detect_pii(text: str) -> tuple[str, list[str]]:
    reasons: list[str] = []
    out = text
    for rx, label in PII_REGEXES:
        try:
            if re.search(rx, out, flags=re.IGNORECASE):
                out = re.sub(rx, "[[REDACTED_PII]]", out, flags=re.IGNORECASE)
                reasons.append(f"PII detected: {label}")
        except re.error:
            pass
    return out, reasons


class BehaviorAgent:
    name = "behavior"

    async def analyze(self, req: AnalyzeRequest) -> dict[str, Any]:
        signals: list[AgentSignal] = []

        # --- Tool abuse detection (OWASP LLM06 + Agentic AI #2) ---
        tool_calls = req.tool_calls or []
        if tool_calls:
            suspicious = []
            for call in tool_calls:
                s = json.dumps(call, default=str, ensure_ascii=False).lower()
                if any(h in s for h in TOOL_ABUSE_HINTS):
                    suspicious.append(call)
            if suspicious:
                signals.append(
                    AgentSignal(
                        agent=self.name,
                        threat_type=ThreatType.tool_abuse,
                        score=min(95.0, 60.0 + 10.0 * (len(suspicious) - 1)),
                        confidence=0.7,
                        reasons=["Suspicious tool-call content detected"],
                        evidence={"suspicious_tool_calls": suspicious[:10]},
                    )
                )

        for call in tool_calls:
            s = json.dumps(call, default=str, ensure_ascii=False)
            for rx in CODE_EXECUTION_REGEXES:
                try:
                    if re.search(rx, s, flags=re.IGNORECASE):
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.tool_abuse,
                                score=90.0,
                                confidence=0.85,
                                reasons=[f"Code execution pattern in tool call: {rx[:60]}"],
                                evidence={"pattern": rx[:60]},
                            )
                        )
                        break
                except re.error:
                    pass

        # --- Model output analysis ---
        out = req.model_output
        sanitized_output = out
        if out:
            # Secret redaction
            redacted, redact_reasons = _redact_output(out)
            if redact_reasons:
                signals.append(
                    AgentSignal(
                        agent=self.name,
                        threat_type=ThreatType.data_exfiltration,
                        score=85.0,
                        confidence=0.8,
                        reasons=redact_reasons[:10],
                        evidence={},
                    )
                )
                sanitized_output = redacted

            # PII detection
            redacted_pii, pii_reasons = _detect_pii(sanitized_output or "")
            if pii_reasons:
                signals.append(
                    AgentSignal(
                        agent=self.name,
                        threat_type=ThreatType.data_exfiltration,
                        score=75.0,
                        confidence=0.7,
                        reasons=pii_reasons[:10],
                        evidence={"pii_types": [r.split(": ")[1] for r in pii_reasons[:10]]},
                    )
                )
                sanitized_output = redacted_pii

            # System prompt leakage detection (OWASP LLM07)
            for rx in SYSTEM_PROMPT_LEAK_INDICATORS:
                try:
                    if re.search(rx, out, flags=re.IGNORECASE):
                        signals.append(
                            AgentSignal(
                                agent=self.name,
                                threat_type=ThreatType.data_exfiltration,
                                score=80.0,
                                confidence=0.75,
                                reasons=["Model output appears to leak system prompt"],
                                evidence={"indicator": rx[:80]},
                            )
                        )
                        break
                except re.error:
                    pass

            # Output injection / XSS detection (OWASP LLM05)
            injection_hits = []
            for rx in OUTPUT_INJECTION_REGEXES:
                try:
                    if re.search(rx, out, flags=re.IGNORECASE):
                        injection_hits.append(rx[:60])
                except re.error:
                    pass
            if injection_hits:
                signals.append(
                    AgentSignal(
                        agent=self.name,
                        threat_type=ThreatType.anomaly,
                        score=min(90.0, 55.0 + 10.0 * (len(injection_hits) - 1)),
                        confidence=0.8,
                        reasons=[f"Output injection detected: {h}" for h in injection_hits[:5]],
                        evidence={"patterns": injection_hits[:10]},
                    )
                )

            # Role-prefixed directives in output (jailbreak artifact)
            if re.search(r"(?im)^\s*(system|developer|admin)\s*:\s*", out):
                signals.append(
                    AgentSignal(
                        agent=self.name,
                        threat_type=ThreatType.anomaly,
                        score=55.0,
                        confidence=0.6,
                        reasons=[
                            "Output contains role-prefixed directives (possible jailbreak artifact)"
                        ],
                        evidence={},
                    )
                )

        return {"signals": signals, "sanitized_output": sanitized_output}
