from __future__ import annotations

import re
import unicodedata
from typing import Any

from app.core.models import AgentSignal, AnalyzeRequest, ThreatType
from app.core.rules_store import DynamicRules


def _normalize_text(text: str) -> str:
    """
    Normalize Unicode and whitespace to defeat evasion techniques:
    - NFKC normalization collapses full-width, math-bold, and other
      visually-similar Unicode into their ASCII equivalents.
    - Strip zero-width characters used for token fragmentation.
    - Collapse internal whitespace/newlines to single spaces so
      multi-line splits don't evade phrase-matching regexes.
    """
    out = unicodedata.normalize("NFKC", text)
    out = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]", "", out)
    out = re.sub(r"\s+", " ", out)
    return out


# ---------------------------------------------------------------------------
# Prompt injection patterns (OWASP LLM01)
# ---------------------------------------------------------------------------

BASE_INJECTION_REGEXES: list[str] = [
    # Instruction override
    r"ignore (all|any) (previous|prior) (instructions|directions|rules|context)",
    r"disregard (the )?(system|developer|above|previous) (message|prompt|instructions|directions)",
    r"forget (everything|all|your) (above|previous|prior|instructions|rules)",
    r"do not follow (the )?(rules|policies|guidelines|instructions|system prompt)",
    r"override (security|safety|content|output) (rules|policy|filter|guidelines)",
    r"bypass (the )?(filter|safety|content|restriction|guardrail|alignment)",
    r"(new|updated|revised) (instructions|rules|policy|system prompt)[:\s]",
    # System prompt extraction
    r"reveal (the )?(system prompt|hidden instructions|initial prompt|developer message)",
    r"(show|display|print|output|repeat|recite) (the )?(system prompt|hidden instructions|full prompt)",
    r"what (is|are) your (system prompt|instructions|rules|guidelines|initial prompt)",
    r"(copy|paste|echo|dump|write out) (the )?(system|initial) (prompt|instructions|message)",
    # Delimiter / context manipulation
    r"---\s*(system|assistant|developer)\s*---",
    r"\[system\]|\[developer\]|\[admin\]",
    r"<\|?(system|developer|admin)\|?>",
    r"```system\b",
    # Indirect injection via structured data
    r"(when|if) (the )?(user|human|person) (asks|says|requests).*?(instead|actually|really)",
]

# ---------------------------------------------------------------------------
# Jailbreak patterns (OWASP LLM01 + red team catalogs)
# ---------------------------------------------------------------------------

BASE_JAILBREAK_REGEXES: list[str] = [
    # DAN variants
    r"you are now (DAN|dan|do anything now|developer mode|unfiltered|uncensored|unrestricted|evil)",
    r"(enable|activate|switch to|enter) (DAN|developer|god|admin|sudo|root|debug|jailbreak) mode",
    r"(DAN|developer) mode (enabled|activated|on)",
    r"stay in (DAN|developer|character|unrestricted) mode",
    # Roleplay exploitation
    r"(pretend|act|behave|roleplay|imagine) (you are|you'?re|to be|as) (a |an )?(evil|malicious|unfiltered|unrestricted|uncensored|unethical|amoral)",
    r"(pretend|act|imagine) (there are|that) no (rules|restrictions|limitations|guidelines|ethical|moral)",
    r"in this (fictional|hypothetical|alternate|imaginary) (scenario|world|universe|reality).*?(no|without) (rules|restrictions|limits|ethics)",
    # Persona/character injection
    r"from now on,? (you will|you must|you shall|you are|always)",
    r"for the rest of this conversation",
    r"(you are|you'?re) (no longer|not) (bound by|subject to|limited by|restricted by)",
    r"(respond|answer|reply) (without|ignoring|bypassing) (any )?(filter|safety|restriction|guideline|rule|ethical|moral)",
    # Dual-response / split personality
    r"\b(two|dual|both|split) (response|answer|output|mode|persona)",
    r"(classic|normal|gpt) mode.{0,30}(developer|DAN|jailbreak|unrestricted) mode",
    r"response 1.{0,20}response 2",
    # Token smuggling / continuation
    r"(continue|complete|finish) (the )?(following|this|above) (without|ignoring) (filter|safety|restriction|censorship)",
    r"(please|just|simply) (answer|respond|say|tell me) (directly|honestly|truthfully|without filter)",
    # Encoding evasion (detect references to encoding tricks)
    r"(encode|decode|translate|convert) (this|the|my|it) (to|from|in|using|into) (base64|hex|rot13|binary|morse|unicode|pig latin)",
    r"(base64|b64|hex|rot13|binary|morse)\s*[:=]\s*[A-Za-z0-9+/=]{20,}",
    # Authority impersonation
    r"(i am|this is) (the )?(developer|admin|administrator|owner|creator|openai|anthropic|system)",
    r"(my )?(admin|root|sudo|developer|override) (password|key|code|token) is",
    r"authorization[:\s]+(granted|approved|confirmed|override)",
    # Multi-language injection (common non-English override phrases)
    r"ignorez (toutes? )?(les )?(instructions|consignes|règles)",  # French
    r"ignoriere (alle )?(vorherigen )?(anweisungen|regeln)",  # German
    r"ignora (todas? )?(las )?(instrucciones|reglas|directrices)",  # Spanish
    r"前の指示を無視",  # Japanese: ignore previous instructions
    r"忽略之前的指令",  # Chinese: ignore previous instructions
    r"предыдущие инструкции игнорируй",  # Russian
]

# ---------------------------------------------------------------------------
# Data exfiltration patterns (OWASP LLM02 + LLM07)
# ---------------------------------------------------------------------------

BASE_EXFIL_REGEXES: list[str] = [
    # Credential patterns
    r"(api|access|secret|private|auth|bearer|refresh) (key|token|secret|credential)",
    r"(ssh|gpg|pgp|private|rsa|ecdsa|ed25519) key",
    r"password(s)?(\s+is|\s*[:=])?",
    r"\bAWS_(SECRET|ACCESS)_",
    r"\bBEGIN (RSA|OPENSSH|DSA|EC|PGP|ENCRYPTED) PRIVATE KEY\b",
    # Environment / config extraction
    r"(print|show|display|dump|list|read|cat|echo) .{0,30}(env|\.env|environment|config|credential|secret)",
    r"(env|environment|config) (variable|file|secret|dump)",
    r"(os\.environ|process\.env|getenv|dotenv)",
    # Database extraction
    r"(dump|export|extract|show|select \*) .{0,30}(database|table|collection|schema|users?|accounts?|passwords?)",
    r"(connection string|database url|db_password|db_user)",
    # File system access
    r"(read|open|cat|type|get) .{0,20}(/etc/passwd|/etc/shadow|\.ssh/|\.aws/|\.env|secrets?\.ya?ml|\.git/config)",
    r"(list|ls|dir) .{0,20}(credentials?|secrets?|keys?|tokens?|passwords?)",
    # Network exfiltration
    r"(send|post|upload|exfiltrate|transfer) .{0,30}(to |via )?(http|ftp|webhook|external|server|endpoint)",
    r"(curl|wget|fetch|requests\.post|axios\.post|http\.post) .{0,30}(http|ftp)",
]


def _score_matches(text: str, regexes: list[str]) -> tuple[float, list[str], list[str]]:
    matches: list[str] = []
    reasons: list[str] = []
    for rx in regexes:
        try:
            if re.search(rx, text, flags=re.IGNORECASE):
                matches.append(rx)
                reasons.append(f"Matched: {rx[:80]}")
        except re.error:
            pass
    if not matches:
        return 0.0, [], []
    score = min(95.0, 35.0 + 15.0 * (len(matches) - 1))
    return score, reasons, matches


def _detect_encoding_evasion(text: str) -> tuple[float, list[str]]:
    """Detect common obfuscation used to bypass text filters."""
    reasons: list[str] = []

    # Homoglyph / unicode substitution (Latin look-alikes mixed with ASCII)
    ascii_count = sum(1 for c in text if ord(c) < 128)
    if len(text) > 20 and ascii_count < len(text) * 0.7:
        non_ascii = [c for c in text if ord(c) >= 128 and c.isalpha()]
        if len(non_ascii) > 5:
            reasons.append("High non-ASCII alphabetic density — possible homoglyph evasion")

    # Excessive whitespace / zero-width chars used to fragment tokens
    zw_chars = sum(1 for c in text if c in "\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad")
    if zw_chars > 2:
        reasons.append(f"Zero-width characters detected ({zw_chars}) — token fragmentation attempt")

    # Char-by-char spelling (i-g-n-o-r-e)
    if re.search(
        r"[a-z][\s\-_.]{1,3}[a-z][\s\-_.]{1,3}[a-z][\s\-_.]{1,3}[a-z][\s\-_.]{1,3}[a-z]", text, re.I
    ):
        collapsed = re.sub(r"[\s\-_.]+", "", text.lower())
        for keyword in ("ignore", "bypass", "override", "system", "prompt", "jailbreak"):
            if keyword in collapsed:
                reasons.append(f"Char-by-char spelling evasion detected for '{keyword}'")

    if not reasons:
        return 0.0, []
    return min(80.0, 40.0 + 15.0 * (len(reasons) - 1)), reasons


def _sanitize(text: str, matched_regexes: list[str]) -> str:
    sanitized = text
    for rx in matched_regexes:
        try:
            sanitized = re.sub(rx, "[[REDACTED]]", sanitized, flags=re.IGNORECASE)
        except re.error:
            pass
    return sanitized


class SentinelAgent:
    name = "sentinel"

    def __init__(self):
        pass

    async def analyze(
        self, req: AnalyzeRequest, dynamic: DynamicRules | None = None
    ) -> dict[str, Any]:
        text = req.user_input or ""
        normalized = _normalize_text(text)
        inj = BASE_INJECTION_REGEXES + (dynamic.injection_regex_append if dynamic else [])
        exf = BASE_EXFIL_REGEXES + (dynamic.exfil_regex_append if dynamic else [])

        # Match against both raw and normalized forms to catch evasion
        inj_score, inj_reasons, inj_matches = _score_matches(normalized, inj)
        exf_score, exf_reasons, exf_matches = _score_matches(normalized, exf)
        jb_score, jb_reasons, jb_matches = _score_matches(normalized, BASE_JAILBREAK_REGEXES)
        evasion_score, evasion_reasons = _detect_encoding_evasion(text)

        signals: list[AgentSignal] = []
        if inj_score:
            signals.append(
                AgentSignal(
                    agent=self.name,
                    threat_type=ThreatType.prompt_injection,
                    score=inj_score,
                    confidence=0.75,
                    reasons=inj_reasons,
                    evidence={"matches": inj_matches},
                )
            )
        if jb_score:
            signals.append(
                AgentSignal(
                    agent=self.name,
                    threat_type=ThreatType.jailbreak,
                    score=jb_score,
                    confidence=0.80,
                    reasons=jb_reasons,
                    evidence={"matches": jb_matches},
                )
            )
        if exf_score:
            signals.append(
                AgentSignal(
                    agent=self.name,
                    threat_type=ThreatType.data_exfiltration,
                    score=exf_score,
                    confidence=0.70,
                    reasons=exf_reasons,
                    evidence={"matches": exf_matches},
                )
            )
        if evasion_score:
            signals.append(
                AgentSignal(
                    agent=self.name,
                    threat_type=ThreatType.prompt_injection,
                    score=evasion_score,
                    confidence=0.65,
                    reasons=evasion_reasons,
                    evidence={"type": "encoding_evasion"},
                )
            )

        matched = list(set(inj_matches + jb_matches + exf_matches))
        sanitized_input = _sanitize(normalized, matched) if matched else normalized

        if inj_matches or jb_matches:
            sanitized_input = re.sub(
                r"(?im)^\s*(system|developer|admin|root)\s*:\s*.*$",
                "[[REDACTED_ROLE_LINE]]",
                sanitized_input,
            )

        return {"signals": signals, "sanitized_input": sanitized_input}
