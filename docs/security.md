# Security

**Scope:** This document describes how the **implemented system** is designed to behave. OWASP tables indicate whether a threat category has **runtime mitigations in this codebase**, is **partially** addressed, or is **out of scope** (handled elsewhere or not covered). Nothing here is a guarantee of security in your environment; combine with updates, monitoring, and your own assessments.

## Threat model

### Attacker goals

1. **Prompt injection** — Override system instructions to control AI behavior
2. **Jailbreak** — Bypass safety alignment via personas, roleplay, or encoding tricks
3. **Data exfiltration** — Extract secrets, PII, credentials, or system prompts
4. **Tool abuse** — Exploit AI tool-calling to execute destructive commands
5. **Malicious artifacts** — Upload malware, polyglots, or archive bombs
6. **Network intrusion** — Sniff traffic, spoof ARP, establish MITM positions
7. **Kernel compromise** — Install rootkits, exploit kernel vulnerabilities
8. **Crypto downgrade** — Force `alg:none` or weak encryption to bypass data protection
9. **DoS / resource exhaustion** — Overwhelm rate limits, body size checks, or event loops

### Defense layers

```
┌─────────────────────────────────────────────────┐
│  Sealed transport (AES-256-GCM + HKDF)           │  ← Layer 1: Wire security
├─────────────────────────────────────────────────┤
│  API key authentication (constant-time)         │  ← Layer 2: AuthN
├─────────────────────────────────────────────────┤
│  Rate limiting (per-IP, Redis fixed-window)      │  ← Layer 3: DoS prevention
├─────────────────────────────────────────────────┤
│  Body size limits (Content-Length + chunked)     │  ← Layer 4: Input bounds
├─────────────────────────────────────────────────┤
│  Input validation (Pydantic + NFKC + ReDoS)     │  ← Layer 5: Input hygiene
├─────────────────────────────────────────────────┤
│  Sentinel Agent (injection + jailbreak + exfil)  │  ← Layer 6: Input defense
│  Policy Agent (blocked/sanitize regexes)         │
├─────────────────────────────────────────────────┤
│  Behavior Agent (output + tool monitoring)       │  ← Layer 7: Output defense
│  Artifact Agent (file + URL + SSRF scanning)     │
├─────────────────────────────────────────────────┤
│  Risk scoring + Response engine                  │  ← Layer 8: Decision
├─────────────────────────────────────────────────┤
│  Self-healing (dynamic rule generation)          │  ← Layer 9: Adaptation
├─────────────────────────────────────────────────┤
│  Forensics (encrypted audit trail)               │  ← Layer 10: Accountability
├─────────────────────────────────────────────────┤
│  At-rest encryption in Redis (AES-256-GCM)       │  ← Layer 11: Data protection
├─────────────────────────────────────────────────┤
│  Host scanners (kernel/network/integrity)        │  ← Layer 12: Host defense
└─────────────────────────────────────────────────┘
```

## Encryption

### AES-256-GCM (v3 envelope)

At-rest and sealed transport use **one 32-byte master key** per domain. New payloads use **single-layer AES-256-GCM** with an HKDF-derived AES key:

| Material | HKDF `info` (UTF-8) | Purpose |
|----------|---------------------|---------|
| `key_aes` | `autodefense-aes-v3` | AES-256-GCM encrypt/decrypt |

#### Encrypt path (v3)

1. Canonical JSON serialization on the backend (`sort_keys=True`, compact separators); browser sealed transport uses `JSON.stringify` of the request object.
2. **AES-256-GCM**(key_aes, random 12-byte nonce, plaintext, AAD) — confidentiality and authenticity (AEAD).

#### Decrypt path (v3)

1. AES-256-GCM decrypt — GCM authentication tag must verify.
2. JSON parse of plaintext; any failure returns empty (transport) or raises (at-rest stores).

#### v3 envelope format

```json
{
  "v": 3,
  "alg": "AES-256-GCM",
  "nonce_b64": "base64(12 random bytes)",
  "ct_b64": "base64(ciphertext + GCM tag)"
}
```

#### Backward compatibility

- **v2** double-layer envelopes (`alg: "AES-256-GCM-DOUBLE"`) and **v1** single-layer envelopes (`v: 1`, raw master key) remain **decrypt-only** for migration.
- All **new writes** use v3.
- `alg: "none"` downgrade is rejected when encryption is enabled (at-rest loads fail loudly).

### HKDF parameters (backend and browser)

- **Backend** (`app/core/crypto.py`): `cryptography` HKDF-SHA256, output length 32, **`salt=None`** (digest-sized zero salt in extract).
- **Dashboard** (`frontend/src/lib/api.ts`): Web Crypto HKDF-SHA256, **`salt` = 32 zero bytes**, **`info` = `autodefense-aes-v3`** — must stay aligned with the backend.

Third-party sealed-transport clients should use the v3 layout and HKDF label above.

### Key validation and failure modes

- Malformed `AUTODEFENSE_DATA_KEY_B64` or `AUTODEFENSE_TRANSPORT_KEY_B64` (invalid base64 or not 32 bytes after decode) **prevents startup**.
- `AUTODEFENSE_SCANNER_HMAC_KEY`, when set, must be at least **16 characters**.
- At-rest decrypt failures (wrong key, tampering, `alg: "none"` while encryption is on) raise errors instead of silently resetting config/rules to defaults.
- Sealed transport decrypt failures return HTTP **400** (unchanged).

### Key management

| Layer | Protects | Key env var |
|-------|----------|-------------|
| At-rest | Config, forensics, dynamic rules, kernel status in Redis | `AUTODEFENSE_DATA_KEY_B64` |
| Sealed transport | Client-to-backend request payloads | `AUTODEFENSE_TRANSPORT_KEY_B64` |

- Each env var holds **one** 256-bit master; v3 derives a single AES key via HKDF (same algorithm for data and transport managers).
- Keys are base64-encoded 32-byte values. Invalid keys fail at startup.
- Backend uses the audited Python `cryptography` library (`AESGCM`, `HKDF`)
- Frontend uses the Web Crypto API (`AES-GCM`, `HKDF`) — browser-native, no JS crypto libraries
- **Do not embed `VITE_TRANSPORT_KEY_B64` in production frontend builds** — anyone with the bundle can forge sealed payloads. Prefer session-only entry in the dashboard; rely on TLS + API key as the primary transport trust boundary.
- AAD (Additional Authenticated Data) binds ciphertext to its context (e.g., `"analyze"`, `"scan"`, `"runtime_config"`)
- If `AUTODEFENSE_DATA_KEY_B64` is empty **and** `AUTODEFENSE_ENVIRONMENT` is `local`, the backend generates an ephemeral at-rest key (data lost on restart). Outside `local`, an empty data key with encryption enabled prevents startup.
- If `AUTODEFENSE_TRANSPORT_KEY_B64` is empty, sealed endpoints return 400

To generate a key manually:

```bash
openssl rand -base64 32
```

### Scanner payload integrity

Host scanners (Linux, macOS, Windows) sign their POST payloads with HMAC-SHA256 using `AUTODEFENSE_SCANNER_HMAC_KEY` (minimum **16 characters** when set; use `openssl rand -hex 32` in production). The backend verifies the signature on the raw request body before processing when that key is configured. Outside `local`, `POST /scan/kernel` is rejected if the scanner HMAC key is unset so unsigned ingest cannot be mistaken for a verified scan.

## Authentication

- **HTTP endpoints**: Bearer token in `Authorization` header, verified with `hmac.compare_digest()` (constant-time)
- **WebSocket**: API key passed via `Sec-WebSocket-Protocol: auth.<key>` header (never in URL query parameters — prevents logging/caching leaks)
- **Public endpoints** (`/health`, `/docs`, `/openapi.json`, `/redoc`): no authentication required
- **Disabled auth warning**: if `AUTODEFENSE_API_KEY` is unset in `local`, all endpoints are unauthenticated (startup warning logged). Outside `local`, startup fails until an API key is set.

## Input validation hardening

- **Unicode normalization**: NFKC applied before all regex matching (prevents homoglyph/encoding bypass)
- **Zero-width character stripping**: U+200B through U+FEFF and soft hyphens removed
- **Whitespace collapsing**: Multiple whitespace characters collapsed to single space
- **ReDoS protection**: All dynamic regexes (from Redis `ConfigStore` and `RulesStore`) are validated before use:
  - Compiled with `re.compile()` — rejects invalid syntax
  - Nested quantifier detection via `\([^)]*[+*][^)]*\)[+*]`
  - Timeout-bounded probe test (0.5s) on adversarial input string
  - Unsafe regexes silently dropped with warning log
- **Pydantic field constraints**: `min_length`, `max_length`, `ge`, `le` on all model fields; metadata size capped
- **Request body size**: 10 MB global limit enforced for both `Content-Length` and chunked transfer encoding

## SSRF protection

The `ArtifactAgent` defends against SSRF at three levels:

1. **Regex patterns**: 17 patterns matching internal IPs, cloud metadata endpoints, and dangerous URI schemes (`file://`, `gopher://`, `dict://`)
2. **Numeric IP resolution**: Parses hex, decimal, and octal IP representations via `ipaddress` module
3. **Async DNS resolution**: Resolves hostnames via `socket.getaddrinfo()` in a thread executor with a 2-second timeout, then checks resolved IPs against private network ranges — catches DNS rebinding attacks without blocking the event loop

## OWASP LLM Top 10 (2025) coverage

| # | Threat | Status | Implementation |
|---|--------|--------|----------------|
| 1 | Prompt Injection | Defended | SentinelAgent: multi-layer injection and jailbreak detection with NFKC Unicode normalization, encoding evasion analysis, multi-language support. PolicyAgent: configurable regexes. Self-healing: auto-generates blocking rules. |
| 2 | Sensitive Information Disclosure | Defended | BehaviorAgent: cloud credential, VCS token, database URI, and generic API key detection. PII detectors for common formats. System prompt leak indicators. All auto-redacted. |
| 3 | Supply Chain | Out of scope (runtime) | Runtime cannot fully mitigate compromised upstream packages. **Mitigation in this repo:** `.github/dependabot.yml` (grouped weekly updates), frozen `backend/uv.lock` + `frontend/package-lock.json`, local quality gate [docs/CI_LOCAL.md](CI_LOCAL.md) (`npm audit`, OSV lockfile scan via `make ci`); enable [Dependabot security updates](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates) on GitHub and review changelogs for deployments. |
| 4 | Data and Model Poisoning | Out of scope | Training-time concern |
| 5 | Improper Output Handling | Defended | BehaviorAgent: output injection detection (XSS, event handlers, iframes, eval, markdown injection, data URIs) |
| 6 | Excessive Agency | Defended | BehaviorAgent: extensive tool abuse and code execution detection covering destructive ops, shell execution, privilege escalation, container escape, cloud infra, network tools |
| 7 | System Prompt Leakage | Defended | SentinelAgent: input-side extraction blocking. BehaviorAgent: output-side leak detection. |
| 8 | Vector and Embedding Weaknesses | Out of scope | RAG-specific (no vector database in this system) |
| 9 | Misinformation | Out of scope | Requires fact-checking capability |
| 10 | Unbounded Consumption | Defended | Rate limiting (120 req/min/IP, Redis-backed fixed window with bounded in-memory fallback on Redis errors), 10 MB body limit (Content-Length + chunked), Pydantic size constraints, artifact caps (50 per request), SSE/WebSocket connection limits and timeouts |

## OWASP Agentic AI Top 10 (2026) coverage

| # | Threat | Status | Implementation |
|---|--------|--------|----------------|
| 1 | Agent Goal Hijack | Defended | Full jailbreak + prompt injection defense layer |
| 2 | Tool Misuse and Exploitation | Defended | Comprehensive tool abuse and code execution pattern detection |
| 3 | Identity and Privilege Abuse | Partial | Detects privilege escalation commands (sudo, chmod +s, chown root, etc.) |
| 4 | Agentic Supply Chain Vulns | Out of scope | Build-time concern |
| 5 | Unexpected Code Execution | Defended | eval/exec/subprocess/os.system/child_process/Runtime.exec detection in tool calls |
| 6 | Memory and Context Poisoning | Defended | Delimiter injection detection (`[system]`, `<|system|>`, `---system---`), role-line redaction |
| 7 | Insecure Inter-Agent Comms | Defended | AES-256-GCM (HKDF-derived keys) at rest and sealed transport |
| 8 | Cascading Failures | Defended | React ErrorBoundary, graceful Redis shutdown (lifespan), health endpoint, WebSocket auto-reconnect with exponential backoff |
| 9 | Human-Agent Trust Exploitation | Defended | Phishing pattern detection, authority impersonation detection in input |
| 10 | Rogue Agents | Defended | Linux kernel rootkit + zero-day detection layer |

## Attack pattern coverage

### Sentinel Agent
- Prompt injection detection (instruction overrides, system prompt extraction, delimiter manipulation, indirect injection)
- Jailbreak detection (DAN variants, roleplay, persona injection, dual-response, token smuggling, authority impersonation, encoding tricks, multi-language)
- Encoding evasion analysis (homoglyphs, zero-width characters, char-by-char spelling, NFKC normalization)

### Behavior Agent
- Secret and credential detection across major cloud providers, VCS platforms, messaging services, databases
- PII detection and auto-redaction (identity numbers, financial data, contact info)
- Tool abuse and code execution pattern analysis (JSON-serialized tool call inspection)
- Output injection / XSS detection
- System prompt leak indicators

### Artifact Agent
- Blocked file extensions with double-extension detection
- Script marker and polyglot file detection
- Archive bomb heuristics (multi-entry ZIP scanning, 100:1 compression ratio threshold)
- SSRF detection with numeric IP resolution and async DNS rebinding detection
- Phishing detection with link density analysis

## Security-focused development history

During iterative development, several passes addressed concrete issues (crypto edge cases, SSRF, DoS limits, WebSocket auth, ReDoS on dynamic rules, etc.). The table below is a **historical log of engineering themes**, not an external penetration-test report or certification.

| Pass | Themes addressed (examples) |
|------|----------------------------|
| R1 | `alg:none` downgrade rejection, constant-time API key comparison, NFKC Unicode normalization, SSRF numeric IP parsing |
| R2 | Archive bomb multi-entry scanning, body size limit middleware, WebSocket timeouts, scanner HMAC authentication |
| R3 | Forensics stores sanitized input (not raw), tool call JSON serialization for pattern matching, dependency update automation via Dependabot config in-repo |
| R4 | Redis healthcheck password exposure addressed, chunked body size enforcement, SSRF DNS rebinding checks, dynamic rules ReDoS validation, WebSocket `Sec-WebSocket-Protocol` auth, Nginx security header inheritance, `/health` info redaction |
| R5 | Self-healing pipeline wired so dynamic rules load per request, `ConfigStore` ReDoS validation, async DNS for SSRF (non-blocking), WebSocket query-string auth removed |
| R6 | `asyncio.get_running_loop()` usage fix, baseline policy caching, review pass closing tracked findings from earlier rounds |

Severity labels in older notes were **informal** and not tied to a published external rubric.

## Reporting a vulnerability

Do **not** file unfixed vulnerabilities as public issues. Follow **[SECURITY.md](../SECURITY.md)** in the repository root (private GitHub reporting preferred when enabled).
