# AUTO DEFENSE

Autonomous, event-driven, multi-agent defense system that monitors AI inputs, outputs, and tool calls in real time — scoring risk, responding autonomously, self-healing with dynamic guardrails, and streaming full observability to a React dashboard.

**Double-layer AES-256-GCM encryption by default** — for each 32-byte master key (transport + at-rest), the code derives **exactly three** HKDF-SHA256 subkeys (inner AES, outer AES, HMAC); each payload is verified with **four** checks on decrypt (outer GCM tag, inner GCM tag, HMAC, SHA-256 of plaintext). Details: [Security → Encryption](docs/security.md#encryption). Keys can be auto-generated on first run via `scripts/start.sh`.

This software uses **pattern-based heuristics and configurable rules**. It **does not guarantee** detection of every attack, elimination of false positives, or fitness for any particular compliance regime or threat model. Evaluate against your own requirements.

```mermaid
flowchart LR
  subgraph Client
    App[AI App / Tools]
  end
  subgraph Backend[FastAPI Backend]
    GW[API Gateway] --> Pipeline
    Pipeline --> Sentinel[Sentinel Agent]
    Pipeline --> Policy[Policy Agent]
    Pipeline --> Behavior[Behavior Agent]
    Pipeline --> Artifact[Artifact Agent]
    Pipeline --> Coordinator
    Coordinator --> Risk[Risk Engine]
    Risk --> Response[Response Engine]
    Response --> Forensics
    Response --> SelfHeal[Self-Healing]
  end
  subgraph Infra
    Redis[(Redis Streams)]
  end
  subgraph UI[React Dashboard]
    FE[Frontend]
  end
  App -->|POST /analyze| GW
  Pipeline -->|events| Redis
  FE <-->|WebSocket| GW
  FE -->|REST| GW
```

## Quick start

```bash
# macOS / Linux
./scripts/start.sh

# Windows PowerShell
.\scripts\start.ps1
```

This copies `.env.example` to `.env`, auto-generates encryption keys and API key, and runs `docker compose up --build`.

**Full walkthrough from `git clone`:** [docs/setup.md](docs/setup.md) (prerequisites, `.env`, Docker, local dev, scanners, links to encryption docs).

| URL | What |
|-----|------|
| http://localhost:3000 | Dashboard |
| http://localhost:8000/docs | API docs (Swagger) — served only when `AUTODEFENSE_ENVIRONMENT` normalizes to `local` |
| http://localhost:8000/health | Health + Redis status; full platform detail only in `local` |

## What it defends against

Coverage mapped to [OWASP LLM Top 10 (2025)](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/) and [OWASP Agentic AI Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):

| Threat | Defense |
|--------|---------|
| Prompt injection | 17 injection + 26 jailbreak patterns, encoding evasion, multi-language (FR/DE/ES/JA/ZH/RU), self-healing rules |
| Sensitive info disclosure | 17 secret patterns, 7 PII detectors, system prompt leak detection, auto-redaction |
| Improper output handling | 14 XSS / injection patterns in model output |
| Excessive agency / tool abuse | 60+ tool abuse patterns, 16 code execution regexes |
| System prompt leakage | Input-side extraction blocking + output-side leak detection |
| Unbounded consumption | Rate limiting (120 req/min/IP), 10 MB body limit, Pydantic size constraints, artifact caps |
| Malicious artifacts | Extension blocking, polyglot detection, archive bombs (multi-entry), script markers |
| SSRF | 17 internal/metadata/cloud URL patterns + async DNS rebinding detection |
| Network sniffing & MITM | 30+ sniffer process detection, promiscuous interface detection, ARP spoofing, pcap files |
| Rootkits & kernel exploits | Linux kernel scanner (hidden procs, LD_PRELOAD, kernel modules, sysctl hardening) |

Counts in this table are **illustrative** and can change as rules evolve; they are not a runtime contract.

## Security hardening

The codebase has been refined through **multiple internal security-focused review passes** during development (summarized in [docs/security.md](docs/security.md)). That is **not** a substitute for independent penetration testing, formal certification, or your own deployment reviews.

| Area | Hardening |
|------|-----------|
| **Encryption** | Double-layer AES-256-GCM: **3** HKDF-SHA256 subkeys per master (inner AES, outer AES, HMAC); decrypt runs **4** checks (both GCM tags + HMAC + SHA-256 of plaintext) |
| **Authentication** | Constant-time API key comparison (HMAC), WebSocket auth via `Sec-WebSocket-Protocol` header (no query param leakage) |
| **Input validation** | NFKC Unicode normalization, zero-width character stripping, ReDoS guards on all dynamic regexes (config + rules), Pydantic field constraints |
| **SSRF** | Regex patterns + numeric IP resolution (hex/octal/decimal) + non-blocking async DNS with 2s timeout |
| **DoS protection** | 10 MB body limit (Content-Length + chunked), per-IP rate limiting in **Redis** (shared across workers), WebSocket timeouts + connection caps |
| **Infrastructure** | Non-root Docker containers, Redis password via `REDISCLI_AUTH` (no process list leaks), hardened Nginx CSP, platform info redaction in production |
| **Self-healing** | Dynamic rules actually loaded and applied per-request, validated against ReDoS before activation |
| **Crypto integrity** | `alg:none` downgrade rejection, HMAC-SHA256 scanner payload signing, sealed transport with AAD binding |

## Project structure

```
AUTO DEFENSE/
├── backend/                 # FastAPI + Python agents + Redis event bus
│   ├── app/
│   │   ├── agents/          # Sentinel, Policy, Behavior, Artifact, Coordinator, Forensics, Kernel
│   │   ├── api/routes/      # REST + WebSocket + SSE endpoints
│   │   ├── core/            # Crypto, risk engine, response engine, self-heal, models
│   │   ├── policies/        # Default blocked/sanitize regexes
│   │   └── services/        # Defense pipeline orchestration
│   └── tests/               # pytest suite
├── frontend/                # React 18 + Tailwind + Vite dashboard
│   └── src/
│       ├── components/      # StatCard, RiskChart, EventFeed, ConfigPanel, KernelHealth, ...
│       ├── lib/             # API client, WebSocket hook
│       └── pages/           # App layout
├── scanners/                # Shared helpers imported by platform scanners
├── kernel/                  # Linux host scanner (needs repo `scanners/` on path)
├── macos/                   # macOS host scanner (needs repo `scanners/` on path)
├── windows/                 # Windows host scanner (needs repo `scanners/` on path)
├── simulations/             # Attack simulation scripts
├── scripts/                 # Start scripts (sh + ps1)
├── docs/                    # Documentation
├── SECURITY.md              # Vulnerability reporting
├── CONTRIBUTING.md          # Development and PR guidelines
├── CHANGELOG.md             # Release notes
├── CODE_OF_CONDUCT.md       # Community standards
└── docker-compose.yml
```

## Contributing / security / changelog

| Document | Contents |
|----------|----------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Local dev, tests, PR expectations |
| [SECURITY.md](SECURITY.md) | How to report vulnerabilities responsibly |
| [CHANGELOG.md](CHANGELOG.md) | Release-oriented change summary |
| [Code of Conduct](CODE_OF_CONDUCT.md) | Community expectations |

## Documentation

| Document | Contents |
|----------|----------|
| [Setup from clone](docs/setup.md) | Git clone → `.env` → Docker or local backend/frontend → scanners |
| [Architecture](docs/architecture.md) | System design, agent pipeline, data flow, event streaming |
| [API Reference](docs/api.md) | Every endpoint with request/response examples |
| [Security](docs/security.md) | Threat model, encryption, OWASP coverage matrix, attack patterns |
| [Host Scanners](docs/scanners.md) | Linux, macOS, and Windows scanner documentation |
| [Configuration](docs/configuration.md) | All environment variables, runtime config, tuning |
| [Deployment](docs/deployment.md) | Docker install, local dev, testing, production ops |
| [GitHub: protect `main`](docs/maintainers/github-repository-setup.md) | Rulesets, PR-only workflow, required CI (`gh` script) |

## License

MIT — see [LICENSE](LICENSE).
