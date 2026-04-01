# AUTO DEFENSE

Autonomous, event-driven, multi-agent defense system that monitors AI inputs, outputs, and tool calls in real time — scoring risk, responding autonomously, self-healing with dynamic guardrails, and streaming full observability to a React dashboard.

**End-to-end AES-256-GCM encryption by default.** Keys auto-generated on first run.

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

This copies `.env.example` to `.env`, auto-generates encryption keys, and runs `docker compose up --build`.

| URL | What |
|-----|------|
| http://localhost:3000 | Dashboard |
| http://localhost:8000/docs | API docs (Swagger) |
| http://localhost:8000/health | Health + platform info |

## What it defends against

Coverage mapped to [OWASP LLM Top 10 (2025)](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/) and [OWASP Agentic AI Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):

| Threat | Defense |
|--------|---------|
| Prompt injection | 17 injection + 26 jailbreak patterns, encoding evasion, multi-language (FR/DE/ES/JA/ZH/RU), self-healing rules |
| Sensitive info disclosure | 17 secret patterns, 7 PII detectors, system prompt leak detection, auto-redaction |
| Improper output handling | 14 XSS / injection patterns in model output |
| Excessive agency / tool abuse | 60+ tool abuse patterns, 16 code execution regexes |
| System prompt leakage | Input-side extraction blocking + output-side leak detection |
| Unbounded consumption | Rate limiting (120 req/min/IP), input size limits, artifact caps |
| Malicious artifacts | Extension blocking, polyglot detection, archive bombs, script markers |
| SSRF | 17 internal/metadata/cloud URL patterns |
| Network sniffing & MITM | 30+ sniffer process detection, promiscuous interface detection, ARP spoofing, pcap files |
| Rootkits & kernel exploits | Linux kernel scanner (hidden procs, LD_PRELOAD, kernel modules, sysctl hardening) |

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
├── kernel/                  # Linux host scanner (zero deps)
├── macos/                   # macOS host scanner (zero deps)
├── windows/                 # Windows host scanner (zero deps)
├── simulations/             # Attack simulation scripts
├── scripts/                 # Start scripts (sh + ps1)
├── docs/                    # Documentation
└── docker-compose.yml
```

## Documentation

| Document | Contents |
|----------|----------|
| [Architecture](docs/architecture.md) | System design, agent pipeline, data flow, event streaming |
| [API Reference](docs/api.md) | Every endpoint with request/response examples |
| [Security](docs/security.md) | Threat model, encryption, OWASP coverage matrix, attack patterns |
| [Host Scanners](docs/scanners.md) | Linux, macOS, and Windows scanner documentation |
| [Configuration](docs/configuration.md) | All environment variables, runtime config, tuning |
| [Deployment](docs/deployment.md) | Docker install, local dev, testing, production ops |

## License

MIT
