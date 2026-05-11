# Deployment

Step-by-step from clone (including `.env` and encryption keys): **[Setup from Git clone](setup.md)**.

## Prerequisites

- **Docker** (Docker Desktop or Docker Engine with Compose V2)
- **Python 3.11+** (for local development or running host scanners)
- **Node.js 18+** (for frontend local development only)

## Docker install (recommended)

### One-command start

```bash
# macOS / Linux
./scripts/start.sh

# Windows PowerShell
.\scripts\start.ps1
```

The start script:
1. Copies `.env.example` to `.env` (if not already present)
2. Auto-generates AES-256 encryption keys, API key, and scanner HMAC key if they are empty
3. Runs `docker compose up --build`

### What gets deployed

| Service | Port | Health check |
|---------|------|-------------|
| Redis 7 | 6379 | `redis-cli PING` |
| Backend (FastAPI + uvicorn) | 8000 | `GET /health` |
| Frontend (React + nginx) | 3000 | `wget --spider http://localhost:80/` |

### Verify

```bash
# Health check
curl http://localhost:8000/health | jq

# Dashboard
open http://localhost:3000

# API docs
open http://localhost:8000/docs
```

### Run attack simulation

```bash
docker compose --profile demo run --rm simulator
```

### Run kernel scanner (Linux host)

```bash
docker compose --profile security up kernel-scanner
```

## Local development

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate    # macOS/Linux
# .venv\Scripts\activate     # Windows

pip install -e ".[dev]"

# Start Redis (required)
docker run -d --name redis -p 6379:6379 redis:7-alpine

# If .env still uses docker hostname `redis`, override for localhost:
export AUTODEFENSE_REDIS_URL=redis://127.0.0.1:6379/0

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Or with **uv** from `backend/`: `uv sync --all-extras` then `uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Opens at `http://localhost:3000`. Vite proxies API calls to `http://localhost:8000` by default.

### Run tests

```bash
cd backend
python -m pytest tests/ -q

# With coverage
python -m pytest tests/ --cov=app --cov-report=term-missing
```

### Lint

```bash
cd backend
ruff check .
ruff format --check .
```

## Host scanner deployment

The host scanners are Python scripts under `kernel/`, `macos/`, and `windows/`. They import **`scanners/finding.py`** from the repository — run them from the **repo root** (or set `PYTHONPATH` to the repo root) so `import scanners.finding` resolves. Standard library only besides that shared module.

### Manual (any platform)

```bash
cd /path/to/AutoDefense   # repository root
python3 kernel/scanner.py --post http://your-backend:8000 --api-key YOUR_KEY --loop 120
python3 macos/scanner.py --post http://your-backend:8000 --api-key YOUR_KEY --loop 120
python windows\scanner.py --post http://your-backend:8000 --api-key YOUR_KEY --loop 120
```

The `--api-key` flag (or `AUTODEFENSE_API_KEY` in the environment) is required whenever the backend is configured with an API key (including any non-`local` deployment, where the key is mandatory at startup). Pass `--hmac-key` or set `SCANNER_HMAC_KEY` / align with backend `AUTODEFENSE_SCANNER_HMAC_KEY` so payloads are signed with HMAC-SHA256. Outside `local`, the backend rejects `POST /scan/kernel` with **503** if the scanner HMAC key is not configured, so scanners must use the shared secret there.

### Cron (Linux/macOS)

```bash
# Every 2 minutes — run from repo root so `scanners/` is importable
*/2 * * * * cd /opt/autodefense && /usr/bin/python3 kernel/scanner.py --post http://backend:8000 >> /var/log/autodefense-scanner.log 2>&1
```

### Systemd timer (Linux)

```ini
# /etc/systemd/system/autodefense-scanner.service
[Unit]
Description=AUTO DEFENSE kernel scanner

[Service]
Type=oneshot
Environment=PYTHONPATH=/opt/autodefense
WorkingDirectory=/opt/autodefense
ExecStart=/usr/bin/python3 /opt/autodefense/kernel/scanner.py --post http://backend:8000
```

```ini
# /etc/systemd/system/autodefense-scanner.timer
[Unit]
Description=Run AUTO DEFENSE scanner every 2 minutes

[Timer]
OnBootSec=30s
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now autodefense-scanner.timer
```

### Windows Task Scheduler

```powershell
$action = New-ScheduledTaskAction -Execute "python" -Argument "C:\autodefense\windows\scanner.py --post http://backend:8000"
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 2) -Once -At (Get-Date)
Register-ScheduledTask -TaskName "AutoDefenseScanner" -Action $action -Trigger $trigger -RunLevel Highest
```

## Production considerations

### Security

- **Never expose Redis** to the public internet — it should only be accessible within the Docker network
- **Set `AUTODEFENSE_API_KEY`** — required whenever `AUTODEFENSE_ENVIRONMENT` is not `local` (startup fails otherwise). In `local`, the start script can auto-generate a key; leaving it empty keeps the API unauthenticated with a startup warning
- **Use HTTPS** in production — put a reverse proxy (nginx, Caddy, Traefik) in front of the backend; HSTS headers are automatically added for HTTPS connections
- **Rotate encryption keys** periodically — update `AUTODEFENSE_DATA_KEY_B64` and `AUTODEFENSE_TRANSPORT_KEY_B64`; note that existing encrypted data in Redis will become unreadable after rotation
- **Restrict CORS origins** — set `AUTODEFENSE_CORS_ORIGINS` to your actual frontend domain(s)
- **Run scanners with least privilege** — they work as unprivileged users for most checks (root recommended only for full Linux visibility)
- **Set `AUTODEFENSE_ENVIRONMENT`** to a non-local value in production (any string that does not normalize to `local`, trimmed and case-insensitive) — disables Swagger/ReDoc and redacts detailed platform info from `/health`

### Scaling

- The backend is stateless (Redis is the only state) — it can be horizontally scaled behind a load balancer
- Rate limiting is **Redis-backed** (shared per IP across workers); an in-process fallback applies only if Redis errors — monitor Redis availability in multi-instance setups
- Redis Streams handle high throughput — the stream is trimmed to ~5,000 entries; forensic records keep the last 1,000

### Monitoring

- `GET /health` — returns backend status, Redis connectivity, and platform info (full detail only when the environment is `local`)
- `GET /metrics` — returns event counts by type
- Docker healthchecks are configured for all services
- WebSocket auto-reconnects with exponential backoff (1s to 30s)

### Backup

- Runtime config, dynamic rules, forensic records, and kernel status are stored with double-layer encryption in Redis
- Back up Redis with `redis-cli BGSAVE` or Redis persistence (`appendonly yes`)
- Encryption keys and API keys in `.env` should be stored securely (vault, secrets manager)
- The `.env` file is excluded from version control via `.gitignore`

## File structure reference

```
AUTO DEFENSE/
├── .env.example              # Backend environment template
├── .gitignore
├── LICENSE
├── README.md                 # Project entry point
├── docker-compose.yml        # All services
├── docs/                     # Documentation
│   ├── setup.md              # Clone → env → Docker / local dev
│   ├── api.md                # API reference
│   ├── security.md           # Threat model & OWASP coverage
│   ├── scanners.md           # Host scanner docs
│   ├── configuration.md      # All config options
│   └── deployment.md         # This file
├── backend/
│   ├── Dockerfile
│   ├── pyproject.toml
│   ├── pytest.ini
│   ├── app/
│   │   ├── main.py           # FastAPI app factory
│   │   ├── settings.py       # Pydantic Settings
│   │   ├── agents/           # Defense agents
│   │   ├── api/routes/       # HTTP endpoints
│   │   ├── core/             # Crypto, risk, models, event bus
│   │   ├── policies/         # Default policy regexes
│   │   └── services/         # Defense pipeline
│   └── tests/                # pytest suite
├── frontend/
│   ├── .env.example          # Frontend env template
│   ├── Dockerfile
│   ├── package.json
│   ├── index.html
│   └── src/
│       ├── main.tsx          # Entry point + ErrorBoundary
│       ├── styles.css        # Tailwind + custom scrollbars
│       ├── components/       # UI components
│       ├── lib/              # API client + WebSocket hook
│       └── pages/            # App layout
├── scanners/               # Shared scanner helpers (imported by kernel/macos/windows)
├── kernel/                   # Linux scanner
│   ├── Dockerfile
│   └── scanner.py
├── macos/                    # macOS scanner
│   ├── Dockerfile
│   └── scanner.py
├── windows/                  # Windows scanner
│   └── scanner.py
├── simulations/              # Attack simulations
│   ├── Dockerfile
│   ├── attacks.http
│   └── run_simulations.py
└── scripts/
    ├── start.sh              # Linux/macOS start script
    └── start.ps1             # Windows start script
```
