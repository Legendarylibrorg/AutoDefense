# Setup from Git clone

This guide takes you from a fresh **git clone** to a running stack (Docker) or local development. For encryption details (HKDF subkeys, envelope format), see **[Security: Encryption](security.md#encryption)**.

## Prerequisites

| Tool | Purpose |
|------|---------|
| **Git** | Clone the repository |
| **Docker** + **Docker Compose v2** | Recommended full stack (`./scripts/start.sh`) |
| **Python 3.11+** | Backend tests, optional local uvicorn, host scanners |
| **Node.js 20+** (optional) | Local Vite dev server instead of the nginx container |
| **OpenSSL** or **Python 3** | Key generation inside `scripts/start.sh` |

## 1. Clone and enter the repository

```bash
git clone https://github.com/Legendarylibrorg/AutoDefense.git
cd AutoDefense
```

Use your fork URL if you contribute via a fork.

## 2. Environment file

Copy the template once:

```bash
cp .env.example .env
```

### Secrets the backend expects

| Variable | Role |
|----------|------|
| `AUTODEFENSE_API_KEY` | Bearer token for REST (and WebSocket `Sec-WebSocket-Protocol: auth.<key>`) |
| `AUTODEFENSE_SCANNER_HMAC_KEY` | HMAC over raw JSON for host scanners posting to `/scan/kernel` |
| `AUTODEFENSE_DATA_KEY_B64` | **32-byte** master (base64) for **at-rest** Redis payloads — see [Encryption](security.md#encryption) (**three** HKDF subkeys) |
| `AUTODEFENSE_TRANSPORT_KEY_B64` | **32-byte** master (base64) for **sealed** HTTP bodies — same three-subkey scheme; must match the dashboard if you use sealed routes |
| `AUTODEFENSE_REDIS_PASSWORD` | Redis ACL password (Compose wires this into Redis and the backend) |

Leave values empty in `.env` for a first run on **local**; the start script fills them (see below). Outside `local`, empty API / data keys cause startup to fail — see [Configuration](configuration.md).

## 3. Run with Docker (recommended)

From the **repository root**:

```bash
# macOS / Linux
chmod +x scripts/start.sh
./scripts/start.sh

# Windows (PowerShell)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\start.ps1
```

The script:

1. Ensures `.env` exists (copies from `.env.example` if missing).
2. Generates any **still-empty** secrets: data key, transport key, API key, scanner HMAC key, Redis password (`openssl` or `python3`).
3. Prints the **API key** once — save it for the dashboard and `curl`.
4. Runs **`docker compose config -q`** so invalid `.env` / Compose files fail before image builds.
5. Runs **`docker compose up --build`** (or **`docker-compose`** if the V2 plugin is not installed).

### After containers are healthy

| URL | Notes |
|-----|--------|
| http://localhost:3000 | Dashboard (nginx + static build) |
| http://localhost:8000/health | JSON health (no auth) |
| http://localhost:8000/docs | Swagger — only when `AUTODEFENSE_ENVIRONMENT` is **`local`** |

Paste the API key into the dashboard **Connection / credentials** panel (session storage), or set `VITE_API_KEY` / `VITE_TRANSPORT_KEY_B64` in `frontend/.env` for dev — transport key must match `AUTODEFENSE_TRANSPORT_KEY_B64` if sealed transport is enabled (default).

### Optional Compose profiles

```bash
docker compose --profile demo up --build          # attack simulator
docker compose --profile security up --build      # Linux kernel scanner sidecar
```

See [Deployment](deployment.md) and [Configuration](configuration.md).

## 4. Local backend without full Compose (developers)

You still need **Redis** (or use fakeredis only inside unit tests).

```bash
# Terminal A: Redis
docker run --rm -p 6379:6379 redis:7-alpine

# Terminal B: backend
cd AutoDefense/backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
# Point Redis at localhost if .env still says redis:6379:
export AUTODEFENSE_REDIS_URL=redis://127.0.0.1:6379/0
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Run tests (no real Redis required):

```bash
cd AutoDefense/backend
python -m pytest tests/ -q
```

Using **uv** (lockfile in `backend/uv.lock`):

```bash
cd AutoDefense/backend
uv sync --all-extras
uv run pytest tests/ -q
```

## 5. Local frontend (Vite)

```bash
cd AutoDefense/frontend
cp .env.example .env   # optional; tune VITE_* URLs
npm ci
npm run dev
```

Set `VITE_BACKEND_HTTP` / `VITE_BACKEND_WS` if the API is not on localhost:8000. For sealed `/analyze` and `/scan`, align `VITE_TRANSPORT_KEY_B64` with the backend’s `AUTODEFENSE_TRANSPORT_KEY_B64` (same **32-byte** master → same **three** HKDF subkeys; see [Security](security.md#hkdf-parameters-backend-and-browser)).

## 6. Host scanners (optional)

Scanners live under `kernel/`, `macos/`, and `windows/`. They import shared helpers from the repo’s **`scanners/`** package — run them **from the repository root** (or ensure `scanners/` is on `PYTHONPATH`):

```bash
cd AutoDefense
python3 kernel/scanner.py --json
python3 macos/scanner.py --post http://localhost:8000
```

See [Host scanners](scanners.md) for flags, HMAC signing, and backend contract.

## 7. Where to read next

| Topic | Document |
|--------|-----------|
| All env vars | [Configuration](configuration.md) |
| Crypto (3 subkeys, v2 envelope, AAD) | [Security → Encryption](security.md#encryption) |
| API routes | [API reference](api.md) |
| Production hardening | [Deployment](deployment.md) |
| Architecture | [Architecture](architecture.md) |
