# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where versioning applies.

## [Unreleased]

### Changed

- **Quality gate:** GitHub Actions CI workflows removed; run `make ci` / `make ci-fast` locally ([docs/CI_LOCAL.md](docs/CI_LOCAL.md)). `scripts/precheck.sh` delegates to the local runner.

### Fixed

- **Supply chain CI:** Pin `google/osv-scanner-action` to `v2.3.8` (reusable PR/full lockfile workflows); upgrade `dependency-review-action` to v5; use `npm ci --ignore-scripts` in audit/install paths.
- **Docs:** Align stack versions (React 19, Vite 8), clarify Compose Redis is internal-only, and document frontend dev API URLs / Vite proxy behavior.
- **Backend:** Skip broken WebSocket auth in HTTP middleware (routes close with 1008); key `/health` platform cache by environment; pin Docker image deps via `uv.lock`.
- **Frontend:** Vite dev proxy for API paths; use same-origin URLs in dev when `VITE_BACKEND_*` are unset.
- **Tooling:** Generalize `scripts/publish-pr.sh` (`--fill` or `PR_TITLE` / `PR_BODY_FILE`).

### Added

- **Tests:** `test_routes_and_middleware.py` for `/alerts`, `/metrics`, security headers, body-size limit, SSE content-type, and platform cache keys.

### Security

- **Supply chain:** Bump frontend lockfile (Vite 8.0.14, Vitest 4.1.7, PostCSS/autoprefixer) and backend `uv.lock` (FastAPI 0.136.3, Uvicorn 0.48, redis-py 8.0, Starlette 1.2); Tailwind CSS remains on v3.
- **API:** Hide OpenAPI outside `local`; redact sensitive `/health` fields in non-local environments; require API key on WebSocket connections; add security headers on HTTP responses.
- **Docker:** Read-only root filesystem defaults where applicable; dashboard nginx CSP via `nginx.conf.template` and envsubst for connect-src.
- **Supply chain:** Dependabot grouping tweaks; backend minimum versions for cryptography and related deps; Vite/Rolldown bump in frontend lockfile; `scripts/sync_vite_lock.py` for lockfile hygiene.
- **Supply chain (hardening):** `.github/workflows/supply-chain.yml` (weekly `npm audit`, OSV lockfile scan, PR dependency review); backend CI uses `uv sync --frozen`; frontend CI runs `npm audit`; `frontend/.npmrc` audit defaults; refreshed `uv.lock` and `package-lock.json`.

### Fixed

- **`scripts/start.sh` / `scripts/start.ps1`:** Use **`docker compose`** or fall back to **`docker-compose`**; run **`compose config -q`** before **`up`** so bad `.env` / Compose files fail fast; portable empty-value checks (`grep -E`); print API keys with **`cut -f2-`** so values containing `=` are not truncated. PowerShell writes UTF-8 `.env` with a trailing newline, uses a StrictMode-safe compose wrapper, and **`exit`s** with the same code as Compose.

### Documentation

- [docs/setup.md](docs/setup.md): clone → `.env` → Docker (`start.sh`), local backend/frontend, uv/pytest, host scanners; links to encryption and configuration docs.
- [docs/security.md](docs/security.md), [docs/configuration.md](docs/configuration.md), [docs/api.md](docs/api.md), [docs/architecture.md](docs/architecture.md), [README.md](README.md): clarify **three** HKDF-SHA256 subkeys per 32-byte master and **four** independent decrypt checks (not a fourth subkey); document backend vs bundled-dashboard HKDF salt handling for sealed transport.
- [docs/deployment.md](docs/deployment.md), [docs/scanners.md](docs/scanners.md): host scanners require repo `scanners/` on `PYTHONPATH` / run from repo root; systemd/cron examples updated.
- [.env.example](.env.example) and [frontend/.env.example](frontend/.env.example): encryption comments aligned with the three-subkey design.

### Added

- [docs/maintainers/github-repository-setup.md](docs/maintainers/github-repository-setup.md) and [scripts/configure-github-ruleset-main.sh](scripts/configure-github-ruleset-main.sh) to enforce **PR-only updates to `main`** via GitHub rulesets (with required CI checks).
- Open-source governance: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, this changelog
- GitHub Dependabot configuration for pip, npm, and GitHub Actions (with **grouped** npm/pip updates to reduce conflicting one-off bumps)
- Frontend CI workflow (install + production build)
- Issue templates and pull request template
- Package metadata in `backend/pyproject.toml` (license, Trove classifiers); `backend/README.md` links to the root README for PyPI long description packaging
- `license` field in `frontend/package.json`

### Changed

- **Runtime secrets:** `AUTODEFENSE_API_KEY` is required whenever `AUTODEFENSE_ENVIRONMENT` is not `local`; with data encryption on, `AUTODEFENSE_DATA_KEY_B64` is also required outside local (local may still use an ephemeral generated key). Production-like environments still require the scanner HMAC key at startup.
- **Kernel API:** `POST /scan/kernel` returns **503** if the scanner HMAC key is unset outside `local` (unsigned ingest disabled). Verify scanner **HMAC on raw bytes before JSON parse** when the key is configured; `GET /kernel/status` returns `scanned: false` and `kernel_status_unavailable` when stored status cannot be decrypted (avoids implying a successful scan after tampering or key mismatch).
- **Self-heal / dynamic rules:** Redis updates use **optimistic locking** (`WATCH` + transaction) to reduce last-writer races; the watched key is read via the same pipeline connection as `WATCH`.
- **Removed** unused optional LLM settings from the backend (`AUTODEFENSE_LLM_*`); documentation updated accordingly.
- **Validation errors:** non-local environments return a generic `422` body; detailed field errors remain in `local` only. Rate-limit fallback logging omits full exception values.
- **Environment:** `Settings.is_local` treats `AUTODEFENSE_ENVIRONMENT` as local when trimmed case-insensitively equals `local` (used for docs exposure, `/health` platform detail redaction, and secret checks).
- **Documentation:** Aligned API reference, deployment guide, security diagrams, scanners contract, README quick links, and configuration table with actual auth, rate limiting (Redis + fallback), kernel HMAC/503 behavior, and `/health` redaction rules.
- **Dependencies:** Frontend aligned on React 19, Vite 8, `@vitejs/plugin-react` 6, and Tailwind **3.4** (latest `v3-lts`); new `package-lock.json` (replaces fragmented Dependabot PRs that failed CI in isolation). Backend lower bounds raised for current FastAPI, Pydantic, Redis 7, Cryptography, pytest 9, Ruff 0.15, etc., after passing the full test suite.
- Dependabot: ignore **semver-major** updates for `tailwindcss` until Tailwind v4 PostCSS migration is planned; raise **lodash** override floor to **4.18.0** (transitive prototype-pollution advisories).
- Documentation wording aligned with transparent scope: security history framed as iterative development-time review, not external certification

## [0.1.0] — 2026

Initial published layout: FastAPI backend with multi-agent pipeline, React dashboard, Docker Compose, host scanners, and documentation under `docs/`.
