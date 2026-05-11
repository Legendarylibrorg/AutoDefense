# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where versioning applies.

## [Unreleased]

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
