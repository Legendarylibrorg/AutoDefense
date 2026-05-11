# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) where versioning applies.

## [Unreleased]

### Added

- Open-source governance: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, this changelog
- GitHub Dependabot configuration for pip, npm, and GitHub Actions (with **grouped** npm/pip updates to reduce conflicting one-off bumps)
- Frontend CI workflow (install + production build)
- Issue templates and pull request template
- Package metadata in `backend/pyproject.toml` (license, Trove classifiers); `backend/README.md` links to the root README for PyPI long description packaging
- `license` field in `frontend/package.json`

### Changed

- **Dependencies:** Frontend aligned on React 19, Vite 8, `@vitejs/plugin-react` 6, and Tailwind **3.4** (latest `v3-lts`); new `package-lock.json` (replaces fragmented Dependabot PRs that failed CI in isolation). Backend lower bounds raised for current FastAPI, Pydantic, Redis 7, Cryptography, pytest 9, Ruff 0.15, etc., after passing the full test suite.
- Documentation wording aligned with transparent scope: security history framed as iterative development-time review, not external certification

## [0.1.0] — 2026

Initial published layout: FastAPI backend with multi-agent pipeline, React dashboard, Docker Compose, host scanners, and documentation under `docs/`.
