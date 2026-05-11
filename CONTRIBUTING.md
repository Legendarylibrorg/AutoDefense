# Contributing

Thank you for helping improve AutoDefense. This document describes how to work on the project locally and what we expect in pull requests.

**First-time setup from a git clone** (Docker, `.env`, optional local backend/frontend): [docs/setup.md](docs/setup.md).

## Code of conduct

Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

### Backend (Python)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest tests/ -q
ruff check .
ruff format --check .
```

### Frontend (Node.js)

```bash
cd frontend
npm ci
npm run build
```

### Full stack (Docker)

From the repository root:

```bash
./scripts/start.sh          # macOS / Linux
# or
.\scripts\start.ps1         # Windows PowerShell
```

This uses `.env` (seeded from `.env.example`) and `docker compose`.

## Pull requests

1. **Focus:** One logical change per PR when practical.
2. **Tests:** Add or update tests for behavior changes in `backend/tests/`. Run `pytest` before opening the PR.
3. **Lint:** Backend must pass `ruff check` and `ruff format --check` (see CI).
4. **Frontend:** `npm run build` must succeed (TypeScript + Vite).
5. **Documentation:** Update `CHANGELOG.md` under **Unreleased** for user-visible changes. Adjust `docs/` if behavior or configuration changes.

## Commits

Write clear commit messages. Signed commits are welcome but not required unless maintainers later adopt a DCO or signing policy.

## Questions

Open a [GitHub discussion](https://docs.github.com/en/discussions) if enabled for this repo, or an issue labeled **question**, for design questions before large refactors.

## Maintainers

- **Protect `main`:** run `./scripts/configure-github-ruleset-main.sh` once (with `gh` + admin rights) so `main` only accepts merges via **pull request** and required CI checks pass. See [docs/maintainers/github-repository-setup.md](docs/maintainers/github-repository-setup.md).
- **`CODEOWNERS`:** add real `@username` / `@org/team` lines in `.github/CODEOWNERS` before enabling “require code owner review” in GitHub rules.
