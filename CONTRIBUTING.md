# Contributing

Thank you for helping improve AutoDefense. This document describes how to work on the project locally and what we expect in pull requests.

**First-time setup from a git clone** (Docker, `.env`, optional local backend/frontend): [docs/setup.md](docs/setup.md).

## Code of conduct

Contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security vulnerabilities

Do **not** open a public issue for unfixed security bugs. Use [SECURITY.md](SECURITY.md) (private GitHub reporting or the fallback described there).

## Development setup

### Quality gate (before every PR)

From the repository root:

```bash
make ci-fast    # backend + frontend (daily loop)
make ci         # full gate including OSV lockfile scan
make ci-list    # show jobs and recommended Python/Node matrix
```

See [docs/CI_LOCAL.md](docs/CI_LOCAL.md) for job details, matrix guidance, and tool requirements (`uv`, Node 20+, optional `osv-scanner`).

### Backend (Python)

```bash
cd backend
uv sync --all-extras --frozen
uv run ruff check .
uv run ruff format --check .
uv run pytest tests/ -q
```

### Frontend (Node.js)

```bash
cd frontend
npm ci --ignore-scripts
npm audit --audit-level=moderate
npm test
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
3. **Quality gate:** Run `make ci-fast` (or `make ci` before release merges). See [docs/CI_LOCAL.md](docs/CI_LOCAL.md).
4. **Lint:** Backend must pass `ruff check` and `ruff format --check`.
5. **Frontend:** `npm test` and `npm run build` must succeed (TypeScript + Vite).
6. **Documentation:** Update `CHANGELOG.md` under **Unreleased** for user-visible changes. Adjust `docs/` if behavior or configuration changes.

## Commits

Write clear commit messages. Signed commits are welcome but not required unless maintainers later adopt a DCO or signing policy.

## Questions

Open a [GitHub discussion](https://docs.github.com/en/discussions) if enabled for this repo, or an issue labeled **question**, for design questions before large refactors.

## Maintainers

- **Protect `main`:** run `./scripts/configure-github-ruleset-main.sh` once (with `gh` + admin rights) so `main` only accepts merges via **pull request**. See [docs/maintainers/github-repository-setup.md](docs/maintainers/github-repository-setup.md).
- **`CODEOWNERS`:** add real `@username` / `@org/team` lines in `.github/CODEOWNERS` before enabling “require code owner review” in GitHub rules.
