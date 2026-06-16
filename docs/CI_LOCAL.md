# Local quality gate

This repository does **not** run GitHub Actions CI workflows on push/PR. Run the same checks **locally** before opening or updating a pull request.

**Entrypoints:**

```bash
python3 scripts/run_ci_local.py          # all jobs
python3 scripts/run_ci_local.py --fast   # backend + frontend (daily loop)
python3 scripts/run_ci_local.py --list   # show jobs and recommended matrix
make ci                                    # same as run_ci_local.py
make ci-fast
```

Requires **uv**, **Node.js 20+**, and **npm** (see [docs/setup.md](setup.md)). For the full gate, install [OSV-Scanner](https://google.github.io/osv-scanner/installation/).

---

## Jobs

| Job | Steps (matches former GitHub workflow) |
| --- | --- |
| **backend** | `uv sync --all-extras --frozen` → `ruff check` → `ruff format --check` → `pytest tests/ -q --tb=short` |
| **frontend** | `npm ci --ignore-scripts` → `npm audit --audit-level=moderate` → `npm test` → `npm run build` |
| **supply-chain** | `osv-scanner scan` on `backend/uv.lock` and `frontend/package-lock.json` |

### Backend detail (former `backend-ci.yml`)

Run from `backend/` with a frozen lockfile:

1. **Install:** `uv sync --all-extras --frozen`
2. **Lint:** `uv run ruff check .`
3. **Format:** `uv run ruff format --check .`
4. **Tests:** `uv run pytest tests/ -q --tb=short`

### Frontend detail (former `frontend-ci.yml`)

Run from `frontend/`:

1. **Install:** `npm ci --ignore-scripts`
2. **Audit:** `npm audit --audit-level=moderate` (also `npm run audit`)
3. **Unit tests:** `npm test` (Vitest)
4. **Build:** `npm run build` (`tsc -b` + Vite production build)

### Supply chain (former `supply-chain.yml`)

- **OSV scan:** `osv-scanner scan --lockfile=backend/uv.lock --lockfile=frontend/package-lock.json`
- **npm audit** is already covered by the **frontend** job.
- **GitHub dependency review** (PR-only, moderate+) has no local equivalent; rely on Dependabot alerts and lockfile review when bumping dependencies.

---

## Recommended matrix

Run **`python3 scripts/run_ci_local.py --fast`** (or full **`make ci`**) on each row before a release merge:

| OS | Python | Node |
| --- | --- | --- |
| Linux | 3.11 | 20 |
| Linux | 3.12 | 22 |
| macOS | 3.12 | 22 |
| Windows | 3.11 | 20 |

Use **`UV_PYTHON=3.11`** (or `uv python pin 3.11`) and **`nvm use 20`** (or similar) to match matrix rows on one machine.

---

## Lighter checks

For quick iteration without OSV scan:

```bash
make ci-fast
# or
./scripts/precheck.sh
```

Backend-only or frontend-only:

```bash
python3 scripts/run_ci_local.py --job backend
python3 scripts/run_ci_local.py --job frontend
```

---

## Environment

`run_ci_local.py` sets:

| Variable | Value |
| --- | --- |
| `PIP_DISABLE_PIP_VERSION_CHECK` | `1` |
| `PYTHONUTF8` | `1` |
| `PYTHONIOENCODING` | `utf-8` |

Optional overrides:

| Variable | Purpose |
| --- | --- |
| `UV_BIN` | Path to `uv` |
| `UV_PYTHON` | Python version for uv (e.g. `3.12`) |
| `NPM_BIN` | Path to `npm` |
| `OSV_SCANNER_BIN` | Path to `osv-scanner` |

See also [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md).
