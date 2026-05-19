#!/usr/bin/env bash
# Run the same checks as GitHub Actions before pushing or opening a PR.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Backend (ruff + pytest)"
cd "$ROOT/backend"
python3 -m venv .venv 2>/dev/null || true
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -e ".[dev]"
ruff check .
ruff format --check .
python -m pytest tests/ -q --tb=short

echo "==> Frontend (npm ci + build)"
export PATH="/opt/homebrew/opt/node@22/bin:/opt/homebrew/bin:$PATH"
cd "$ROOT/frontend"
npm ci
npm run build

echo "==> Precheck passed"
