#!/usr/bin/env bash
# Run the same checks as GitHub Actions before pushing or opening a PR.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Backend (uv lock + ruff + pytest)"
cd "$ROOT/backend"
if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required (https://docs.astral.sh/uv/getting-started/installation/)" >&2
  exit 1
fi
uv sync --all-extras --frozen
uv run ruff check .
uv run ruff format --check .
uv run pytest tests/ -q --tb=short

echo "==> Frontend (npm ci + audit + build)"
export PATH="/opt/homebrew/opt/node@22/bin:/opt/homebrew/bin:$PATH"
cd "$ROOT/frontend"
npm ci
npm audit --audit-level=moderate
npm run build

echo "==> Precheck passed"
