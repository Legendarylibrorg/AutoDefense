#!/usr/bin/env bash
# Precheck, push branch, and open a PR against main (requires: gh auth login).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRANCH="${1:-chore/security-hardening-and-deps}"

cd "$ROOT"
"$ROOT/scripts/precheck.sh"

if ! gh auth status >/dev/null 2>&1; then
  echo "GitHub CLI is not authenticated. Run: gh auth login" >&2
  exit 1
fi

git push -u origin "$BRANCH"

gh pr create --base main --head "$BRANCH" --title "security: tighten API surface and supply chain; refresh Vite stack" --body "$(cat <<'EOF'
## Summary

Hardens the API and deployment surface for non-local environments and refreshes the frontend toolchain.

- Lock down OpenAPI outside `local`, redact `/health` in production-like envs, authenticate WebSockets, and add security headers
- Docker read-only defaults and CSP templating for the dashboard nginx image
- Vite/Rolldown lockfile bump, backend crypto floor, Dependabot grouping, simulation script formatting

## Checklist

- [x] Backend: `ruff check`, `ruff format --check`, and `pytest` pass locally
- [x] Frontend: `npm run build` passes
- [x] `CHANGELOG.md` updated under **Unreleased**
- [x] Docs updated where behavior or deployment assumptions changed (`SECURITY.md`, `.env.example`, `docker-compose.yml`)

## Notes for reviewers

Precheck script: `./scripts/precheck.sh`
EOF
)"
