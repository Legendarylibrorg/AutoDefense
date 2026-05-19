#!/usr/bin/env bash
# Precheck, push branch, and open a PR against main (requires: gh auth login).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BRANCH="${1:-$(git -C "$ROOT" branch --show-current)}"
BASE="${PR_BASE:-main}"

cd "$ROOT"
"$ROOT/scripts/precheck.sh"

if ! gh auth status >/dev/null 2>&1; then
  echo "GitHub CLI is not authenticated. Run: gh auth login" >&2
  exit 1
fi

git push -u origin "$BRANCH"

if [[ -n "${PR_TITLE:-}" && -n "${PR_BODY_FILE:-}" ]]; then
  gh pr create --base "$BASE" --head "$BRANCH" --title "$PR_TITLE" --body-file "$PR_BODY_FILE"
elif [[ -n "${PR_TITLE:-}" ]]; then
  gh pr create --base "$BASE" --head "$BRANCH" --title "$PR_TITLE" --fill
else
  gh pr create --base "$BASE" --head "$BRANCH" --fill
fi
