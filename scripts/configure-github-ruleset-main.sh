#!/usr/bin/env sh
# Create or update a GitHub repository ruleset: no direct pushes to main,
# required CI checks, no force-push, branch deletion blocked.
#
# Requires: gh (repo admin), jq
# Usage: ./scripts/configure-github-ruleset-main.sh
# Docs: docs/maintainers/github-repository-setup.md

set -eu

RULESET_NAME='AutoDefense: protect main'
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"
# 0 = require PR to merge but no review quorum (solo-friendly). Set to 1+ for teams.
REQUIRED_APPROVALS="${REQUIRED_APPROVALS:-0}"
REQUIRE_CODEOWNERS="${REQUIRE_CODEOWNERS:-0}"
REQUIRE_CONVERSATIONS_RESOLVED="${REQUIRE_CONVERSATIONS_RESOLVED:-0}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh (GitHub CLI) is required: https://cli.github.com/" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required." >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "Run: gh auth login" >&2
  exit 1
fi

slug="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
owner="${slug%%/*}"
repo="${slug#*/}"

case "$REQUIRE_CODEOWNERS" in 1 | true | yes) co_json=true ;; *) co_json=false ;; esac
case "$REQUIRE_CONVERSATIONS_RESOLVED" in 1 | true | yes) rt_json=true ;; *) rt_json=false ;; esac

# Single-line default so every /bin/sh passes valid JSON to jq --argjson.
_default_contexts='[{"context":"Backend CI / Python 3.11"},{"context":"Backend CI / Python 3.12"},{"context":"Frontend CI / Node 20"},{"context":"Frontend CI / Node 22"}]'
CONTEXTS_JSON="${CONTEXTS_JSON:-$_default_contexts}"

reviews_raw="${REQUIRED_APPROVALS:-0}"
reviews_json=$(printf '%s' "$reviews_raw" | tr -cd '0123456789')
[ -n "$reviews_json" ] || reviews_json=0

body_file="$(mktemp)"
trap 'rm -f "$body_file"' EXIT

jq -n \
  --arg name "$RULESET_NAME" \
  --arg branch "refs/heads/${DEFAULT_BRANCH}" \
  --argjson reviews "$reviews_json" \
  --argjson codeowners "$co_json" \
  --argjson resolve_threads "$rt_json" \
  --argjson contexts "$CONTEXTS_JSON" \
  '{
    name: $name,
    target: "branch",
    enforcement: "active",
    conditions: {
      ref_name: {
        include: [$branch],
        exclude: []
      }
    },
    rules: [
      { type: "deletion" },
      { type: "non_fast_forward" },
      {
        type: "pull_request",
        parameters: {
          allowed_merge_methods: ["merge", "squash", "rebase"],
          dismiss_stale_reviews_on_push: true,
          require_code_owner_review: $codeowners,
          require_last_push_approval: false,
          required_approving_review_count: $reviews,
          required_review_thread_resolution: $resolve_threads
        }
      },
      {
        type: "required_status_checks",
        parameters: {
          strict_required_status_checks_policy: true,
          do_not_enforce_on_create: false,
          required_status_checks: $contexts
        }
      }
    ]
  }' >"$body_file"

existing_id="$(gh api "repos/${owner}/${repo}/rulesets" --paginate -q ".[] | select(.name==\"${RULESET_NAME}\") | .id" | head -n1)"

if [ -n "${existing_id}" ]; then
  echo "Updating ruleset id=${existing_id} on ${slug} ..."
  gh api "repos/${owner}/${repo}/rulesets/${existing_id}" --method PUT --input "$body_file"
else
  echo "Creating ruleset on ${slug} ..."
  gh api "repos/${owner}/${repo}/rulesets" --method POST --input "$body_file"
fi

echo "Done. Settings → Rules → Rulesets on ${slug} should list \"${RULESET_NAME}\"."
