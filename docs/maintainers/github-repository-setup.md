# GitHub: protect `main` (rulesets)

The repository should use a **branch ruleset** so `main` cannot receive direct pushes: all changes go through **pull requests**, with the local quality gate green and (optionally) reviews.

## Apply or refresh the ruleset

From the repo root (requires [GitHub CLI](https://cli.github.com/) `gh` with **admin** on the repo, plus `jq`):

```bash
./scripts/configure-github-ruleset-main.sh
```

This creates or updates the ruleset **`AutoDefense: protect main`** with:

- Block **branch deletion** and **force-push** (`non_fast_forward`)
- **Pull request required** before merging to `main` (no direct pushes)
- **No required GitHub status checks by default** — CI runs locally via [docs/CI_LOCAL.md](../CI_LOCAL.md) (`make ci` / `scripts/run_ci_local.py`)

Contributors must run **`make ci-fast`** (or **`make ci`** before release merges) before opening PRs. Reviewers should confirm the PR checklist reflects that.

### Environment overrides

| Variable | Default | Notes |
|----------|---------|--------|
| `DEFAULT_BRANCH` | `main` | Branch to protect |
| `REQUIRED_APPROVALS` | `0` | Approving reviews before merge; use `1` or more for teams |
| `REQUIRE_CODEOWNERS` | `0` | Set `1` only with real entries in `.github/CODEOWNERS` |
| `CONTEXTS_JSON` | `[]` | Optional JSON array of `{ "context": "<check name>" }` for required GitHub status checks |

If you add external required checks later (e.g. org-wide security gates), pass them via `CONTEXTS_JSON` when running `configure-github-ruleset-main.sh`.

## Manual alternative

GitHub → **Settings** → **Rules** → **Rulesets** → create a ruleset targeting `main` with the same options (PR required, block force-push).
