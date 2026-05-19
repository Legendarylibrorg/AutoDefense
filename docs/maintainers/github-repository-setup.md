# GitHub: protect `main` (rulesets)

The repository should use a **branch ruleset** so `main` cannot receive direct pushes: all changes go through **pull requests**, with CI green and (optionally) reviews.

## Apply or refresh the ruleset

From the repo root (requires [GitHub CLI](https://cli.github.com/) `gh` with **admin** on the repo, plus `jq`):

```bash
./scripts/configure-github-ruleset-main.sh
```

This creates or updates the ruleset **`AutoDefense: protect main`** with:

- Block **branch deletion** and **force-push** (`non_fast_forward`)
- **Pull request required** before merging to `main` (no direct pushes)
- **Required status checks** (strict): `Python 3.11`, `Python 3.12`, `Node 20`, and `Node 22` — these are the **job `name:`** values from `.github/workflows/backend-ci.yml` and `frontend-ci.yml` (what GitHub lists as the check name), not `Workflow title / job`.

**Optional (recommended after one green run):** add supply-chain jobs from `.github/workflows/supply-chain.yml` — `npm audit`, `OSV lockfile scan` (push/schedule) or `OSV lockfile scan (PR)` (pull requests), and `Dependency review (PR)` — via `CONTEXTS_JSON` when running `configure-github-ruleset-main.sh`.

### Environment overrides

| Variable | Default | Notes |
|----------|---------|--------|
| `DEFAULT_BRANCH` | `main` | Branch to protect |
| `REQUIRED_APPROVALS` | `0` | Approving reviews before merge; use `1` or more for teams |
| `REQUIRE_CODEOWNERS` | `0` | Set `1` only with real entries in `.github/CODEOWNERS` |
| `CONTEXTS_JSON` | (built-in) | JSON array of `{ "context": "<job name>" }` matching each required workflow job’s `name:` field |

**First-time setup:** merge at least one PR so the four required checks exist on GitHub; otherwise the UI may not list them when editing the ruleset.

## Manual alternative

GitHub → **Settings** → **Rules** → **Rulesets** → create a ruleset targeting `main` with the same options (PR required, required checks, block force-push).
