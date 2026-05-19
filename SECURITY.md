# Security policy

## Supported versions

Security fixes land on the default branch (`main`). Tagged releases are cut as needed; there is no separate long-term support branch.

## Vulnerability reporting

**Do not open a public GitHub issue for an unfixed security vulnerability** — that can put users at risk before a fix ships.

### How to report

1. **Preferred:** [Security → Report a vulnerability](https://github.com/Legendarylibrorg/AutoDefense/security) for this repository (private GitHub reporting). If the button is missing, maintainers should enable it under **Settings → Security → Code security → Private vulnerability reporting**.
2. **Fallback:** A confidential channel published on the repo or organization profile (security contact email, etc.), if any.

### What to include

- Affected area (backend, frontend, Docker defaults, etc.) and paths or endpoints
- Steps or a minimal repro (request, script, or config)
- Observed vs expected behavior
- Impact (confidentiality, integrity, availability)
- Optional: patch or mitigation idea

### What to expect

We aim to acknowledge within a few business days. **Coordinated disclosure** is preferred: please avoid public technical detail until maintainers agree on a release or advisory timeline.

## Scope

In scope: this repository’s code, default Docker Compose setup, and documented configuration.

Out of scope: vulnerabilities only present in outdated dependencies **after** fixes exist upstream (use Dependabot/updates); issues in your custom deployment without a clear defect in this repo; generic threats already described as out of scope in [docs/security.md](docs/security.md) (e.g. model training poisoning without a runtime mitigation path here).

## More detail

For threat model, crypto design, and OWASP coverage notes, see [docs/security.md](docs/security.md).

## Supply-chain and malware hygiene

This repository ships **application code**, not antivirus signatures. Routine checks maintainers expect before releases:

- **Frontend:** `npm ci` with the committed `package-lock.json`; `npm audit --audit-level=moderate` (also `npm run audit` and CI in `.github/workflows/frontend-ci.yml` + `supply-chain.yml`). `frontend/.npmrc` sets `audit-level=moderate` and `engine-strict=true`.
- **Backend:** `uv sync --all-extras --frozen` from `backend/uv.lock` (Docker and CI use the same lockfile); after bumps run `uv lock` and review `uv.lock` diffs. CI runs [OSV-Scanner](https://google.github.io/osv-scanner/) on `uv.lock` and `package-lock.json`.
- **Pull requests:** GitHub **dependency review** runs on PRs via `.github/workflows/supply-chain.yml` (fails on moderate+ severity advisories in changed dependencies).
- **Heuristic review:** Scripts under `scripts/`, scanners under `kernel/`, `macos/`, `windows/`, and the optional `demo` Compose profile deserve the same scrutiny as production code (`subprocess`, `urllib`, host mounts).

For authoritative malware verdicts on third-party packages, rely on OS-level scanners, Sigstore attestations where available, and your organization's software supply-chain policy — not grep alone.
