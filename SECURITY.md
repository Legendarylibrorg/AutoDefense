# Security policy

## Supported versions

Security fixes are applied on the default branch (`main`). Releases are tagged as needed; there is no separate long-term support branch yet.

## Reporting a vulnerability

**Please do not open a public GitHub issue for unfixed security vulnerabilities** — that can put users at risk before a fix exists.

1. **Preferred:** Use GitHub’s [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) for this repository when it is enabled for the repo. *(Maintainers: turn it on under **Settings → Security → Code security** so reporters can use it.)*
2. **Alternative:** Use a confidential channel maintainers publish (security email, bug bounty program, etc.), if any is listed on the repo or organization profile.

Include as much of the following as you can:

- Affected component (backend, frontend, Docker setup, etc.) and paths or endpoints
- Steps or a minimal request/script to reproduce
- What you observed vs. what you expected
- Impact assessment (confidentiality, integrity, availability)
- Optional: suggested fix or patch idea

We aim to acknowledge receipt within a few business days. Coordination on disclosure timing (e.g. after a patch release) is welcome.

## Scope

In scope: this repository’s code, default Docker Compose setup, and documented configuration.

Out of scope: vulnerabilities only present in outdated dependencies **after** fixes exist upstream (use Dependabot/updates); issues in your custom deployment without a clear defect in this repo; generic threats already described as out of scope in [docs/security.md](docs/security.md) (e.g. model training poisoning without a runtime mitigation path here).

## More detail

For threat model, crypto design, and OWASP coverage notes, see [docs/security.md](docs/security.md).
