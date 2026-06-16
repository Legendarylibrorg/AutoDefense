## Summary

<!-- What does this PR change and why? -->

## Checklist

- [ ] Local quality gate: `make ci-fast` (or `make ci` for dependency/lockfile changes)
- [ ] Backend: `ruff check`, `ruff format --check`, and `pytest` pass (if `backend/` changed)
- [ ] Frontend: `npm test` and `npm run build` pass (if UI or `frontend/` changed)
- [ ] `CHANGELOG.md` updated under **Unreleased** if users/operators should know about the change
- [ ] Docs updated if behavior, env vars, or deployment assumptions changed

## Notes for reviewers

<!-- Risks, follow-ups, or testing gaps -->
