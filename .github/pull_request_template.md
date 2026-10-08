## Summary
<!-- What this PR does, in two or three sentences. Title in Conventional Commits format: feat(agent): … -->

## ROADMAP task
<!-- e.g. P2-B -->

## Task report
- **Done:**
- **Not done (and why):**
- **Decisions that would warrant an ADR:**
- **Files from other owners to modify:**

## Invariants
- [ ] This PR touches the network, sampled data, the protocol or secrets → invariants I1–I7 checked and `security-reviewer` review done
- [ ] Otherwise: not applicable

## Checklist
- [ ] Lint and tests green for the affected component
- [ ] Documentation and ROADMAP up to date
- [ ] DCO-signed commits (`git commit -s`)
- [ ] Release PR (`dev` → `main`, title `release: X.Y.Z`) only: [RELEASE.md § 7](../RELEASE.md#7-pre-release-checklist) checklist done, including the holdout seed rotated on `dev` since the previous release ([§ 8](../RELEASE.md#8-holdout-seed-rotation); the "Release version" check fails otherwise, unless `[skip-holdout]` is justified)
