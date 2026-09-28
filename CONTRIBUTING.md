# Contributing to DataBastion

Thank you for your interest! The project is in the design phase: architecture discussions are as useful as code.

## Before you start
1. Read [CONTEXT.md](CONTEXT.md) and the [architecture decisions](docs/adr/README.md).
2. For any non-trivial change, open an issue first to discuss it.
3. A change that contradicts an accepted ADR goes through a **new ADR**, not a code PR.

## Invariants to respect
Any PR that violates them will be rejected:
- Agents open **no** inbound port.
- **No raw sensitive value** leaves the agent (masking + HMAC required).
- Database credentials are never sent to the console.
- The agent only performs **read** operations.

## Workflow
- **PRs target the `dev` branch**, never `main` directly (`main` = released code).
- Branch from `dev`, named by type: `feat/…`, `fix/…`, `docs/…`, `chore/…`, `ci/…`, `refactor/…`, `perf/…`, `test/…`
- Commits and PR titles in [Conventional Commits](https://www.conventionalcommits.org/) format: `feat(agent): …`, `fix(console): …`. Scopes: `console`, `agent`, `protocol`, `classifiers`, `postgres`, `mysql`, `mongodb`, `openldap`, `deploy`, `docs`
- Breaking change: `feat!:` or a `BREAKING CHANGE: …` commit footer
- Tests and lint green locally; recommended hooks: `pre-commit install --hook-type pre-commit --hook-type commit-msg` (gitleaks + commit format)
- One PR = one topic; it is squashed on merge

Full rules for branches, tags and releases: [RELEASE.md](RELEASE.md).

## Developer Certificate of Origin (DCO)
Every commit must be signed off, which certifies that you have the right to submit this code under the Apache 2.0 license ([developercertificate.org](https://developercertificate.org/)):

```bash
git commit -s -m "feat(agent): add IBAN classifier"
```

This adds the line `Signed-off-by: Your Name <email>`. No CLA is required.

## License of contributions
Every contribution is published under the [Apache 2.0 license](LICENSE) (section 5 of the license).
