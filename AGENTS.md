# AGENTS.md – rules for coding agents

This file is for every coding agent (Claude Code, Codex, Cursor…) and the humans who drive them. The domain context is in [CONTEXT.md](CONTEXT.md).

## Before each task
1. Read [CONTEXT.md](CONTEXT.md), especially the **invariants I1 to I7**.
2. Find the task in [docs/ROADMAP.md](docs/ROADMAP.md) (identifier `Px-Y`) and set it to `[~]`.
3. Read the related ADRs. **Never work around an accepted ADR**: if it blocks you, stop and propose a new ADR ([docs/adr/template.md](docs/adr/template.md)).

## Languages
- Everything in the repository is in **English**: documentation, code, identifiers, comments, commit messages, branch names

## Tree and owners
| Path | Content | Main owner |
|--------|---------|------------------------|
| `console/` | Next.js (web + worker), Drizzle, pg-boss | `console-engineer` |
| `agent/` | Cargo workspace (core, classifiers, connectors) | `agent-engineer` |
| `shared/protocol/` | OpenAPI + JSON Schemas + fixtures | `agent-engineer`, `security-reviewer` review **required** |
| `dev/` | Dev environment, seeded databases, ground truth | `agent-engineer` |
| `e2e/` | End-to-end harness (containers: console, agent, target) | `agent-engineer`, `security-reviewer` review for TLS / secrets changes |
| `deploy/` | Compose, Helm later | `console-engineer` |
| `docs/`, root `*.md` | Documentation, ROADMAP, ADRs | `docs-keeper` |

An agent does **not** modify files belonging to another owner, unless the task explicitly requires it. If it needs to, it says so in its task report.

## Conventions – Console (`console/`)
- TypeScript `strict`, no unjustified `any`
- Next.js App Router; the agent API server code lives in `console/src/app/api/agent/v1/`
- Every agent API input is validated against the schema generated from `shared/protocol/` (rejected on unknown fields)
- Versioned Drizzle migrations; never modify the schema by hand
- pnpm; commands (to be filled in as soon as they exist): `pnpm lint`, `pnpm test`, `pnpm build`

## Conventions – Agent (`agent/`)
- Stable Rust, `#![forbid(unsafe_code)]` in every crate
- `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test` must pass
- rustls only (no OpenSSL)
- Every query against a target database: `statement_timeout` / equivalent, and bounds on sampling
- All data leaving a connector goes through `classifiers::masking` **before** reaching the uplink. No direct uplink access from a connector.
- No `println!`: `tracing` with structured JSON logs; **never** any sampled value in the logs

## Protocol (`shared/protocol/`)
- Single source of truth between agent ↔ console
- Compatible change (adding an optional field): regular PR + `security-reviewer` review
- Incompatible change: new ADR + new version (`/api/agent/v2`)
- TS and Rust types are **generated**, never edited by hand

## Useful commands (root)
- `python3 scripts/check-md-links.py`: internal documentation links
- `node scripts/bump-version.mjs <X.Y.Z>`: aligns versions (normally called by the release CI, not by hand)
- `pre-commit install --hook-type pre-commit --hook-type commit-msg`: gitleaks + commit format hooks

## Required tests
- Classifiers: positive / negative cases + property tests on masking
- Connectors: integration tests against `dev/` (containers)
- Console: agent API tests with the fixtures from `shared/protocol/fixtures/`
- **Invariant I2 test** (from phase 2): no value from `dev/ground-truth.json` in clear text in the console database

## Multi-agent work
- **One task = one branch = one worktree** (`git worktree`), created from `dev`, named `<type>/<roadmap-id>-<slug>` (e.g. `feat/p2-b-pg-discovery`). PRs target `dev`.
- Parallel tasks do not touch the same directories. The ROADMAP's split into workstreams is designed for this.
- Single synchronization point: `shared/protocol/`. The contract is frozen **before** console and agent implement it in parallel.
- **Task report** (in the PR description):
  1. What was done (ROADMAP tasks checked off)
  2. What was not done, and why
  3. Decisions made that would warrant an ADR
  4. Files from other owners that should be modified
- The `docs-keeper` updates `docs/ROADMAP.md` and `CONTEXT.md` (current phase) after each merge.

## Long-running tasks
- Every task has a time budget, set by whoever launches it. When it runs out: stop, commit what is consistent, and report what is left.
- Wrap potentially long commands in `timeout` (e.g. `timeout 300 cargo test`).
- No watch modes (`vitest` without `run`, `cargo watch`, `next dev` left running).
- Stop any server or container started for a test before ending the task.
- If a command keeps failing, report the partial result instead of retrying in a loop.
- Every CI job sets `timeout-minutes`.

## Definition of Done
- [ ] Lint + tests green for the affected component
- [ ] Invariants I1–I7 respected (state it explicitly in the PR if the task touches the network, data or the protocol)
- [ ] Documentation updated if visible behavior changes
- [ ] ROADMAP updated

## Git
- Branches, tags and releases: [RELEASE.md](RELEASE.md). Never commit directly to `main` or `dev`; never create a release tag.
- Conventional Commits: `feat(agent): …`, `fix(console): …`, `docs(adr): …`
- DCO-signed commits (`git commit -s`)
- **No AI tool attribution** in commits or PRs: no assistant `Co-Authored-By` trailer, no "Generated with …" mention. Only the git identity of the maintainer or contributor appears.
- Do not edit `CHANGELOG.md` by hand (generated at release), except for the "Unreleased" section
- Never commit secrets, database dumps, or files from `dev/.state/`
- Never push or open a PR without an explicit request from the maintainer
