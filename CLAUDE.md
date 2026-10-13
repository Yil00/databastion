# CLAUDE.md

@CONTEXT.md
@AGENTS.md

## Claude Code specifics
- Project subagents: `.claude/agents/` (`console-engineer`, `agent-engineer`, `security-reviewer`, `docs-keeper`). Delegate according to the ROADMAP's "Owner" column.
- To parallelize: one worktree per task, one subagent per worktree. Never run two subagents on the same owner directory, with one exception: under `agent/`, two `agent-engineer` subagents may run at the same time when their tasks touch disjoint crates (`agent/crates/<name>`); neither may change the other's crates, `agent/crates/core`, `agent/crates/classifiers` or `shared/protocol/` while the other runs.
  - Each such subagent runs its integration services in its own `dev/` Compose project (`COMPOSE_PROJECT_NAME`) on its own ports (the `*_PORT` variables), and never stops a Docker daemon or containers it did not start.
  - Shared files (`CHANGELOG.md`, `docs/ROADMAP.md`, `docs/08-engine-capabilities.md`, `Cargo.lock`) are reconciled when the second branch is merged with `dev`.
- Any task that touches `shared/protocol/`, the uplink, masking or authentication ends with a `security-reviewer` review.
- If a request contradicts an invariant or an ADR, flag it and propose an ADR instead of implementing it.
