# CLAUDE.md

@CONTEXT.md
@AGENTS.md

## Claude Code specifics
- Project subagents: `.claude/agents/` (`console-engineer`, `agent-engineer`, `security-reviewer`, `docs-keeper`). Delegate according to the ROADMAP's "Owner" column.
- To parallelize: one worktree per task, one subagent per worktree. Never run two subagents on the same owner directory.
- Any task that touches `shared/protocol/`, the uplink, masking or authentication ends with a `security-reviewer` review.
- If a request contradicts an invariant or an ADR, flag it and propose an ADR instead of implementing it.
