# CLAUDE.md

@CONTEXT.md
@AGENTS.md

## Spécifique à Claude Code
- Sous-agents du projet : `.claude/agents/` (`console-engineer`, `agent-engineer`, `security-reviewer`, `docs-keeper`). Déléguer selon la colonne « Propriétaire » de la ROADMAP.
- Pour paralléliser : un worktree par tâche, un sous-agent par worktree. Ne jamais lancer deux sous-agents sur le même dossier propriétaire.
- Toute tâche qui touche `shared/protocol/`, l'uplink, le masquage ou l'authentification se termine par une revue `security-reviewer`.
- Si une demande contredit un invariant ou un ADR, le signaler et proposer un ADR au lieu de l'implémenter.
