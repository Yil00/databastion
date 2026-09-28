# ADR-0014: Policy and incident model

- **Status**: Accepted
- **Date**: 2026-09-28
- **Context references**: P3-A and P3-B, branch `feat/p3-a-policies-incidents` (`console/src/lib/policy-model.ts`, `console/src/lib/incident-lifecycle.ts`, `console/src/server/incidents.ts`, `console/src/server/policy-queue.ts`, migrations `0014_p3_policies_incidents.sql` and `0015_incidents_runtime_grants.sql`)

## Context
Phase 3 turns findings into incidents. The model must stay valid when phase 4 adds access events as a second source, must not duplicate or lose incidents when jobs are lost, repeated or run concurrently, must agree with the existing false-positive decision on findings (migration 0013), and must hold no sampled value (I2). Several of these choices are hard to change once policies and incidents exist in deployed databases.

## Decision
1. **Condition model.** A policy has a `source` (`policy_source` enum, currently only `finding`) and a JSON condition document validated strictly against the keys of that source; unknown keys are rejected. Keys for `finding`: `classifiers` (registered ids or families such as `pii.*`), `agent_ids`, `target_ids`, `engines`, `location` (globs on the normalized `database`, `schema`, `object`, `field` names), `min_confidence`, `min_match_ratio`, `min_matched`. All present keys must hold (AND); the values of one list are alternatives (OR). Globs support `*`, `?` and `\` escapes, are case-insensitive, and are matched by a linear-time matcher with no regular expression. Phase 4 adds an `access_event` enum value with its own keys (e.g. `signals`); existing documents keep their meaning, with no schema break. Actions (v1): exactly one `create_incident` with a severity, and up to 5 `notify` actions naming a channel slug. Channels are stored on the policy and copied to each incident; delivery is P3-C.
2. **Queue design.** The pending work is recorded in console tables, not in the queue. A finding is pending while `findings.policy_evaluated_at` differs from `last_seen_at`. A policy needs a full pass while `evaluated_at` is older than `changed_at` or than the expiry of one of its exceptions. The pg-boss job `policies.evaluate` carries no payload and only wakes the worker. The queue is `stately`, so bursts coalesce. The web process sends the job after commit through a send-only pg-boss instance (no migration, maintenance or schedule), on a best-effort basis. The worker also sends it at start and schedules it every minute. Findings are processed in row-locked chunks with `SKIP LOCKED`, so an evaluation never races an ingestion or a false-positive marking.
3. **Dedup and reopen.** `dedup_key = policy:<id>|finding:<id>`. A partial unique index allows only one active (`open` or `acknowledged`) incident per key. A rescan of the finding increments `match_count` on the active incident. A `resolved` incident is final. A new incident opens only when the finding matches more values than it did at the incident, or has another `classifiers_version`, which is the same rule as the false-positive reset on findings.
4. **False-positive alignment.** The false-positive decision lives only on the finding. Moving an incident to `false_positive` marks its finding (admin only, with the `matched` / `classifiers_version` snapshot) and closes every active incident of that finding. The policy engine skips false-positive findings. Unmarking the finding clears `policy_evaluated_at`, so it becomes pending again.
5. **Authorization split.** Analysts can acknowledge and resolve incidents. Administrators mark false positives and manage policies and exceptions. All of these actions are audited. The runtime database role has `DELETE` and `TRUNCATE` revoked on `incidents` (migration 0015), so a compromised console process cannot erase incidents. Deleting a policy keeps its incidents (`policy_id` set to null; name and revision copied on the incident).

## Consequences
- Adding a source is a compatible change: a new enum value, a new key set and a new matcher. It is not a migration of existing documents.
- Lost, duplicated or concurrent `policies.evaluate` jobs change nothing. A lost wake-up delays evaluation by at most the one-minute schedule.
- A full pass over all findings runs on every policy change. Its cost grows with the findings table; it runs in chunks under a per-job time budget and re-queues itself.
- Incidents and findings cannot disagree on false positives. The cost is that one incident marked false positive also closes the incidents raised for the same finding by other policies.
- `notify` actions are accepted and stored before any channel exists. P3-C must resolve slugs to channels and define what happens when a slug is unknown.
- Incidents accumulate with no retention mechanism at the application level. A future retention policy needs a separate, owner-level mechanism.

## Rejected alternatives
- **A free-form expression language, or regular expressions on names**: harder to validate strictly, and regular expressions expose the worker to catastrophic backtracking on hostile names.
- **A single condition schema shared by all sources**: phase 4 keys would be meaningless on findings, and adding them would change how old documents validate.
- **Carrying finding ids in the job payload**: a lost or failed job would lose the evaluation, and bursts would enqueue one job per batch.
- **Reopening the resolved incident, or opening a new one on every rescan**: reopening rewrites a closed record. Opening on every rescan floods users with incidents for data they have already handled.
- **A separate false-positive flag on incidents**: two sources of truth that can diverge between the findings and incidents pages.
