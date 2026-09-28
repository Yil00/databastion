# ADR-0014: Policy and incident model

- **Status**: Accepted
- **Date**: 2026-09-28
- **Context references**: P3-A and P3-B, branch `feat/p3-a-policies-incidents` (`console/src/lib/policy-model.ts`, `console/src/lib/incident-lifecycle.ts`, `console/src/server/incidents.ts`, `console/src/server/policy-queue.ts`, migrations `0014_p3_policies_incidents.sql` and `0015_incidents_runtime_grants.sql`)

## Context
Phase 3 turns findings into incidents. The model must stay valid when phase 4 adds access events as a second source, must not duplicate or lose incidents when jobs are lost, repeated or run concurrently, must agree with the existing false-positive decision on findings (migration 0013), and must hold no sampled value (I2). Several of these choices are hard to change once policies and incidents exist in deployed databases.

## Decision
1. **Condition model.** A policy has a `source` (`policy_source` enum, currently only `finding`) and a JSON condition document validated strictly against the keys of that source; unknown keys are rejected. Keys for `finding`: `classifiers` (registered ids or families such as `pii.*`), `agent_ids`, `target_ids`, `engines`, `location` (globs on the normalized `database`, `schema`, `object`, `field` names), `min_confidence`, `min_match_ratio`, `min_matched`. All present keys must hold (AND); the values of one list are alternatives (OR). Globs support `*`, `?` and `\` escapes, are case-insensitive, and are matched by a linear-time matcher with no regular expression. Phase 4 adds an `access_event` enum value with its own keys (e.g. `signals`); existing documents keep their meaning, with no schema break. Actions (v1): exactly one `create_incident` with a severity, and up to 5 `notify` actions naming a channel slug. Channels are stored on the policy and copied to each incident; delivery is P3-C.
2. **Queue design.** The pending work is recorded in console tables, not in the queue. A finding is pending while `findings.policy_evaluated_at` differs from `last_seen_at`. A policy needs a full pass while `evaluated_at` is older than `changed_at` or than the expiry of one of its exceptions. The pg-boss job `policies.evaluate` carries no payload and only wakes the worker. The queue is `stately`, so bursts coalesce. The web process sends the job after commit through a send-only pg-boss instance (no migration, maintenance or schedule), on a best-effort basis. The worker also sends it at start and schedules it every minute. Findings are processed in row-locked chunks with `SKIP LOCKED`, so an evaluation never races an ingestion or a false-positive marking.
3. **Dedup and reopen: resolved means remediated.** `dedup_key = policy:<id>|finding:<id>`. A partial unique index allows only one active (`open` or `acknowledged`) incident per key. A rescan of the finding increments `match_count` on the active incident. A `resolved` incident is final and is never reopened. A new incident opens for the same key when either of these holds:
   - a later scan still sees the finding, that is, the finding was seen after the incident's `resolved_at`;
   - the finding matches more values than it did at the incident, or has another `classifiers_version`. This is the same rule as the false-positive reset on findings.

   Resolving therefore does not suppress anything durably. Durable suppression is admin-only: `false_positive` (on the finding, decision 4) and exceptions. The reason is separation of duties: an analyst's resolve must not act as a de facto false positive.
4. **False-positive alignment.** The false-positive decision lives only on the finding. Moving an incident to `false_positive` marks its finding (admin only, with the `matched` / `classifiers_version` snapshot) and closes every active incident of that finding. The policy engine skips false-positive findings. Unmarking the finding clears `policy_evaluated_at`, so it becomes pending again.
   A lifecycle transition locks the finding before the incident. This is the same lock order as the worker, so a transition and an evaluation cannot deadlock.
5. **Authorization split.** Analysts can acknowledge and resolve incidents. Administrators mark false positives and manage policies and exceptions. All of these actions are audited. An exception with `policy_id` null that is scoped to a classifier family (e.g. `pii.*`) silences that family for every policy. It is admin-only and audited for that reason. On `incidents`, the runtime database role has column-level `UPDATE` on the lifecycle and match columns only, and no `DELETE` or `TRUNCATE`, so a compromised console process can neither erase incidents nor rewrite what they record. Deleting a policy keeps its incidents (`policy_id` set to null; name and revision copied on the incident).

## Consequences
- Adding a source is a compatible change: a new enum value, a new key set and a new matcher. It is not a migration of existing documents.
- Lost, duplicated or concurrent `policies.evaluate` jobs change nothing. A lost wake-up delays evaluation by at most the one-minute schedule.
- A full pass over all findings runs on every policy change. Its cost grows with the findings table; it runs in chunks under a per-job time budget and re-queues itself.
- A finding that is still present after a resolve keeps raising incidents. This continues until it is remediated, or until an administrator marks it a false positive or covers it with an exception. Analysts cannot silence a finding on their own.
- Broad exceptions (no policy, classifier family) can hide a whole data category. Their audit entries are the control, and they should be surfaced in reviews.
- Incidents and findings cannot disagree on false positives. The cost is that one incident marked false positive also closes the incidents raised for the same finding by other policies.
- `notify` actions are accepted and stored before any channel exists. P3-C must resolve slugs to channels and define what happens when a slug is unknown.
- Incidents accumulate with no retention mechanism at the application level. A future retention policy needs a separate, owner-level mechanism.

## Rejected alternatives
- **A free-form expression language, or regular expressions on names**: harder to validate strictly, and regular expressions expose the worker to catastrophic backtracking on hostile names.
- **A single condition schema shared by all sources**: phase 4 keys would be meaningless on findings, and adding them would change how old documents validate.
- **Carrying finding ids in the job payload**: a lost or failed job would lose the evaluation, and bursts would enqueue one job per batch.
- **Reopening the resolved incident**: it rewrites a closed record and loses the trace of the earlier resolve.
- **Resolved as durable suppression, where a new incident opens only on more matched values or another classifier set**: this was the first design. The security review rejected it because an analyst's resolve would then work as a false positive without admin approval.
- **A new incident on every rescan, even while one is active**: it floods users. The active-incident dedup keeps one incident per policy and finding.
- **A separate false-positive flag on incidents**: two sources of truth that can diverge between the findings and incidents pages.
