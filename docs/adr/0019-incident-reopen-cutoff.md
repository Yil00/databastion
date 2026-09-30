# ADR-0019: "Seen after the resolution" is decided on the scan job's first delivery

- **Status**: Accepted
- **Date**: 2026-09-28
- **Refines**: [ADR-0014](0014-policy-and-incident-model.md) (which stays Accepted), decision 3
- **Context references**: P3-C security review of #49 (N1), `console/src/server/incidents.ts` (`reopensResolved`), `console/src/server/jobs.ts`, migration `0017_jobs_first_delivered_at.sql`

## Context
[ADR-0014](0014-policy-and-incident-model.md) decision 3 opens a new incident for a resolved one when "a later scan still sees the finding, that is, the finding was seen after the incident's `resolved_at`". As first implemented, "seen" was the ingestion time of the finding (`findings.last_seen_at`). The security review of #49 (N1) found that a scan already running when an analyst resolves an incident delivers its findings after `resolved_at`, and so reopens the incident at once with data that was read **before** the resolution. The remediation the resolve asserts has then not been checked by any scan.

## Decision
"Seen after the resolution" means: the finding's latest revision comes from a scan job **first delivered to the agent after `resolved_at`**.

- The console records `jobs.first_delivered_at` when the agent first fetches the job. A redelivery never moves it. Both `first_delivered_at` and `resolved_at` come from the database clock.
- An agent cannot read anything for a job before fetching it, so a job first delivered after the resolution can only carry data read after it.
- Jobs delivered before migration `0017` have no `first_delivered_at`; their `delivered_at` is used. A finding whose job no longer exists falls back to its `last_seen_at`.
- The second reopening condition of ADR-0014 decision 3 (more matched values, or another `classifiers_version`) is unchanged.

## Consequences
- A scan in flight during the resolution no longer reopens the incident; the next scan job fetched by the agent after the resolution does, if the finding is still there.
- The rest of ADR-0014 is unchanged: `resolved` still means remediated, and durable suppression remains an administrator decision.

## Rejected alternatives
- **Ingestion time (`last_seen_at`)**: reopens on data read before the resolution (N1).
- **A read time reported by the agent**: agent-supplied, so an agent could choose it, and not comparable with the database clock.
- **The latest delivery time of the job**: a redelivery after the resolution would make old reads count as new.
