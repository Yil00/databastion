# ADR-0033: System-alert budget per channel and hour, per-agent share and critical bypass

- **Status**: Accepted
- **Date**: 2026-09-30
- **Refines**: [ADR-0017](0017-alerting.md) (which stays Accepted), decisions 5 (system alerts) and 9 (volume bounds). Records how [ADR-0031](0031-openldap-principals-dedup-and-stream-alerts.md) decisions 2 and 3 were implemented.
- **Context references**: #75 review L4, PR #81 (commit ced95c1) and its security review (M1, Low-1, L1); `console/src/server/notifications.ts` (`enqueueSystemAlert`, `chargeSystemAlertBudget`, `systemAlertAgentShare`, `criticalSystemAlert`, `enqueueSystemAlertDigests`), `console/src/server/alerting-config.ts`, `console/src/db/schema.ts` (`system_alert_budgets`, `system_alert_agent_budgets`), `console/src/server/event-engine.ts` (`rematch`, `link`); `console/README.md` ("Alerting")

## Context
[ADR-0017](0017-alerting.md) bounds system alerts per agent only:
- one silence alert per agent and episode;
- one integrity alert per agent, kind and hour;
- since #75, one `agent.batches_dropped` alert per agent and hour;
- since ADR-0031, one `agent.audit_stream_stopped` alert per agent and hour.

Its decision 9 budget covers incident notifications only ("System alerts … are not counted"). A fleet of N misbehaving or compromised agents therefore sends N alerts an hour to every system-alert channel. That is enough to bury the one that matters, or to exhaust a paging service's quota (#75 review L4).

A plain global budget has the opposite problem, found by the PR #81 security review (M1): one compromised agent could spend the whole budget and push the other agents' alerts, a rotation conflict included, into the digest.

## Decision
1. **Global budget per channel and hour.** Every system alert is charged to a budget per channel and UTC clock hour, all agents together:
   - **Alerts covered**: `agent.silent`, `agent.recovered`, `agent.integrity`, `agent.batches_dropped` and `agent.audit_stream_stopped`.
   - **Limit**: `DATABASTION_SYSTEM_ALERTS_MAX_PER_HOUR`, default 20, accepted from 1 to 10 000. Any other value falls back to the default, with a startup warning.
   - **Storage and charging**: the count lives in PostgreSQL (`system_alert_budgets`, one row per channel and hour). It is charged by a conditional upsert (`… on conflict do update set sent = sent + 1 where sent < limit`) in the transaction that records the alert, so concurrent heartbeats, web replicas and workers never exceed it. An aborted transaction gives its charge back, and a repeated alert (same idempotency key) is not charged.
   - **Over the budget**: the delivery is recorded as `skipped` (`rate_limited`). One `system_alerts.suppressed` digest per channel and closed hour reports the count. The digest carries counts only, and is not charged.
   - **What stays unchanged**: the security events themselves are always recorded, within their own write budget. The incident budget (`DATABASTION_NOTIFY_MAX_PER_HOUR`) still does not count system alerts.
2. **Per-agent share.** One agent may use at most `max(2, ceil(limit / 4))` of a channel's hourly budget (5 of the default 20).
   - **Storage**: the share is counted in `system_alert_agent_budgets`, one row per channel, agent and hour, with the same kind of conditional upsert.
   - **Order of charging**: the agent row is charged before the channel row. When the channel budget then refuses, the agent's charge is given back in the same transaction.
   - **Lock order**: channels are charged in sorted order, the agent row before the channel row, and a transaction charges only its own agent's rows. Every transaction takes these row locks in one global order, so they cannot deadlock. Callers take the budget rows last, after their agent row.
3. **No foreign key from `system_alert_agent_budgets.agent_id` to `agents`.** The key check would take a `KEY SHARE` lock on the agent row after the budget row is inserted. It would deadlock with a heartbeat that holds the agent row and charges the same budget row. The rows are pruned by the worker after two hours; a deleted agent's rows live until then.
4. **Critical alerts bypass both budgets.** A system alert is critical, and is neither charged to nor refused by either budget, only when all of these hold:
   - its event is `agent.integrity`;
   - its kind is in an explicit allowlist, today only `agent.rotation_conflict` (another party may hold the agent's secret);
   - its severity is `critical`.
   The allowlist is on the kind, not the severity alone, so a future caller that derives a severity from agent data cannot skip the budgets (PR #81 re-review Low-1). Each allowed kind is bounded by its own cause: a rotation conflict locks the agent.
5. **ADR-0031 as implemented** (#81):
   - Decision 1 (dedup per `principal_key`, coarse principal for `auth_failure` only) is implemented as written.
   - The optional row-total rule of decision 2 is implemented. After a false positive, a later event of the key within the hour opens a new incident when the rows of the events linked to the incident since it was marked, this one included, exceed the incident's own row total. Links are timestamped with the wall clock of the insert (`clock_timestamp()`), so a chunk transaction that started before a concurrent mark counts its links as after it.
   - The decision 3 alert is charged to the budgets of decisions 1 and 2.
   - The optional alert on a rise of `connector_panics_total` is not implemented.

## Consequences
- **The alert volume is bounded.** A channel receives at most `limit` non-critical system alerts per hour, plus one digest per suppressed hour. One agent receives at most its share, so the other agents keep at least `limit − share` slots.
- **Silent-agent and recovery alerts are counted** (they were not under ADR-0017): a large outage can push some silence alerts into the digest. The digest reports how many.
- **Critical rotation-conflict alerts** are never delayed to the digest.
- Operators set `DATABASTION_SYSTEM_ALERTS_MAX_PER_HOUR` to the same value in every console process (web and worker).

### Residual risks
- **Each process computes the limit and the share from its own environment.** A process with a higher value charges up to its own limit, so the budget and the per-agent share hold only when every console process uses the same `DATABASTION_SYSTEM_ALERTS_MAX_PER_HOUR`.
- **The share has a cost.** An agent that legitimately raises several kinds of alerts in one hour (dropped batches, a stopped stream, integrity events) can have some of them sent to the digest by its own share. Several misbehaving agents together can still use the whole channel budget and delay the others' non-critical alerts to the digest.
- **The row-total rule does nothing for sources that report no row counts** (MySQL / MariaDB audit-log files, the MongoDB `auditLog`, OpenLDAP compares and binds). There, only a new `signature.*` signal or a higher score opens a new incident after a false positive.
- **An event that finds its incident closed concurrently is only linked.** When `rematch` finds the incident closed meanwhile (a user marked it after the chunk read it), the event is linked to the closed incident without the "clearly worse" check. A new incident can open only from the next event of the key.

## Rejected alternatives
- **Global budget only**: one compromised agent could spend it for everyone (PR #81 review M1).
- **Per-agent bounds only** (ADR-0017 as accepted): no bound on a fleet.
- **In-memory counters per process**: N web replicas would allow N times the budget; the budget is a hard limit shared through PostgreSQL, as the rate limits of [ADR-0024](0024-shared-rate-limits.md).
- **Bypass by severity**: a severity can be derived from agent data; an allowlist of kinds cannot be widened by an agent.
- **A foreign key on the agent id**: deadlock with heartbeats (decision 3).
- **Edit ADR-0017 in place**: the ADR convention does not allow editing an accepted ADR.
