# ADR-0036: Console Discovery scan scheduling: one scan per agent at a time

- **Status**: Accepted
- **Date**: 2026-09-30
- **Refines**: [ADR-0035](0035-discovery-pacing.md) (which stays Accepted): decision 9 (the console's handling of queued scans) and the consequence "a queued scan counts its queue time in its `max_duration_s` window"
- **Context references**: end-of-phase-7 security review M1; PR #98 (`fix/p7-console-one-scan-per-agent`) and its security review (L1 to L4); `console/src/server/jobs.ts` (`claimJobs`, `applyJobStatus`), `console/src/server/scans.ts` (`sweepDeadScans`, `requestScan`, held-scan expiry), `console/src/server/job-lock.ts`, `console/src/server/agent-api/handlers.ts` (`GET /jobs` rate limit); [console/README.md](../../console/README.md); [09-agent-protocol.md](../09-agent-protocol.md#jobs-console--agent-via-long-poll)

## Context
Since #93 the agent runs its Discovery scans one at a time, paced to a bounded duty cycle ([ADR-0035](0035-discovery-pacing.md)), so a scan can last up to its full budget (3600 s by default). The agent counts a scan's `max_duration_s` window from the moment it receives the job, queue time included ([09-agent-protocol.md, "Scan worker"](../09-agent-protocol.md#agent-side-handling-of-job-parameters)).

Before #98 the console delivered every pending job at each poll. Scans requested together for several targets of one agent were therefore delivered together. The first one could use its whole budget, and the ones queued behind it in the agent reached the end of their window before they started: they ended `failed` / `timeout` without touching their target. #94 kept such queued scans from being given up by the console, but it did not give them their budget back. The end-of-phase-7 security review recorded this as M1.

## Decision
1. **At most one `discovery.scan` per agent in flight.** `GET /jobs` delivers a pending `discovery.scan` only when the agent has no other `discovery.scan` `delivered` or `running` and no older pending scan. The oldest pending scan goes out only after the previous one reaches a terminal state (`succeeded`, `failed`, `cancelled`, or given up / timed out by the console). Other job types are never held.
2. **Claims are serialized per agent.** Each claim takes a transaction-scoped advisory lock per agent (`jobs.claim:<agent id>`, `lockAgentJobs`), so concurrent polls of one agent cannot each deliver a different scan.
3. **One lock order everywhere**: the `agents` row, then the per-agent job lock, then the agent's `jobs` rows. Revocation, the rotation-conflict lock ([ADR-0008](0008-agent-generated-secret-rotation.md), [ADR-0010](0010-rotation-conflict-window.md)), scan requests (`requestScan`), Audit settings (`audit.configure`) and the claim all follow it. The claim takes no `agents` row lock. With no lock cycle, a revocation concurrent with polls cannot deadlock, so revocation reliably cancels the agent's pending jobs.
4. **Wake-up.** When a `discovery.scan` reaches a terminal state, the console sends a NOTIFY on the jobs channel, so the agent's held long-poll receives the next scan without waiting for the next poll.
5. **Dead-scan sweep at claim.** At each claim, when the agent has a scan in flight, the console first fails the agent's dead scans (delivered or running past `first_delivered_at + max_duration_s + 1 h`: `failed`, `timeout`, audited `job.timeout`), then refreshes the held scans (decision 6), then expires the pending scans past `expires_at`. A scan that died silently therefore neither holds the next scan back nor keeps it alive. When no scan is in flight, the sweep is skipped: there is nothing to hold, and pending jobs past `expires_at` are expired as before.
6. **Expiry of a held scan.**
   - While a scan is held and its agent is online (heartbeat within 90 s), its `expires_at` is refreshed to now + 1 h whenever less than 30 min remain.
   - The refresh never goes past `created_at + 24 h`, an absolute cap.
   - When a pending scan is delivered, its `expires_at` is raised, if lower, to at least now + 1 h, under the same cap, so a scan that waited does not reach the agent with only minutes left.
   - Scans of an offline, revoked or locked agent are never refreshed: they expire at their `expires_at` (6 h after the request by default).
7. **A rejected scan does not hold the next one.** A scan that fails the contract check when it is claimed is marked `failed` (`internal`) and never sent; the claim is repeated (bounded), so the next pending scan is served in the same response.
8. **`GET /jobs` is rate-limited per agent**: 20 requests per 20 s, shared by the console processes ([ADR-0024](0024-shared-rate-limits.md), per-process fallback), answered `429` with `Retry-After` beyond. Each claim is a transaction under the agent's job lock, so a flood of `wait=0` polls would otherwise contend with that agent's revocation and scan requests. A held long-poll is counted once, when admitted.
9. **The agent is unchanged.** It still counts a scan's window from its reception. That is now harmless: a scan is delivered only when the agent's scan worker is free, so its window starts when it can run. The #94 tolerance for queued scans stays, for the remaining cases (a scan the agent still runs after the console timed it out, scans delivered by an older console before an upgrade).

## Consequences
- Scans requested together for several targets of one agent run one after another, each with its full budget. A full pass over N targets of one agent takes about N × the scan budget.
- A held scan is shown on the agent page as "pending (waiting for the previous scan of this agent)".
- A scan still waiting 24 h after its request expires (about 20 scans of the default 3600 s budget queued on one agent). The user requests it again; an order older than a day is considered stale.
- A held scan of an agent that goes offline expires at its `expires_at`, as before.
- No protocol change: `openapi.yaml`, the job schema and the agent are unchanged.
- The one-scan rule lives in the console only. Scans of different agents still run in parallel, even when those agents monitor the same server.

## Rejected alternatives
- **Changing the agent to count the window from the scan's start.** The console would then no longer bound when a delivered scan can still touch the target, and agents without the change would keep the old behaviour. Holding scans in the console needs no agent or protocol change.
- **Letting held scans expire at their original `expires_at` (6 h).** Waiting behind several full-budget scans would expire them, and the user would see scans expire that never had a chance to run.
- **Refreshing `expires_at` without a cap.** A held scan on an agent whose scans never end would live forever.
- **A per-agent claim lock without a global lock order.** Revocation, rotation locking and scan requests take the `agents` row and then write the agent's jobs; a claim taking the locks in another order could deadlock with them and make revocation fail.
