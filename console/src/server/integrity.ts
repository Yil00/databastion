import { and, desc, eq, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { securityEvents } from "@/db/schema";
import { logger } from "@/lib/logger";
import type { ValidationDetail } from "@/lib/protocol/validate";

import { writeAudit, type AuditAction } from "./audit";
import { RateLimiter } from "./rate-limit";
import { requestNotificationDelivery } from "./notification-queue";
import { notifyIntegrityEvent } from "./system-alerts";

/**
 * Agent-integrity events of the results endpoints (docs/09-agent-protocol.md, ADR-0009): a rejected
 * (`400`) findings batch, a `batch_conflict` (`409`) and a finding for a target the agent does not
 * own (`404`) cannot come from a conforming agent; nor can a heartbeat target whose
 * `audit_source` does not serve its `engine` (`target_mismatch`, P9-E review M2: the target is
 * stored without the source and the heartbeat is accepted, status `200`). Each one writes a `security_events` row, an
 * `audit_log` entry and (P3-C) the notifications of the system-alert channels, in one transaction.
 *
 * Details are console-computed scalars only: the endpoint, the HTTP status, the number of error
 * details and the first `{pointer, keyword}` (pointers are built from contract property names and
 * array indices only, see `validate.ts`); for `target_mismatch` also `target_ids`, the sorted,
 * comma-separated ids of the mismatched targets (agent-declared identifiers, validated against
 * the contract `TargetId` slug pattern, which has no comma; every mismatched target, up to the
 * contract's 64 targets per heartbeat, while the error details stay capped at
 * `MAX_VALIDATION_DETAILS`, #274 review L5). `details_count` is the number of details found: for
 * `target_mismatch`, every mismatched target (#277; rows written before count at most 20, and their
 * `target_ids` give the true count); the other kinds' validators stop at `MAX_VALIDATION_DETAILS`,
 * so theirs is at most 20.
 * Never another submitted value, a sample or a fingerprint.
 *
 * A misbehaving agent can send such batches in a loop: writes are bounded per agent
 * (`integrityWriteBudget`); beyond it, events are only counted (`integrityStats.suppressed`) and
 * logged at most once per window per agent.
 *
 * `target_mismatch` has its own budget (`targetMismatchWriteBudget`, #235 review N1): it is
 * detected at every heartbeat for as long as the target's `audit_source` does not serve its
 * engine, so in the shared budget a single persistent mismatch would use the slots of the
 * other kinds (a rejected findings batch, a `batch_conflict`, a foreign target) every window.
 * It is recorded once per agent and hour while the set of mismatched targets stays the same, and
 * at once when that set differs from the last recorded row's (PR #274 review L1: a mismatch that
 * starts on another target within the hour is not hidden), within `targetMismatchChangeBudget`;
 * the heartbeats in between are counted (`suppressed_before` of the next `target_mismatch` row,
 * separately from the other kinds). The system alert stays at most one per agent, kind and hour.
 *
 * `accepts_flapping` (security review of #280 re-review, N1): the agent's capability tokens changed
 * more often than the Audit settings requeue budget allows (`auditRequeueBudget`,
 * src/server/audit-config.ts); recorded at most once per agent and hour
 * (`acceptsFlappingAlertBudget`), within `integrityWriteBudget`.
 */
export type IntegrityKind = "batch_rejected" | "batch_conflict" | "foreign_target" | "target_mismatch" | "accepts_flapping";

const ACTION: Record<IntegrityKind, AuditAction> = {
  batch_rejected: "agent.batch_rejected",
  batch_conflict: "agent.batch_conflict",
  foreign_target: "agent.foreign_target",
  target_mismatch: "agent.target_mismatch",
  accepts_flapping: "agent.accepts_flapping",
};

/**
 * Integrity rows written per agent (security event + audit entry) per 10 minutes, shared by every
 * console process (P4-D). When the shared store fails it falls back to its per-process counters
 * (`local`): the rows go to the same database, and failing closed would hide integrity events.
 */
export const integrityWriteBudget = RateLimiter.shared("integrity.writes_per_agent", 20, 10 * 60_000, "local");
/**
 * `target_mismatch` rows written per agent per hour (#235 review N1), shared by every console
 * process with the same per-process fallback. One row an hour is enough to show a persistent
 * mismatch (the system alert is sent at most once per agent, kind and hour anyway), and a
 * mismatch on another target of the same agent within the hour is in the next row. The target
 * itself is stored without `audit_source` at every heartbeat, whatever this budget decides.
 */
export const targetMismatchWriteBudget = RateLimiter.shared("integrity.target_mismatch_per_agent", 1, 60 * 60_000, "local");
/**
 * `target_mismatch` rows written per agent and hour because the set of mismatched targets changed
 * (review L1): bounds an agent that alternates between sets at every heartbeat.
 */
export const targetMismatchChangeBudget = RateLimiter.shared("integrity.target_mismatch_changes", 12, 60 * 60_000, "local");
export const integrityStats = { recorded: 0, suppressed: 0 };

/** The comma-separated, sorted set of mismatched target ids (`TargetId` slugs have no comma). */
function targetIdSet(ids: readonly string[] | undefined): string {
  return [...new Set(ids ?? [])].sort().join(",");
}

/**
 * Whether a `target_mismatch` row may be written: when the set of mismatched targets differs from
 * the agent's last recorded row, within the change budget (the hourly slot is used as well, so the
 * next heartbeat with the same set waits for the next hour); otherwise within the hourly budget.
 */
async function reserveTargetMismatch(db: Database, agentId: string, ids: string): Promise<boolean> {
  const [last] = await db
    .select({ ids: sql<string | null>`${securityEvents.details}->>'target_ids'` })
    .from(securityEvents)
    .where(and(eq(securityEvents.agentId, agentId), eq(securityEvents.kind, "agent.target_mismatch")))
    .orderBy(desc(securityEvents.at))
    .limit(1);
  if (last === undefined || last.ids !== ids) {
    await targetMismatchWriteBudget.reserveShared(agentId);
    return (await targetMismatchChangeBudget.reserveShared(agentId)).ok;
  }
  return (await targetMismatchWriteBudget.reserveShared(agentId)).ok;
}
/** Log de-duplication only: per process by design (each process logs its own suppressions). */
const warnedSuppression = new RateLimiter(1, 10 * 60_000);
/**
 * Events suppressed per agent since its last recorded one: the next recorded event carries the
 * count (`suppressed_before`), so a flood is still visible in `security_events`. Bounded map.
 */
const suppressedSince = new Map<string, number>();
const MAX_SUPPRESSED_KEYS = 10_000;

export interface IntegrityEvent {
  agentId: string;
  kind: IntegrityKind;
  endpoint: "findings" | "events" | "heartbeat";
  status: number;
  details?: readonly ValidationDetail[];
  /**
   * The number of error details found, when `details` holds only the first
   * `MAX_VALIDATION_DETAILS` of them (`target_mismatch`: every mismatched target, #277). Defaults to
   * `details.length`.
   */
  detailsCount?: number;
  /** `target_mismatch`: the ids of the mismatched targets (contract `TargetId`). */
  targetIds?: readonly string[];
  ip: string | null;
}

export async function recordIntegrityEvent(db: Database, event: IntegrityEvent): Promise<boolean> {
  const mismatch = event.kind === "target_mismatch";
  const ids = mismatch ? targetIdSet(event.targetIds) : "";
  const counterKey = `${mismatch ? "target_mismatch" : "shared"}:${event.agentId}`;
  const allowed = mismatch ? await reserveTargetMismatch(db, event.agentId, ids) : (await integrityWriteBudget.reserveShared(event.agentId)).ok;
  if (!allowed) {
    integrityStats.suppressed++;
    if (suppressedSince.has(counterKey) || suppressedSince.size < MAX_SUPPRESSED_KEYS) {
      suppressedSince.set(counterKey, (suppressedSince.get(counterKey) ?? 0) + 1);
    }
    if (warnedSuppression.reserve(counterKey)) {
      logger.warn(
        { agentId: event.agentId, kind: event.kind },
        "agent-integrity events over their per-agent budget: further events are counted, not recorded",
      );
    }
    return false;
  }
  const first = event.details?.[0];
  const details = {
    endpoint: event.endpoint,
    status: event.status,
    // #277: the true count when the caller knows it, the stored details staying capped.
    details_count: Math.max(event.detailsCount ?? 0, event.details?.length ?? 0),
    pointer: first?.pointer ?? null,
    keyword: first?.keyword ?? null,
    suppressed_before: suppressedSince.get(counterKey) ?? 0,
    ...(mismatch ? { target_ids: ids } : {}),
  };
  suppressedSince.delete(counterKey);
  await db.transaction(async (tx) => {
    const [row] = await tx
      .insert(securityEvents)
      .values({
        kind: `agent.${event.kind}`,
        severity: "high",
        agentId: event.agentId,
        details,
      })
      .returning({ id: securityEvents.id, at: securityEvents.at });
    // P3-C: alert the system-alert channels (at most once per agent, kind and hour).
    if (row) {
      await notifyIntegrityEvent(tx, {
        securityEventId: row.id,
        agentId: event.agentId,
        kind: `agent.${event.kind}`,
        severity: "high",
        details,
        at: row.at,
      });
    }
    await writeAudit(tx, {
      actorType: "agent",
      actorId: event.agentId,
      action: ACTION[event.kind],
      outcome: "failure",
      targetType: "agent",
      targetId: event.agentId,
      sourceIp: event.ip,
      details,
    });
  });
  void requestNotificationDelivery();
  integrityStats.recorded++;
  logger.warn({ agentId: event.agentId, kind: event.kind, status: event.status }, "agent-integrity event recorded");
  return true;
}
