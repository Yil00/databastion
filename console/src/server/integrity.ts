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
 * array indices only, see `validate.ts`). Never a submitted value, sample or fingerprint.
 *
 * A misbehaving agent can send such batches in a loop: writes are bounded per agent
 * (`integrityWriteBudget`); beyond it, events are only counted (`integrityStats.suppressed`) and
 * logged at most once per window per agent.
 *
 * `target_mismatch` has its own budget (`targetMismatchWriteBudget`, #235 review N1): it is
 * detected at every heartbeat for as long as the target's `audit_source` does not serve its
 * engine, so in the shared budget a single persistent mismatch would use the slots of the
 * other kinds (a rejected findings batch, a `batch_conflict`, a foreign target) every window.
 * It is recorded at most once per agent and hour; the heartbeats in between are counted
 * (`suppressed_before` of the next `target_mismatch` row, separately from the other kinds).
 */
export type IntegrityKind = "batch_rejected" | "batch_conflict" | "foreign_target" | "target_mismatch";

const ACTION: Record<IntegrityKind, AuditAction> = {
  batch_rejected: "agent.batch_rejected",
  batch_conflict: "agent.batch_conflict",
  foreign_target: "agent.foreign_target",
  target_mismatch: "agent.target_mismatch",
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
export const integrityStats = { recorded: 0, suppressed: 0 };

/** The write budget of an integrity kind, and the namespace of its suppression counters. */
function budgetOf(kind: IntegrityKind): { budget: RateLimiter; scope: string } {
  return kind === "target_mismatch" ? { budget: targetMismatchWriteBudget, scope: "target_mismatch" } : { budget: integrityWriteBudget, scope: "shared" };
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
  ip: string | null;
}

export async function recordIntegrityEvent(db: Database, event: IntegrityEvent): Promise<boolean> {
  const { budget, scope } = budgetOf(event.kind);
  const counterKey = `${scope}:${event.agentId}`;
  if (!(await budget.reserveShared(event.agentId)).ok) {
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
    details_count: event.details?.length ?? 0,
    pointer: first?.pointer ?? null,
    keyword: first?.keyword ?? null,
    suppressed_before: suppressedSince.get(counterKey) ?? 0,
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
