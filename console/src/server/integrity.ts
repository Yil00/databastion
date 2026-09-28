import type { Database } from "@/db/client";
import { securityEvents } from "@/db/schema";
import { logger } from "@/lib/logger";
import type { ValidationDetail } from "@/lib/protocol/validate";

import { writeAudit, type AuditAction } from "./audit";
import { RateLimiter } from "./rate-limit";

/**
 * Agent-integrity events of the results endpoints (docs/09-agent-protocol.md, ADR-0009): a rejected
 * (`400`) findings batch, a `batch_conflict` (`409`) and a finding for a target the agent does not
 * own (`404`) cannot come from a conforming agent. Each one writes a `security_events` row (the
 * placeholder of the phase 3 incident model; alerting comes with P3) and an `audit_log` entry, in
 * one transaction.
 *
 * Details are console-computed scalars only: the endpoint, the HTTP status, the number of error
 * details and the first `{pointer, keyword}` (pointers are built from contract property names and
 * array indices only, see `validate.ts`). Never a submitted value, sample or fingerprint.
 *
 * A misbehaving agent can send such batches in a loop: writes are bounded per agent
 * (`integrityWriteBudget`); beyond it, events are only counted (`integrityStats.suppressed`) and
 * logged at most once per window per agent.
 */
export type IntegrityKind = "batch_rejected" | "batch_conflict" | "foreign_target";

const ACTION: Record<IntegrityKind, AuditAction> = {
  batch_rejected: "agent.batch_rejected",
  batch_conflict: "agent.batch_conflict",
  foreign_target: "agent.foreign_target",
};

/** Integrity rows written per agent (security event + audit entry) per 10 minutes. */
export const integrityWriteBudget = new RateLimiter(20, 10 * 60_000);
export const integrityStats = { recorded: 0, suppressed: 0 };
const warnedSuppression = new RateLimiter(1, 10 * 60_000);

export interface IntegrityEvent {
  agentId: string;
  kind: IntegrityKind;
  endpoint: "findings" | "events";
  status: number;
  details?: readonly ValidationDetail[];
  ip: string | null;
}

export async function recordIntegrityEvent(db: Database, event: IntegrityEvent): Promise<boolean> {
  if (!integrityWriteBudget.reserve(event.agentId)) {
    integrityStats.suppressed++;
    if (warnedSuppression.reserve(event.agentId)) {
      logger.warn(
        { agentId: event.agentId, kind: event.kind },
        "agent-integrity events over the per-agent budget: further events are counted, not recorded",
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
  };
  await db.transaction(async (tx) => {
    await tx.insert(securityEvents).values({
      kind: `agent.${event.kind}`,
      severity: "high",
      agentId: event.agentId,
      details,
    });
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
  integrityStats.recorded++;
  logger.warn({ agentId: event.agentId, kind: event.kind, status: event.status }, "agent-integrity event recorded");
  return true;
}
