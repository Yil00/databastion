import { and, eq, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { auditLog, findings } from "@/db/schema";
import { errorSummary, type Logger } from "@/lib/logger";
import { TARGET_SCOPED_EXCEPTION_ENGINES } from "@/lib/policy-common";

import { writeAudit } from "./audit";

/**
 * P10-E, security review L1 of 342a257: a worker of an older build (0.9) evaluates SQLite findings
 * without the reach rule of location exceptions (`exceptionReachesItem`, P10-C review R2), so a
 * SQLite finding it evaluated during a rolling upgrade may have been suppressed by an exception
 * that does not reach it. At the first start of a worker of this build, every finding of a
 * target-scoped engine (`sqlite`) is marked pending again (`policy_evaluated_at = null`), so the
 * policy engine evaluates it with the rule; incidents already open are deduplicated as usual.
 *
 * Once: the run is recorded in the console audit log (`findings.reevaluate_target_scoped`, system
 * actor, the count only) and skipped when a successful entry exists. Under a transaction-level
 * advisory lock taken without waiting, so two workers starting together run it once. Never throws:
 * a failure is logged and retried at the next start (nothing is recorded).
 */
export const REEVALUATION_ACTION = "findings.reevaluate_target_scoped";
const LOCK_KEY = "findings.reevaluate_target_scoped";

/** The number of findings marked pending, or null when it already ran, another worker runs it, or it failed. */
export async function runStartupSqliteReevaluation(db: Database, log: Logger): Promise<number | null> {
  try {
    return await db.transaction(async (tx) => {
      await tx.execute(sql.raw("set local lock_timeout = 5000"));
      const res = await tx.execute<{ locked: boolean }>(sql`select pg_try_advisory_xact_lock(hashtextextended(${LOCK_KEY}, 0)) as locked`);
      if (res.rows[0]?.locked !== true) return null;
      const [done] = await tx
        .select({ id: auditLog.id })
        .from(auditLog)
        .where(and(eq(auditLog.action, REEVALUATION_ACTION), eq(auditLog.outcome, "success")))
        .limit(1);
      if (done) return null;
      const updated = await tx
        .update(findings)
        .set({ policyEvaluatedAt: null })
        .where(sql`${findings.engine} in (${sql.join(
          TARGET_SCOPED_EXCEPTION_ENGINES.map((e) => sql`${e}::text`),
          sql`, `,
        )})`)
        .returning({ id: findings.id });
      await writeAudit(tx, {
        actorType: "system",
        action: REEVALUATION_ACTION,
        targetType: "finding",
        details: { engines: TARGET_SCOPED_EXCEPTION_ENGINES.join(","), findings: updated.length },
      });
      log.info({ engines: TARGET_SCOPED_EXCEPTION_ENGINES, findings: updated.length }, "target-scoped findings marked for re-evaluation");
      return updated.length;
    });
  } catch (err) {
    log.warn({ error: errorSummary(err) }, "target-scoped findings re-evaluation failed; retried at the next start");
    return null;
  }
}
