import { and, eq, inArray, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, jobs, securityEvents } from "@/db/schema";
import type { Schemas } from "@/lib/protocol/validate";

import { purgeSecretCache, TOLERANCE_WINDOW_MS, type SecretSlot } from "./agent-api/auth";
import { jobHub, JOBS_CHANNEL, REVOKED_CHANNEL } from "./agent-api/job-hub";
import { writeAudit } from "./audit";
import { argon2Hash, argon2Verify, isLowEntropySecret, rotateArgon2Gate } from "./crypto";
import { RateLimiter } from "./rate-limit";

/**
 * Agent secret rotation, console side (ADR-0008, refined by ADR-0010).
 *
 * `S0` = previous secret, `S1` = new secret registered by `/rotate`.
 * - `/rotate` authenticated with the current secret and no rotation pending: `S1` is hashed
 *   (argon2id) and stored as pending, `grace_expires_at` = now + 300 s (never extended).
 * - `/rotate` authenticated with `S0` while `S1` is pending, or inside the 60 s window after its
 *   promotion: same `S1` -> `duplicate: true`; different `new_secret` -> `rotation_conflict`.
 * - `/rotate` authenticated with the current secret (e.g. `S1` after promotion) always starts a new
 *   rotation, never a conflict.
 * - `/rotate` with `S0` and the promoted `S1` (current hash): `duplicate` at any time (ADR-0011).
 * - Any other use of `S0` after the window: `rotation_conflict` (see `authenticateAgent`).
 * - `rotation_conflict` locks the agent: every secret revoked, held long-polls closed, jobs
 *   cancelled, audit entry + security event.
 * Promotion (first use of `S1`, or the deadline) is done by `authenticateAgent`.
 *
 * The request body (the new secret) is never logged nor stored in clear; only its hash is.
 */

export const ROTATION_GRACE_S = 300;
/** `/rotate` calls per agent (registrations and retries alike). */
export const rotatePerAgent = new RateLimiter(10, 5 * 60_000);

export type RotateOutcome =
  | { kind: "registered" | "duplicate"; graceExpiresAt: Date }
  | { kind: "invalid_secret" | "not_found" | "conflict" | "busy" | "unauthorized" };

type ConflictReason = "different_new_secret" | "stale_secret";

/**
 * Locks the agent after a rotation conflict. Idempotent (only the first call raises the event).
 * Returns true when this call locked it.
 */
export async function lockAgentForConflict(
  db: Database,
  agentId: string,
  reason: ConflictReason,
  ip: string | null,
): Promise<boolean> {
  const locked = await db.transaction(async (tx) => {
    const rows = await tx
      .update(agents)
      .set({
        status: "locked",
        lockedAt: sql`now()`,
        currentSecretHash: null,
        pendingSecretHash: null,
        previousSecretHash: null,
        graceExpiresAt: null,
        promotedGraceExpiresAt: null,
      })
      .where(and(eq(agents.id, agentId), isNull(agents.lockedAt), isNull(agents.revokedAt)))
      .returning({ id: agents.id });
    if (rows.length === 0) return false;
    await tx
      .update(jobs)
      .set({ status: "cancelled", finishedAt: sql`now()` })
      .where(and(eq(jobs.agentId, agentId), inArray(jobs.status, ["pending", "delivered", "running"])));
    await tx.insert(securityEvents).values({
      kind: "agent.rotation_conflict",
      severity: "critical",
      agentId,
      details: { reason },
    });
    await writeAudit(tx, {
      actorType: "agent",
      actorId: agentId,
      action: "agent.rotation_conflict",
      outcome: "failure",
      targetType: "agent",
      targetId: agentId,
      sourceIp: ip,
      details: { reason, locked: true },
    });
    await tx.execute(sql`select pg_notify(${REVOKED_CHANNEL}, ${agentId})`);
    return true;
  });
  purgeSecretCache(agentId);
  jobHub.closeAgent(agentId);
  return locked;
}

export interface RotateAuth {
  agentId: string;
  via: SecretSlot;
  /** The presented (bearer) secret: compared in memory only, never stored nor logged. */
  presented: string;
  matchedHash: string;
}

/** Test hook: counts the argon2 operations run by `/rotate` under `rotateArgon2Gate`. */
export const rotateStats = { argon2Ops: 0 };

/** Handles a validated `RotateRequest` of an authenticated agent. */
export async function rotateSecret(
  db: Database,
  auth: RotateAuth,
  body: Schemas["RotateRequest"],
  ip: string | null,
): Promise<RotateOutcome> {
  const next = body.new_secret;
  if (isLowEntropySecret(next)) return { kind: "invalid_secret" };
  // Equal to the current secret. With `S0` inside the window, the current one is `S1`: that case
  // is the duplicate check below.
  if (auth.via !== "previous" && next === auth.presented) return { kind: "invalid_secret" };

  if (body.job_id !== undefined) {
    const [job] = await db
      .select({ id: jobs.id })
      .from(jobs)
      .where(and(eq(jobs.id, body.job_id), eq(jobs.agentId, auth.agentId), eq(jobs.type, "agent.rotate_secret")))
      .limit(1);
    if (!job) return { kind: "not_found" };
  }

  const release = rotateArgon2Gate.tryAcquire();
  if (!release) return { kind: "busy" };
  const verify = (hash: string) => {
    rotateStats.argon2Ops++;
    return argon2Verify(hash, next);
  };
  const conflict = async (reason: ConflictReason): Promise<RotateOutcome> => {
    await lockAgentForConflict(db, auth.agentId, reason, ip);
    return { kind: "conflict" };
  };
  try {
    let newHash: string | undefined;
    // Optimistic concurrency: a registration only succeeds on the row state it was decided on;
    // a concurrent `/rotate` that lost the race re-reads and becomes a duplicate or a conflict.
    for (let attempt = 0; attempt < 3; attempt++) {
      const [row] = await db.select().from(agents).where(eq(agents.id, auth.agentId)).limit(1);
      if (!row || !row.currentSecretHash || row.revokedAt || row.lockedAt) return { kind: "unauthorized" };

      // Slot of the presented secret against the fresh row (a promotion may have landed).
      let slot: "current" | "previous";
      if (row.currentSecretHash === auth.matchedHash) slot = "current";
      else if (row.previousSecretHash === auth.matchedHash) slot = "previous";
      else return { kind: "unauthorized" };

      if (slot === "previous") {
        // ADR-0011 (M1): `S0` + the promoted `S1` (the current hash) is a late retry of a rotation
        // whose response was lost, at ANY time: only the holder of `S1` can send it. Answered with
        // that rotation's deadline (L4), even if a newer rotation has started since.
        if (await verify(row.currentSecretHash)) {
          return {
            kind: "duplicate",
            graceExpiresAt: row.promotedGraceExpiresAt ?? row.promotedAt ?? new Date(),
          };
        }
        const promotedAt = row.promotedAt?.getTime() ?? 0;
        return conflict(Date.now() - promotedAt >= TOLERANCE_WINDOW_MS ? "stale_secret" : "different_new_secret");
      }

      if (row.pendingSecretHash) {
        // Authenticated with the current secret while `S1` is pending: the current secret is `S0`.
        if (await verify(row.pendingSecretHash)) {
          return { kind: "duplicate", graceExpiresAt: row.graceExpiresAt ?? new Date() };
        }
        return conflict("different_new_secret");
      }

      // No rotation pending, authenticated with the current secret: new rotation.
      if (newHash === undefined) {
        rotateStats.argon2Ops++;
        newHash = await argon2Hash(next);
      }
      const graceExpiresAt = new Date(Date.now() + ROTATION_GRACE_S * 1000);
      const registered = await db.transaction(async (tx) => {
        const rows = await tx
          .update(agents)
          .set({ pendingSecretHash: newHash, graceExpiresAt })
          .where(
            and(
              eq(agents.id, auth.agentId),
              eq(agents.currentSecretHash, row.currentSecretHash as string),
              isNull(agents.pendingSecretHash),
              isNull(agents.lockedAt),
              isNull(agents.revokedAt),
            ),
          )
          .returning({ id: agents.id });
        if (rows.length === 0) return false;
        await writeAudit(tx, {
          actorType: "agent",
          actorId: auth.agentId,
          action: "agent.rotate",
          targetType: "agent",
          targetId: auth.agentId,
          sourceIp: ip,
          details: { job_id: body.job_id ?? null, grace_s: ROTATION_GRACE_S },
        });
        return true;
      });
      if (registered) return { kind: "registered", graceExpiresAt };
    }
    return { kind: "busy" };
  } finally {
    release();
  }
}

export type RotationRequestOutcome = "queued" | "not_found" | "busy";

/**
 * Admin action: queues an `agent.rotate_secret` job (which carries no secret). Refused (`busy`)
 * while a secret is pending, within 60 s of a promotion (ADR-0010), or while another rotate job is
 * still open. The agent row is locked for the decision, so concurrent requests queue one job.
 */
export async function requestSecretRotation(
  db: Database,
  agentId: string,
  actor: { userId: string; ip: string | null },
  reason: "manual" | "scheduled" = "manual",
): Promise<{ outcome: RotationRequestOutcome; jobId?: string }> {
  const result = await db.transaction(async (tx) => {
    const [row] = await tx.select().from(agents).where(eq(agents.id, agentId)).for("update").limit(1);
    if (!row || !row.currentSecretHash || row.revokedAt || row.lockedAt) return { outcome: "not_found" as const };
    if (rotationBlocked(row)) return { outcome: "busy" as const };
    const [open] = await tx
      .select({ id: jobs.id })
      .from(jobs)
      .where(
        and(
          eq(jobs.agentId, agentId),
          eq(jobs.type, "agent.rotate_secret"),
          inArray(jobs.status, ["pending", "delivered", "running"]),
        ),
      )
      .limit(1);
    if (open) return { outcome: "busy" as const };
    const [job] = await tx
      .insert(jobs)
      .values({
        agentId,
        type: "agent.rotate_secret",
        params: { reason },
        expiresAt: new Date(Date.now() + 3600_000),
        createdBy: actor.userId,
      })
      .returning({ id: jobs.id });
    if (!job) throw new Error("job insert returned no row");
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "agent.rotate_request",
      targetType: "agent",
      targetId: agentId,
      sourceIp: actor.ip,
      details: { job_id: job.id, reason },
    });
    await tx.execute(sql`select pg_notify(${JOBS_CHANNEL}, ${agentId})`);
    return { outcome: "queued" as const, jobId: job.id };
  });
  if (result.outcome !== "queued") {
    await writeAudit(db, {
      actorType: "user",
      actorId: actor.userId,
      action: "agent.rotate_request",
      outcome: "failure",
      targetType: "agent",
      targetId: agentId,
      sourceIp: actor.ip,
      details: { reason: result.outcome },
    });
  }
  return result;
}

/**
 * ADR-0010: no rotation while a secret is pending or within 60 s after a promotion. A pending secret
 * whose deadline has passed counts as promoted at the deadline.
 */
export function rotationBlocked(
  row: Pick<typeof agents.$inferSelect, "pendingSecretHash" | "graceExpiresAt" | "promotedAt">,
  now = Date.now(),
): boolean {
  if (row.pendingSecretHash) {
    const deadline = row.graceExpiresAt?.getTime() ?? Number.POSITIVE_INFINITY;
    return deadline > now || now - deadline < TOLERANCE_WINDOW_MS;
  }
  return row.promotedAt !== null && now - row.promotedAt.getTime() < TOLERANCE_WINDOW_MS;
}

/**
 * Late retries with a stale `S0` (after the 60 s window) on `/rotate` (ADR-0011, review N1). The
 * ONLY non-locking outcome is `duplicate`: a valid body whose `new_secret` verifies against the
 * current (promoted `S1`) hash. Everything else (invalid body, low-entropy secret, unknown
 * `job_id`, another secret, too many retries) locks the agent. This path uses its own small bucket
 * (never `rotatePerAgent`, so it cannot drain the legitimate agent's rotations). Its only argon2id
 * work (does `new_secret` verify against the current hash?) is done by `authenticateAgent`, under
 * the pool slot and the counted attempt that verified `S0` (P1-D): no verification outside the
 * bounded pools, and a busy rotate pool neither confirms `S0` with a `503` nor locks a legitimate
 * late retry.
 */
export const staleRetriesPerAgent = new RateLimiter(10, 5 * 60_000);

export async function staleRotateRetry(
  db: Database,
  auth: {
    agentId: string;
    matchedHash: string;
    /** The current hash `staleDuplicate` was computed against (`authenticateAgent`). */
    verifiedCurrentHash: string | null;
    /** `new_secret` verified against `verifiedCurrentHash` (see `AuthOptions.staleCandidate`). */
    staleDuplicate: boolean | undefined;
  },
  body: Schemas["RotateRequest"] | null,
  ip: string | null,
): Promise<RotateOutcome> {
  const conflict = async (): Promise<RotateOutcome> => {
    await lockAgentForConflict(db, auth.agentId, "stale_secret", ip);
    return { kind: "conflict" };
  };
  if (body === null || isLowEntropySecret(body.new_secret)) return conflict();
  if (staleRetriesPerAgent.check(auth.agentId).limited) return conflict();
  staleRetriesPerAgent.hit(auth.agentId);
  if (body.job_id !== undefined) {
    const [job] = await db
      .select({ id: jobs.id })
      .from(jobs)
      .where(and(eq(jobs.id, body.job_id), eq(jobs.agentId, auth.agentId), eq(jobs.type, "agent.rotate_secret")))
      .limit(1);
    if (!job) return conflict();
  }
  const [row] = await db.select().from(agents).where(eq(agents.id, auth.agentId)).limit(1);
  if (!row || !row.currentSecretHash || row.revokedAt || row.lockedAt) return { kind: "unauthorized" };
  // S0 replaced by a newer promotion meanwhile: it is now an unknown secret, like any other.
  if (row.previousSecretHash !== auth.matchedHash) return { kind: "unauthorized" };
  // The check was made against another current hash (a promotion landed meanwhile), or not made:
  // decide nothing, and run no argon2id here.
  if (row.currentSecretHash !== auth.verifiedCurrentHash || auth.staleDuplicate === undefined) {
    return { kind: "unauthorized" };
  }
  if (auth.staleDuplicate) {
    return { kind: "duplicate", graceExpiresAt: row.promotedGraceExpiresAt ?? row.promotedAt ?? new Date() };
  }
  return conflict();
}
