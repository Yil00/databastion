import { and, desc, eq, inArray, isNull, notInArray, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, agentTargets, enrollmentTokens, jobs, securityEvents } from "@/db/schema";
import { auditSourceEngines } from "@/lib/location-labels";
import { MAX_VALIDATION_DETAILS, type Schemas, type ValidationDetail } from "@/lib/protocol/validate";
import { parseDetectedTargets } from "@/lib/detected-targets";
import { notesToStore, parseStoredNotes } from "@/lib/target-notes";

import { writeAudit } from "./audit";
import { raiseAuditStreamStoppedAlert, recordAuditStreamStops, stoppedStreams } from "./audit-stream-alerts";
import { addDroppedBatches, droppedBatchesDelta, raiseDroppedBatchesAlert } from "./dropped-batches";
import { requestNotificationDelivery } from "./notification-queue";
import { purgeSecretCache } from "./agent-api/auth";
import { jobHub, REVOKED_CHANNEL } from "./agent-api/job-hub";
import { argon2Hash, enrollArgon2Gate, newAgentSecret, sha256Hex } from "./crypto";
import { RateLimiter } from "./rate-limit";
import { lockAgentJobs } from "./job-lock";

/**
 * Consumes an enrollment token and creates the agent.
 * 1. The token is looked up by hash (cheap, not consuming): an unknown, expired, revoked or
 *    consumed token is rejected before any argon2id work (M4).
 * 2. Only then is the new secret generated and hashed, inside the bounded enroll pool
 *    (`enrollArgon2Gate`, L4): `busy` when it is full (the token is not consumed).
 * 3. The conditional UPDATE (unused, unrevoked, unexpired -> used) keeps single use atomic under
 *    concurrency; the agent insert happens in the same transaction.
 * Returns null when the token is not usable. Failures are audited without any token material.
 */
export async function enrollAgent(
  db: Database,
  req: Schemas["EnrollRequest"],
  ip: string | null,
): Promise<{ agentId: string; secret: string } | "busy" | null> {
  const tokenHash = sha256Hex(req.token);
  const usable = and(
    eq(enrollmentTokens.tokenHash, tokenHash),
    isNull(enrollmentTokens.consumedAt),
    isNull(enrollmentTokens.revokedAt),
    sql`${enrollmentTokens.expiresAt} > now()`,
  );
  const [candidate] = await db
    .select({ id: enrollmentTokens.id })
    .from(enrollmentTokens)
    .where(usable)
    .limit(1);
  if (!candidate) {
    await auditEnrollFailure(db, ip);
    return null;
  }
  const release = enrollArgon2Gate.tryAcquire();
  if (!release) return "busy";
  const secret = newAgentSecret();
  let secretHash: string;
  try {
    secretHash = await argon2Hash(secret);
  } finally {
    release();
  }
  const result = await db.transaction(async (tx) => {
    const [token] = await tx
      .update(enrollmentTokens)
      .set({ consumedAt: sql`now()` })
      .where(usable)
      .returning({ id: enrollmentTokens.id, createdBy: enrollmentTokens.createdBy });
    if (!token) return null;
    const [agent] = await tx
      .insert(agents)
      .values({
        name: req.hostname,
        hostname: req.hostname,
        version: req.agent_version,
        os: req.os ?? null,
        arch: req.arch ?? null,
        connectors: req.connectors,
        currentSecretHash: secretHash,
      })
      .returning({ id: agents.id });
    if (!agent) throw new Error("agent insert returned no row");
    await tx
      .update(enrollmentTokens)
      .set({ consumedByAgentId: agent.id })
      .where(eq(enrollmentTokens.id, token.id));
    await writeAudit(tx, {
      actorType: "agent",
      actorId: agent.id,
      action: "agent.enroll",
      targetType: "agent",
      targetId: agent.id,
      sourceIp: ip,
      details: { enrollment_ref: token.id, issued_by: token.createdBy },
    });
    return { agentId: agent.id, secret };
  });
  if (!result) await auditEnrollFailure(db, ip);
  return result;
}

/**
 * Failed enrollments are audited (L3) within a budget shared by every console process (P4-D), so
 * that an unauthenticated flood cannot turn into unbounded audit-log writes. Beyond the budget they
 * are only counted. Per-process fallback when the shared store fails (`local`): the audit rows go
 * to the same database.
 */
export const enrollFailureAuditBudget = RateLimiter.shared("enroll.failure_audit", 60, 60_000, "local");
export const enrollFailureStats = { unaudited: 0 };

async function auditEnrollFailure(db: Database, ip: string | null): Promise<void> {
  if ((await enrollFailureAuditBudget.hitShared("global")).limited) {
    enrollFailureStats.unaudited++;
    return;
  }
  await writeAudit(db, {
    actorType: "agent",
    action: "agent.enroll",
    outcome: "failure",
    sourceIp: ip,
    details: { reason: "token_not_usable" },
  });
}

/**
 * Heartbeat target checks against the target's engine (P9-E, contract "Heartbeat target checks"):
 * a target's `audit_source` must serve its `engine` (`/targets/<i>/audit_source`, keyword
 * `const`; the MySQL / MariaDB sources serve both engines, the `redis_*` sources Redis and
 * Valkey). The schema cannot express it (`TargetStatus` names both values independently). A
 * conforming agent reports the source it reads for the engine it declared, so a mismatch is an
 * agent-integrity event; per target (P9-E review M2): the target is stored **without**
 * `audit_source` ({@link withoutMismatchedSources}) and the rest of the heartbeat is processed
 * (no `400`, so a non-conforming target never makes the agent look silent).
 */
export function targetSourceDetails(hb: Pick<Schemas["HeartbeatRequest"], "targets">): ValidationDetail[] {
  const details: ValidationDetail[] = [];
  hb.targets.forEach((t, i) => {
    if (details.length >= MAX_VALIDATION_DETAILS || t.audit_source === undefined) return;
    if (!(auditSourceEngines(t.audit_source) as readonly string[]).includes(t.engine)) {
      details.push({ pointer: `/targets/${i}/audit_source`, keyword: "const" });
    }
  });
  return details;
}

/**
 * Stores a (validated) heartbeat: agent status, targets, detections, spool and metrics. A rise of
 * `spool.dropped_batches` since the previous heartbeat is counted and alerted (P7, see
 * `dropped-batches.ts`), in the same transaction.
 */
/** Indices of the targets pointed at by `targetSourceDetails` pointers. */
function mismatchedIndices(details: readonly ValidationDetail[]): Set<number> {
  return new Set(details.map((d) => Number(/^\/targets\/(\d+)\/audit_source$/.exec(d.pointer)?.[1] ?? -1)));
}

/** The ids (contract `TargetId`) of the targets pointed at by `details` (#274 review L1). */
export function mismatchedTargetIds(hb: Pick<Schemas["HeartbeatRequest"], "targets">, details: readonly ValidationDetail[]): string[] {
  const at = mismatchedIndices(details);
  return hb.targets.filter((_t, i) => at.has(i)).map((t) => t.target_id);
}

/** The heartbeat with `audit_source` removed from the targets pointed at by `details`. */
export function withoutMismatchedSources(hb: Schemas["HeartbeatRequest"], details: readonly ValidationDetail[]): Schemas["HeartbeatRequest"] {
  if (details.length === 0) return hb;
  const drop = mismatchedIndices(details);
  return {
    ...hb,
    targets: hb.targets.map((t, i) => {
      if (!drop.has(i)) return t;
      const { audit_source: _dropped, ...rest } = t;
      return rest;
    }),
  };
}

export async function recordHeartbeat(
  db: Database,
  agentId: string,
  hb: Schemas["HeartbeatRequest"],
): Promise<void> {
  const skew = Date.parse(hb.ts) - Date.now();
  const clockSkewMs = Math.max(-2_000_000_000, Math.min(2_000_000_000, Math.round(skew)));
  const alerted = await db.transaction(async (tx) => {
    // The previous spool counters, under the row lock (concurrent heartbeats count a rise once).
    const [previous] = await tx
      .select({
        spool: agents.spool,
        uptimeS: agents.uptimeS,
        unalerted: agents.droppedBatchesUnalerted,
        stopsUnalerted: agents.auditStreamStopsUnalerted,
      })
      .from(agents)
      .where(and(eq(agents.id, agentId), isNull(agents.revokedAt), isNull(agents.lockedAt)))
      .for("update");
    await tx
      .update(agents)
      .set({
        version: hb.agent_version,
        uptimeS: Math.min(hb.uptime_s, 2_147_483_647),
        classifiersVersion: hb.classifiers_version ?? null,
        connectors: hb.connectors,
        detectedTargets: hb.detected_targets,
        spool: { ...hb.spool },
        metrics: hb.metrics ?? null,
        clockSkewMs,
        lastSeenAt: sql`now()`,
        status: "online",
      })
      .where(and(eq(agents.id, agentId), isNull(agents.revokedAt), isNull(agents.lockedAt)));
    const ids = hb.targets.map((t) => t.target_id);
    for (const t of hb.targets) {
      const values = {
        engine: t.engine,
        edition: t.edition ?? null,
        serverVersion: t.server_version ?? null,
        reachable: t.reachable,
        auditLevel: t.audit_level,
        auditSource: t.audit_source ?? null,
        lastError: t.last_error ?? null,
        // The notes of the latest heartbeat only: absent -> cleared.
        notes: notesToStore(t.notes),
        metrics: t.metrics ?? null,
        present: true,
        lastReportedAt: sql`now()`,
      };
      await tx
        .insert(agentTargets)
        .values({ agentId, targetId: t.target_id, ...values })
        .onConflictDoUpdate({ target: [agentTargets.agentId, agentTargets.targetId], set: values });
    }
    await tx
      .update(agentTargets)
      .set({ present: false })
      .where(
        ids.length > 0
          ? and(eq(agentTargets.agentId, agentId), notInArray(agentTargets.targetId, ids))
          : eq(agentTargets.agentId, agentId),
      );
    if (!previous) return false;
    const delta = droppedBatchesDelta(previous, { spool: hb.spool, uptimeS: hb.uptime_s });
    await addDroppedBatches(tx, agentId, delta);
    const stops = stoppedStreams(hb.targets);
    await recordAuditStreamStops(tx, agentId, stops);
    let raised = false;
    if (previous.unalerted + delta > 0) raised = (await raiseDroppedBatchesAlert(tx, agentId)) !== null;
    if (previous.stopsUnalerted + stops > 0) raised = (await raiseAuditStreamStoppedAlert(tx, agentId)) !== null || raised;
    return raised;
  });
  if (alerted) void requestNotificationDelivery();
}

/**
 * Revokes an agent (admin action). Effective immediately: both secret hashes are cleared (every
 * console process re-reads them on each request), the verified-secret cache is purged, held
 * long-polls are closed in this process and, via NOTIFY, in every other one; pending jobs are
 * cancelled.
 */
export async function revokeAgent(
  db: Database,
  agentId: string,
  actor: { userId: string; ip: string | null },
): Promise<boolean> {
  const done = await db.transaction(async (tx) => {
    const rows = await tx
      .update(agents)
      .set({
        status: "revoked",
        revokedAt: sql`now()`,
        revokedBy: actor.userId,
        currentSecretHash: null,
        pendingSecretHash: null,
        previousSecretHash: null,
        graceExpiresAt: null,
        promotedGraceExpiresAt: null,
        knownGoodFingerprint: null,
        knownGoodAt: null,
        knownGoodPendingFingerprint: null,
      })
      .where(and(eq(agents.id, agentId), isNull(agents.revokedAt)))
      .returning({ id: agents.id });
    if (rows.length === 0) return false;
    // After the agent row, before its jobs: same order as every job writer (job-lock.ts, L1).
    await lockAgentJobs(tx, agentId);
    await tx
      .update(jobs)
      .set({ status: "cancelled", finishedAt: sql`now()` })
      .where(and(eq(jobs.agentId, agentId), inArray(jobs.status, ["pending", "delivered", "running"])));
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "agent.revoke",
      targetType: "agent",
      targetId: agentId,
      sourceIp: actor.ip,
    });
    await tx.execute(sql`select pg_notify(${REVOKED_CHANNEL}, ${agentId})`);
    return true;
  });
  purgeSecretCache(agentId);
  jobHub.closeAgent(agentId);
  if (!done) {
    // Unknown or already revoked agent (L3).
    await writeAudit(db, {
      actorType: "user",
      actorId: actor.userId,
      action: "agent.revoke",
      outcome: "failure",
      targetType: "agent",
      targetId: agentId,
      sourceIp: actor.ip,
      details: { reason: "not_found_or_already_revoked" },
    });
  }
  return done;
}

export async function listAgents(db: Database) {
  const rows = await db
    .select({
      id: agents.id,
      name: agents.name,
      hostname: agents.hostname,
      version: agents.version,
      status: agents.status,
      enrolledAt: agents.enrolledAt,
      lastSeenAt: agents.lastSeenAt,
      revokedAt: agents.revokedAt,
      lockedAt: agents.lockedAt,
      connectors: agents.connectors,
      classifiersVersion: agents.classifiersVersion,
      rotationPending: sql<boolean>`${agents.pendingSecretHash} is not null`,
      graceExpiresAt: agents.graceExpiresAt,
      promotedAt: agents.promotedAt,
    })
    .from(agents)
    .orderBy(agents.enrolledAt)
    .limit(1000);
  const targets = await db.select().from(agentTargets);
  return rows.map((a) => ({
    ...a,
    targets: targets
      .filter((t) => t.agentId === a.id)
      .map((t) => ({
        targetId: t.targetId,
        engine: t.engine,
        reachable: t.reachable,
        auditLevel: t.auditLevel,
        auditSource: t.auditSource,
        lastError: t.lastError,
        notes: parseStoredNotes(t.notes),
        present: t.present,
        lastReportedAt: t.lastReportedAt,
      })),
  }));
}

/** One agent and its reported targets, for the detail page. Never returns a secret hash. */
export async function getAgentDetail(db: Database, agentId: string) {
  const [agent] = await db
    .select({
      id: agents.id,
      name: agents.name,
      hostname: agents.hostname,
      version: agents.version,
      os: agents.os,
      arch: agents.arch,
      status: agents.status,
      connectors: agents.connectors,
      classifiersVersion: agents.classifiersVersion,
      enrolledAt: agents.enrolledAt,
      lastSeenAt: agents.lastSeenAt,
      uptimeS: agents.uptimeS,
      clockSkewMs: agents.clockSkewMs,
      revokedAt: agents.revokedAt,
      lockedAt: agents.lockedAt,
      rotationPending: sql<boolean>`${agents.pendingSecretHash} is not null`,
      graceExpiresAt: agents.graceExpiresAt,
      promotedAt: agents.promotedAt,
      spool: agents.spool,
      droppedBatchesUnalerted: agents.droppedBatchesUnalerted,
      droppedBatchesSince: agents.droppedBatchesSince,
      droppedBatchesAlertedAt: agents.droppedBatchesAlertedAt,
      auditStreamStopsUnalerted: agents.auditStreamStopsUnalerted,
      auditStreamStopsSince: agents.auditStreamStopsSince,
      auditStreamStopsAlertedAt: agents.auditStreamStopsAlertedAt,
      detectedTargets: agents.detectedTargets,
    })
    .from(agents)
    .where(eq(agents.id, agentId))
    .limit(1);
  if (!agent) return null;
  // The latest dropped-batches alerts (P7): console-computed counts and timestamps only.
  const droppedAlerts = (
    await db
      .select({ id: securityEvents.id, at: securityEvents.at, details: securityEvents.details })
      .from(securityEvents)
      .where(and(eq(securityEvents.agentId, agentId), eq(securityEvents.kind, "agent.batches_dropped")))
      .orderBy(desc(securityEvents.at))
      .limit(5)
  ).map((e) => ({
    id: e.id,
    at: e.at,
    droppedBatches: typeof e.details?.dropped_batches === "number" ? e.details.dropped_batches : null,
    since: typeof e.details?.since === "string" ? e.details.since : null,
  }));
  // The latest Audit-stream-stopped alerts (P7, ADR-0031): console-computed counts and timestamps.
  const streamStopAlerts = (
    await db
      .select({ id: securityEvents.id, at: securityEvents.at, details: securityEvents.details })
      .from(securityEvents)
      .where(and(eq(securityEvents.agentId, agentId), eq(securityEvents.kind, "agent.audit_stream_stopped")))
      .orderBy(desc(securityEvents.at))
      .limit(5)
  ).map((e) => ({
    id: e.id,
    at: e.at,
    stoppedStreams: typeof e.details?.stopped_streams === "number" ? e.details.stopped_streams : null,
    since: typeof e.details?.since === "string" ? e.details.since : null,
  }));
  const targets = await db
    .select({
      targetId: agentTargets.targetId,
      engine: agentTargets.engine,
      edition: agentTargets.edition,
      serverVersion: agentTargets.serverVersion,
      reachable: agentTargets.reachable,
      auditLevel: agentTargets.auditLevel,
      auditSource: agentTargets.auditSource,
      lastError: agentTargets.lastError,
      notes: agentTargets.notes,
      present: agentTargets.present,
      lastReportedAt: agentTargets.lastReportedAt,
    })
    .from(agentTargets)
    .where(eq(agentTargets.agentId, agentId))
    .orderBy(agentTargets.targetId);
  return {
    ...agent,
    // ADR-0006: local engines the agent spotted but that are not declared (re-checked on read).
    detectedTargets: parseDetectedTargets(agent.detectedTargets),
    droppedAlerts,
    streamStopAlerts,
    targets: targets.map((t) => ({ ...t, notes: parseStoredNotes(t.notes) })),
  };
}
