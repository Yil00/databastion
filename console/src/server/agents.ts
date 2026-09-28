import { and, eq, inArray, isNull, notInArray, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { agents, agentTargets, enrollmentTokens, jobs } from "@/db/schema";
import type { Schemas } from "@/lib/protocol/validate";

import { writeAudit } from "./audit";
import { purgeSecretCache } from "./agent-api/auth";
import { jobHub, REVOKED_CHANNEL } from "./agent-api/job-hub";
import { argon2Hash, newAgentSecret, sha256Hex } from "./crypto";

/**
 * Consumes an enrollment token and creates the agent, atomically: the conditional UPDATE only
 * matches an unused, unrevoked, unexpired token, so two concurrent enrollments with the same token
 * cannot both succeed; the agent insert happens in the same transaction.
 * Returns null when the token is unknown, expired, revoked or already consumed.
 */
export async function enrollAgent(
  db: Database,
  req: Schemas["EnrollRequest"],
  ip: string,
): Promise<{ agentId: string; secret: string } | null> {
  const secret = newAgentSecret();
  const secretHash = await argon2Hash(secret);
  return db.transaction(async (tx) => {
    const [token] = await tx
      .update(enrollmentTokens)
      .set({ consumedAt: sql`now()` })
      .where(
        and(
          eq(enrollmentTokens.tokenHash, sha256Hex(req.token)),
          isNull(enrollmentTokens.consumedAt),
          isNull(enrollmentTokens.revokedAt),
          sql`${enrollmentTokens.expiresAt} > now()`,
        ),
      )
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
}

/** Stores a (validated) heartbeat: agent status, targets, detections, spool and metrics. */
export async function recordHeartbeat(
  db: Database,
  agentId: string,
  hb: Schemas["HeartbeatRequest"],
): Promise<void> {
  const skew = Date.parse(hb.ts) - Date.now();
  const clockSkewMs = Math.max(-2_000_000_000, Math.min(2_000_000_000, Math.round(skew)));
  await db.transaction(async (tx) => {
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
  });
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
  actor: { userId: string; ip: string },
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
      })
      .where(and(eq(agents.id, agentId), isNull(agents.revokedAt)))
      .returning({ id: agents.id });
    if (rows.length === 0) return false;
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
        present: t.present,
        lastReportedAt: t.lastReportedAt,
      })),
  }));
}
