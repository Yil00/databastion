import { and, desc, eq, gt, isNull, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { enrollmentTokens } from "@/db/schema";

import { writeAudit } from "./audit";
import { newEnrollmentToken, sha256Hex } from "./crypto";

export const ENROLLMENT_TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

export interface Actor {
  userId: string;
  ip: string;
}

/** Creates a single-use token. The clear token is returned ONCE; only its SHA-256 is stored. */
export async function createEnrollmentToken(
  db: Database,
  actor: Actor,
  label: string | null,
): Promise<{ id: string; token: string; expiresAt: Date }> {
  const token = newEnrollmentToken();
  const expiresAt = new Date(Date.now() + ENROLLMENT_TOKEN_TTL_MS);
  return db.transaction(async (tx) => {
    const [row] = await tx
      .insert(enrollmentTokens)
      .values({ tokenHash: sha256Hex(token), label, createdBy: actor.userId, expiresAt })
      .returning({ id: enrollmentTokens.id });
    if (!row) throw new Error("enrollment token insert returned no row");
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "enrollment_token.create",
      targetType: "enrollment_token",
      targetId: row.id,
      sourceIp: actor.ip,
      details: { expires_at: expiresAt.toISOString() },
    });
    return { id: row.id, token, expiresAt };
  });
}

export type TokenState = "active" | "consumed" | "expired" | "revoked";

export async function listEnrollmentTokens(db: Database) {
  const rows = await db
    .select({
      id: enrollmentTokens.id,
      label: enrollmentTokens.label,
      createdBy: enrollmentTokens.createdBy,
      createdAt: enrollmentTokens.createdAt,
      expiresAt: enrollmentTokens.expiresAt,
      consumedAt: enrollmentTokens.consumedAt,
      consumedByAgentId: enrollmentTokens.consumedByAgentId,
      revokedAt: enrollmentTokens.revokedAt,
    })
    .from(enrollmentTokens)
    .orderBy(desc(enrollmentTokens.createdAt))
    .limit(500);
  const now = Date.now();
  return rows.map((r) => {
    const state: TokenState = r.revokedAt
      ? "revoked"
      : r.consumedAt
        ? "consumed"
        : r.expiresAt.getTime() <= now
          ? "expired"
          : "active";
    return { ...r, state };
  });
}

/** Revokes an unused token. Returns false when it does not exist or is no longer usable. */
export async function revokeEnrollmentToken(db: Database, actor: Actor, id: string): Promise<boolean> {
  return db.transaction(async (tx) => {
    const rows = await tx
      .update(enrollmentTokens)
      .set({ revokedAt: sql`now()` })
      .where(
        and(
          eq(enrollmentTokens.id, id),
          isNull(enrollmentTokens.consumedAt),
          isNull(enrollmentTokens.revokedAt),
          gt(enrollmentTokens.expiresAt, sql`now()`),
        ),
      )
      .returning({ id: enrollmentTokens.id });
    if (rows.length === 0) return false;
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "enrollment_token.revoke",
      targetType: "enrollment_token",
      targetId: id,
      sourceIp: actor.ip,
    });
    return true;
  });
}
