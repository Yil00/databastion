import { count, eq, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { users } from "@/db/schema";
import { writeAudit } from "@/server/audit";
import { argon2Hash, argon2Verify, argon2VerifyDummy } from "@/server/crypto";

export const USERNAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 1024;

export class BootstrapError extends Error {
  override name = "BootstrapError";
}

/**
 * Creates the first administrator. Refuses when any user already exists: there is no default
 * account and no default password.
 */
export async function bootstrapAdmin(db: Database, username: string, password: string): Promise<string> {
  const name = username.trim().toLowerCase();
  if (!USERNAME.test(name)) throw new BootstrapError("Invalid administrator username.");
  if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    throw new BootstrapError(
      `The administrator password must be ${MIN_PASSWORD_LENGTH} to ${MAX_PASSWORD_LENGTH} characters long.`,
    );
  }
  const passwordHash = await argon2Hash(password);
  return db.transaction(async (tx) => {
    // Serialize concurrent bootstraps.
    await tx.execute(sql`select pg_advisory_xact_lock(7234001)`);
    const [existing] = await tx.select({ n: count() }).from(users);
    if ((existing?.n ?? 0) > 0) throw new BootstrapError("Users already exist: bootstrap refused.");
    const [row] = await tx
      .insert(users)
      .values({ username: name, passwordHash, role: "admin" })
      .returning({ id: users.id });
    if (!row) throw new Error("user insert returned no row");
    await writeAudit(tx, {
      actorType: "system",
      action: "user.bootstrap",
      targetType: "user",
      targetId: row.id,
      details: { role: "admin" },
    });
    return row.id;
  });
}

/** Verifies credentials. Always runs one argon2id verification (unknown user: dummy hash). */
export async function verifyCredentials(db: Database, username: string, password: string) {
  const name = username.trim().toLowerCase();
  const [user] = USERNAME.test(name)
    ? await db.select().from(users).where(eq(users.username, name)).limit(1)
    : [];
  if (!user || user.disabledAt) {
    await argon2VerifyDummy(password);
    return { ok: false as const, userId: user?.id ?? null };
  }
  const ok = await argon2Verify(user.passwordHash, password);
  return ok
    ? { ok: true as const, user: { id: user.id, username: user.username, role: user.role } }
    : { ok: false as const, userId: user.id };
}
