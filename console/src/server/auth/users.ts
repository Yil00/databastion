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

export interface LoginUser {
  id: string;
  username: string;
  role: "admin" | "analyst";
  passwordHash: string;
}

/**
 * Enabled local user by login name, or null (unknown, malformed, disabled, or a single sign-on user
 * without a local password: ADR-0038 decision 11). No argon2id work.
 */
export async function findLoginUser(db: Database, username: string): Promise<LoginUser | null> {
  const name = username.trim().toLowerCase();
  if (!USERNAME.test(name)) return null;
  const [user] = await db.select().from(users).where(eq(users.username, name)).limit(1);
  if (!user || user.disabledAt || user.passwordHash === null) return null;
  return { id: user.id, username: user.username, role: user.role, passwordHash: user.passwordHash };
}

/** Checks a password. Always runs one argon2id verification (unknown user: dummy hash). */
export async function checkPassword(user: LoginUser | null, password: string): Promise<boolean> {
  if (!user) {
    await argon2VerifyDummy(password);
    return false;
  }
  return argon2Verify(user.passwordHash, password);
}

/** Verifies credentials (lookup + one argon2id verification). */
export async function verifyCredentials(db: Database, username: string, password: string) {
  const user = await findLoginUser(db, username);
  const ok = await checkPassword(user, password);
  return ok && user
    ? { ok: true as const, user: { id: user.id, username: user.username, role: user.role } }
    : { ok: false as const, userId: user?.id ?? null };
}
