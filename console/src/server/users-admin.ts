import { and, asc, desc, eq, gt, isNull, ne, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { oidcPendingLogins, userIdentities, users } from "@/db/schema";
import { writeAudit } from "@/server/audit";
import { revokeAllSessions } from "@/server/auth/session";
import { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, USERNAME } from "@/server/auth/users";
import { argon2Hash } from "@/server/crypto";
import { pendingEvictions } from "@/server/oidc/service";

/**
 * User management (ADR-0038 consequences): local users, roles, disabling, and the OIDC pending
 * logins, approved only as NEW users bound to their (`iss`, `sub`) (decision 8). There is no
 * administrator linking of an identity to an existing account (decision 6). Every change is audit
 * logged with the acting administrator's id.
 */

export type Role = "admin" | "analyst";

export interface UserView {
  id: string;
  username: string;
  role: Role;
  ssoOnly: boolean;
  hasPassword: boolean;
  disabledAt: string | null;
  createdAt: string;
  lastLoginAt: string | null;
  identities: { issuer: string; subject: string; email: string | null }[];
}

export async function listUsers(db: Database): Promise<UserView[]> {
  const rows = await db.select().from(users).orderBy(asc(users.username)).limit(1000);
  const idents = await db
    .select({ userId: userIdentities.userId, issuer: userIdentities.issuer, subject: userIdentities.subject, email: userIdentities.email })
    .from(userIdentities)
    .limit(5000);
  return rows.map((u) => ({
    id: u.id,
    username: u.username,
    role: u.role,
    ssoOnly: u.ssoOnly,
    hasPassword: u.passwordHash !== null,
    disabledAt: u.disabledAt?.toISOString() ?? null,
    createdAt: u.createdAt.toISOString(),
    lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
    identities: idents.filter((i) => i.userId === u.id).map(({ issuer, subject, email }) => ({ issuer, subject, email })),
  }));
}

export interface PendingLoginView {
  id: string;
  issuer: string;
  subject: string;
  login: string | null;
  email: string | null;
  emailVerified: boolean;
  displayName: string | null;
  groups: string[];
  mappedRole: Role | null;
  attempts: number;
  createdAt: string;
  lastAttemptAt: string;
  expiresAt: string;
}

export async function listPendingLogins(db: Database): Promise<{ pending: PendingLoginView[]; evicted: number }> {
  const rows = await db
    .select()
    .from(oidcPendingLogins)
    .where(gt(oidcPendingLogins.expiresAt, sql`now()`))
    .orderBy(desc(oidcPendingLogins.lastAttemptAt))
    .limit(1000);
  return {
    pending: rows.map((p) => ({
      id: p.id,
      issuer: p.issuer,
      subject: p.subject,
      login: p.login,
      email: p.email,
      emailVerified: p.emailVerified,
      displayName: p.displayName,
      groups: p.groups,
      mappedRole: p.mappedRole,
      attempts: p.attempts,
      createdAt: p.createdAt.toISOString(),
      lastAttemptAt: p.lastAttemptAt.toISOString(),
      expiresAt: p.expiresAt.toISOString(),
    })),
    evicted: await pendingEvictions(db),
  };
}

export interface AdminActor {
  userId: string;
  ip: string | null;
}

export type AdminResult<T = object> = ({ ok: true } & T) | { ok: false; status: number; code: string };

const fail = (status: number, code: string) => ({ ok: false as const, status, code });

/** Approves a pending login as a NEW user (role chosen by the administrator) bound to its (`iss`, `sub`). */
export async function approvePendingLogin(db: Database, id: string, role: Role, actor: AdminActor): Promise<AdminResult<{ userId: string }>> {
  return db.transaction(async (tx) => {
    const [p] = await tx.select().from(oidcPendingLogins).where(and(eq(oidcPendingLogins.id, id), gt(oidcPendingLogins.expiresAt, sql`now()`))).for("update");
    if (!p) return fail(404, "not_found");
    if (p.login === null || !USERNAME.test(p.login)) return fail(409, "invalid_login");
    const [taken] = await tx.select({ id: users.id }).from(users).where(eq(users.username, p.login));
    if (taken) return fail(409, "username_taken");
    const [bound] = await tx.select({ id: userIdentities.id }).from(userIdentities).where(and(eq(userIdentities.issuer, p.issuer), eq(userIdentities.subject, p.subject)));
    if (bound) return fail(409, "identity_bound");
    const [u] = await tx.insert(users).values({ username: p.login, passwordHash: null, ssoOnly: true, role }).returning({ id: users.id });
    if (!u) throw new Error("user insert returned no row");
    await tx.insert(userIdentities).values({ userId: u.id, issuer: p.issuer, subject: p.subject, email: p.email, emailVerified: p.emailVerified, displayName: p.displayName });
    await tx.delete(oidcPendingLogins).where(eq(oidcPendingLogins.id, p.id));
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "user.pending_login_approve",
      targetType: "user",
      targetId: u.id,
      sourceIp: actor.ip,
      details: { role, issuer: p.issuer, subject: p.subject, email_verified: p.emailVerified },
    });
    return { ok: true as const, userId: u.id };
  });
}

export async function discardPendingLogin(db: Database, id: string, actor: AdminActor): Promise<AdminResult> {
  const rows = await db.delete(oidcPendingLogins).where(eq(oidcPendingLogins.id, id)).returning({ issuer: oidcPendingLogins.issuer, subject: oidcPendingLogins.subject });
  const p = rows[0];
  if (!p) return fail(404, "not_found");
  await writeAudit(db, {
    actorType: "user",
    actorId: actor.userId,
    action: "user.pending_login_discard",
    targetType: "oidc_pending_login",
    targetId: id,
    sourceIp: actor.ip,
    details: { issuer: p.issuer, subject: p.subject },
  });
  return { ok: true };
}

export async function createLocalUser(db: Database, input: { username: string; password: string; role: Role }, actor: AdminActor): Promise<AdminResult<{ userId: string }>> {
  const name = input.username.trim().toLowerCase();
  if (!USERNAME.test(name)) return fail(400, "invalid_username");
  if (input.password.length < MIN_PASSWORD_LENGTH || input.password.length > MAX_PASSWORD_LENGTH) return fail(400, "invalid_password");
  const passwordHash = await argon2Hash(input.password);
  return db.transaction(async (tx) => {
    const [taken] = await tx.select({ id: users.id }).from(users).where(eq(users.username, name));
    if (taken) return fail(409, "username_taken");
    const [u] = await tx.insert(users).values({ username: name, passwordHash, role: input.role }).returning({ id: users.id });
    if (!u) throw new Error("user insert returned no row");
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "user.create",
      targetType: "user",
      targetId: u.id,
      sourceIp: actor.ip,
      details: { role: input.role, method: "local" },
    });
    return { ok: true as const, userId: u.id };
  });
}

/** Whether another enabled administrator than `userId` exists (never leave the console without one). */
async function otherEnabledAdmin(tx: Pick<Database, "select">, userId: string): Promise<boolean> {
  const [row] = await tx.select({ id: users.id }).from(users).where(and(eq(users.role, "admin"), isNull(users.disabledAt), ne(users.id, userId))).limit(1);
  return row !== undefined;
}

/**
 * Changes a user's role (source `user`). Refused for a user bound to an OIDC identity while role
 * sync is on (the next login would overwrite it), for oneself, and for the last enabled admin.
 * A demotion ends the user's sessions.
 */
export async function setUserRole(db: Database, id: string, role: Role, actor: AdminActor, roleSyncOn: boolean): Promise<AdminResult> {
  if (id === actor.userId) return fail(409, "self");
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(7234039)`);
    const [u] = await tx.select({ role: users.role }).from(users).where(eq(users.id, id)).for("update");
    if (!u) return fail(404, "not_found");
    if (u.role === role) return { ok: true as const };
    if (roleSyncOn) {
      const [ident] = await tx.select({ id: userIdentities.id }).from(userIdentities).where(eq(userIdentities.userId, id)).limit(1);
      if (ident) return fail(409, "role_managed_by_provider");
    }
    if (u.role === "admin" && !(await otherEnabledAdmin(tx, id))) return fail(409, "last_admin");
    await tx.update(users).set({ role }).where(eq(users.id, id));
    if (u.role === "admin") await revokeAllSessions(tx as unknown as Database, id);
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: "user.role_change",
      targetType: "user",
      targetId: id,
      sourceIp: actor.ip,
      details: { source: "user", from: u.role, to: role },
    });
    return { ok: true as const };
  });
}

/** Disables (ends every session; no login by any method, decision 8) or re-enables a user. */
export async function setUserDisabled(db: Database, id: string, disabled: boolean, actor: AdminActor): Promise<AdminResult> {
  if (id === actor.userId) return fail(409, "self");
  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(7234039)`);
    const [u] = await tx.select({ role: users.role, disabledAt: users.disabledAt }).from(users).where(eq(users.id, id)).for("update");
    if (!u) return fail(404, "not_found");
    if ((u.disabledAt !== null) === disabled) return { ok: true as const };
    if (disabled && u.role === "admin" && !(await otherEnabledAdmin(tx, id))) return fail(409, "last_admin");
    await tx.update(users).set({ disabledAt: disabled ? sql`now()` : null }).where(eq(users.id, id));
    if (disabled) await revokeAllSessions(tx as unknown as Database, id);
    await writeAudit(tx, {
      actorType: "user",
      actorId: actor.userId,
      action: disabled ? "user.disable" : "user.enable",
      targetType: "user",
      targetId: id,
      sourceIp: actor.ip,
    });
    return { ok: true as const };
  });
}

/** The current user's own account view (`/account`). */
export async function accountView(db: Database, userId: string): Promise<UserView | null> {
  const [u] = await db.select().from(users).where(eq(users.id, userId));
  if (!u) return null;
  const idents = await db.select({ issuer: userIdentities.issuer, subject: userIdentities.subject, email: userIdentities.email }).from(userIdentities).where(eq(userIdentities.userId, userId));
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    ssoOnly: u.ssoOnly,
    hasPassword: u.passwordHash !== null,
    disabledAt: u.disabledAt?.toISOString() ?? null,
    createdAt: u.createdAt.toISOString(),
    lastLoginAt: u.lastLoginAt?.toISOString() ?? null,
    identities: idents,
  };
}
