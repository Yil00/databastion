import { and, asc, count, eq, isNull, lte, ne, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { meta, oidcPendingLogins, userIdentities, users } from "@/db/schema";
import { writeAudit } from "@/server/audit";
import { createSession, revokeOtherSessions } from "@/server/auth/session";
import { consoleUrl } from "@/server/alerting-config";
import { enqueueSystemAlert } from "@/server/notifications";

import type { LoginDeniedReason, MappedIdentity, Role } from "./claims";
import type { OidcConfig } from "./config";

/**
 * Console side of an OIDC login (ADR-0038 decisions 6, 8, 9, 15): identity lookup by (`iss`, `sub`)
 * only, sign-up or pending login, role synchronization, self-service linking, audit entries.
 * Audit entries reference the user id; tokens, codes, the state, the nonce and raw claims are
 * never recorded.
 */

export const PENDING_LOGIN_TTL_MS = 7 * 24 * 3600_000;
export const MAX_PENDING_LOGINS = 1000;
export const PENDING_EVICTIONS_KEY = "oidc.pending_logins_evicted";
/** Serializes pending-login writes (cap and eviction count). */
const PENDING_LOCK = 7234_038;

type Tx = Parameters<Parameters<Database["transaction"]>[0]>[0];

export interface Actor {
  ip: string | null;
}

export async function auditDenied(
  db: Pick<Database, "insert">,
  reason: LoginDeniedReason,
  ctx: { ip: string | null; userId?: string | null; purpose?: "login" | "link" },
): Promise<void> {
  await writeAudit(db, {
    actorType: "user",
    actorId: ctx.userId ?? null,
    action: "user.login_denied",
    outcome: "failure",
    sourceIp: ctx.ip,
    details: { method: "oidc", reason, ...(ctx.purpose === "link" ? { purpose: "link" } : {}) },
  });
}

export interface VerifiedIdentity {
  issuer: string;
  subject: string;
  sid: string | null;
  mapped: MappedIdentity;
  /** Role for a new user or a role sync (mapping result). */
  effectiveRole: Role;
}

export type LoginOutcome =
  | { ok: true; userId: string; session: Awaited<ReturnType<typeof createSession>> }
  | { ok: false; reason: LoginDeniedReason; userId: string | null };

/** Role a user created by sign-up or approval starts with (decision 9): never `admin` by default. */
export function initialRole(cfg: Pick<OidcConfig, "skipRoleSync" | "roleStrict" | "rolePath">, effectiveRole: Role): Role {
  if (cfg.rolePath === null) return "analyst";
  if (cfg.skipRoleSync && !cfg.roleStrict) return "analyst";
  return effectiveRole;
}

/** Serializes changes to the set of enabled administrators (shared with users-admin.ts). */
export const ADMIN_SET_LOCK = 7234039;

async function otherEnabledAdmin(tx: Tx, userId: string): Promise<boolean> {
  const [row] = await tx.select({ id: users.id }).from(users).where(and(eq(users.role, "admin"), isNull(users.disabledAt), ne(users.id, userId))).limit(1);
  return row !== undefined;
}

async function roleSyncAlert(tx: Tx, userId: string, username: string, kind: "last_admin_kept" | "local_admin_demoted"): Promise<void> {
  const at = new Date();
  await enqueueSystemAlert(tx, {
    // At most one per user, kind and hour (a refused demotion repeats at every login).
    subjectKey: `user:${userId}|role_sync:${kind}|hour:${at.toISOString().slice(0, 13)}`,
    agentId: null,
    securityEventId: null,
    payload: { event: "user.role_sync", occurred_at: at.toISOString(), url: consoleUrl("/users"), user_id: userId, username, kind },
  });
}

/**
 * Applies a role mapped by the provider (login or refresh, ADR-0038 decision 9) and returns the
 * resulting role. Security review L3: role sync never demotes the last enabled administrator (the
 * role is kept, the refusal audited and alerted), and demoting an account that holds a local
 * password (a break-glass account) raises a system alert. A demotion ends the user's other sessions.
 */
export async function syncRole(tx: Tx, userId: string, from: Role, to: Role, ctx: { ip: string | null; keepTokenHash: string | null }): Promise<Role> {
  if (from === to) return from;
  const demotion = from === "admin";
  if (demotion) {
    await tx.execute(sql`select pg_advisory_xact_lock(${ADMIN_SET_LOCK})`);
  }
  const [u] = await tx.select({ username: users.username, passwordHash: users.passwordHash }).from(users).where(eq(users.id, userId));
  if (!u) return from;
  if (demotion && !(await otherEnabledAdmin(tx, userId))) {
    await writeAudit(tx, {
      actorType: "system",
      action: "user.role_change",
      outcome: "failure",
      targetType: "user",
      targetId: userId,
      sourceIp: ctx.ip,
      details: { source: "oidc", from, to, reason: "last_admin" },
    });
    await roleSyncAlert(tx, userId, u.username, "last_admin_kept");
    return from;
  }
  await tx.update(users).set({ role: to }).where(eq(users.id, userId));
  await writeAudit(tx, {
    actorType: "system",
    action: "user.role_change",
    targetType: "user",
    targetId: userId,
    sourceIp: ctx.ip,
    details: { source: "oidc", from, to },
  });
  if (demotion) {
    await revokeOtherSessions(tx, userId, ctx.keepTokenHash);
    if (u.passwordHash !== null) await roleSyncAlert(tx, userId, u.username, "local_admin_demoted");
  }
  return to;
}

async function bumpIdentity(tx: Tx, identityId: string, m: MappedIdentity): Promise<void> {
  await tx
    .update(userIdentities)
    .set({ email: m.email, emailVerified: m.emailVerified, displayName: m.name, lastLoginAt: sql`now()` })
    .where(eq(userIdentities.id, identityId));
}

/**
 * A successful OIDC authentication of `id` (validated `id_token`, filters passed): finds the user
 * by (`iss`, `sub`), signs up or records a pending login, syncs the role, opens the session.
 */
export async function completeOidcLogin(
  db: Database,
  cfg: OidcConfig,
  id: VerifiedIdentity,
  refreshToken: string | null,
  actor: Actor,
): Promise<LoginOutcome> {
  const outcome = await db.transaction(async (tx): Promise<LoginOutcome | { pending: true }> => {
    const [found] = await tx
      .select({ identityId: userIdentities.id, userId: users.id, role: users.role, disabledAt: users.disabledAt })
      .from(userIdentities)
      .innerJoin(users, eq(users.id, userIdentities.userId))
      .where(and(eq(userIdentities.issuer, id.issuer), eq(userIdentities.subject, id.subject)))
      .for("update", { of: users })
      .limit(1);
    let userId: string;
    let identityId: string;
    if (found) {
      if (found.disabledAt) return { ok: false, reason: "disabled", userId: found.userId };
      userId = found.userId;
      identityId = found.identityId;
      if (!cfg.skipRoleSync && found.role !== id.effectiveRole) {
        // A demotion ends every existing session of the user (the new one carries the new role).
        await syncRole(tx, userId, found.role, id.effectiveRole, { ip: actor.ip, keepTokenHash: null });
      }
      await bumpIdentity(tx, identityId, id.mapped);
    } else {
      if (!cfg.allowSignUp) {
        await recordPendingLogin(tx, id);
        return { pending: true };
      }
      const login = id.mapped.login as string;
      const [taken] = await tx.select({ id: users.id }).from(users).where(eq(users.username, login)).limit(1);
      // Never merged into an existing account, local or not (decision 6).
      if (taken) return { ok: false, reason: "username", userId: null };
      const role = initialRole(cfg, id.effectiveRole);
      const [u] = await tx.insert(users).values({ username: login, passwordHash: null, ssoOnly: true, role }).returning({ id: users.id });
      if (!u) throw new Error("user insert returned no row");
      userId = u.id;
      const [ident] = await tx
        .insert(userIdentities)
        .values({ userId, issuer: id.issuer, subject: id.subject, email: id.mapped.email, emailVerified: id.mapped.emailVerified, displayName: id.mapped.name, lastLoginAt: sql`now()` })
        .returning({ id: userIdentities.id });
      if (!ident) throw new Error("identity insert returned no row");
      identityId = ident.id;
      await writeAudit(tx, {
        actorType: "user",
        actorId: userId,
        action: "user.signup",
        targetType: "user",
        targetId: userId,
        sourceIp: actor.ip,
        details: { method: "oidc", role, issuer: id.issuer, subject: id.subject },
      });
    }
    await tx.update(users).set({ lastLoginAt: sql`now()` }).where(eq(users.id, userId));
    const session = await createSession(tx as unknown as Database, userId, {
      identityId,
      providerSid: id.sid,
      refreshToken: cfg.useRefreshToken ? refreshToken : null,
      ttlMs: cfg.sessionMaxAgeMs,
    });
    await writeAudit(tx, {
      actorType: "user",
      actorId: userId,
      action: "user.login",
      sourceIp: actor.ip,
      details: { method: "oidc" },
    });
    return { ok: true, userId, session };
  });
  if ("pending" in outcome) return { ok: false, reason: "sign_up", userId: null };
  return outcome;
}

/**
 * Records (or refreshes) a pending login of an unknown identity. At most {@link MAX_PENDING_LOGINS}
 * rows: expired ones are deleted first, then the least recent attempt is evicted and the eviction
 * counted (`meta`, shown in the view).
 */
export async function recordPendingLogin(tx: Tx, id: VerifiedIdentity): Promise<void> {
  await tx.execute(sql`select pg_advisory_xact_lock(${PENDING_LOCK})`);
  await tx.delete(oidcPendingLogins).where(lte(oidcPendingLogins.expiresAt, sql`now()`));
  const values = {
    login: id.mapped.login,
    email: id.mapped.email,
    emailVerified: id.mapped.emailVerified,
    displayName: id.mapped.name,
    groups: id.mapped.groups.slice(0, 64),
    mappedRole: id.mapped.role,
    lastAttemptAt: sql`now()`,
    expiresAt: sql`now() + interval '7 days'`,
  };
  const updated = await tx
    .update(oidcPendingLogins)
    .set({ ...values, attempts: sql`least(${oidcPendingLogins.attempts} + 1, 1000000)` })
    .where(and(eq(oidcPendingLogins.issuer, id.issuer), eq(oidcPendingLogins.subject, id.subject)))
    .returning({ id: oidcPendingLogins.id });
  if (updated.length > 0) return;
  const [{ n } = { n: 0 }] = await tx.select({ n: count() }).from(oidcPendingLogins);
  const over = n - MAX_PENDING_LOGINS + 1;
  if (over > 0) {
    const oldest = await tx.select({ id: oidcPendingLogins.id }).from(oidcPendingLogins).orderBy(asc(oidcPendingLogins.lastAttemptAt)).limit(over);
    for (const o of oldest) await tx.delete(oidcPendingLogins).where(eq(oidcPendingLogins.id, o.id));
    await tx.execute(sql`
      insert into meta (key, value, updated_at) values (${PENDING_EVICTIONS_KEY}, ${String(oldest.length)}, now())
      on conflict (key) do update set value = ((meta.value)::bigint + ${oldest.length})::text, updated_at = now()`);
  }
  await tx.insert(oidcPendingLogins).values({ issuer: id.issuer, subject: id.subject, ...values });
}

export async function pendingEvictions(db: Database): Promise<number> {
  const [row] = await db.select({ value: meta.value }).from(meta).where(eq(meta.key, PENDING_EVICTIONS_KEY));
  return row ? Number(row.value) || 0 : 0;
}

export type LinkOutcome = { ok: true } | { ok: false; reason: "session" | "already_linked" | "user_has_identity" | "disabled" };

/**
 * Self-service link (decision 6): binds (`iss`, `sub`) to the user of the LOCAL session that
 * started the flow, if that session still exists and the identity is not bound already.
 */
export async function linkIdentity(
  db: Database,
  id: VerifiedIdentity,
  link: { userId: string; sessionHash: string },
  actor: Actor,
): Promise<LinkOutcome> {
  const result = await db.transaction(async (tx): Promise<LinkOutcome> => {
    const rows = await tx.execute<{ disabled: boolean }>(sql`
      select (u.disabled_at is not null) as disabled from sessions s join users u on u.id = s.user_id
      where s.token_hash = ${link.sessionHash} and s.user_id = ${link.userId} and s.method = 'local'
        and s.expires_at > now() for update of u`);
    const row = rows.rows[0];
    if (!row) return { ok: false, reason: "session" };
    if (row.disabled) return { ok: false, reason: "disabled" };
    const [bound] = await tx
      .select({ id: userIdentities.id })
      .from(userIdentities)
      .where(and(eq(userIdentities.issuer, id.issuer), eq(userIdentities.subject, id.subject)))
      .limit(1);
    if (bound) return { ok: false, reason: "already_linked" };
    const [mine] = await tx
      .select({ id: userIdentities.id })
      .from(userIdentities)
      .where(and(eq(userIdentities.userId, link.userId), eq(userIdentities.issuer, id.issuer)))
      .limit(1);
    if (mine) return { ok: false, reason: "user_has_identity" };
    await tx.insert(userIdentities).values({
      userId: link.userId,
      issuer: id.issuer,
      subject: id.subject,
      email: id.mapped.email,
      emailVerified: id.mapped.emailVerified,
      displayName: id.mapped.name,
    });
    await writeAudit(tx, {
      actorType: "user",
      actorId: link.userId,
      action: "user.identity_link",
      targetType: "user",
      targetId: link.userId,
      sourceIp: actor.ip,
      details: { session_method: "local", issuer: id.issuer, subject: id.subject },
    });
    return { ok: true };
  });
  if (!result.ok) {
    await writeAudit(db, {
      actorType: "user",
      actorId: link.userId,
      action: "user.identity_link",
      outcome: "failure",
      targetType: "user",
      targetId: link.userId,
      sourceIp: actor.ip,
      details: { session_method: "local", reason: result.reason, issuer: id.issuer, subject: id.subject },
    });
  }
  return result;
}
