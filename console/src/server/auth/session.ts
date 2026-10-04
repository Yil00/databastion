import { createHmac } from "node:crypto";

import { and, eq, gt, lte, ne, or, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { sessions, users } from "@/db/schema";
import { randomToken, safeEqual, sha256Hex } from "@/server/crypto";
import { revokeRefreshTokensInBackground, type EndedSessionRow } from "@/server/oidc/revoke";
import { encryptRefreshToken } from "@/server/oidc/tokens";

/**
 * Cookie sessions for console users.
 * - The cookie carries 256 random bits; the database stores only their SHA-256.
 * - `HttpOnly`, `SameSite=Strict`, `Path=/`; `Secure` (and the `__Host-` prefix) in production.
 * - Absolute lifetime 12 h (OIDC sessions: `DATABASTION_OIDC_SESSION_MAX_AGE`, at most 12 h), idle
 *   timeout 2 h. Each session records its method (`local` / `oidc`, ADR-0038 decision 13).
 * - CSRF token: HMAC-SHA256 keyed by the session token (never stored), sent back by the UI in
 *   `X-CSRF-Token` on every state-changing request, in addition to the Origin check and SameSite.
 */
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const SESSION_IDLE_MS = 2 * 60 * 60 * 1000;

export function secureCookies(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.NODE_ENV === "production" && env.DATABASTION_INSECURE_COOKIES !== "1";
}

export function sessionCookieName(env: NodeJS.ProcessEnv = process.env): string {
  return secureCookies(env) ? "__Host-databastion_session" : "databastion_session";
}

export function sessionCookie(token: string, maxAgeS: number): string {
  const parts = [
    `${sessionCookieName()}=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${maxAgeS}`,
  ];
  if (secureCookies()) parts.push("Secure");
  return parts.join("; ");
}

export const clearSessionCookie = () => sessionCookie("", 0);

export function csrfTokenFor(sessionToken: string): string {
  return createHmac("sha256", sessionToken).update("databastion-csrf-v1").digest("base64url");
}

export function readSessionToken(req: Request): string | null {
  const cookie = req.headers.get("cookie");
  if (!cookie) return null;
  const name = sessionCookieName();
  for (const part of cookie.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) {
      const value = v.join("=");
      return /^dbu_[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
    }
  }
  return null;
}

export interface OidcSessionOptions {
  identityId: string;
  /** The provider's `sid` claim (bounded, validated by the caller). */
  providerSid: string | null;
  /** Kept encrypted (`oidc-tokens.v1`) only with `DATABASTION_OIDC_USE_REFRESH_TOKEN=1`. */
  refreshToken: string | null;
  /** Absolute lifetime, `DATABASTION_OIDC_SESSION_MAX_AGE` (at most 12 h). */
  ttlMs: number;
}

export async function createSession(db: Database, userId: string, oidc?: OidcSessionOptions) {
  const token = randomToken("dbu_");
  const tokenHash = sha256Hex(token);
  const ttlMs = oidc ? Math.min(oidc.ttlMs, SESSION_TTL_MS) : SESSION_TTL_MS;
  const expiresAt = new Date(Date.now() + ttlMs);
  await db.insert(sessions).values({
    tokenHash,
    userId,
    expiresAt,
    ...(oidc
      ? {
          method: "oidc" as const,
          identityId: oidc.identityId,
          providerSid: oidc.providerSid,
          refreshTokenEnc: oidc.refreshToken === null ? null : encryptRefreshToken(oidc.refreshToken, tokenHash),
          refreshedAt: sql`now()`,
        }
      : {}),
  });
  return { token, expiresAt, csrfToken: csrfTokenFor(token), maxAgeS: Math.floor(ttlMs / 1000) };
}

export interface SessionUser {
  id: string;
  username: string;
  role: "admin" | "analyst";
}

export interface Session {
  token: string;
  tokenHash: string;
  user: SessionUser;
  method: "local" | "oidc";
  identityId: string | null;
}

/** OIDC refresh of a session due for it (`DATABASTION_OIDC_USE_REFRESH_TOKEN=1`), every 5 min at most. */
export const OIDC_REFRESH_INTERVAL_MS = 5 * 60_000;

export async function loadSession(db: Database, req: Request): Promise<Session | null> {
  const token = readSessionToken(req);
  if (!token) return null;
  const tokenHash = sha256Hex(token);
  const idleLimit = new Date(Date.now() - SESSION_IDLE_MS);
  const [row] = await db
    .select({
      id: users.id,
      username: users.username,
      role: users.role,
      disabledAt: users.disabledAt,
      lastSeenAt: sessions.lastSeenAt,
      method: sessions.method,
      identityId: sessions.identityId,
      hasRefreshToken: sql<boolean>`${sessions.refreshTokenEnc} is not null`,
      refreshedAt: sessions.refreshedAt,
    })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(
      and(
        eq(sessions.tokenHash, tokenHash),
        gt(sessions.expiresAt, sql`now()`),
        gt(sessions.lastSeenAt, idleLimit),
      ),
    )
    .limit(1);
  if (!row || row.disabledAt) return null;
  if (Date.now() - row.lastSeenAt.getTime() > 60_000) {
    await db.update(sessions).set({ lastSeenAt: sql`now()` }).where(eq(sessions.tokenHash, tokenHash));
  }
  const session: Session = {
    token,
    tokenHash,
    user: { id: row.id, username: row.username, role: row.role },
    method: row.method,
    identityId: row.identityId,
  };
  if (row.method === "oidc" && row.hasRefreshToken && (row.refreshedAt === null || Date.now() - row.refreshedAt.getTime() >= OIDC_REFRESH_INTERVAL_MS)) {
    // Imported lazily: the OIDC client is only loaded by consoles that use refresh tokens.
    const { refreshOidcSession } = await import("@/server/oidc/refresh");
    return refreshOidcSession(db, session);
  }
  return session;
}

/**
 * Deletes one session. A refresh token it held is revoked at the provider in the background (best
 * effort, security review L5) unless `revokeRefresh` is false (logout revokes it itself, inline).
 */
export async function deleteSession(db: Pick<Database, "delete">, tokenHash: string, opts: { revokeRefresh?: boolean } = {}): Promise<void> {
  const rows = await db.delete(sessions).where(eq(sessions.tokenHash, tokenHash)).returning(ENDED);
  if (opts.revokeRefresh !== false) revokeRefreshTokensInBackground(rows);
}

/** Columns of deleted sessions needed to revoke their refresh tokens (L5). */
const ENDED = { h: sessions.tokenHash, enc: sessions.refreshTokenEnc };

/** Deletes expired and idle sessions (run on every login). */
export async function purgeStaleSessions(db: Database): Promise<number> {
  const idleLimit = new Date(Date.now() - SESSION_IDLE_MS);
  const rows = await db
    .delete(sessions)
    .where(or(lte(sessions.expiresAt, sql`now()`), lte(sessions.lastSeenAt, idleLimit)))
    .returning(ENDED);
  revokeRefreshTokensInBackground(rows);
  return rows.length;
}

/** Ends every session of a user except `keepTokenHash` (a demotion at login or refresh, ADR-0038 decision 9). */
/**
 * Revocation of the refresh tokens of deleted rows: into `deferred` when the caller runs in a
 * transaction (it schedules them after the commit, so a rollback revokes nothing), else now.
 */
function ended(rows: EndedSessionRow[], deferred: EndedSessionRow[] | undefined): void {
  if (deferred) deferred.push(...rows);
  else revokeRefreshTokensInBackground(rows);
}

export async function revokeOtherSessions(db: Pick<Database, "delete">, userId: string, keepTokenHash: string | null, deferred?: EndedSessionRow[]): Promise<number> {
  const where = keepTokenHash === null ? eq(sessions.userId, userId) : and(eq(sessions.userId, userId), ne(sessions.tokenHash, keepTokenHash));
  const rows = await db.delete(sessions).where(where).returning(ENDED);
  ended(rows, deferred);
  return rows.length;
}

/** Ends every session of a user (password change, account disabled, suspected compromise). */
export async function revokeAllSessions(db: Pick<Database, "delete">, userId: string, deferred?: EndedSessionRow[]): Promise<number> {
  return revokeOtherSessions(db, userId, null, deferred);
}

/** Ends the sessions opened with one OIDC identity (before unlinking it). */
export async function revokeIdentitySessions(db: Pick<Database, "delete">, identityId: string, deferred?: EndedSessionRow[]): Promise<number> {
  const rows = await db.delete(sessions).where(eq(sessions.identityId, identityId)).returning(ENDED);
  ended(rows, deferred);
  return rows.length;
}

/**
 * Same-origin check for state-changing user routes: rejects cross-site `Sec-Fetch-Site` and any
 * `Origin` other than the console's (`DATABASTION_PUBLIC_URL` if set, else the request origin).
 */
export function isSameOrigin(req: Request, env: NodeJS.ProcessEnv = process.env): boolean {
  const site = req.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin" && site !== "none") return false;
  const origin = req.headers.get("origin");
  if (origin === null) return true;
  let expected: string;
  try {
    expected = new URL(env.DATABASTION_PUBLIC_URL ?? req.url).origin;
  } catch {
    return false;
  }
  return origin === expected;
}

export function validCsrf(req: Request, session: Session): boolean {
  const header = req.headers.get("x-csrf-token");
  return header !== null && safeEqual(header, csrfTokenFor(session.token));
}
