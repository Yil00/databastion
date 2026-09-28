import { createHmac } from "node:crypto";

import { and, eq, gt, sql } from "drizzle-orm";

import type { Database } from "@/db/client";
import { sessions, users } from "@/db/schema";
import { randomToken, safeEqual, sha256Hex } from "@/server/crypto";

/**
 * Cookie sessions for console users.
 * - The cookie carries 256 random bits; the database stores only their SHA-256.
 * - `HttpOnly`, `SameSite=Strict`, `Path=/`; `Secure` (and the `__Host-` prefix) in production.
 * - Absolute lifetime 12 h, idle timeout 2 h.
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

export async function createSession(db: Database, userId: string) {
  const token = randomToken("dbu_");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await db.insert(sessions).values({ tokenHash: sha256Hex(token), userId, expiresAt });
  return { token, expiresAt, csrfToken: csrfTokenFor(token) };
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
}

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
  return { token, tokenHash, user: { id: row.id, username: row.username, role: row.role } };
}

export async function deleteSession(db: Database, tokenHash: string): Promise<void> {
  await db.delete(sessions).where(eq(sessions.tokenHash, tokenHash));
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
