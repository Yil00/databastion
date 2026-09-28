import { getDb } from "@/db/client";
import { errorSummary, logger } from "@/lib/logger";
import { listAgents, revokeAgent } from "@/server/agents";
import { writeAudit } from "@/server/audit";
import {
  clearSessionCookie,
  createSession,
  csrfTokenFor,
  deleteSession,
  isSameOrigin,
  loadSession,
  SESSION_TTL_MS,
  sessionCookie,
  validCsrf,
  type Session,
} from "@/server/auth/session";
import { MAX_PASSWORD_LENGTH, verifyCredentials } from "@/server/auth/users";
import {
  createEnrollmentToken,
  listEnrollmentTokens,
  revokeEnrollmentToken,
} from "@/server/enrollment";
import { RateLimiter } from "@/server/rate-limit";
import { clientIp, readJsonBody } from "@/server/request";

/**
 * User (UI) API: login / logout / session, enrollment tokens, agents. Every state-changing route
 * requires a same-origin request and, when authenticated, a valid `X-CSRF-Token`. Every user action
 * writes to the console audit log.
 */

const NO_STORE = { "Cache-Control": "no-store" } as const;
const MAX_USER_BODY = 16 * 1024;

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers: { ...NO_STORE, ...headers } });
}
const error = (status: number, code: string, headers: Record<string, string> = {}) =>
  json({ error: code }, status, headers);

async function guardedUser(route: string, fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (err) {
    logger.error({ route, error: errorSummary(err) }, "user API request failed");
    return error(500, "internal");
  }
}

type Guard = { ok: true; session: Session; ip: string } | { ok: false; response: Response };

async function requireUser(
  req: Request,
  opts: { admin?: boolean; stateChanging?: boolean },
): Promise<Guard> {
  if (opts.stateChanging && !isSameOrigin(req)) return { ok: false, response: error(403, "forbidden") };
  const session = await loadSession(getDb(), req);
  if (!session) return { ok: false, response: error(401, "unauthorized") };
  if (opts.stateChanging && !validCsrf(req, session)) {
    return { ok: false, response: error(403, "csrf") };
  }
  if (opts.admin && session.user.role !== "admin") {
    return { ok: false, response: error(403, "forbidden") };
  }
  return { ok: true, session, ip: clientIp(req) };
}

/** Failed logins: per source IP and per username, checked before argon2id. */
export const loginFailuresPerIp = new RateLimiter(20, 15 * 60_000);
export const loginFailuresPerUser = new RateLimiter(5, 15 * 60_000);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function onlyKeys(v: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(v).every((k) => allowed.includes(k));
}

export function handleLogin(req: Request): Promise<Response> {
  return guardedUser("login", async () => {
    if (!isSameOrigin(req)) return error(403, "forbidden");
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (!body.ok) return error(body.reason === "too_large" ? 413 : 400, "invalid_request");
    const v = body.value;
    if (
      !isPlainObject(v) ||
      !onlyKeys(v, ["username", "password"]) ||
      typeof v.username !== "string" ||
      typeof v.password !== "string" ||
      v.username.length < 1 ||
      v.username.length > 64 ||
      v.password.length < 1 ||
      v.password.length > MAX_PASSWORD_LENGTH
    ) {
      return error(400, "invalid_request");
    }
    const ip = clientIp(req);
    const userKey = v.username.trim().toLowerCase();
    const byIp = loginFailuresPerIp.check(ip);
    const byUser = loginFailuresPerUser.check(userKey);
    if (byIp.limited || byUser.limited) {
      const retry = Math.max(byIp.retryAfterS, byUser.retryAfterS);
      return error(429, "rate_limited", { "Retry-After": String(retry) });
    }
    const db = getDb();
    const result = await verifyCredentials(db, v.username, v.password);
    if (!result.ok) {
      loginFailuresPerIp.hit(ip);
      loginFailuresPerUser.hit(userKey);
      // The attempted username is not recorded for unknown users (it may be a mistyped password).
      await writeAudit(db, {
        actorType: "user",
        actorId: result.userId,
        action: "user.login",
        outcome: "failure",
        sourceIp: ip,
      });
      return error(401, "invalid_credentials");
    }
    const session = await createSession(db, result.user.id);
    await writeAudit(db, {
      actorType: "user",
      actorId: result.user.id,
      action: "user.login",
      sourceIp: ip,
    });
    return json({ user: result.user, csrf_token: session.csrfToken }, 200, {
      "Set-Cookie": sessionCookie(session.token, Math.floor(SESSION_TTL_MS / 1000)),
    });
  });
}

export function handleLogout(req: Request): Promise<Response> {
  return guardedUser("logout", async () => {
    const g = await requireUser(req, { stateChanging: true });
    if (!g.ok) return g.response;
    await deleteSession(getDb(), g.session.tokenHash);
    await writeAudit(getDb(), {
      actorType: "user",
      actorId: g.session.user.id,
      action: "user.logout",
      sourceIp: g.ip,
    });
    return new Response(null, {
      status: 204,
      headers: { ...NO_STORE, "Set-Cookie": clearSessionCookie() },
    });
  });
}

export function handleSession(req: Request): Promise<Response> {
  return guardedUser("session", async () => {
    const g = await requireUser(req, {});
    if (!g.ok) return g.response;
    return json({ user: g.session.user, csrf_token: csrfTokenFor(g.session.token) });
  });
}

const LABEL = /^[^\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]{1,64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function handleCreateToken(req: Request): Promise<Response> {
  return guardedUser("enrollment_token.create", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true });
    if (!g.ok) return g.response;
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (!body.ok || !isPlainObject(body.value) || !onlyKeys(body.value, ["label"])) {
      return error(400, "invalid_request");
    }
    const label = body.value.label;
    if (label !== undefined && (typeof label !== "string" || !LABEL.test(label))) {
      return error(400, "invalid_request");
    }
    const created = await createEnrollmentToken(
      getDb(),
      { userId: g.session.user.id, ip: g.ip },
      label ?? null,
    );
    // The clear token is returned once, never stored, never logged.
    return json(
      { id: created.id, token: created.token, expires_at: created.expiresAt.toISOString() },
      201,
    );
  });
}

export function handleListTokens(req: Request): Promise<Response> {
  return guardedUser("enrollment_token.list", async () => {
    const g = await requireUser(req, { admin: true });
    if (!g.ok) return g.response;
    return json({ tokens: await listEnrollmentTokens(getDb()) });
  });
}

export function handleRevokeToken(req: Request, id: string): Promise<Response> {
  return guardedUser("enrollment_token.revoke", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const ok = await revokeEnrollmentToken(getDb(), { userId: g.session.user.id, ip: g.ip }, id);
    return ok ? new Response(null, { status: 204, headers: NO_STORE }) : error(404, "not_found");
  });
}

export function handleListAgents(req: Request): Promise<Response> {
  return guardedUser("agent.list", async () => {
    const g = await requireUser(req, {});
    if (!g.ok) return g.response;
    return json({ agents: await listAgents(getDb()) });
  });
}

export function handleRevokeAgent(req: Request, id: string): Promise<Response> {
  return guardedUser("agent.revoke", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const ok = await revokeAgent(getDb(), id, { userId: g.session.user.id, ip: g.ip });
    return ok ? new Response(null, { status: 204, headers: NO_STORE }) : error(404, "not_found");
  });
}
