import { getDb } from "@/db/client";
import { errorSummary, logger } from "@/lib/logger";
import { listAgents, revokeAgent } from "@/server/agents";
import { requestSecretRotation } from "@/server/rotation";
import { setFalsePositive } from "@/server/findings";
import { buildScanParams, requestScan } from "@/server/scans";
import { validateSchema } from "@/lib/protocol/validate";
import { writeAudit } from "@/server/audit";
import {
  clearSessionCookie,
  createSession,
  csrfTokenFor,
  deleteSession,
  isSameOrigin,
  loadSession,
  purgeStaleSessions,
  readSessionToken,
  SESSION_TTL_MS,
  sessionCookie,
  validCsrf,
  type Session,
} from "@/server/auth/session";
import { issueDeviceCookie, readDeviceCookie } from "@/server/auth/device-cookie";
import { checkPassword, findLoginUser, MAX_PASSWORD_LENGTH, type LoginUser } from "@/server/auth/users";
import {
  createEnrollmentToken,
  listEnrollmentTokens,
  revokeEnrollmentToken,
} from "@/server/enrollment";
import { argon2MedianMs, loginArgon2Gate, sha256Hex } from "@/server/crypto";
import { RateLimiter } from "@/server/rate-limit";
import { clientIp, ipBucket, readJsonBody } from "@/server/request";

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

type Guard = { ok: true; session: Session; ip: string | null } | { ok: false; response: Response };

async function requireUser(
  req: Request,
  opts: { admin?: boolean; stateChanging?: boolean; route: string },
): Promise<Guard> {
  const ip = clientIp(req);
  const crossOrigin = opts.stateChanging && !isSameOrigin(req);
  const session = await loadSession(getDb(), req);
  let reason: string | null = null;
  if (crossOrigin) reason = "cross_origin";
  else if (!session) return { ok: false, response: error(401, "unauthorized") };
  else if (opts.stateChanging && !validCsrf(req, session)) reason = "csrf";
  else if (opts.admin && session.user.role !== "admin") reason = "role";
  if (reason !== null) {
    // Authorization failures of authenticated users are audited (L3).
    if (session) {
      await writeAudit(getDb(), {
        actorType: "user",
        actorId: session.user.id,
        action: "user.access_denied",
        outcome: "failure",
        sourceIp: ip,
        details: { route: opts.route, reason },
      });
    }
    return { ok: false, response: error(403, reason === "csrf" ? "csrf" : "forbidden") };
  }
  if (!session) return { ok: false, response: error(401, "unauthorized") };
  return { ok: true, session, ip };
}

/**
 * Failed logins, checked before argon2id:
 * - per source IP (IPv6 bucketed by /56 for logins, P1-D N1);
 * - per username, keyed by `username|ipBucket` when the client IP is known (P1-D M2), so failures
 *   from one IP never lock the account out for another. When the IP is unknown (no trusted proxy),
 *   it is keyed by username alone and reaching it never answers `429` (N2): the login degrades
 *   like the global cap below;
 * - per username across all IPs (`loginFailuresPerUserGlobal`, much higher): reaching it never
 *   refuses the login outright. It degrades to a slow-down (`loginSlowdown`) with at most one
 *   attempt in flight per username (`503` + `Retry-After` for the others).
 * A valid device cookie for the username (N1, `device-cookie.ts`) skips the global cap and the
 * degraded slot (a distributed attacker holding that slot cannot keep the real user out); it stays
 * subject to the per-(username, IP) limit, its own per-cookie failure limit and the argon2id pool.
 */
export const LOGIN_IPV6_PREFIX = 56;
export const loginFailuresPerIp = new RateLimiter(20, 15 * 60_000);
export const loginFailuresPerUser = new RateLimiter(5, 15 * 60_000);
export const loginFailuresPerUserGlobal = new RateLimiter(100, 15 * 60_000);
/** Failed logins per device cookie (nonce): beyond, the cookie gives no bypass (a stolen cookie). */
export const loginFailuresPerDevice = new RateLimiter(5, 15 * 60_000);
/** Delay before each verification of a username over its global cap (test hook: tests shorten it). */
export const loginSlowdown = { ms: 2000 };
/** Usernames over their global cap with a (slowed-down) attempt in flight. */
const degradedLoginsInFlight = new Set<string>();
/** Process-wide budget of argon2id-backed failed logins on unknown usernames (slow refill). */
export const loginFailuresUnknownUser = new RateLimiter(30, 5 * 60_000);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function onlyKeys(v: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(v).every((k) => allowed.includes(k));
}

const noop = () => undefined;

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
    const { username, password } = { username: v.username, password: v.password };
    const ip = clientIp(req);
    const ipKey = ip ? ipBucket(ip, LOGIN_IPV6_PREFIX) : null;
    const userKey = username.trim().toLowerCase();
    // M2: per username AND source IP when the IP is known (no remote lock-out of the account).
    const userIpKey = ipKey ? `${userKey}|${ipKey}` : userKey;
    const rateLimited = (...retries: number[]) =>
      error(429, "rate_limited", { "Retry-After": String(Math.max(1, ...retries)) });
    // H1: attempts are reserved synchronously before argon2id and refunded on success, so
    // concurrent requests cannot overrun the limits. H2: no per-IP limit when the IP is unknown.
    const refundIp = ipKey ? loginFailuresPerIp.reserve(ipKey) : noop;
    if (!refundIp) return rateLimited(ipKey ? loginFailuresPerIp.check(ipKey).retryAfterS : 1);
    let refundUser = loginFailuresPerUser.reserve(userIpKey);
    // N2: with an unknown IP the per-username counter is shared by everyone: never a hard 429 on
    // it, the login degrades (slow-down, single slot) instead, unless a device cookie vouches.
    const degradeUnknownIp = !refundUser && ipKey === null;
    if (!refundUser) {
      if (!degradeUnknownIp) {
        refundIp();
        return rateLimited(loginFailuresPerUser.check(userIpKey).retryAfterS);
      }
      refundUser = noop;
    }
    const baseRefunds = [refundIp, refundUser];

    // N1: a valid device cookie for this very username skips the global cap and the degraded slot.
    const device = readDeviceCookie(req);
    if (device && !loginFailuresPerDevice.check(device.nonce).limited) {
      const user = await findLoginUser(getDb(), username);
      if (user && user.id === device.userId) {
        const refundDevice = loginFailuresPerDevice.reserve(device.nonce) ?? noop;
        return verifyLogin(req, username, password, ip, [...baseRefunds, refundDevice], { user });
      }
    }

    // M2: global per-username cap. Beyond it (or N2 above): slow-down, one attempt in flight per
    // username; never a hard refusal (the correct password from a fresh IP still logs in).
    const refundGlobal = degradeUnknownIp ? null : loginFailuresPerUserGlobal.reserve(userKey);
    if (!refundGlobal) {
      if (degradedLoginsInFlight.has(userKey)) {
        baseRefunds.forEach((refund) => refund());
        const retry = Math.max(1, Math.ceil(loginSlowdown.ms / 1000) + 1);
        return error(503, "busy", { "Retry-After": String(retry) });
      }
      degradedLoginsInFlight.add(userKey);
      try {
        await new Promise((r) => setTimeout(r, loginSlowdown.ms));
        return await verifyLogin(req, username, password, ip, baseRefunds);
      } finally {
        degradedLoginsInFlight.delete(userKey);
      }
    }
    return verifyLogin(req, username, password, ip, [...baseRefunds, refundGlobal]);
  });
}

/**
 * The argon2id part of a login, after the failure limits reserved the attempt. `refunds` give the
 * reservations back on success, or when the pool is full (not a failed attempt).
 */
async function verifyLogin(
  req: Request,
  username: string,
  password: string,
  ip: string | null,
  refunds: (() => void)[],
  preloaded?: { user: LoginUser },
): Promise<Response> {
  const refundAll = () => refunds.forEach((refund) => refund());
  const db = getDb();
  const user = preloaded ? preloaded.user : await findLoginUser(db, username);
  // N1: failures on unknown usernames share one process-wide budget, so random-username
  // floods (fresh per-username buckets, unknown IP) are bounded.
  if (!user) {
    const reserved = loginFailuresUnknownUser.reserve("global");
    if (!reserved) {
      // L2: same answer as a wrong password, after a delay close to an argon2id verification,
      // without running one (no username enumeration through 429 vs 401 during a flood).
      await new Promise((r) => setTimeout(r, argon2MedianMs()));
      return error(401, "invalid_credentials");
    }
    refunds.push(reserved);
  }
  // Login has its own argon2id pool: it can never starve agent authentication (N1).
  const release = loginArgon2Gate.tryAcquire();
  if (!release) {
    refundAll();
    return error(503, "busy", { "Retry-After": "1" });
  }
  let ok: boolean;
  try {
    ok = await checkPassword(user, password);
  } finally {
    release();
  }
  const result =
    ok && user
      ? { ok: true as const, user: { id: user.id, username: user.username, role: user.role } }
      : { ok: false as const, userId: user?.id ?? null };
  if (!result.ok) {
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
  refundAll();
  // L4: drop the session this browser already had, and expired / idle sessions.
  const previous = readSessionToken(req);
  if (previous) await deleteSession(db, sha256Hex(previous));
  await purgeStaleSessions(db);
  const session = await createSession(db, result.user.id);
  await writeAudit(db, {
    actorType: "user",
    actorId: result.user.id,
    action: "user.login",
    sourceIp: ip,
  });
  const headers = new Headers(NO_STORE);
  headers.append("Set-Cookie", sessionCookie(session.token, Math.floor(SESSION_TTL_MS / 1000)));
  // N1: (re)issue the device cookie of this browser for this user (none without the server key).
  const device = issueDeviceCookie(result.user.id);
  if (device) headers.append("Set-Cookie", device);
  return Response.json({ user: result.user, csrf_token: session.csrfToken }, { status: 200, headers });
}

export function handleLogout(req: Request): Promise<Response> {
  return guardedUser("logout", async () => {
    const g = await requireUser(req, { stateChanging: true, route: "logout" });
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
    const g = await requireUser(req, { route: "session" });
    if (!g.ok) return g.response;
    return json({ user: g.session.user, csrf_token: csrfTokenFor(g.session.token) });
  });
}

const LABEL = /^[^\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]{1,64}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function handleCreateToken(req: Request): Promise<Response> {
  return guardedUser("enrollment_token.create", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "enrollment_token.create" });
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
    const g = await requireUser(req, { admin: true, route: "enrollment_token.list" });
    if (!g.ok) return g.response;
    return json({ tokens: await listEnrollmentTokens(getDb()) });
  });
}

export function handleRevokeToken(req: Request, id: string): Promise<Response> {
  return guardedUser("enrollment_token.revoke", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "enrollment_token.revoke" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const ok = await revokeEnrollmentToken(getDb(), { userId: g.session.user.id, ip: g.ip }, id);
    return ok ? new Response(null, { status: 204, headers: NO_STORE }) : error(404, "not_found");
  });
}

export function handleListAgents(req: Request): Promise<Response> {
  return guardedUser("agent.list", async () => {
    const g = await requireUser(req, { route: "agent.list" });
    if (!g.ok) return g.response;
    return json({ agents: await listAgents(getDb()) });
  });
}

export function handleRevokeAgent(req: Request, id: string): Promise<Response> {
  return guardedUser("agent.revoke", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "agent.revoke" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const ok = await revokeAgent(getDb(), id, { userId: g.session.user.id, ip: g.ip });
    return ok ? new Response(null, { status: 204, headers: NO_STORE }) : error(404, "not_found");
  });
}

export function handleRotateAgent(req: Request, id: string): Promise<Response> {
  return guardedUser("agent.rotate_request", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "agent.rotate_request" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const r = await requestSecretRotation(getDb(), id, { userId: g.session.user.id, ip: g.ip });
    if (r.outcome === "not_found") return error(404, "not_found");
    // ADR-0010: never while a secret is pending or within 60 s of a promotion.
    if (r.outcome === "busy") return error(409, "rotation_in_progress");
    return json({ job_id: r.jobId }, 202);
  });
}

const SCAN_ERRORS = {
  not_found: [404, "not_found"],
  not_ready: [409, "agent_not_ready"],
  busy: [409, "scan_in_progress"],
} as const;

/**
 * Launches a Discovery scan of one target (admin, CSRF): body = contract `DiscoveryScanParams`
 * (all optional; defaults for `sample_rows`, `max_duration_s`, `statement_timeout_ms`), unknown
 * keys, out-of-range values and empty include filters rejected. `202 {job_id}`; audited.
 */
export function handleRequestScan(req: Request, agentId: string, targetId: string): Promise<Response> {
  return guardedUser("discovery.scan_request", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "discovery.scan_request" });
    if (!g.ok) return g.response;
    if (!UUID.test(agentId) || !validateSchema("TargetId", targetId).ok) return error(404, "not_found");
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (!body.ok) return error(body.reason === "too_large" ? 413 : 400, "invalid_request");
    const params = buildScanParams(body.value);
    if (!params.ok) return error(400, "invalid_params");
    const r = await requestScan(getDb(), agentId, targetId, params.params, { userId: g.session.user.id, ip: g.ip });
    if (r.outcome !== "queued") {
      const [status, code] = SCAN_ERRORS[r.outcome];
      return error(status, code);
    }
    return json({ job_id: r.jobId }, 202);
  });
}

/**
 * Marks (`{"false_positive": true}`) or unmarks a finding as a false positive (admin, CSRF; M2: it
 * hides a finding from everyone). Audited. False positives are hidden from the view by default.
 */
export function handleFalsePositive(req: Request, findingId: string): Promise<Response> {
  return guardedUser("finding.false_positive", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "finding.false_positive" });
    if (!g.ok) return g.response;
    if (!UUID.test(findingId)) return error(404, "not_found");
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (
      !body.ok ||
      !isPlainObject(body.value) ||
      !onlyKeys(body.value, ["false_positive"]) ||
      typeof body.value.false_positive !== "boolean"
    ) {
      return error(400, "invalid_request");
    }
    const ok = await setFalsePositive(getDb(), findingId, body.value.false_positive, {
      userId: g.session.user.id,
      ip: g.ip,
    });
    return ok ? new Response(null, { status: 204, headers: NO_STORE }) : error(404, "not_found");
  });
}
