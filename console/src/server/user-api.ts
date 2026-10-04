import { getDb } from "@/db/client";
import { errorSummary, logger } from "@/lib/logger";
import { listAgents, revokeAgent } from "@/server/agents";
import { requestSecretRotation } from "@/server/rotation";
import { setFalsePositive } from "@/server/findings";
import { transitionIncident } from "@/server/incidents";
import { isIncidentStatus, transitionNeedsAdmin } from "@/lib/policy-model";
import {
  createException,
  createPolicy,
  deleteException,
  deletePolicy,
  parseExceptionInput,
  parsePolicyInput,
  policySource,
  updatePolicy,
  type PolicyInput,
} from "@/server/policies";
import { requestPolicyEvaluation } from "@/server/policy-queue";
import {
  channelType,
  createChannel,
  deleteChannel,
  listChannels,
  parseChannelCreate,
  parseChannelUpdate,
  rotateWebhookSecret,
  updateChannel,
} from "@/server/channels";
import { requestNotificationDelivery } from "@/server/notification-queue";
import { enqueueTestNotification } from "@/server/notifications";
import type { ChannelView } from "@/lib/notification-model";
import { buildScanParams, requestScan } from "@/server/scans";
import { configureAudit, parseAuditConfigInput } from "@/server/audit-config";
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
import { currentLocalLoginMode, oidcProvider } from "@/server/oidc/runtime";
import { handleOidcLinkStart } from "@/server/oidc/routes";
import { endSessionUrl, revokeRefreshToken } from "@/server/oidc/client";
import { decryptRefreshToken } from "@/server/oidc/tokens";
import { consoleUrl } from "@/server/alerting-config";
import { enqueueSystemAlert } from "@/server/notifications";
import { sessions, userIdentities } from "@/db/schema";
import { eq } from "drizzle-orm";

/**
 * User (UI) API: login / logout / session, enrollment tokens, agents. Every state-changing route
 * requires a same-origin request and, when authenticated, a valid `X-CSRF-Token`. Every user action
 * writes to the console audit log.
 */

const NO_STORE = { "Cache-Control": "no-store" } as const;
const MAX_USER_BODY = 16 * 1024;
/** Audit settings carry up to 1000 manual objects (contract `SensitiveObject`). */
const MAX_AUDIT_BODY = 1024 * 1024;

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers: { ...NO_STORE, ...headers } });
}
const error = (status: number, code: string, headers: Record<string, string> = {}) =>
  json({ error: code }, status, headers);

export async function guardedUser(route: string, fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (err) {
    logger.error({ route, error: errorSummary(err) }, "user API request failed");
    return error(500, "internal");
  }
}

type Guard = { ok: true; session: Session; ip: string | null } | { ok: false; response: Response };

export async function requireUser(
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
 * With an unknown IP, the slow-down past the per-username counter grows with the username's failed
 * degraded attempts (`loginDegradedFailures`): `loginSlowdown.ms` (2 s), doubling, capped at
 * `loginSlowdown.maxMs` (30 s). Over the global cap with a known IP it stays at 2 s.
 * A valid device cookie for the username (N1, `device-cookie.ts`) skips the global cap, the
 * degraded slot and the slow-down (a distributed attacker holding that slot cannot keep the real
 * user out); it stays subject to the per-(username, IP) limit, its own per-cookie failure limit
 * and the argon2id pool, and its failures still count toward the global per-username cap.
 */
export const LOGIN_IPV6_PREFIX = 56;
/*
 * Every login limiter is shared by all console processes (P4-D, `src/server/rate-limit.ts`) and
 * fails closed: when the shared store fails, a limit is treated as reached (`429` for the per-IP
 * and per-(username, IP) limits; the degraded path, never a refusal, where reaching the limit
 * degrades the login).
 */
export const loginFailuresPerIp = RateLimiter.shared("login.failures_per_ip", 20, 15 * 60_000, "closed");
/*
 * The username-derived keys (`username|IP`, username) are shared only with a server key (HMAC):
 * without one they stay per process, as before P4-D, rather than store an unkeyed hash of what was
 * typed in the username field, possibly a password (review M1; `startupErrors` says so).
 */
export const loginFailuresPerUser = RateLimiter.shared("login.failures_per_user_ip", 5, 15 * 60_000, "closed", { requiresServerKey: true });
export const loginFailuresPerUserGlobal = RateLimiter.shared("login.failures_per_user", 100, 15 * 60_000, "closed", { requiresServerKey: true });
/** Failed logins per device cookie (nonce): beyond, the cookie gives no bypass (a stolen cookie). */
export const loginFailuresPerDevice = RateLimiter.shared("login.failures_per_device", 5, 15 * 60_000, "closed");
/**
 * Delay before each verification of a degraded login. Unknown IP: `ms * 2^n` for the n-th failed
 * degraded attempt of the username in the window, at most `maxMs`. Test hooks: tests shorten the
 * delays and replace `sleep` (the wait itself) to observe and control it without wall-clock timing.
 */
export const loginSlowdown = {
  ms: 2000,
  maxMs: 30_000,
  sleep: (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms)),
};
/** Failed degraded logins per username with an unknown IP (drives the growing slow-down). */
export const loginDegradedFailures = RateLimiter.shared("login.degraded_failures", Number.MAX_SAFE_INTEGER, 15 * 60_000, "closed", {
  requiresServerKey: true,
});

/**
 * Slow-down before a degraded login of `userKey` (see {@link loginSlowdown}). `failures`: the
 * username's failed degraded attempts (the login passes the shared count; default: this process's).
 */
export function loginSlowdownMs(userKey: string, unknownIp: boolean, failures = loginDegradedFailures.count(userKey)): number {
  if (!unknownIp) return loginSlowdown.ms;
  return Math.min(loginSlowdown.maxMs, loginSlowdown.ms * 2 ** Math.min(failures, 30));
}
/** Usernames over their global cap with a (slowed-down) attempt in flight. */
const degradedLoginsInFlight = new Set<string>();
/** Budget of argon2id-backed failed logins on unknown usernames, shared by all processes (slow refill). */
export const loginFailuresUnknownUser = RateLimiter.shared("login.failures_unknown_user", 30, 5 * 60_000, "closed");

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function onlyKeys(v: Record<string, unknown>, allowed: string[]): boolean {
  return Object.keys(v).every((k) => allowed.includes(k));
}

const noop = () => undefined;

export function handleLogin(req: Request): Promise<Response> {
  return guardedUser("login", async () => {
    // ADR-0038 decision 11: `disabled` hides the local login entirely.
    if (currentLocalLoginMode() === "disabled") return error(404, "not_found");
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
    // H1: attempts are reserved (atomically, in the store shared by every console process) before
    // argon2id and refunded on success, so concurrent requests cannot overrun the limits. H2: no
    // per-IP limit when the IP is unknown.
    const byIp = ipKey ? await loginFailuresPerIp.reserveShared(ipKey) : null;
    if (byIp && !byIp.ok) return rateLimited(byIp.retryAfterS);
    const refundIp = byIp?.refund ?? noop;
    const byUser = await loginFailuresPerUser.reserveShared(userIpKey);
    // N2: with an unknown IP the per-username counter is shared by everyone: never a hard 429 on
    // it, the login degrades (slow-down, single slot) instead, unless a device cookie vouches.
    const degradeUnknownIp = !byUser.ok && ipKey === null;
    if (!byUser.ok && !degradeUnknownIp) {
      refundIp();
      return rateLimited(byUser.retryAfterS);
    }
    const refundUser = byUser.ok ? byUser.refund : noop;
    const baseRefunds = [refundIp, refundUser];

    // N1: a valid device cookie for this very username skips the global cap and the degraded slot.
    const device = readDeviceCookie(req);
    if (device && !(await loginFailuresPerDevice.checkShared(device.nonce)).limited) {
      const user = await findLoginUser(getDb(), username);
      if (user && user.id === device.userId) {
        const byDevice = await loginFailuresPerDevice.reserveShared(device.nonce);
        const refundDevice = byDevice.ok ? byDevice.refund : noop;
        // Bypasses the global cap, but its failures still count toward it.
        const refundGlobal = await loginFailuresPerUserGlobal.chargeShared(userKey);
        return verifyLogin(req, username, password, ip, [...baseRefunds, refundDevice, refundGlobal], { user });
      }
    }

    // M2: global per-username cap. Beyond it (or N2 above): slow-down, one attempt in flight per
    // username; never a hard refusal (the correct password from a fresh IP still logs in).
    const byUserGlobal = degradeUnknownIp ? null : await loginFailuresPerUserGlobal.reserveShared(userKey);
    const refundGlobal = byUserGlobal?.ok ? byUserGlobal.refund : null;
    if (!refundGlobal) {
      const failures = degradeUnknownIp ? await loginDegradedFailures.countShared(userKey) : 0;
      const delayMs = loginSlowdownMs(userKey, degradeUnknownIp, failures);
      if (degradedLoginsInFlight.has(userKey)) {
        baseRefunds.forEach((refund) => refund());
        const retry = Math.max(1, Math.ceil(delayMs / 1000) + 1);
        return error(503, "busy", { "Retry-After": String(retry) });
      }
      degradedLoginsInFlight.add(userKey);
      try {
        // Counted before the delay (refunded on success), so the next attempt waits longer.
        const refunds = degradeUnknownIp ? [...baseRefunds, await loginDegradedFailures.chargeShared(userKey)] : baseRefunds;
        await loginSlowdown.sleep(delayMs);
        return await verifyLogin(req, username, password, ip, refunds);
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
  // N1: failures on unknown usernames share one budget (all console processes), so random-username
  // floods (fresh per-username buckets, unknown IP) are bounded. Review L1: the reservation runs for
  // EVERY login, concurrently with the user lookup, so known and unknown usernames pay the same
  // store latency (no timing oracle); a known user gives it back (or ignores a refusal).
  const [user, reserved] = await Promise.all([
    preloaded ? Promise.resolve(preloaded.user) : findLoginUser(db, username),
    loginFailuresUnknownUser.reserveShared("global"),
  ]);
  if (user) {
    if (reserved.ok) reserved.refund();
  } else {
    if (!reserved.ok) {
      // L2: same answer as a wrong password, after a delay close to an argon2id verification,
      // without running one (no username enumeration through 429 vs 401 during a flood).
      await new Promise((r) => setTimeout(r, argon2MedianMs()));
      return error(401, "invalid_credentials");
    }
    refunds.push(reserved.refund);
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
  // ADR-0038 decision 11: with `admins`, only local administrators may log in locally. Checked after
  // the password, with the same answer as a wrong one (no role oracle); counted as a failure.
  if (currentLocalLoginMode() === "admins" && result.user.role !== "admin") {
    await writeAudit(db, {
      actorType: "user",
      actorId: result.user.id,
      action: "user.login",
      outcome: "failure",
      sourceIp: ip,
      details: { method: "local", reason: "local_login_admins_only" },
    });
    return error(401, "invalid_credentials");
  }
  refundAll();
  // L4: drop the session this browser already had, and expired / idle sessions.
  const previous = readSessionToken(req);
  if (previous) await deleteSession(db, sha256Hex(previous));
  await purgeStaleSessions(db);
  const session = await createSession(db, result.user.id);
  const breakGlass = result.user.role === "admin" && oidcProvider() !== null;
  await db.transaction(async (tx) => {
    await writeAudit(tx, {
      actorType: "user",
      actorId: result.user.id,
      action: "user.login",
      sourceIp: ip,
      ...(breakGlass ? { details: { method: "local", break_glass: true } } : {}),
    });
    // ADR-0038 decision 11: a local administrator login while OIDC is enabled is the break-glass
    // path: a system alert (budgeted like the others, ADR-0033) makes its use visible.
    if (breakGlass) {
      await enqueueSystemAlert(tx, {
        subjectKey: `user:${result.user.id}|local_login:${session.expiresAt.toISOString()}|${sha256Hex(session.token).slice(0, 16)}`,
        agentId: null,
        securityEventId: null,
        payload: {
          event: "user.local_login",
          occurred_at: new Date().toISOString(),
          url: consoleUrl("/users"),
          user_id: result.user.id,
          username: result.user.username,
          source_ip: ip,
        },
      });
    }
  });
  const headers = new Headers(NO_STORE);
  headers.append("Set-Cookie", sessionCookie(session.token, Math.floor(SESSION_TTL_MS / 1000)));
  // N1: (re)issue the device cookie of this browser for this user (none without the server key).
  const device = issueDeviceCookie(result.user.id);
  if (device) headers.append("Set-Cookie", device);
  return Response.json({ user: result.user, csrf_token: session.csrfToken }, { status: 200, headers });
}

/**
 * Logout (`POST` + CSRF). For an OIDC session (ADR-0038 decision 14): the session is deleted, the
 * refresh token held (if any) is revoked at the provider when it advertises a
 * `revocation_endpoint` (RFC 7009), then the answer carries the RP-initiated logout URL
 * (`200 {redirect_url}`) when the provider advertises an `end_session_endpoint` or
 * `DATABASTION_OIDC_SIGNOUT_REDIRECT_URL` is set. Otherwise `204`.
 */
export function handleLogout(req: Request): Promise<Response> {
  return guardedUser("logout", async () => {
    const g = await requireUser(req, { stateChanging: true, route: "logout" });
    if (!g.ok) return g.response;
    const db = getDb();
    let refreshToken: string | null = null;
    let subject: string | null = null;
    if (g.session.method === "oidc") {
      const [row] = await db
        .select({ enc: sessions.refreshTokenEnc, subject: userIdentities.subject })
        .from(sessions)
        .leftJoin(userIdentities, eq(userIdentities.id, sessions.identityId))
        .where(eq(sessions.tokenHash, g.session.tokenHash));
      subject = row?.subject ?? null;
      refreshToken = row?.enc ? decryptRefreshToken(row.enc, g.session.tokenHash) : null;
    }
    await deleteSession(db, g.session.tokenHash);
    let redirectUrl: string | null = null;
    let revoked: boolean | null = null;
    const provider = g.session.method === "oidc" ? oidcProvider() : null;
    if (provider !== null) {
      const md = await provider.getMetadata().catch(() => null);
      if (md !== null && refreshToken !== null && md.revocationEndpoint !== null) revoked = await revokeRefreshToken(provider, md, refreshToken);
      redirectUrl = endSessionUrl(provider, md, subject);
    }
    await writeAudit(db, {
      actorType: "user",
      actorId: g.session.user.id,
      action: "user.logout",
      sourceIp: g.ip,
      details: { method: g.session.method, ...(revoked === null ? {} : { refresh_revoked: revoked }) },
    });
    const headers = { ...NO_STORE, "Set-Cookie": clearSessionCookie() };
    if (redirectUrl !== null) return json({ redirect_url: redirectUrl }, 200, headers);
    return new Response(null, { status: 204, headers });
  });
}

/** `POST /api/auth/oidc/link`: self-service "Link single sign-on" from a local session (ADR-0038 decision 6). */
export function handleOidcLink(req: Request): Promise<Response> {
  return guardedUser("oidc.link", async () => {
    const g = await requireUser(req, { stateChanging: true, route: "oidc.link" });
    if (!g.ok) return g.response;
    return handleOidcLinkStart(req, { userId: g.session.user.id, tokenHash: g.session.tokenHash, method: g.session.method });
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
  classifiers_version_unregistered: [409, "classifiers_version_unregistered"],
  unknown_classifiers: [422, "unknown_classifiers"],
} as const;

/**
 * Launches a Discovery scan of one target (admin, CSRF): body = contract `DiscoveryScanParams`
 * (all optional; defaults for `sample_rows`, `max_duration_s`, `statement_timeout_ms`), unknown
 * keys, out-of-range values and empty include filters rejected. The job carries the
 * `classifiers_version` of the agent's latest heartbeat: `409 agent_not_ready` without one,
 * `409 classifiers_version_unregistered` when it is not in the contract registry,
 * `422 unknown_classifiers` when `classifiers` holds ids outside it. `202 {job_id}`; audited.
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
 * Audit settings of one target (admin, CSRF; P4-C): body = `enabled`, optional
 * `aggregation_window_s`, `poll_interval_s`, `min_rows`, `derive_from_findings` (default true),
 * `manual_objects` (contract `SensitiveObject[]`) and `confirm`. Unknown keys rejected. A change
 * that disables Audit, empties `sensitive_objects` or removes many objects answers
 * `409 confirmation_required` with the counts and the `digest` to send back as `confirm`; nothing is
 * queued until then. `202 {job_id, ...counts}` when the `audit.configure` job is queued. Audited.
 */
export function handleConfigureAudit(req: Request, agentId: string, targetId: string): Promise<Response> {
  return guardedUser("audit.configure", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "audit.configure" });
    if (!g.ok) return g.response;
    if (!UUID.test(agentId) || !validateSchema("TargetId", targetId).ok) return error(404, "not_found");
    const body = await readJsonBody(req, MAX_AUDIT_BODY);
    if (!body.ok) return error(body.reason === "too_large" ? 413 : 400, "invalid_request");
    const input = parseAuditConfigInput(body.value);
    if (!input.ok) return json({ error: "invalid_audit_settings", field: input.error }, 400);
    const r = await configureAudit(getDb(), agentId, targetId, input.value, { userId: g.session.user.id, ip: g.ip });
    const counts = (c: { previousCount: number; nextCount: number; added: number; removed: number; warning: string | null }) => ({
      warning: c.warning,
      previous_objects: c.previousCount,
      next_objects: c.nextCount,
      added_objects: c.added,
      removed_objects: c.removed,
    });
    switch (r.outcome) {
      case "queued":
        return json({ job_id: r.jobId, ...counts(r.change), truncated_objects: r.truncated }, 202);
      case "confirmation_required":
        return json({ error: "confirmation_required", ...counts(r.change), truncated_objects: r.truncated, digest: r.digest }, 409);
      case "invalid":
        return error(400, "invalid_params");
      case "not_found":
        return error(404, "not_found");
    }
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
    // Unmarked: the finding is pending for the policy engine again.
    if (ok && !body.value.false_positive) void requestPolicyEvaluation();
    return ok ? new Response(null, { status: 204, headers: NO_STORE }) : error(404, "not_found");
  });
}

// ------------------------------------------------------------------ policies (P3-A)

/**
 * Creates a policy (admin, CSRF): `{name, description?, enabled?, source?, conditions, actions}`,
 * strictly validated (`src/lib/policy-model.ts`; unknown keys, unregistered classifiers, bad
 * globs or thresholds -> `400 invalid_policy` with the failing `field`). `409 name_taken` on a
 * duplicate name (case-insensitive). `201 {id}`; audited `policy.create` (identifiers only). The
 * worker then applies it to the existing findings.
 */
export function handleCreatePolicy(req: Request): Promise<Response> {
  return guardedUser("policy.create", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "policy.create" });
    if (!g.ok) return g.response;
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (!body.ok) return error(body.reason === "too_large" ? 413 : 400, "invalid_request");
    const parsed = parsePolicyInput(body.value, false);
    if (!parsed.ok) return json({ error: "invalid_policy", field: parsed.error }, 400);
    const input: PolicyInput = {
      name: parsed.value.name as string,
      description: parsed.value.description ?? null,
      enabled: parsed.value.enabled ?? true,
      source: parsed.value.source ?? "finding",
      conditions: parsed.value.conditions ?? {},
      actions: parsed.value.actions ?? [],
    };
    const r = await createPolicy(getDb(), input, { userId: g.session.user.id, ip: g.ip });
    if (r.outcome === "name_taken") return error(409, "name_taken");
    if (r.outcome !== "ok") return error(404, "not_found");
    void requestPolicyEvaluation();
    return json({ id: r.id }, 201);
  });
}

/** Updates a policy (admin, CSRF): any subset of the create keys (`source` cannot change). `204`. */
export function handleUpdatePolicy(req: Request, id: string): Promise<Response> {
  return guardedUser("policy.update", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "policy.update" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (!body.ok) return error(body.reason === "too_large" ? 413 : 400, "invalid_request");
    const source = await policySource(getDb(), id);
    if (!source) return error(404, "not_found");
    const parsed = parsePolicyInput(body.value, true, { source });
    if (!parsed.ok) return json({ error: "invalid_policy", field: parsed.error }, 400);
    const r = await updatePolicy(getDb(), id, parsed.value, { userId: g.session.user.id, ip: g.ip });
    if (r.outcome === "name_taken") return error(409, "name_taken");
    if (r.outcome === "not_found") return error(404, "not_found");
    void requestPolicyEvaluation();
    return new Response(null, { status: 204, headers: NO_STORE });
  });
}

/** Deletes a policy and its exceptions (admin, CSRF); its incidents are kept. `204`. */
export function handleDeletePolicy(req: Request, id: string): Promise<Response> {
  return guardedUser("policy.delete", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "policy.delete" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const ok = await deletePolicy(getDb(), id, { userId: g.session.user.id, ip: g.ip });
    return ok ? new Response(null, { status: 204, headers: NO_STORE }) : error(404, "not_found");
  });
}

/**
 * Creates an exception (admin, CSRF): `{policy_id?, agent_id?, target_id?, classifier?, location?,
 * reason, expires_at?}`, at least one of agent / target / classifier / location. `400
 * invalid_exception` (+ `field`), `404 not_found` for an unknown policy or agent. `201 {id}`.
 */
export function handleCreateException(req: Request): Promise<Response> {
  return guardedUser("policy_exception.create", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "policy_exception.create" });
    if (!g.ok) return g.response;
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (!body.ok) return error(body.reason === "too_large" ? 413 : 400, "invalid_request");
    const parsed = parseExceptionInput(body.value);
    if (!parsed.ok) return json({ error: "invalid_exception", field: parsed.error }, 400);
    const r = await createException(getDb(), parsed.value, { userId: g.session.user.id, ip: g.ip });
    if (r.outcome !== "ok") return error(404, "not_found");
    return json({ id: r.id }, 201);
  });
}

/** Deletes an exception (admin, CSRF); the policies it covered are re-evaluated. `204`. */
export function handleDeleteException(req: Request, id: string): Promise<Response> {
  return guardedUser("policy_exception.delete", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "policy_exception.delete" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const ok = await deleteException(getDb(), id, { userId: g.session.user.id, ip: g.ip });
    if (ok) void requestPolicyEvaluation();
    return ok ? new Response(null, { status: 204, headers: NO_STORE }) : error(404, "not_found");
  });
}

// ----------------------------------------------------------------- incidents (P3-B)

/**
 * Moves an incident (`{"status": "acknowledged" | "resolved" | "false_positive"}`, CSRF). Any
 * signed-in user acknowledges and resolves; `false_positive` is an administrator decision (same
 * rule as on findings: it marks the linked finding). `409 invalid_transition` outside the
 * lifecycle; `204`. Audited `incident.transition`, refusals included.
 */
export function handleIncidentTransition(req: Request, id: string): Promise<Response> {
  return guardedUser("incident.transition", async () => {
    const g = await requireUser(req, { stateChanging: true, route: "incident.transition" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (!body.ok) return error(body.reason === "too_large" ? 413 : 400, "invalid_request");
    const v = body.value;
    if (!isPlainObject(v) || !onlyKeys(v, ["status"]) || !isIncidentStatus(v.status) || v.status === "open") {
      return error(400, "invalid_request");
    }
    const status = v.status;
    if (transitionNeedsAdmin(status) && g.session.user.role !== "admin") {
      // Same audit as the other authorization failures (L3).
      await writeAudit(getDb(), {
        actorType: "user",
        actorId: g.session.user.id,
        action: "user.access_denied",
        outcome: "failure",
        sourceIp: g.ip,
        details: { route: "incident.transition", reason: "role" },
      });
      return error(403, "forbidden");
    }
    const r = await transitionIncident(getDb(), id, status, { userId: g.session.user.id, ip: g.ip });
    if (r.outcome === "not_found") return error(404, "not_found");
    if (r.outcome === "invalid_transition") return json({ error: "invalid_transition", from: r.from }, 409);
    return new Response(null, { status: 204, headers: NO_STORE });
  });
}

// ------------------------------------------------------- notification channels (P3-C)

const CHANNEL_ERRORS = {
  slug_taken: [409, "slug_taken"],
  not_found: [404, "not_found"],
  key_unavailable: [409, "encryption_key_unavailable"],
} as const;

function channelError(outcome: keyof typeof CHANNEL_ERRORS | "invalid_password" | "password_required"): Response {
  if (outcome === "invalid_password") return json({ error: "invalid_channel", field: "password" }, 400);
  if (outcome === "password_required") return error(400, "password_required");
  const [status, code] = CHANNEL_ERRORS[outcome];
  return error(status, code);
}

function channelJson(c: ChannelView) {
  return {
    id: c.id,
    slug: c.slug,
    type: c.type,
    enabled: c.enabled,
    system_alerts: c.systemAlerts,
    config: c.config,
    secret_set: c.secretSet,
    created_at: c.createdAt.toISOString(),
    updated_at: c.updatedAt.toISOString(),
  };
}

/** Lists the channels (admin): settings without any secret (webhooks: URL origin only). */
export function handleListChannels(req: Request): Promise<Response> {
  return guardedUser("notification_channel.list", async () => {
    const g = await requireUser(req, { admin: true, route: "notification_channel.list" });
    if (!g.ok) return g.response;
    return json({ channels: (await listChannels(getDb())).map(channelJson) });
  });
}

/**
 * Creates a channel (admin, CSRF): `{slug, type, enabled?, system_alerts?, config, password?}`,
 * strictly validated (`400 {"error": "invalid_channel", "field"}`), `409 slug_taken`, `409
 * encryption_key_unavailable` (a secret is needed and the server key is missing). `201 {id}`; a
 * webhook also gets `signing_secret`, returned this once only. Audited without any secret.
 */
export function handleCreateChannel(req: Request): Promise<Response> {
  return guardedUser("notification_channel.create", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "notification_channel.create" });
    if (!g.ok) return g.response;
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (!body.ok) return error(body.reason === "too_large" ? 413 : 400, "invalid_request");
    const parsed = parseChannelCreate(body.value);
    if (!parsed.ok) return json({ error: "invalid_channel", field: parsed.error }, 400);
    const r = await createChannel(getDb(), parsed.value, { userId: g.session.user.id, ip: g.ip });
    if (r.outcome !== "ok") return channelError(r.outcome);
    return json(r.signingSecret ? { id: r.id, signing_secret: r.signingSecret } : { id: r.id }, 201);
  });
}

/** Updates a channel (admin, CSRF): any subset of `{enabled, system_alerts, config, password}`. `204`. */
export function handleUpdateChannel(req: Request, id: string): Promise<Response> {
  return guardedUser("notification_channel.update", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "notification_channel.update" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const body = await readJsonBody(req, MAX_USER_BODY);
    if (!body.ok) return error(body.reason === "too_large" ? 413 : 400, "invalid_request");
    const type = await channelType(getDb(), id);
    if (!type) return error(404, "not_found");
    const parsed = parseChannelUpdate(body.value, type);
    if (!parsed.ok) return json({ error: "invalid_channel", field: parsed.error }, 400);
    const r = await updateChannel(getDb(), id, parsed.value, { userId: g.session.user.id, ip: g.ip });
    if (r.outcome !== "ok") return channelError(r.outcome);
    return new Response(null, { status: 204, headers: NO_STORE });
  });
}

/** Deletes a channel (admin, CSRF); its delivery records are kept. `204`. */
export function handleDeleteChannel(req: Request, id: string): Promise<Response> {
  return guardedUser("notification_channel.delete", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "notification_channel.delete" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const ok = await deleteChannel(getDb(), id, { userId: g.session.user.id, ip: g.ip });
    return ok ? new Response(null, { status: 204, headers: NO_STORE }) : error(404, "not_found");
  });
}

/** New signing secret for a webhook channel (admin, CSRF): `200 {signing_secret}`, shown once. */
export function handleRotateChannelSecret(req: Request, id: string): Promise<Response> {
  return guardedUser("notification_channel.rotate_signing_key", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "notification_channel.rotate_signing_key" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    const r = await rotateWebhookSecret(getDb(), id, { userId: g.session.user.id, ip: g.ip });
    if (r.outcome !== "ok") return channelError(r.outcome);
    return json({ signing_secret: r.signingSecret });
  });
}

/**
 * L3: test sends are bounded per administrator and per channel (a test is an outbound connection
 * chosen by the caller: no scanning through it). Shared by every console process (P4-D, P3-D) and
 * fail closed: when the shared store fails, test sends are refused (`429`).
 */
export const channelTestsPerUser = RateLimiter.shared("channel_test.per_user", 10, 10 * 60_000, "closed");
export const channelTestsPerChannel = RateLimiter.shared("channel_test.per_channel", 3, 10 * 60_000, "closed");

/** Queues a test notification on a channel (admin, CSRF, audited): `202`; `429` over the limits. */
export function handleTestChannel(req: Request, id: string): Promise<Response> {
  return guardedUser("notification_channel.test", async () => {
    const g = await requireUser(req, { admin: true, stateChanging: true, route: "notification_channel.test" });
    if (!g.ok) return g.response;
    if (!UUID.test(id)) return error(404, "not_found");
    // Both limits are checked and counted atomically; a refused test counts toward neither.
    const [byUser, byChannel] = await Promise.all([
      channelTestsPerUser.reserveShared(g.session.user.id),
      channelTestsPerChannel.reserveShared(id),
    ]);
    if (!byUser.ok || !byChannel.ok) {
      if (byUser.ok) byUser.refund();
      if (byChannel.ok) byChannel.refund();
      await writeAudit(getDb(), {
        actorType: "user",
        actorId: g.session.user.id,
        action: "notification_channel.test",
        outcome: "failure",
        targetType: "notification_channel",
        targetId: id,
        sourceIp: g.ip,
        details: { reason: "rate_limited" },
      });
      const retry = Math.max(byUser.ok ? 1 : byUser.retryAfterS, byChannel.ok ? 1 : byChannel.retryAfterS);
      return error(429, "rate_limited", { "Retry-After": String(retry) });
    }
    const ok = await enqueueTestNotification(getDb(), id, { userId: g.session.user.id, ip: g.ip });
    if (!ok) return error(404, "not_found");
    void requestNotificationDelivery();
    return new Response(null, { status: 202, headers: NO_STORE });
  });
}
