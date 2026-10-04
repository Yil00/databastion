import { getDb } from "@/db/client";
import { errorSummary, logger } from "@/lib/logger";
import { safeEqual, sha256Hex } from "@/server/crypto";
import { deleteSession, readSessionToken, sessionCookie } from "@/server/auth/session";
import { processGlobal } from "@/server/process-global";
import { RateLimiter } from "@/server/rate-limit";
import { clientIp, ipBucket } from "@/server/request";

import { mapClaims, type LoginDeniedReason } from "./claims";
import { authorizationUrl, exchangeCode, OidcFlowError, withUserinfo } from "./client";
import { CLOCK_SKEW_S } from "./id-token";
import { oidcProvider } from "./runtime";
import { auditDenied, completeOidcLogin, linkIdentity } from "./service";
import {
  clearStateCookie,
  consumeState,
  newFlowState,
  openState,
  pruneConsumedStates,
  readStateCookie,
  sealState,
  stateCookie,
  type FlowState,
} from "./state-cookie";

/**
 * OIDC routes (ADR-0038 decisions 5, 12, 15): `GET /api/auth/oidc/start`, `GET
 * /api/auth/oidc/callback`, and the start of a self-service link (`handleOidcLinkStart`, called by
 * the user API with an authenticated local session).
 *
 * Rate limits, shared by every console process and failing closed (ADR-0024; security review M1):
 * - per client IP (when known), only unfinished or failed flows count: a `/start` (or link start)
 *   is given back when its callback succeeds, and a callback reservation is refunded on success,
 *   so many users behind one NAT address are not throttled by their successful logins;
 * - globally, only failures AFTER a valid, unconsumed state cookie that come from the code
 *   exchange or the `id_token` validation are charged, and the global budget is checked only once
 *   the state cookie is valid: cookie-less or garbage callbacks cost their sender's per-IP budget
 *   only and cannot block single sign-on for everyone.
 */
export const OIDC_IPV6_PREFIX = 56;
export const oidcStartPerIp = RateLimiter.shared("oidc.start_per_ip", 60, 5 * 60_000, "closed");
export const oidcCallbackPerIp = RateLimiter.shared("oidc.callback_per_ip", 30, 5 * 60_000, "closed");
export const oidcFailedCallbacks = RateLimiter.shared("oidc.failed_callbacks", 300, 5 * 60_000, "closed");

const NO_STORE = { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } as const;
/** HTML pages of the callback: no script, nothing loaded. */
const PAGE_CSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const MAX_PARAM = 4096;

/** `rate_limited` denials are audited at most once a minute per process (no audit flood). */
const rateLimitedAudit = processGlobal("oidc.rateLimitedAudit", () => ({ last: 0 }));

function escapeHtml(v: string): string {
  return v.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Same-origin page that navigates to `path` (a constant console path, never request input). */
function navigationPage(path: string, title: string, message: string, status: number, cookies: string[] = []): Response {
  const p = escapeHtml(path);
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=${p}"><title>${escapeHtml(title)}</title></head><body><p>${escapeHtml(message)} <a href="${p}">Continue</a></p></body></html>`;
  const headers = new Headers({ ...NO_STORE, "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": PAGE_CSP, "X-Content-Type-Options": "nosniff" });
  for (const c of cookies) headers.append("Set-Cookie", c);
  return new Response(body, { status, headers });
}

/** Generic failure page: the provider's `error_description` is never echoed (decision 5). */
function failurePage(status = 400): Response {
  return navigationPage("/login?sso_error=1", "Sign-in failed", "Single sign-on failed.", status, [clearStateCookie()]);
}

function ipKey(req: Request): string | null {
  const ip = clientIp(req);
  return ip ? ipBucket(ip, OIDC_IPV6_PREFIX) : null;
}

/** Reserves one attempt of the client IP (none when unknown). `null`: over the limit. */
async function reserveIp(limiter: RateLimiter, req: Request): Promise<(() => void) | null> {
  const key = ipKey(req);
  if (key === null) return () => undefined;
  const r = await limiter.reserveShared(key);
  return r.ok ? r.refund : null;
}

async function auditRateLimited(ip: string | null): Promise<void> {
  const now = Date.now();
  if (now - rateLimitedAudit.last < 60_000) return;
  rateLimitedAudit.last = now;
  await auditDenied(getDb(), "rate_limited", { ip });
}

async function startFlow(state: FlowState): Promise<{ url: string; cookie: string } | null> {
  const p = oidcProvider();
  if (p === null) return null;
  const md = await p.getMetadata();
  return { url: authorizationUrl(md, p, state), cookie: stateCookie(sealState(state)) };
}

/** `GET /api/auth/oidc/start`: redirect to the provider with a fresh state cookie. */
export async function handleOidcStart(req: Request): Promise<Response> {
  try {
    if (oidcProvider() === null) return new Response(null, { status: 404, headers: NO_STORE });
    if ((await reserveIp(oidcStartPerIp, req)) === null) {
      await auditRateLimited(clientIp(req));
      return navigationPage("/login?sso_error=rate_limited", "Too many attempts", "Too many sign-in attempts. Try again later.", 429);
    }
    const flow = await startFlow(newFlowState("login"));
    if (flow === null) return new Response(null, { status: 404, headers: NO_STORE });
    const headers = new Headers({ ...NO_STORE, Location: flow.url });
    headers.append("Set-Cookie", flow.cookie);
    return new Response(null, { status: 302, headers });
  } catch (err) {
    logger.warn({ component: "oidc", error: errorSummary(err) }, "OIDC start failed (provider unavailable?)");
    return navigationPage("/login?sso_error=unavailable", "Single sign-on unavailable", "Single sign-on is unavailable.", 503);
  }
}

/**
 * Start of a self-service link from an authenticated LOCAL session (decision 6). The caller has
 * checked the session, the Origin and the CSRF token. Returns the provider URL for the browser.
 */
export async function handleOidcLinkStart(req: Request, session: { userId: string; tokenHash: string; method: "local" | "oidc" }): Promise<Response> {
  if (oidcProvider() === null) return Response.json({ error: "not_found" }, { status: 404, headers: NO_STORE });
  if (session.method !== "local") return Response.json({ error: "local_session_required" }, { status: 409, headers: NO_STORE });
  if ((await reserveIp(oidcStartPerIp, req)) === null) return Response.json({ error: "rate_limited" }, { status: 429, headers: { ...NO_STORE, "Retry-After": "60" } });
  try {
    const flow = await startFlow(newFlowState("link", { userId: session.userId, sessionHash: session.tokenHash }));
    if (flow === null) return Response.json({ error: "not_found" }, { status: 404, headers: NO_STORE });
    const headers = new Headers(NO_STORE);
    headers.append("Set-Cookie", flow.cookie);
    return Response.json({ redirect_url: flow.url }, { status: 200, headers });
  } catch (err) {
    logger.warn({ component: "oidc", error: errorSummary(err) }, "OIDC link start failed (provider unavailable?)");
    return Response.json({ error: "provider_unavailable" }, { status: 503, headers: NO_STORE });
  }
}

/** `GET /api/auth/oidc/callback` (`query` response mode only). */
export async function handleOidcCallback(req: Request): Promise<Response> {
  const ip = clientIp(req);
  const db = getDb();
  let purpose: "login" | "link" = "login";
  let linkUserId: string | null = null;
  /** Set once the state cookie is valid and consumed: only then do failures charge the global budget. */
  let stateConsumed = false;
  const deny = async (reason: LoginDeniedReason, userId: string | null = null): Promise<Response> => {
    await auditDenied(db, reason, { ip, userId: userId ?? linkUserId, purpose });
    return failurePage(reason === "rate_limited" ? 429 : 400);
  };
  /** A code exchange or `id_token` failure after a valid state: charged to the global budget. */
  const denyCharged = async (reason: LoginDeniedReason): Promise<Response> => {
    if (stateConsumed) await oidcFailedCallbacks.hitShared("global");
    return deny(reason);
  };
  try {
    const p = oidcProvider();
    if (p === null) return new Response(null, { status: 404, headers: NO_STORE });
    // Per IP: every callback reserves one attempt, refunded on success (failures only count).
    const refundIp = await reserveIp(oidcCallbackPerIp, req);
    if (refundIp === null) {
      await auditRateLimited(ip);
      return failurePage(429);
    }
    const q = new URL(req.url).searchParams;
    for (const [, v] of q) if (v.length > MAX_PARAM) return deny("state");
    const cookieValue = readStateCookie(req);
    const s = cookieValue === null ? null : openState(cookieValue);
    const returnedState = q.get("state");
    const stateMatches = s !== null && returnedState !== null && safeEqual(returnedState, s.state);
    if (s !== null && stateMatches) {
      purpose = s.purpose;
      linkUserId = s.linkUserId ?? null;
    }
    // An error answer from the provider: generic page, its description never echoed nor stored.
    if (q.has("error")) {
      if (s !== null && stateMatches) await consumeState(db, s);
      return deny("provider_error");
    }
    if (s === null || !stateMatches) return deny("state");
    await pruneConsumedStates(db);
    if (!(await consumeState(db, s))) return deny("state");
    stateConsumed = true;
    // The global budget of failed callbacks, checked only for a valid, unconsumed state.
    if ((await oidcFailedCallbacks.checkShared("global")).limited) {
      await auditRateLimited(ip);
      return failurePage(429);
    }
    const md = await p.getMetadata();
    // RFC 9207: `iss` checked when advertised, and whenever present.
    const iss = q.get("iss");
    if ((md.issParameterSupported && iss === null) || (iss !== null && iss !== md.issuer)) return deny("iss");
    const code = q.get("code");
    if (code === null || code === "") return deny("token");

    const { tokens, claims } = await exchangeCode(p, md, code, s);
    // L1: a link requires a fresh authentication at the provider (prompt=login, max_age=0).
    if (s.purpose === "link" && !(typeof claims.auth_time === "number" && claims.auth_time >= s.iat - CLOCK_SKEW_S)) return denyCharged("id_token");
    const merged = await withUserinfo(p, md, claims, tokens.accessToken);
    const mapping = mapClaims(merged, p.config);
    if (!mapping.ok) return deny(mapping.reason);
    const verified = {
      issuer: md.issuer,
      subject: claims.sub,
      sid: typeof claims.sid === "string" ? claims.sid : null,
      mapped: mapping.identity,
      effectiveRole: mapping.effectiveRole,
    };
    const succeeded = async () => {
      refundIp();
      const key = ipKey(req);
      if (key !== null) await oidcStartPerIp.giveBackShared(key);
    };

    if (s.purpose === "link") {
      if (!s.linkUserId || !s.linkSessionHash) return deny("state");
      const linked = await linkIdentity(db, verified, { userId: s.linkUserId, sessionHash: s.linkSessionHash }, { ip });
      if (!linked.ok) return navigationPage("/account?link_error=1", "Link failed", "The single sign-on identity could not be linked.", 400, [clearStateCookie()]);
      await succeeded();
      const who = verified.mapped.name ?? verified.mapped.email ?? verified.subject;
      return navigationPage("/account?linked=1", "Linked", `Single sign-on linked: ${who} (subject ${verified.subject} at ${verified.issuer}).`, 200, [clearStateCookie()]);
    }

    const outcome = await completeOidcLogin(db, p.config, verified, tokens.refreshToken, { ip });
    if (!outcome.ok) return deny(outcome.reason, outcome.userId);
    await succeeded();
    // L4 of the local login: drop the session this browser already had.
    const previous = readSessionToken(req);
    if (previous) await deleteSession(db, sha256Hex(previous));
    return navigationPage("/agents", "Signed in", "Signed in.", 200, [sessionCookie(outcome.session.token, outcome.session.maxAgeS), clearStateCookie()]);
  } catch (err) {
    if (err instanceof OidcFlowError) return denyCharged(err.reason);
    logger.warn({ component: "oidc", error: errorSummary(err) }, "OIDC callback failed");
    try {
      return await denyCharged("provider_error");
    } catch {
      return failurePage(500);
    }
  }
}
