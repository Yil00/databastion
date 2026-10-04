import { and, eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { auditLog, notificationChannels, notificationDeliveries, oidcPendingLogins, sessions, userIdentities, users } from "@/db/schema";
import { argon2Hash } from "@/server/crypto";
import { loadSession, sessionCookieName } from "@/server/auth/session";
import { hasDb, setupTestDatabase } from "@/test/db";
import { idClaims, oidcEnv, startFakeProvider, type FakeProvider } from "@/test/fake-oidc";
import { handleLogin, handleLogout, handleOidcLink, loginFailuresPerIp, loginFailuresPerUser, loginFailuresPerUserGlobal, loginFailuresUnknownUser } from "@/server/user-api";

import { loadOidcConfig, type OidcConfig } from "./config";
import { OidcProvider } from "./provider";
import { handleOidcCallback, handleOidcStart, oidcCallbackPerIp, oidcFailedCallbacks, oidcStartPerIp } from "./routes";
import { setOidcProviderForTests } from "./runtime";
import { pkceChallenge } from "./state-cookie";

const ORIGIN = "http://console.test";
const PASSWORD = "correct horse battery staple";
const ROLE_PATH = "contains(groups[*], 'databastion-admins') && 'admin' || 'analyst'";

let fp: FakeProvider;
const saved: Record<string, string | undefined> = {};

function configure(extra: Record<string, string> = {}): OidcConfig {
  const vars = { ...oidcEnv(fp), DATABASTION_OIDC_GROUPS_ATTRIBUTE_PATH: "groups", DATABASTION_OIDC_ROLE_ATTRIBUTE_PATH: ROLE_PATH, ...extra };
  for (const k of Object.keys(process.env)) if (k.startsWith("DATABASTION_OIDC_") || k === "DATABASTION_LOCAL_LOGIN") delete process.env[k];
  Object.assign(process.env, vars);
  const cfg = loadOidcConfig() as OidcConfig;
  setOidcProviderForTests(new OidcProvider(cfg));
  return cfg;
}

const cookieOf = (res: Response, name: string) => (res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`)) ?? "").split(";")[0] ?? "";

interface Started {
  state: string;
  nonce: string;
  challenge: string;
  cookie: string;
}

async function start(headers: Record<string, string> = {}): Promise<Started> {
  const res = await handleOidcStart(new Request(`${ORIGIN}/api/auth/oidc/start`, { headers }));
  expect(res.status).toBe(302);
  const loc = new URL(res.headers.get("location") ?? "");
  expect(loc.origin + loc.pathname).toBe(`${fp.issuer}/auth`);
  expect(loc.searchParams.get("response_type")).toBe("code");
  expect(loc.searchParams.get("response_mode")).toBe("query");
  expect(loc.searchParams.get("code_challenge_method")).toBe("S256");
  expect(loc.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/api/auth/oidc/callback`);
  const setCookie = res.headers.getSetCookie().find((c) => c.startsWith("databastion_oidc=")) ?? "";
  expect(setCookie).toMatch(/HttpOnly/);
  expect(setCookie).toMatch(/SameSite=Lax/);
  expect(setCookie).toMatch(/Max-Age=600/);
  return {
    state: loc.searchParams.get("state") ?? "",
    nonce: loc.searchParams.get("nonce") ?? "",
    challenge: loc.searchParams.get("code_challenge") ?? "",
    cookie: setCookie.split(";")[0] ?? "",
  };
}

async function callback(s: Started, params: Record<string, string>, headers: Record<string, string> = {}): Promise<Response> {
  const q = new URLSearchParams({ state: s.state, ...params });
  return handleOidcCallback(new Request(`${ORIGIN}/api/auth/oidc/callback?${q}`, { headers: { Cookie: s.cookie, ...headers } }));
}

let codeN = 0;
/** A full login of `sub` with `claims`; returns the callback response and the session cookie. */
async function oidcLogin(sub: string, extra: Record<string, unknown> = {}, opts: { refreshToken?: string } = {}) {
  const s = await start();
  const code = `code-${++codeN}`;
  fp.codes.set(code, { claims: idClaims(fp, sub, s.nonce, extra), refreshToken: opts.refreshToken });
  const res = await callback(s, { code });
  return { res, s, session: cookieOf(res, sessionCookieName()) };
}

async function denials(reason: string): Promise<number> {
  const rows = await getDb()
    .select({ n: sql<number>`count(*)::int` })
    .from(auditLog)
    .where(and(eq(auditLog.action, "user.login_denied"), sql`${auditLog.details}->>'reason' = ${reason}`));
  return rows[0]?.n ?? 0;
}

function userReq(method: string, p: string, opts: { body?: unknown; cookie?: string; csrf?: string } = {}) {
  const headers: Record<string, string> = { "Content-Type": "application/json", Origin: ORIGIN };
  if (opts.cookie) headers.Cookie = opts.cookie;
  if (opts.csrf) headers["X-CSRF-Token"] = opts.csrf;
  return new Request(`${ORIGIN}${p}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
}

async function localLogin(username: string) {
  const res = await handleLogin(userReq("POST", "/api/auth/login", { body: { username, password: PASSWORD } }));
  const body = res.status === 200 ? ((await res.json()) as { csrf_token: string }) : null;
  return { res, cookie: cookieOf(res, sessionCookieName()), csrf: body?.csrf_token ?? "" };
}

const sessionOf = (cookie: string) => loadSession(getDb(), new Request(`${ORIGIN}/`, { headers: { Cookie: cookie } }));

describe.skipIf(!hasDb)("OIDC login flow (PostgreSQL, fake provider)", () => {
  let teardown: () => Promise<void>;
  beforeAll(async () => {
    for (const k of Object.keys(process.env)) if (k.startsWith("DATABASTION_OIDC_") || k === "DATABASTION_LOCAL_LOGIN" || k === "DATABASTION_PUBLIC_URL" || k === "DATABASTION_TRUSTED_PROXY_HOPS") saved[k] = process.env[k];
    teardown = await setupTestDatabase();
    fp = await startFakeProvider();
    const hash = await argon2Hash(PASSWORD);
    await getDb()
      .insert(users)
      .values([
        { username: "root", passwordHash: hash, role: "admin" },
        { username: "carol", passwordHash: hash, role: "analyst" },
      ]);
  });
  afterAll(async () => {
    setOidcProviderForTests(undefined);
    for (const k of Object.keys(process.env)) if (k.startsWith("DATABASTION_OIDC_") || k === "DATABASTION_LOCAL_LOGIN") delete process.env[k];
    for (const [k, v] of Object.entries(saved)) if (v === undefined) delete process.env[k];
    else process.env[k] = v;
    await fp?.close();
    await teardown?.();
  });
  beforeEach(() => {
    for (const l of [oidcStartPerIp, oidcCallbackPerIp, oidcFailedCallbacks, loginFailuresPerIp, loginFailuresPerUser, loginFailuresPerUserGlobal, loginFailuresUnknownUser]) l.clear();
    delete process.env.DATABASTION_TRUSTED_PROXY_HOPS;
  });

  it("signs up with PKCE and client_secret_basic, lands on /agents with an oidc session", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" });
    const { res, s, session } = await oidcLogin("sub-alice", { preferred_username: "Alice", email: "alice@example.com", email_verified: true, groups: ["databastion-admins"], sid: "sid-1" });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('content="0;url=/agents"');
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    expect(session).toMatch(/^databastion_session=dbu_/);
    expect(res.headers.getSetCookie().some((c) => c.startsWith("databastion_oidc=;") && c.includes("Max-Age=0"))).toBe(true);
    const req = fp.tokenRequests.at(-1);
    expect(req?.authorization).toMatch(/^Basic /);
    expect(req?.form.get("client_secret")).toBeNull();
    expect(pkceChallenge(req?.form.get("code_verifier") ?? "")).toBe(s.challenge);
    const [u] = await getDb().select().from(users).where(eq(users.username, "alice"));
    expect(u).toMatchObject({ role: "admin", ssoOnly: true, passwordHash: null });
    const [ident] = await getDb().select().from(userIdentities).where(eq(userIdentities.userId, u?.id ?? ""));
    expect(ident).toMatchObject({ issuer: fp.issuer, subject: "sub-alice", email: "alice@example.com", emailVerified: true });
    const loaded = await sessionOf(session);
    expect(loaded).toMatchObject({ method: "oidc", user: { username: "alice", role: "admin" } });
    const [row] = await getDb().select().from(sessions).where(eq(sessions.userId, u?.id ?? ""));
    expect(row).toMatchObject({ providerSid: "sid-1", refreshTokenEnc: null });
    const logins = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.login"), eq(auditLog.actorId, u?.id ?? "")));
    expect(logins[0]?.details).toEqual({ method: "oidc" });
    expect(await getDb().select().from(auditLog).where(eq(auditLog.action, "user.signup"))).toHaveLength(1);
    // An SSO-only user has no local login.
    process.env.DATABASTION_LOCAL_LOGIN = "enabled";
    expect((await localLogin("alice")).res.status).toBe(401);
  });

  it("keeps a password for local users (users_password_hash_local)", async () => {
    await expect(getDb().insert(users).values({ username: "nopass", passwordHash: null })).rejects.toThrow();
    await expect(getDb().insert(users).values({ username: "nopass", passwordHash: null, ssoOnly: true })).resolves.toBeTruthy();
    await getDb().delete(users).where(eq(users.username, "nopass"));
  });

  it("refuses a replayed, missing or mismatched state (single use, server side)", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" });
    const s = await start();
    fp.codes.set("replay-code", { claims: idClaims(fp, "sub-alice", s.nonce, { preferred_username: "alice", groups: [] }) });
    expect((await callback(s, { code: "replay-code" })).status).toBe(200);
    const before = await denials("state");
    fp.codes.set("replay-code", { claims: idClaims(fp, "sub-alice", s.nonce, { preferred_username: "alice", groups: [] }) });
    const replay = await callback(s, { code: "replay-code" });
    expect(replay.status).toBe(400);
    expect(cookieOf(replay, sessionCookieName())).toBe("");
    const other = await start();
    expect((await callback({ ...other, state: s.state }, { code: "x" })).status).toBe(400);
    expect((await callback({ ...other, cookie: "" }, { code: "x" })).status).toBe(400);
    expect((await callback({ ...other, cookie: `${other.cookie.slice(0, -4)}AAAA` }, { code: "x" })).status).toBe(400);
    expect(await denials("state")).toBe(before + 4);
  });

  it("shows a generic page for provider errors, never the error_description", async () => {
    configure();
    const s = await start();
    const res = await callback(s, { error: "access_denied", error_description: "<script>evil</script> user is locked" });
    const html = await res.text();
    expect(html).not.toContain("evil");
    expect(html).not.toContain("locked");
    expect(html).toContain("/login?sso_error=1");
    expect(await denials("provider_error")).toBeGreaterThanOrEqual(1);
  });

  it("refuses a wrong nonce, a missing id_token and a wrong RFC 9207 iss", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" });
    let s = await start();
    fp.codes.set("c-nonce", { claims: idClaims(fp, "sub-x", "w".repeat(43), { preferred_username: "x" }) });
    expect((await callback(s, { code: "c-nonce" })).status).toBe(400);
    expect(await denials("nonce")).toBe(1);
    s = await start();
    fp.codes.set("c-noid", { claims: {}, noIdToken: true });
    expect((await callback(s, { code: "c-noid" })).status).toBe(400);
    expect(await denials("id_token")).toBe(1);
    s = await start();
    expect((await callback(s, { code: "c", iss: "https://evil.example.com" })).status).toBe(400);
    expect(await denials("iss")).toBe(1);
  });

  it("records a pending login when sign-up is off, and never merges into an existing username", async () => {
    configure();
    const first = await oidcLogin("sub-dave", { preferred_username: "dave", email: "dave@example.com", email_verified: false, groups: ["staff"] });
    expect(first.res.status).toBe(400);
    expect(first.session).toBe("");
    await oidcLogin("sub-dave", { preferred_username: "dave", groups: ["staff"] });
    const [p] = await getDb().select().from(oidcPendingLogins).where(eq(oidcPendingLogins.subject, "sub-dave"));
    expect(p).toMatchObject({ issuer: fp.issuer, login: "dave", attempts: 2, mappedRole: "analyst", emailVerified: false });
    expect(await denials("sign_up")).toBe(2);
    // With sign-up on, the login claim of an existing local user is refused, not merged.
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" });
    const clash = await oidcLogin("sub-fake-root", { preferred_username: "root", groups: ["databastion-admins"] });
    expect(clash.res.status).toBe(400);
    expect(await denials("username")).toBe(1);
    expect(await getDb().select().from(userIdentities).where(eq(userIdentities.subject, "sub-fake-root"))).toHaveLength(0);
  });

  it("applies the group filter and the strict role mode", async () => {
    configure({ DATABASTION_OIDC_ALLOWED_GROUPS: "databastion-users,databastion-admins" });
    expect((await oidcLogin("sub-g", { preferred_username: "g", groups: ["other"] })).res.status).toBe(400);
    expect(await denials("group")).toBe(1);
    configure({ DATABASTION_OIDC_ROLE_ATTRIBUTE_PATH: "role" });
    expect((await oidcLogin("sub-r", { preferred_username: "r", role: "Admin" })).res.status).toBe(400);
    expect(await denials("role")).toBe(1);
  });

  it("syncs the role at each login; a demotion ends the user's other sessions; a disabled user is refused", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" });
    const a = await oidcLogin("sub-erin", { preferred_username: "erin", groups: ["databastion-admins"] });
    expect((await sessionOf(a.session))?.user.role).toBe("admin");
    const b = await oidcLogin("sub-erin", { preferred_username: "erin", groups: [] });
    expect(await sessionOf(a.session)).toBeNull();
    expect((await sessionOf(b.session))?.user.role).toBe("analyst");
    const changes = await getDb().select().from(auditLog).where(eq(auditLog.action, "user.role_change"));
    expect(changes.at(-1)?.details).toEqual({ source: "oidc", from: "admin", to: "analyst" });
    // SKIP_ROLE_SYNC keeps the console role.
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_SKIP_ROLE_SYNC: "1" });
    const c = await oidcLogin("sub-erin", { preferred_username: "erin", groups: ["databastion-admins"] });
    expect((await sessionOf(c.session))?.user.role).toBe("analyst");
    await getDb().update(users).set({ disabledAt: new Date() }).where(eq(users.username, "erin"));
    expect((await oidcLogin("sub-erin", { preferred_username: "erin", groups: [] })).res.status).toBe(400);
    expect(await denials("disabled")).toBe(1);
  });

  it("links an identity only from the user's own local session (self-service)", async () => {
    configure();
    process.env.DATABASTION_LOCAL_LOGIN = "enabled";
    const local = await localLogin("carol");
    expect(local.res.status).toBe(200);
    const res = await handleOidcLink(userReq("POST", "/api/auth/oidc/link", { cookie: local.cookie, csrf: local.csrf }));
    expect(res.status).toBe(200);
    const url = new URL(((await res.json()) as { redirect_url: string }).redirect_url);
    const s: Started = { state: url.searchParams.get("state") ?? "", nonce: url.searchParams.get("nonce") ?? "", challenge: "", cookie: cookieOf(res, "databastion_oidc") };
    fp.codes.set("link-1", { claims: idClaims(fp, "sub-carol", s.nonce, { preferred_username: "carol.sso", groups: [] }) });
    const done = await callback(s, { code: "link-1" });
    expect(await done.text()).toContain("/account?linked=1");
    const [carol] = await getDb().select().from(users).where(eq(users.username, "carol"));
    const [ident] = await getDb().select().from(userIdentities).where(eq(userIdentities.subject, "sub-carol"));
    expect(ident?.userId).toBe(carol?.id);
    const [entry] = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.identity_link"), eq(auditLog.outcome, "success")));
    expect(entry?.details).toMatchObject({ session_method: "local", issuer: fp.issuer, subject: "sub-carol" });
    // Carol now logs in through OIDC (role managed in the console: no role expression).
    configure({ DATABASTION_OIDC_ROLE_ATTRIBUTE_PATH: "" });
    const sso = await oidcLogin("sub-carol", { preferred_username: "carol.sso" });
    expect((await sessionOf(sso.session))?.user).toMatchObject({ username: "carol", role: "analyst" });
    // No link from an OIDC session, and no CSRF-less link.
    expect((await handleOidcLink(userReq("POST", "/api/auth/oidc/link", { cookie: sso.session, csrf: "x" }))).status).toBe(403);
    expect((await handleOidcLink(userReq("POST", "/api/auth/oidc/link", { cookie: local.cookie }))).status).toBe(403);
  });

  it("local login modes: admins only with OIDC on (break-glass alert), disabled answers 404", async () => {
    configure();
    await getDb().insert(notificationChannels).values({ slug: "ops", type: "email", systemAlerts: true, config: { host: "smtp.example.com", port: 587, tls: "starttls", from: "a@example.com", recipients: ["b@example.com"], username: null } });
    delete process.env.DATABASTION_LOCAL_LOGIN; // default with OIDC on: admins
    expect((await localLogin("carol")).res.status).toBe(401);
    const admin = await localLogin("root");
    expect(admin.res.status).toBe(200);
    const alerts = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.event, "user.local_login"));
    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.payload).toMatchObject({ event: "user.local_login", username: "root" });
    process.env.DATABASTION_LOCAL_LOGIN = "disabled";
    expect((await localLogin("root")).res.status).toBe(404);
    process.env.DATABASTION_LOCAL_LOGIN = "enabled";
    expect((await localLogin("carol")).res.status).toBe(200);
  });

  it("logout revokes the refresh token and answers the RP-initiated logout URL", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_USE_REFRESH_TOKEN: "1" });
    const { session } = await oidcLogin("sub-frank", { preferred_username: "frank", groups: [] }, { refreshToken: "rt-frank-1" });
    const [row] = await getDb().select().from(sessions).where(sql`${sessions.providerSid} is null and ${sessions.refreshTokenEnc} is not null`);
    expect(row?.refreshTokenEnc?.includes(Buffer.from("rt-frank-1"))).toBe(false);
    const loaded = await sessionOf(session);
    const csrf = (await import("@/server/auth/session")).csrfTokenFor(session.split("=")[1] ?? "");
    const res = await handleLogout(userReq("POST", "/api/auth/logout", { cookie: session, csrf }));
    expect(loaded?.method).toBe("oidc");
    expect(res.status).toBe(200);
    const url = new URL(((await res.json()) as { redirect_url: string }).redirect_url);
    expect(url.pathname).toBe("/realms/test/logout");
    expect(url.searchParams.get("client_id")).toBe(fp.clientId);
    expect(url.searchParams.get("logout_hint")).toBe("sub-frank");
    expect(url.searchParams.get("post_logout_redirect_uri")).toBe(`${ORIGIN}/login`);
    expect(fp.revoked).toContain("rt-frank-1");
    expect(await sessionOf(session)).toBeNull();
  });

  it("refreshes on activity at most every 5 minutes; a failed refresh ends the session", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_USE_REFRESH_TOKEN: "1" });
    const { session } = await oidcLogin("sub-gina", { preferred_username: "gina", groups: ["databastion-admins"] }, { refreshToken: "rt-gina" });
    const age = () => getDb().update(sessions).set({ refreshedAt: sql`now() - interval '6 minutes'` }).where(sql`${sessions.refreshTokenEnc} is not null`);
    // The refresh demotes (new id_token without the admin group).
    fp.refreshes.set("rt-gina", { claims: { iss: fp.issuer, aud: fp.clientId, sub: "sub-gina", iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300, preferred_username: "gina", groups: [] }, refreshToken: "rt-gina-2" });
    await age();
    expect((await sessionOf(session))?.user.role).toBe("analyst");
    // Within 5 minutes: no new refresh.
    const before = fp.tokenRequests.length;
    await sessionOf(session);
    expect(fp.tokenRequests.length).toBe(before);
    // The provider refuses the rotated token: the session ends.
    fp.refreshes.clear();
    await age();
    expect(await sessionOf(session)).toBeNull();
    expect(await sessionOf(session)).toBeNull();
  });

  it("rate limits /start and the callback per client IP", async () => {
    configure();
    process.env.DATABASTION_TRUSTED_PROXY_HOPS = "1";
    const ip = { "X-Forwarded-For": "203.0.113.7" };
    for (let i = 0; i < 30; i++) await start(ip);
    const res = await handleOidcStart(new Request(`${ORIGIN}/api/auth/oidc/start`, { headers: ip }));
    expect(res.status).toBe(429);
    const other = await handleOidcStart(new Request(`${ORIGIN}/api/auth/oidc/start`, { headers: { "X-Forwarded-For": "203.0.113.8" } }));
    expect(other.status).toBe(302);
    oidcCallbackPerIp.clear();
    const s = await start({ "X-Forwarded-For": "203.0.113.9" });
    for (let i = 0; i < 30; i++) await callback(s, { code: "nope" }, { "X-Forwarded-For": "198.51.100.1" });
    expect((await callback(s, { code: "nope" }, { "X-Forwarded-For": "198.51.100.1" })).status).toBe(429);
    expect(await denials("rate_limited")).toBeGreaterThanOrEqual(1);
  });
});
