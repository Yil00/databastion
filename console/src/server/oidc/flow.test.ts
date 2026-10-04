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
import { MAX_PENDING_LOGINS, pendingEvictions, recordPendingLogin } from "./service";
import { handleApprovePendingLogin, handleCreateUser, handleDiscardPendingLogin, handleListPendingLogins, handleUnlinkIdentity, handleUpdateUser } from "@/server/users-api";
import { settleRevocationsForTests } from "./revoke";
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
    // Review L1: a link forces a fresh authentication at the provider.
    expect(url.searchParams.get("prompt")).toBe("login");
    expect(url.searchParams.get("max_age")).toBe("0");
    const now = Math.floor(Date.now() / 1000);
    // A reused provider session (auth_time before the link started) is refused.
    fp.codes.set("link-0", { claims: idClaims(fp, "sub-carol", s.nonce, { preferred_username: "carol.sso", groups: [], auth_time: now - 3600 }) });
    expect((await callback(s, { code: "link-0" })).status).toBe(400);
    expect(await getDb().select().from(userIdentities).where(eq(userIdentities.subject, "sub-carol"))).toHaveLength(0);
    const again = await handleOidcLink(userReq("POST", "/api/auth/oidc/link", { cookie: local.cookie, csrf: local.csrf }));
    const url2 = new URL(((await again.json()) as { redirect_url: string }).redirect_url);
    const s2: Started = { state: url2.searchParams.get("state") ?? "", nonce: url2.searchParams.get("nonce") ?? "", challenge: "", cookie: cookieOf(again, "databastion_oidc") };
    fp.codes.set("link-1", { claims: idClaims(fp, "sub-carol", s2.nonce, { preferred_username: "carol.sso", groups: [], auth_time: now }) });
    const done = await callback(s2, { code: "link-1" });
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

  it("refresh without an id_token re-checks role and filters on userinfo, bound to the session's subject (end-of-phase-8 review L2)", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_USE_REFRESH_TOKEN: "1", DATABASTION_OIDC_USE_USERINFO: "1" });
    const age = () => getDb().update(sessions).set({ refreshedAt: sql`now() - interval '6 minutes'` }).where(sql`${sessions.refreshTokenEnc} is not null`);
    const { session } = await oidcLogin("sub-olga", { preferred_username: "olga", groups: ["databastion-admins"] }, { refreshToken: "rt-olga" });
    expect((await sessionOf(session))?.user.role).toBe("admin");
    // No id_token in the refresh answer: userinfo no longer lists the admin group, so she is demoted.
    fp.refreshes.set("rt-olga", { claims: { sub: "sub-olga" }, noIdToken: true, userinfo: { sub: "sub-olga", preferred_username: "olga", groups: [] }, refreshToken: "rt-olga-2" });
    const before = fp.hits["/userinfo"] ?? 0;
    await age();
    expect((await sessionOf(session))?.user.role).toBe("analyst");
    expect(fp.hits["/userinfo"]).toBe(before + 1);
    const [change] = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.role_change"), sql`${auditLog.details}->>'to' = 'analyst'`, sql`${auditLog.details}->>'from' = 'admin'`)).orderBy(sql`${auditLog.id} desc`).limit(1);
    expect(change?.details).toMatchObject({ source: "oidc" });
    // Userinfo of another subject: the session ends, and both the stored and the just-rotated
    // refresh tokens are revoked (review of #147, I1).
    fp.refreshes.set("rt-olga-2", { claims: { sub: "sub-olga" }, noIdToken: true, userinfo: { sub: "sub-someone-else", preferred_username: "olga", groups: ["databastion-admins"] }, refreshToken: "rt-olga-rotated" });
    await age();
    expect(await sessionOf(session)).toBeNull();
    await settleRevocationsForTests();
    expect(fp.revoked).toEqual(expect.arrayContaining(["rt-olga-2", "rt-olga-rotated"]));
    const [ended] = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.logout"), sql`${auditLog.details}->>'reason' = 'refresh_subject'`));
    expect(ended).toBeDefined();
    // Filters are re-checked on userinfo too (a string groups claim is never a group).
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_USE_REFRESH_TOKEN: "1", DATABASTION_OIDC_USE_USERINFO: "1", DATABASTION_OIDC_ALLOWED_GROUPS: "databastion-admins,databastion-analysts" });
    const second = await oidcLogin("sub-olga", { preferred_username: "olga", groups: ["databastion-analysts"] }, { refreshToken: "rt-olga-3" });
    fp.refreshes.set("rt-olga-3", { claims: { sub: "sub-olga" }, noIdToken: true, userinfo: { sub: "sub-olga", groups: "databastion-analysts" } });
    await age();
    expect(await sessionOf(second.session)).toBeNull();
    expect(await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.logout"), sql`${auditLog.details}->>'reason' = 'refresh_group'`))).toHaveLength(1);
    // Without userinfo, a refresh without an id_token proves only that the token is still honored:
    // role and filters are not re-checked (documented residual risk).
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_USE_REFRESH_TOKEN: "1" });
    const third = await oidcLogin("sub-olga", { preferred_username: "olga", groups: ["databastion-analysts"] }, { refreshToken: "rt-olga-4" });
    fp.refreshes.set("rt-olga-4", { claims: { sub: "sub-olga" }, noIdToken: true, userinfo: { sub: "sub-olga", groups: ["databastion-admins"] } });
    const hits = fp.hits["/userinfo"] ?? 0;
    await age();
    expect((await sessionOf(third.session))?.user.role).toBe("analyst");
    expect(fp.hits["/userinfo"] ?? 0).toBe(hits);
  });

  it("admins approve pending logins only as NEW users; with role sync on, only with the mapped role (end-of-phase-8 review L1)", async () => {
    configure();
    process.env.DATABASTION_LOCAL_LOGIN = "enabled";
    const admin = await localLogin("root");
    const analyst = await localLogin("carol");
    await oidcLogin("sub-hank", { preferred_username: "hank", email: "hank@example.com", email_verified: true, groups: ["databastion-admins"] });
    const list = await handleListPendingLogins(userReq("GET", "/api/oidc/pending-logins", { cookie: admin.cookie }));
    const { pending } = (await list.json()) as { pending: { id: string; subject: string; issuer: string; mappedRole: string; syncedRole: string | null }[] };
    const p = pending.find((x) => x.subject === "sub-hank");
    expect(p).toMatchObject({ issuer: fp.issuer, mappedRole: "admin", syncedRole: "admin" });
    const id = p?.id ?? "";
    // Analysts cannot list nor approve.
    expect((await handleListPendingLogins(userReq("GET", "/api/oidc/pending-logins", { cookie: analyst.cookie }))).status).toBe(403);
    expect((await handleApprovePendingLogin(userReq("POST", `/api/oidc/pending-logins/${id}`, { cookie: analyst.cookie, csrf: analyst.csrf, body: { role: "admin" } }), id)).status).toBe(403);
    // Unknown fields (e.g. an attempt to bind an existing user) are refused.
    expect((await handleApprovePendingLogin(userReq("POST", `/api/oidc/pending-logins/${id}`, { cookie: admin.cookie, csrf: admin.csrf, body: { role: "analyst", user_id: "x" } }), id)).status).toBe(400);
    // Role sync on: approving hank as analyst would be overridden to admin at his first login.
    const mismatch = await handleApprovePendingLogin(userReq("POST", `/api/oidc/pending-logins/${id}`, { cookie: admin.cookie, csrf: admin.csrf, body: { role: "analyst" } }), id);
    expect(mismatch.status).toBe(409);
    expect(await mismatch.json()).toEqual({ error: "role_mismatch" });
    const [refusal] = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.pending_login_approve"), eq(auditLog.outcome, "failure")));
    expect(refusal?.details).toMatchObject({ reason: "role_mismatch", role: "analyst", mapped_role: "admin", subject: "sub-hank" });
    expect(await getDb().select().from(users).where(eq(users.username, "hank"))).toHaveLength(0);
    // Nora is mapped to analyst: an admin approval is refused, the analyst one creates her, and
    // her first login keeps that role.
    await oidcLogin("sub-nora", { preferred_username: "nora", groups: [] });
    const [nora] = await getDb().select().from(oidcPendingLogins).where(eq(oidcPendingLogins.subject, "sub-nora"));
    const approve = (pid: string, role: string) => handleApprovePendingLogin(userReq("POST", `/api/oidc/pending-logins/${pid}`, { cookie: admin.cookie, csrf: admin.csrf, body: { role } }), pid);
    expect((await approve(nora?.id ?? "", "admin")).status).toBe(409);
    expect((await approve(nora?.id ?? "", "analyst")).status).toBe(201);
    const noraSso = await oidcLogin("sub-nora", { preferred_username: "nora", groups: [] });
    expect((await sessionOf(noraSso.session))?.user.role).toBe("analyst");
    expect(await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.role_change"), eq(auditLog.targetId, (await getDb().select().from(users).where(eq(users.username, "nora")))[0]?.id ?? "")))).toHaveLength(0);
    // Role sync off (SKIP_ROLE_SYNC): the administrator chooses the role.
    configure({ DATABASTION_OIDC_SKIP_ROLE_SYNC: "1" });
    const listOff = (await (await handleListPendingLogins(userReq("GET", "/api/oidc/pending-logins", { cookie: admin.cookie }))).json()) as { pending: { subject: string; syncedRole: string | null }[] };
    expect(listOff.pending.find((x) => x.subject === "sub-hank")).toMatchObject({ syncedRole: null });
    const ok = await approve(id, "analyst");
    expect(ok.status).toBe(201);
    const [hank] = await getDb().select().from(users).where(eq(users.username, "hank"));
    expect(hank).toMatchObject({ role: "analyst", ssoOnly: true, passwordHash: null });
    const [entry] = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.pending_login_approve"), eq(auditLog.targetId, hank?.id ?? "")));
    expect(entry).toMatchObject({ outcome: "success", details: { role: "analyst", issuer: fp.issuer, subject: "sub-hank", email_verified: true } });
    // Hank logs in; role managed in the console under SKIP_ROLE_SYNC.
    const hankSso = await oidcLogin("sub-hank", { preferred_username: "hank", groups: ["databastion-admins"] });
    expect((await sessionOf(hankSso.session))?.user.role).toBe("analyst");
    // Discard.
    await oidcLogin("sub-ivy", { preferred_username: "ivy", groups: [] });
    const [ivy] = await getDb().select().from(oidcPendingLogins).where(eq(oidcPendingLogins.subject, "sub-ivy"));
    expect((await handleDiscardPendingLogin(userReq("DELETE", `/api/oidc/pending-logins/${ivy?.id}`, { cookie: admin.cookie, csrf: admin.csrf }), ivy?.id ?? "")).status).toBe(200);
    expect(await getDb().select().from(oidcPendingLogins).where(eq(oidcPendingLogins.subject, "sub-ivy"))).toHaveLength(0);
  });

  it("user management: roles, disabling (ends sessions, blocks OIDC), last-admin and role-sync guards", async () => {
    configure();
    process.env.DATABASTION_LOCAL_LOGIN = "enabled";
    const admin = await localLogin("root");
    const [root] = await getDb().select().from(users).where(eq(users.username, "root"));
    const created = await handleCreateUser(userReq("POST", "/api/users", { cookie: admin.cookie, csrf: admin.csrf, body: { username: "Judy", password: PASSWORD, role: "analyst" } }));
    expect(created.status).toBe(201);
    const { userId: judy } = (await created.json()) as { userId: string };
    expect((await handleCreateUser(userReq("POST", "/api/users", { cookie: admin.cookie, csrf: admin.csrf, body: { username: "judy", password: PASSWORD, role: "analyst" } }))).status).toBe(409);
    const patch = (id: string, body: unknown) => handleUpdateUser(userReq("PATCH", `/api/users/${id}`, { cookie: admin.cookie, csrf: admin.csrf, body }), id);
    expect((await patch(root?.id ?? "", { disabled: true })).status).toBe(409); // self
    expect((await patch(judy, { role: "admin" })).status).toBe(200);
    const judySession = await localLogin("judy");
    expect((await patch(judy, { disabled: true })).status).toBe(200);
    expect(await sessionOf(judySession.cookie)).toBeNull();
    expect((await localLogin("judy")).res.status).toBe(401);
    // A user bound to an OIDC identity keeps the provider's role while role sync is on.
    const [hank] = await getDb().select().from(users).where(eq(users.username, "hank"));
    expect((await patch(hank?.id ?? "", { role: "admin" })).status).toBe(409);
    configure({ DATABASTION_OIDC_SKIP_ROLE_SYNC: "1" });
    expect((await patch(hank?.id ?? "", { role: "admin" })).status).toBe(200);
    expect((await patch(hank?.id ?? "", { role: "analyst" })).status).toBe(200);
    const changes = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.role_change"), sql`${auditLog.details}->>'source' = 'user'`));
    expect(changes.length).toBeGreaterThanOrEqual(3);
  });

  it("caps pending logins at 1000, evicting the least recent attempt and counting evictions", async () => {
    await getDb().delete(oidcPendingLogins);
    await getDb()
      .insert(oidcPendingLogins)
      .values(Array.from({ length: MAX_PENDING_LOGINS }, (_, i) => ({ issuer: fp.issuer, subject: `bulk-${i}`, lastAttemptAt: new Date(Date.now() - (i + 1) * 1000), expiresAt: new Date(Date.now() + 86_400_000) })));
    const before = await pendingEvictions(getDb());
    const mapped = { login: "newest", email: null, emailVerified: false, name: null, groups: [], role: null };
    await getDb().transaction((tx) => recordPendingLogin(tx, { issuer: fp.issuer, subject: "newest", sid: null, mapped, effectiveRole: "analyst" }));
    const rows = await getDb().select({ subject: oidcPendingLogins.subject }).from(oidcPendingLogins);
    expect(rows).toHaveLength(MAX_PENDING_LOGINS);
    expect(rows.some((r) => r.subject === `bulk-${MAX_PENDING_LOGINS - 1}`)).toBe(false);
    expect(rows.some((r) => r.subject === "newest")).toBe(true);
    expect(await pendingEvictions(getDb())).toBe(before + 1);
    await getDb().delete(oidcPendingLogins);
  });

  it("rate limits failed or unfinished flows per client IP, never successful ones (review M1)", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" });
    process.env.DATABASTION_TRUSTED_PROXY_HOPS = "1";
    // A NAT office: many successful logins from one address are not throttled.
    const nat = { "X-Forwarded-For": "192.0.2.10" };
    for (let i = 0; i < 70; i++) {
      const s = await start(nat);
      fp.codes.set(`nat-${i}`, { claims: idClaims(fp, "sub-nat", s.nonce, { preferred_username: "nat", groups: [] }) });
      expect((await callback(s, { code: `nat-${i}` }, nat)).status).toBe(200);
    }
    // Unfinished starts count: 60 per IP.
    const ip = { "X-Forwarded-For": "203.0.113.7" };
    for (let i = 0; i < 60; i++) await start(ip);
    expect((await handleOidcStart(new Request(`${ORIGIN}/api/auth/oidc/start`, { headers: ip }))).status).toBe(429);
    expect((await handleOidcStart(new Request(`${ORIGIN}/api/auth/oidc/start`, { headers: { "X-Forwarded-For": "203.0.113.8" } }))).status).toBe(302);
    // Failed callbacks count: 30 per IP.
    const s = await start({ "X-Forwarded-For": "203.0.113.9" });
    for (let i = 0; i < 30; i++) await callback(s, { code: "nope" }, { "X-Forwarded-For": "198.51.100.1" });
    expect((await callback(s, { code: "nope" }, { "X-Forwarded-For": "198.51.100.1" })).status).toBe(429);
    expect(await denials("rate_limited")).toBeGreaterThanOrEqual(1);
  });

  it("cookie-less or garbage callbacks never exhaust the global budget (review M1)", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" });
    delete process.env.DATABASTION_TRUSTED_PROXY_HOPS; // unknown client IPs: no per-IP limit
    const junk = await start();
    for (let i = 0; i < 320; i++) {
      await handleOidcCallback(new Request(`${ORIGIN}/api/auth/oidc/callback?state=x${i}&code=c`));
      if (i % 2 === 0) await handleOidcCallback(new Request(`${ORIGIN}/api/auth/oidc/callback?error=access_denied&state=${junk.state}`));
    }
    expect((await oidcFailedCallbacks.checkShared("global")).limited).toBe(false);
    const ok = await oidcLogin("sub-after-flood", { preferred_username: "after.flood", groups: [] });
    expect(ok.res.status).toBe(200);
    // An id_token refused after a successful exchange (a provider-issued code) is charged.
    const before = await oidcFailedCallbacks.countShared("global");
    const s = await start();
    fp.codes.set("bad-nonce", { claims: idClaims(fp, "sub-x", "w".repeat(43), { preferred_username: "x" }) });
    expect((await callback(s, { code: "bad-nonce" })).status).toBe(400);
    expect(await oidcFailedCallbacks.countShared("global")).toBe(before + 1);
  });

  it("own state + garbage code, repeated from many IPs or with no trusted proxy, never locks out SSO (re-review M1-residual)", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" });
    oidcFailedCallbacks.clear();
    delete process.env.DATABASTION_TRUSTED_PROXY_HOPS;
    for (let i = 0; i < 310; i++) {
      const s = await start();
      expect((await callback(s, { code: `garbage-${i}` })).status).toBe(400);
    }
    process.env.DATABASTION_TRUSTED_PROXY_HOPS = "1";
    for (let ip = 0; ip < 40; ip++) {
      const h = { "X-Forwarded-For": `198.51.100.${ip + 10}` };
      for (let i = 0; i < 8; i++) {
        const s = await start(h);
        await callback(s, { code: `garbage-${ip}-${i}` }, h);
      }
    }
    expect(await oidcFailedCallbacks.countShared("global")).toBe(0);
    expect(await denials("token")).toBeGreaterThanOrEqual(310);
    const ok = await oidcLogin("sub-after-garbage", { preferred_username: "after.garbage", groups: [] });
    expect(ok.res.status).toBe(200);
    delete process.env.DATABASTION_TRUSTED_PROXY_HOPS;
  });

  it("role sync never demotes the last enabled admin, and alerts on a break-glass demotion (review L3)", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1" });
    const [ch] = await getDb().select().from(notificationChannels).where(eq(notificationChannels.slug, "ops"));
    if (!ch) await getDb().insert(notificationChannels).values({ slug: "ops", type: "email", systemAlerts: true, config: { host: "smtp.example.com", port: 587, tls: "starttls", from: "a@example.com", recipients: ["b@example.com"], username: null } });
    await oidcLogin("sub-kate", { preferred_username: "kate", groups: ["databastion-admins"] });
    const [kate] = await getDb().select().from(users).where(eq(users.username, "kate"));
    const others = await getDb().select({ id: users.id }).from(users).where(and(eq(users.role, "admin"), sql`${users.disabledAt} is null`, sql`${users.id} <> ${kate?.id}`));
    await getDb().update(users).set({ disabledAt: new Date() }).where(sql`${users.id} in ${others.map((o) => o.id)}`);
    try {
      const kept = await oidcLogin("sub-kate", { preferred_username: "kate", groups: [] });
      expect((await sessionOf(kept.session))?.user.role).toBe("admin");
      const [refused] = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "user.role_change"), eq(auditLog.outcome, "failure")));
      expect(refused?.details).toMatchObject({ source: "oidc", reason: "last_admin" });
      const alerts = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.event, "user.role_sync"));
      expect(alerts.some((a) => (a.payload as { kind?: string }).kind === "last_admin_kept")).toBe(true);
    } finally {
      await getDb().update(users).set({ disabledAt: null }).where(sql`${users.id} in ${others.map((o) => o.id)}`);
    }
    // Carol (local password, linked) made admin, then demoted by the provider: break-glass alert.
    await getDb().update(users).set({ role: "admin", disabledAt: null }).where(eq(users.username, "carol"));
    configure();
    await oidcLogin("sub-carol", { preferred_username: "carol.sso", groups: [] });
    const [carol] = await getDb().select().from(users).where(eq(users.username, "carol"));
    expect(carol?.role).toBe("analyst");
    const alerts = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.event, "user.role_sync"));
    expect(alerts.some((a) => (a.payload as { kind?: string }).kind === "local_admin_demoted")).toBe(true);
  });

  it("revokes refresh tokens when sessions end other than by logout, and admins can unlink identities (reviews L5, L1)", async () => {
    configure({ DATABASTION_OIDC_ALLOW_SIGN_UP: "1", DATABASTION_OIDC_USE_REFRESH_TOKEN: "1" });
    process.env.DATABASTION_LOCAL_LOGIN = "enabled";
    const admin = await localLogin("root");
    await oidcLogin("sub-leo", { preferred_username: "leo", groups: [] }, { refreshToken: "rt-leo" });
    const [leo] = await getDb().select().from(users).where(eq(users.username, "leo"));
    const patch = (id: string, body: unknown) => handleUpdateUser(userReq("PATCH", `/api/users/${id}`, { cookie: admin.cookie, csrf: admin.csrf, body }), id);
    expect((await patch(leo?.id ?? "", { disabled: true })).status).toBe(200);
    await settleRevocationsForTests();
    expect(fp.revoked).toContain("rt-leo");
    // Unlink: refused for the only identity of an SSO-only user; allowed for a linked local user.
    const [leoIdent] = await getDb().select().from(userIdentities).where(eq(userIdentities.userId, leo?.id ?? ""));
    const unlink = (userId: string, identityId: string, csrf = admin.csrf) =>
      handleUnlinkIdentity(userReq("POST", `/api/users/${userId}/identities/${identityId}/unlink`, { cookie: admin.cookie, csrf }), userId, identityId);
    expect((await unlink(leo?.id ?? "", leoIdent?.id ?? "")).status).toBe(409);
    await getDb().update(users).set({ role: "analyst" }).where(eq(users.username, "carol"));
    const carolSso = await oidcLogin("sub-carol", { preferred_username: "carol.sso", groups: [] }, { refreshToken: "rt-carol" });
    const [carol] = await getDb().select().from(users).where(eq(users.username, "carol"));
    const [carolIdent] = await getDb().select().from(userIdentities).where(eq(userIdentities.userId, carol?.id ?? ""));
    expect((await unlink(carol?.id ?? "", carolIdent?.id ?? "", "bad")).status).toBe(403);
    expect((await unlink(carol?.id ?? "", carolIdent?.id ?? "")).status).toBe(200);
    expect(await sessionOf(carolSso.session)).toBeNull();
    await settleRevocationsForTests();
    expect(fp.revoked).toContain("rt-carol");
    const [entry] = await getDb().select().from(auditLog).where(eq(auditLog.action, "user.identity_unlink"));
    expect(entry).toMatchObject({ targetId: carol?.id, details: { issuer: fp.issuer, subject: "sub-carol" } });
    // The unlinked identity is now unknown: no login into Carol's account.
    configure();
    expect((await oidcLogin("sub-carol", { preferred_username: "carol.sso", groups: [] })).res.status).toBe(400);
  });

  it("refuses to unlink a local user's last identity when the local login is unavailable to them (re-review L-b)", async () => {
    configure();
    process.env.DATABASTION_LOCAL_LOGIN = "enabled";
    const admin = await localLogin("root");
    const [mia] = await getDb().insert(users).values({ username: "mia", passwordHash: await argon2Hash(PASSWORD), role: "analyst" }).returning({ id: users.id });
    const [ident] = await getDb().insert(userIdentities).values({ userId: mia?.id ?? "", issuer: fp.issuer, subject: "sub-mia" }).returning({ id: userIdentities.id });
    const unlink = () => handleUnlinkIdentity(userReq("POST", `/api/users/${mia?.id}/identities/${ident?.id}/unlink`, { cookie: admin.cookie, csrf: admin.csrf }), mia?.id ?? "", ident?.id ?? "");
    process.env.DATABASTION_LOCAL_LOGIN = "disabled";
    let res = await unlink();
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({ error: "no_other_login_method" });
    process.env.DATABASTION_LOCAL_LOGIN = "admins"; // mia is an analyst
    expect((await unlink()).status).toBe(409);
    process.env.DATABASTION_LOCAL_LOGIN = "enabled";
    res = await unlink();
    expect(res.status).toBe(200);
  });
});
