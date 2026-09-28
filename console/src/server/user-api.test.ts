import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { agents, auditLog, sessions, users } from "@/db/schema";
import { argon2Stats, argon2VerifyDummy, MAX_CONCURRENT_LOGIN_ARGON2 } from "@/server/crypto";
import { bootstrapAdmin, BootstrapError } from "@/server/auth/users";
import { handleEnroll } from "@/server/agent-api/handlers";
import { hasDb, setupTestDatabase } from "@/test/db";
import { agentRequest, enroll } from "@/test/helpers";

import {
  handleCreateToken,
  handleListAgents,
  handleListTokens,
  handleLogin,
  handleLogout,
  handleRevokeAgent,
  handleRevokeToken,
  handleSession,
  loginFailuresPerIp,
  loginFailuresPerUser,
  loginFailuresUnknownUser,
} from "./user-api";

const ORIGIN = "http://console.test";
const PASSWORD = "correct horse battery staple";

function userReq(method: string, p: string, opts: { body?: unknown; cookie?: string; csrf?: string; origin?: string } = {}) {
  const headers: Record<string, string> = { "Content-Type": "application/json", Origin: opts.origin ?? ORIGIN };
  if (opts.cookie) headers.Cookie = opts.cookie;
  if (opts.csrf) headers["X-CSRF-Token"] = opts.csrf;
  return new Request(`${ORIGIN}${p}`, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
}

async function login(username = "admin", password = PASSWORD) {
  const res = await handleLogin(userReq("POST", "/api/auth/login", { body: { username, password } }));
  const setCookie = res.headers.get("set-cookie") ?? "";
  const body = res.status === 200 ? ((await res.json()) as { csrf_token: string }) : undefined;
  return { res, setCookie, cookie: setCookie.split(";")[0] ?? "", csrf: body?.csrf_token ?? "" };
}

async function auditCount(action: string, outcome = "success") {
  const rows = await getDb().select().from(auditLog).where(eq(auditLog.action, action));
  return rows.filter((r) => r.outcome === outcome).length;
}

describe.skipIf(!hasDb)("user API (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  beforeAll(async () => {
    teardown = await setupTestDatabase();
  });
  afterAll(async () => teardown?.());
  beforeEach(() => {
    loginFailuresPerIp.clear();
    loginFailuresPerUser.clear();
    loginFailuresUnknownUser.clear();
  });

  it("bootstraps the first admin once, with no default password", async () => {
    await expect(bootstrapAdmin(getDb(), "admin", "short")).rejects.toBeInstanceOf(BootstrapError);
    const id = await bootstrapAdmin(getDb(), "Admin", PASSWORD);
    const [u] = await getDb().select().from(users).where(eq(users.id, id));
    expect(u?.username).toBe("admin");
    expect(u?.role).toBe("admin");
    expect(u?.passwordHash).toMatch(/^\$argon2id\$/);
    await expect(bootstrapAdmin(getDb(), "second", PASSWORD)).rejects.toBeInstanceOf(BootstrapError);
    expect(await auditCount("user.bootstrap")).toBe(1);
  });

  it("logs in with a strict session cookie and audits success and failure", async () => {
    const bad = await login("admin", "wrong password!!");
    expect(bad.res.status).toBe(401);
    expect(await auditCount("user.login", "failure")).toBeGreaterThanOrEqual(1);
    const ok = await login();
    expect(ok.res.status).toBe(200);
    expect(ok.setCookie).toMatch(/HttpOnly/);
    expect(ok.setCookie).toMatch(/SameSite=Strict/);
    expect(ok.csrf).not.toBe("");
    expect(await auditCount("user.login")).toBeGreaterThanOrEqual(1);
    const session = await handleSession(userReq("GET", "/api/auth/session", { cookie: ok.cookie }));
    expect(session.status).toBe(200);
    // Only the SHA-256 of the session token is stored.
    const dump = await getDb().execute(sql`select string_agg(token_hash, ' ') as s from sessions`);
    expect(String(dump.rows[0]?.s)).not.toContain(ok.cookie.split("=")[1]);
  });

  it("rate limits failed logins per username", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await login("admin", "not the password")).res.status);
    expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
    expect(statuses[5]).toBe(429);
  });

  it("40 concurrent wrong logins: at most the per-user limit reaches argon2id (H1)", async () => {
    const before = argon2Stats.started;
    const results = await Promise.all(
      Array.from({ length: 40 }, () =>
        handleLogin(userReq("POST", "/api/auth/login", { body: { username: "admin", password: "wrong wrong wrong" } })),
      ),
    );
    expect(argon2Stats.started - before).toBeLessThanOrEqual(loginFailuresPerUser.limit);
    expect(results.filter((r) => r.status === 401).length).toBeLessThanOrEqual(loginFailuresPerUser.limit);
    expect(results.every((r) => [401, 429, 503].includes(r.status))).toBe(true);
  });

  it("caps concurrent argon2id verifications for logins (H1)", async () => {
    await argon2VerifyDummy("warm-up");
    argon2Stats.maxActive = 0;
    const results = await Promise.all(
      Array.from({ length: 40 }, (_, i) =>
        handleLogin(userReq("POST", "/api/auth/login", { body: { username: `nobody${i}`, password: "wrong wrong" } })),
      ),
    );
    expect(argon2Stats.maxActive).toBeLessThanOrEqual(MAX_CONCURRENT_LOGIN_ARGON2);
    expect(results.every((r) => [401, 429, 503].includes(r.status))).toBe(true);
  });

  it("bounds random-username floods with a process-wide budget (N1)", async () => {
    const before = argon2Stats.started;
    for (let i = 0; i < 40; i++) {
      await handleLogin(userReq("POST", "/api/auth/login", { body: { username: `rnd${i}`, password: "wrong wrong" } }));
    }
    expect(argon2Stats.started - before).toBeLessThanOrEqual(loginFailuresUnknownUser.limit);
    // Known usernames keep their own per-user budget.
    expect((await login()).res.status).toBe(200);
  });

  it("applies no shared per-IP bucket when the client IP is unknown (H2)", async () => {
    // 25 failures on distinct usernames exceed the per-IP limit (20) but no IP is known.
    for (let i = 0; i < 25; i++) {
      await handleLogin(userReq("POST", "/api/auth/login", { body: { username: `ghost${i}`, password: "nope nope" } }));
    }
    expect((await login()).res.status).toBe(200);
  });

  it("audits authorization failures of authenticated users (L3)", async () => {
    const s = await login();
    const before = await auditCount("user.access_denied", "failure");
    await handleCreateToken(userReq("POST", "/api/enrollment-tokens", { cookie: s.cookie, body: {} }));
    expect(await auditCount("user.access_denied", "failure")).toBe(before + 1);
  });

  it("ends the previous session of the browser on login and purges stale sessions (L4)", async () => {
    const first = await login();
    await getDb()
      .insert(sessions)
      .values({ tokenHash: "f".repeat(64), userId: (await getDb().select().from(users))[0]!.id, expiresAt: new Date(Date.now() - 1000) });
    const res = await handleLogin(
      new Request(`${ORIGIN}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: ORIGIN, Cookie: first.cookie },
        body: JSON.stringify({ username: "admin", password: PASSWORD }),
      }),
    );
    expect(res.status).toBe(200);
    expect((await handleSession(userReq("GET", "/api/auth/session", { cookie: first.cookie }))).status).toBe(401);
    const stale = await getDb().select().from(sessions).where(eq(sessions.tokenHash, "f".repeat(64)));
    expect(stale).toHaveLength(0);
  });

  it("rejects cross-origin login and state changes without CSRF token", async () => {
    const cross = await handleLogin(
      userReq("POST", "/api/auth/login", { body: { username: "admin", password: PASSWORD }, origin: "https://evil.example" }),
    );
    expect(cross.status).toBe(403);
    const s = await login();
    const noCsrf = await handleCreateToken(userReq("POST", "/api/enrollment-tokens", { cookie: s.cookie, body: {} }));
    expect(noCsrf.status).toBe(403);
    const badCsrf = await handleCreateToken(
      userReq("POST", "/api/enrollment-tokens", { cookie: s.cookie, csrf: "x".repeat(43), body: {} }),
    );
    expect(badCsrf.status).toBe(403);
    const anon = await handleListTokens(userReq("GET", "/api/enrollment-tokens"));
    expect(anon.status).toBe(401);
  });

  it("creates (shown once), lists and revokes enrollment tokens, with audit entries", async () => {
    const s = await login();
    const created = await handleCreateToken(
      userReq("POST", "/api/enrollment-tokens", { cookie: s.cookie, csrf: s.csrf, body: { label: "db host 1" } }),
    );
    expect(created.status).toBe(201);
    const { id, token, expires_at } = (await created.json()) as { id: string; token: string; expires_at: string };
    expect(token).toMatch(/^dbe_[A-Za-z0-9_-]{43}$/);
    const ttl = Date.parse(expires_at) - Date.now();
    expect(ttl).toBeGreaterThan(23.9 * 3600_000);
    expect(ttl).toBeLessThanOrEqual(24 * 3600_000);
    const list = await handleListTokens(userReq("GET", "/api/enrollment-tokens", { cookie: s.cookie }));
    const text = await list.text();
    expect(text).not.toContain(token);
    expect(text).toContain('"state":"active"');
    const revoked = await handleRevokeToken(
      userReq("DELETE", `/api/enrollment-tokens/${id}`, { cookie: s.cookie, csrf: s.csrf }),
      id,
    );
    expect(revoked.status).toBe(204);
    const enrollRes = await handleEnroll(
      agentRequest("POST", "/enroll", { body: { token, hostname: "h", agent_version: "0.1.0", connectors: [] } }),
    );
    expect(enrollRes.status).toBe(401);
    expect(await auditCount("enrollment_token.create")).toBeGreaterThanOrEqual(1);
    expect(await auditCount("enrollment_token.revoke")).toBe(1);
    const again = await handleRevokeToken(
      userReq("DELETE", `/api/enrollment-tokens/${id}`, { cookie: s.cookie, csrf: s.csrf }),
      id,
    );
    expect(again.status).toBe(404);
  });

  it("lists and revokes agents (admin, CSRF, audit)", async () => {
    const s = await login();
    const a = await enroll("agent-host");
    const list = await handleListAgents(userReq("GET", "/api/agents", { cookie: s.cookie }));
    expect(((await list.json()) as { agents: { id: string }[] }).agents.some((x) => x.id === a.agentId)).toBe(true);
    const res = await handleRevokeAgent(
      userReq("POST", `/api/agents/${a.agentId}/revoke`, { cookie: s.cookie, csrf: s.csrf }),
      a.agentId,
    );
    expect(res.status).toBe(204);
    const [row] = await getDb().select().from(agents).where(eq(agents.id, a.agentId));
    expect(row?.status).toBe("revoked");
    expect(await auditCount("agent.revoke")).toBeGreaterThanOrEqual(1);
  });

  it("logs out: session deleted, cookie cleared, audited", async () => {
    const s = await login();
    const out = await handleLogout(userReq("POST", "/api/auth/logout", { cookie: s.cookie, csrf: s.csrf }));
    expect(out.status).toBe(204);
    expect(out.headers.get("set-cookie")).toMatch(/Max-Age=0/);
    const session = await handleSession(userReq("GET", "/api/auth/session", { cookie: s.cookie }));
    expect(session.status).toBe(401);
    expect(await auditCount("user.logout")).toBe(1);
  });
});
