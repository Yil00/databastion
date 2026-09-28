import { eq, sql } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import { agents, auditLog, sessions, users } from "@/db/schema";
import { argon2Hash, argon2Stats, argon2VerifyDummy, MAX_CONCURRENT_LOGIN_ARGON2 } from "@/server/crypto";
import { issueDeviceCookie } from "@/server/auth/device-cookie";
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
  handleRotateAgent,
  handleSession,
  loginFailuresPerIp,
  loginFailuresPerUser,
  loginFailuresPerDevice,
  loginFailuresPerUserGlobal,
  loginFailuresUnknownUser,
  loginSlowdown,
} from "./user-api";

const ORIGIN = "http://console.test";
const PASSWORD = "correct horse battery staple";

function userReq(
  method: string,
  p: string,
  opts: { body?: unknown; cookie?: string; csrf?: string; origin?: string; headers?: Record<string, string> } = {},
) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Origin: opts.origin ?? ORIGIN,
    ...opts.headers,
  };
  if (opts.cookie) headers.Cookie = opts.cookie;
  if (opts.csrf) headers["X-CSRF-Token"] = opts.csrf;
  return new Request(`${ORIGIN}${p}`, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
}

async function login(username = "admin", password = PASSWORD, ip?: string, cookie?: string) {
  const headers = ip ? { "X-Forwarded-For": ip } : undefined;
  const res = await handleLogin(userReq("POST", "/api/auth/login", { body: { username, password }, headers, cookie }));
  const cookies = res.headers.getSetCookie();
  const setCookie = cookies.find((c) => c.startsWith("databastion_session=")) ?? "";
  const device = (cookies.find((c) => c.startsWith("databastion_device=")) ?? "").split(";")[0] ?? "";
  const body = res.status === 200 ? ((await res.json()) as { csrf_token: string }) : undefined;
  return { res, setCookie, cookie: setCookie.split(";")[0] ?? "", device, csrf: body?.csrf_token ?? "" };
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
    loginFailuresPerUserGlobal.clear();
    loginFailuresPerDevice.clear();
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

  it("unknown IP: the per-username limit degrades to the slow-down, never a hard 429 (N2)", async () => {
    loginSlowdown.ms = 150;
    try {
      const statuses: number[] = [];
      for (let i = 0; i < 5; i++) statuses.push((await login("admin", "not the password")).res.status);
      expect(statuses).toEqual([401, 401, 401, 401, 401]);
      // Over the limit: still 401 for a wrong password, after the slow-down.
      let start = performance.now();
      expect((await login("admin", "not the password")).res.status).toBe(401);
      expect(performance.now() - start).toBeGreaterThanOrEqual(140);
      // One attempt in flight: concurrent ones get 503.
      const burst = await Promise.all([login("admin", "nope nope"), login("admin", "nope nope")]);
      expect(burst.map((r) => r.res.status).sort()).toEqual([401, 503]);
      // The right password still logs in (slowed down).
      start = performance.now();
      expect((await login()).res.status).toBe(200);
      expect(performance.now() - start).toBeGreaterThanOrEqual(140);
    } finally {
      loginSlowdown.ms = 2000;
    }
  });

  it("unknown IP: a valid device cookie skips the degraded slot (N1, N2)", async () => {
    const first = await login();
    expect(first.res.status).toBe(200);
    expect(first.device).toMatch(/^databastion_device=v1\./);
    for (let i = 0; i < 5; i++) await login("admin", "not the password");
    loginSlowdown.ms = 1000;
    try {
      const attacker = login("admin", "held slot guess");
      await new Promise((r) => setTimeout(r, 50));
      expect((await login()).res.status).toBe(503);
      const start = performance.now();
      expect((await login("admin", PASSWORD, undefined, first.device)).res.status).toBe(200);
      expect(performance.now() - start).toBeLessThan(900);
      expect((await attacker).res.status).toBe(401);
    } finally {
      loginSlowdown.ms = 2000;
    }
  });

  describe("P1-D M2: no remote lock-out of an account", () => {
    beforeEach(() => {
      process.env.DATABASTION_TRUST_PROXY = "1";
    });
    afterEach(() => {
      delete process.env.DATABASTION_TRUST_PROXY;
      loginSlowdown.ms = 2000;
    });

    it("the per-username limit is keyed by source IP when it is known", async () => {
      const statuses: number[] = [];
      for (let i = 0; i < 6; i++) statuses.push((await login("admin", "not the password", "203.0.113.5")).res.status);
      expect(statuses).toEqual([401, 401, 401, 401, 401, 429]);
      // The same IP stays limited, even with the right password; another IP logs in.
      expect((await login("admin", PASSWORD, "203.0.113.5")).res.status).toBe(429);
      expect((await login("admin", PASSWORD, "192.0.2.44")).res.status).toBe(200);
      // IPv6 clients are bucketed by /64: another address of the same /64 is the same client.
      for (let i = 0; i < 5; i++) await login("admin", "not the password", "2001:db8:1:2::1");
      expect((await login("admin", PASSWORD, "2001:db8:1:2::ffff")).res.status).toBe(429);
    });

    it("the global per-username cap slows down and serializes, never locks the right password out", async () => {
      for (let i = 0; i < loginFailuresPerUserGlobal.limit; i++) loginFailuresPerUserGlobal.hit("admin");
      loginSlowdown.ms = 150;
      // Correct password from a fresh IP: still logs in, after the slow-down.
      const start = performance.now();
      expect((await login("admin", PASSWORD, "198.51.100.200")).res.status).toBe(200);
      expect(performance.now() - start).toBeGreaterThanOrEqual(140);
      // A wrong password is still a plain 401 (no enumeration of the degraded state through 429).
      expect((await login("admin", "not the password", "198.51.100.201")).res.status).toBe(401);
      // One attempt in flight per username: concurrent ones get 503 + Retry-After.
      const results = await Promise.all(
        ["198.51.100.202", "198.51.100.203", "198.51.100.204"].map((ip) => login("admin", "nope nope nope", ip)),
      );
      const statuses = results.map((r) => r.res.status).sort();
      expect(statuses).toEqual([401, 503, 503]);
      for (const r of results.filter((x) => x.res.status === 503)) {
        expect(Number(r.res.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
      }
      // Other usernames are not affected.
      const other = performance.now();
      expect((await login("someone-else", "nope nope", "198.51.100.205")).res.status).toBe(401);
      expect(performance.now() - other).toBeLessThan(140 + 1000);
    });

    it("a valid device cookie for that username skips the global cap and a held slot (N1)", async () => {
      const admin = await login("admin", PASSWORD, "198.51.100.60");
      expect(admin.res.status).toBe(200);
      expect(admin.device).not.toBe("");
      // Another user, with its own valid device cookie.
      await getDb()
        .insert(users)
        .values({ username: "analyst-n1", role: "analyst", passwordHash: await argon2Hash(PASSWORD) })
        .onConflictDoNothing();
      const analyst = await login("analyst-n1", PASSWORD, "198.51.100.61");
      expect(analyst.res.status).toBe(200);
      const [adminRow] = await getDb().select().from(users).where(eq(users.username, "admin"));
      const tampered = admin.device.slice(0, -1) + (admin.device.endsWith("0") ? "1" : "0");
      const otherKey = (
        issueDeviceCookie(adminRow?.id ?? "", {
          ...process.env,
          DATABASTION_ENCRYPTION_KEY: "another-server-key-0123456789abcdefghijklmnop",
        }) ?? ""
      ).split(";")[0];

      for (let i = 0; i < loginFailuresPerUserGlobal.limit; i++) loginFailuresPerUserGlobal.hit("admin");
      loginSlowdown.ms = 1000;
      // A distributed attacker holds the single degraded slot.
      const attacker = login("admin", "distributed guess", "203.0.113.90");
      await new Promise((r) => setTimeout(r, 50));
      expect((await login("admin", PASSWORD, "198.51.100.62")).res.status).toBe(503);
      for (const cookie of [analyst.device, tampered, otherKey]) {
        expect((await login("admin", PASSWORD, "198.51.100.62", cookie)).res.status).toBe(503);
      }
      const start = performance.now();
      const ok = await login("admin", PASSWORD, "198.51.100.62", admin.device);
      expect(ok.res.status).toBe(200);
      expect(performance.now() - start).toBeLessThan(900);
      // A fresh device cookie is issued on every successful login.
      expect(ok.device).not.toBe("");
      expect(ok.device).not.toBe(admin.device);
      expect((await attacker).res.status).toBe(401);
    });

    it("a device cookie stays subject to the (username, IP) limit and its own failure limit (N1)", async () => {
      const admin = await login("admin", PASSWORD, "198.51.100.70");
      for (let i = 0; i < 5; i++) await login("admin", "not the password", "198.51.100.71", admin.device);
      // Same IP: 429 even with the cookie.
      expect((await login("admin", PASSWORD, "198.51.100.71", admin.device)).res.status).toBe(429);
      // The cookie saw 5 failures: no bypass any more (a stolen cookie cannot be used to guess).
      for (let i = 0; i < loginFailuresPerUserGlobal.limit; i++) loginFailuresPerUserGlobal.hit("admin");
      loginSlowdown.ms = 1000;
      const attacker = login("admin", "distributed guess", "203.0.113.91");
      await new Promise((r) => setTimeout(r, 50));
      expect((await login("admin", PASSWORD, "198.51.100.72", admin.device)).res.status).toBe(503);
      await attacker;
    });

    it("counts failures from every IP toward the global cap", async () => {
      for (let i = 0; i < 3; i++) await login("admin", "not the password", `198.51.100.${10 + i}`);
      for (let i = 0; i < loginFailuresPerUserGlobal.limit - 4; i++) loginFailuresPerUserGlobal.hit("admin");
      expect(loginFailuresPerUserGlobal.check("admin").limited).toBe(false);
      await login("admin", "not the password", "198.51.100.20");
      expect(loginFailuresPerUserGlobal.check("admin").limited).toBe(true);
      // A success refunds its own reservation only.
      loginFailuresPerUserGlobal.clear();
      expect((await login("admin", PASSWORD, "198.51.100.21")).res.status).toBe(200);
      expect(loginFailuresPerUserGlobal.check("admin").limited).toBe(false);
    });
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
    // L2: beyond the budget, unknown usernames get the same 401 (after a delay), never 429.
    const beyond = await handleLogin(
      userReq("POST", "/api/auth/login", { body: { username: "rnd-beyond", password: "wrong wrong" } }),
    );
    expect(beyond.status).toBe(401);
    expect(await beyond.json()).toEqual({ error: "invalid_credentials" });
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

  it("queues a secret rotation (admin, CSRF), refused while one is in progress", async () => {
    const s = await login();
    const a = await enroll("rotate-host");
    const path = `/api/agents/${a.agentId}/rotate`;
    const noCsrf = await handleRotateAgent(userReq("POST", path, { cookie: s.cookie }), a.agentId);
    expect(noCsrf.status).toBe(403);
    const res = await handleRotateAgent(userReq("POST", path, { cookie: s.cookie, csrf: s.csrf }), a.agentId);
    expect(res.status).toBe(202);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = (await res.json()) as { job_id: string };
    expect(body.job_id).toMatch(/^[0-9a-f-]{36}$/);
    const again = await handleRotateAgent(userReq("POST", path, { cookie: s.cookie, csrf: s.csrf }), a.agentId);
    expect(again.status).toBe(409);
    expect(await auditCount("agent.rotate_request")).toBe(1);
    expect(await auditCount("agent.rotate_request", "failure")).toBe(1);
    const unknown = await handleRotateAgent(
      userReq("POST", "/api/agents/x/rotate", { cookie: s.cookie, csrf: s.csrf }),
      "not-a-uuid",
    );
    expect(unknown.status).toBe(404);
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
