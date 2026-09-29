import { sql } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { getDb } from "@/db/client";
import { rateLimitCounters } from "@/db/schema";
import { logger } from "@/lib/logger";
import { hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll } from "@/test/helpers";

import { argon2Stats } from "./crypto";
import {
  FAIL_CLOSED_RETRY_AFTER_S,
  PgRateLimitStore,
  pruneRateLimitCounters,
  RateLimiter,
  rateLimitKeyHash,
  rateLimitStoreStats,
  type RateLimitStore,
} from "./rate-limit";

const down = () => Promise.reject(new Error("store down"));
const failingStore: RateLimitStore = { hit: down, reserve: down, check: down, refund: down, reset: down };
const hangingStore: RateLimitStore = {
  hit: () => new Promise(() => undefined),
  reserve: () => new Promise(() => undefined),
  check: () => new Promise(() => undefined),
  refund: () => new Promise(() => undefined),
  reset: () => new Promise(() => undefined),
};

let seq = 0;
/** A fresh limiter name per test (the store is shared by the whole file). */
const fresh = (prefix = "test") => `${prefix}.l${++seq}`;

describe("RateLimiter.shared: construction and store failures (no database)", () => {
  it("validates the limiter name and window", () => {
    expect(() => RateLimiter.shared("Bad Name", 1, 60_000, "closed")).toThrow(/name/);
    expect(() => RateLimiter.shared("ok.name", 1, 10, "closed")).toThrow(/window/);
    expect(RateLimiter.shared("ok.name", 1, 60_000, "local").name).toBe("ok.name");
    expect(new RateLimiter(1, 1000).name).toBeNull();
  });

  it("fail closed: reservations and checks are refused with Retry-After 5, hits are limited", async () => {
    const rl = RateLimiter.shared(fresh(), 10, 60_000, "closed", { store: failingStore });
    expect(await rl.reserveShared("k")).toEqual({ ok: false, retryAfterS: FAIL_CLOSED_RETRY_AFTER_S });
    expect(await rl.checkShared("k")).toEqual({ limited: true, retryAfterS: FAIL_CLOSED_RETRY_AFTER_S });
    expect((await rl.hitShared("k")).limited).toBe(true);
    // `charge` never refuses: it counts in this process; `count` reads this process.
    const refund = await rl.chargeShared("k");
    expect(await rl.countShared("k")).toBe(2);
    refund();
    expect(await rl.countShared("k")).toBe(1);
  });

  it("fail local: this process's counters decide (the pre-P4-D per-process limit)", async () => {
    const rl = RateLimiter.shared(fresh(), 2, 60_000, "local", { store: failingStore });
    const a = await rl.reserveShared("k");
    const b = await rl.reserveShared("k");
    expect(a.ok && b.ok).toBe(true);
    const c = await rl.reserveShared("k");
    expect(c.ok).toBe(false);
    if (!c.ok) expect(c.retryAfterS).toBeGreaterThan(0);
    if (a.ok) a.refund();
    expect((await rl.reserveShared("k")).ok).toBe(true);
    expect((await rl.checkShared("k")).limited).toBe(true);
    expect((await rl.hitShared("other")).limited).toBe(false);
  });

  it("a store that does not answer in time is a failure", async () => {
    const rl = RateLimiter.shared(fresh(), 10, 60_000, "closed", { store: hangingStore, timeoutMs: 20 });
    expect(await rl.reserveShared("k")).toEqual({ ok: false, retryAfterS: FAIL_CLOSED_RETRY_AFTER_S });
  });

  it("logs a rate-limited warning without the key, and counts every failure", async () => {
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
    const rl = RateLimiter.shared(fresh(), 10, 60_000, "closed", { store: failingStore });
    const before = rateLimitStoreStats.errors;
    for (let i = 0; i < 5; i++) await rl.reserveShared("admin|198.51.100.7");
    expect(rateLimitStoreStats.errors - before).toBe(5);
    expect(warn).toHaveBeenCalledTimes(1);
    const [fields, message] = warn.mock.calls[0] as [Record<string, unknown>, string];
    expect(fields).toMatchObject({ limiter: rl.name, onStoreError: "closed" });
    expect(message).toMatch(/fail closed/);
    expect(JSON.stringify(warn.mock.calls)).not.toContain("198.51.100.7");
  });

  it("the per-process pre-check rejects before any store round-trip", async () => {
    const store = { ...failingStore, reserve: vi.fn(down), check: vi.fn(down) };
    const rl = RateLimiter.shared(fresh(), 2, 60_000, "closed", { store });
    rl.hit("k");
    rl.hit("k");
    expect((await rl.reserveShared("k")).ok).toBe(false);
    expect((await rl.checkShared("k")).limited).toBe(true);
    expect(store.reserve).not.toHaveBeenCalled();
    expect(store.check).not.toHaveBeenCalled();
  });

  it("a process-local limiter keeps its in-memory behavior through the async methods", async () => {
    const rl = new RateLimiter(1, 60_000);
    const a = await rl.reserveShared("k");
    expect(a.ok).toBe(true);
    expect((await rl.reserveShared("k")).ok).toBe(false);
    if (a.ok) a.refund();
    expect(await rl.countShared("k")).toBe(0);
  });
});

describe.skipIf(!hasDb)("RateLimiter.shared (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  beforeAll(async () => {
    teardown = await setupTestDatabase();
  });
  afterAll(async () => teardown?.());
  afterEach(() => {
    delete process.env.DATABASTION_TRUST_PROXY;
  });

  const rows = (limiter: string) =>
    getDb().select().from(rateLimitCounters).where(sql`${rateLimitCounters.limiter} = ${limiter}`);
  /** Moves every window of `limiter` into the past (as if its window had elapsed). */
  const expire = (limiter: string) =>
    getDb().execute(sql`update rate_limit_counters
      set window_start = window_start - interval '1 day', expires_at = now() - interval '1 second'
      where limiter = ${limiter}`);

  describe("two processes (two limiter instances sharing the database)", () => {
    it("their combined reservations are limited as one", async () => {
      const name = fresh();
      const [a, b] = [RateLimiter.shared(name, 5, 60_000, "closed"), RateLimiter.shared(name, 5, 60_000, "closed")];
      const results: boolean[] = [];
      for (let i = 0; i < 10; i++) results.push((await (i % 2 ? b : a).reserveShared("k")).ok);
      expect(results.filter(Boolean)).toHaveLength(5);
      expect(results.slice(5)).toEqual([false, false, false, false, false]);
      // Neither process alone reached the limit: only the shared store refused.
      expect(a.count("k")).toBeLessThan(5);
      expect(b.count("k")).toBeLessThan(5);
      const refused = await a.reserveShared("k");
      expect(refused.ok).toBe(false);
      if (!refused.ok) {
        expect(refused.retryAfterS).toBeGreaterThanOrEqual(1);
        expect(refused.retryAfterS).toBeLessThanOrEqual(60);
      }
    });

    it("concurrent reservations from both cannot overrun the limit", async () => {
      const name = fresh();
      const [a, b] = [RateLimiter.shared(name, 7, 60_000, "closed"), RateLimiter.shared(name, 7, 60_000, "closed")];
      const all = await Promise.all(Array.from({ length: 40 }, (_, i) => (i % 2 ? b : a).reserveShared("k")));
      expect(all.filter((r) => r.ok)).toHaveLength(7);
      expect((await rows(name))[0]?.count).toBe(7);
    });

    it("hits, checks and counts see each other's hits", async () => {
      const name = fresh();
      const [a, b] = [RateLimiter.shared(name, 5, 60_000, "local"), RateLimiter.shared(name, 5, 60_000, "local")];
      for (let i = 0; i < 3; i++) expect((await a.hitShared("k")).limited).toBe(false);
      expect((await b.hitShared("k")).limited).toBe(false);
      expect(await b.countShared("k")).toBe(4);
      expect((await b.checkShared("k")).limited).toBe(false);
      const fifth = await b.hitShared("k");
      expect(fifth.limited).toBe(true);
      expect(fifth.retryAfterS).toBeLessThanOrEqual(60);
      expect((await a.checkShared("k")).limited).toBe(true);
      expect(await RateLimiter.checkAll([[a, "k"], [b, "other"]])).toMatchObject([{ limited: true }, { limited: false }]);
    });

    it("the exported limiters of two module copies are shared (P4-D)", async () => {
      vi.resetModules();
      const first = await import("./agent-api/handlers");
      vi.resetModules();
      const second = await import("./agent-api/handlers");
      expect(first.eventsPerAgent).not.toBe(second.eventsPerAgent);
      const agent = "0192f0a0-0000-7000-8000-00000000abcd";
      const refunds: (() => void)[] = [];
      for (let i = 0; i < first.eventsPerAgent.limit; i++) {
        const r = await (i % 2 ? second : first).eventsPerAgent.reserveShared(agent);
        expect(r.ok).toBe(true);
        if (r.ok) refunds.push(r.refund);
      }
      expect((await second.eventsPerAgent.reserveShared(agent)).ok).toBe(false);
      // A duplicate batch in one process gives its slot back to both.
      refunds[0]?.();
      expect((await second.eventsPerAgent.reserveShared(agent)).ok).toBe(true);
    });

    it("every exported limiter has a unique store name", async () => {
      const modules = await Promise.all([
        import("./agent-api/auth"),
        import("./agent-api/handlers"),
        import("./rotation"),
        import("./integrity"),
        import("./agents"),
        import("./user-api"),
      ]);
      // Duck-typed: modules reloaded by `vi.resetModules` have their own copy of the class.
      const isLimiter = (v: unknown): v is RateLimiter => typeof v === "object" && v !== null && "reserveShared" in v;
      const limiters = modules.flatMap((m) => Object.values(m).filter(isLimiter));
      expect(limiters).toHaveLength(20);
      const names = limiters.map((l) => l.name);
      expect(names.every((n) => n !== null)).toBe(true);
      expect(new Set(names).size).toBe(names.length);
      const closed = limiters.filter((l) => l.onStoreError === "closed").map((l) => l.name).sort();
      expect(closed).toEqual([
        "agent_auth.cheap_failures_per_ip",
        "agent_auth.failures_per_agent_ip",
        "agent_auth.failures_per_ip",
        "channel_test.per_channel",
        "channel_test.per_user",
        "enroll.per_ip",
        "login.degraded_failures",
        "login.failures_per_device",
        "login.failures_per_ip",
        "login.failures_per_user",
        "login.failures_per_user_ip",
        "login.failures_unknown_user",
        "rotate.per_agent",
      ]);
    });
  });

  describe("refunds", () => {
    it("give the slot back to every process, once", async () => {
      const name = fresh();
      const [a, b] = [RateLimiter.shared(name, 2, 60_000, "closed"), RateLimiter.shared(name, 2, 60_000, "closed")];
      const r1 = await a.reserveShared("k");
      expect((await a.reserveShared("k")).ok).toBe(true);
      expect((await b.reserveShared("k")).ok).toBe(false);
      expect(r1.ok).toBe(true);
      if (!r1.ok) return;
      r1.refund();
      r1.refund(); // idempotent
      // `a` waits for its own pending refund; `b` sees it once written.
      expect(await a.countShared("k")).toBe(1);
      expect((await b.reserveShared("k")).ok).toBe(true);
      expect((await b.reserveShared("k")).ok).toBe(false);
      expect((await rows(name))[0]?.count).toBe(2);
    });

    it("a refund is never overtaken by the next operation of the same process", async () => {
      const name = fresh();
      const rl = RateLimiter.shared(name, 1, 60_000, "closed");
      for (let i = 0; i < 5; i++) {
        const r = await rl.reserveShared("k");
        expect(r.ok).toBe(true);
        if (r.ok) r.refund();
      }
    });

    it("a charge's refund works like a reservation's", async () => {
      const name = fresh();
      const rl = RateLimiter.shared(name, 1, 60_000, "closed");
      const refund = await rl.chargeShared("k");
      await rl.chargeShared("k");
      expect(await rl.countShared("k")).toBe(2);
      refund();
      expect(await rl.countShared("k")).toBe(1);
    });

    it("a refund from an elapsed window does not touch the new window", async () => {
      const name = fresh();
      const rl = RateLimiter.shared(name, 3, 60_000, "closed");
      const old = await rl.reserveShared("k");
      await expire(name);
      const other = RateLimiter.shared(name, 3, 60_000, "closed");
      expect((await other.reserveShared("k")).ok).toBe(true);
      expect((await rows(name))[0]?.count).toBe(1);
      if (old.ok) old.refund();
      // `rl` waits for its own pending refund, which matched no window.
      expect(await rl.countShared("k")).toBe(1);
      expect((await rows(name))[0]?.count).toBe(1);
    });
  });

  it("an elapsed window restarts at the next hit", async () => {
    const name = fresh();
    const rl = RateLimiter.shared(name, 1, 60_000, "closed");
    expect((await rl.reserveShared("k")).ok).toBe(true);
    expect((await RateLimiter.shared(name, 1, 60_000, "closed").reserveShared("k")).ok).toBe(false);
    await expire(name);
    expect((await RateLimiter.shared(name, 1, 60_000, "closed").reserveShared("k")).ok).toBe(true);
    const [row] = await rows(name);
    expect(row?.count).toBe(1);
    expect(row && row.expiresAt.getTime() - row.windowStart.getTime()).toBe(60_000);
  });

  it("stores keys as an HMAC, never in clear", async () => {
    const name = fresh();
    const key = "admin|198.51.100.7";
    await RateLimiter.shared(name, 5, 60_000, "closed").hitShared(key);
    const [row] = await rows(name);
    expect(row?.keyHash).toBe(rateLimitKeyHash(name, key));
    expect(row?.keyHash).toMatch(/^[0-9a-f]{64}$/);
    const dump = JSON.stringify(await getDb().execute(sql`select * from rate_limit_counters`));
    expect(dump).not.toContain("198.51.100.7");
    expect(dump).not.toContain("admin");
    // Keyed: another limiter, or another key, never gives the same hash.
    expect(rateLimitKeyHash(`${name}x`, key)).not.toBe(rateLimitKeyHash(name, key));
  });

  it("clear() and reset() empty the store before the next shared operation", async () => {
    const name = fresh();
    const rl = RateLimiter.shared(name, 1, 60_000, "closed");
    await rl.hitShared("a");
    await rl.hitShared("b");
    rl.reset("a");
    expect((await rl.reserveShared("a")).ok).toBe(true);
    expect((await rl.reserveShared("b")).ok).toBe(false);
    rl.clear();
    expect(await rl.countShared("a")).toBe(0);
    expect(await rows(name)).toHaveLength(0);
  });

  it("prunes expired windows only, in chunks", async () => {
    const name = fresh("prune");
    const rl = RateLimiter.shared(name, 5, 60_000, "closed");
    for (const k of ["a", "b", "c", "d", "e"]) await rl.hitShared(k);
    await getDb().execute(sql`update rate_limit_counters
      set window_start = window_start - interval '1 day', expires_at = now() - interval '1 second'
      where limiter = ${name} and key_hash in (${rateLimitKeyHash(name, "a")}, ${rateLimitKeyHash(name, "b")}, ${rateLimitKeyHash(name, "c")})`);
    // Other test windows in this database may be pruned too: count only this limiter's rows.
    const partial = await pruneRateLimitCounters(getDb(), { chunk: 1, budgetMs: 0 });
    expect(partial).toMatchObject({ deleted: 1, more: true });
    const done = await pruneRateLimitCounters(getDb(), { chunk: 2 });
    expect(done.more).toBe(false);
    const left = (await rows(name)).map((r) => r.keyHash).sort();
    expect(left).toEqual([rateLimitKeyHash(name, "d"), rateLimitKeyHash(name, "e")].sort());
    // Nothing expired remains anywhere.
    const [expired] = (await getDb().execute(sql`select count(*)::int as n from rate_limit_counters where expires_at <= now()`)).rows as { n: number }[];
    expect(expired?.n).toBe(0);
  });

  describe("security-sensitive limiters fail closed end to end", () => {
    const ORIGIN = "http://console.test";
    const loginReq = (password: string) =>
      new Request(`${ORIGIN}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Origin: ORIGIN, "X-Forwarded-For": "203.0.113.9" },
        body: JSON.stringify({ username: "admin", password }),
      });

    beforeEach(async () => {
      await adminUser();
    });

    it("two module copies of the login share the per-(username, IP) limit", async () => {
      process.env.DATABASTION_TRUST_PROXY = "1";
      vi.resetModules();
      const a = await import("./user-api");
      vi.resetModules();
      const b = await import("./user-api");
      const statuses: number[] = [];
      for (let i = 0; i < 6; i++) statuses.push((await (i % 2 ? b : a).handleLogin(loginReq("not the password"))).status);
      expect(statuses).toEqual([401, 401, 401, 401, 401, 429]);
      expect(a.loginFailuresPerUser.count("admin|203.0.113.9")).toBe(3);
      expect(b.loginFailuresPerUser.count("admin|203.0.113.9")).toBe(2);
    });

    /** A fresh module copy of `path`, with the store class and crypto stats of the same copy. */
    async function freshCopy<T>(path: string): Promise<{ mod: T; store: typeof PgRateLimitStore; stats: typeof argon2Stats }> {
      vi.resetModules();
      const mod = (await import(/* @vite-ignore */ path)) as T;
      const store = (await import("./rate-limit")).PgRateLimitStore;
      const stats = (await import("./crypto")).argon2Stats;
      vi.spyOn((await import("@/lib/logger")).logger, "warn").mockImplementation(() => undefined);
      return { mod, store, stats };
    }

    it("login: a store failure answers 429 + Retry-After before any argon2id", async () => {
      process.env.DATABASTION_TRUST_PROXY = "1";
      const copy = await freshCopy<typeof import("./user-api")>("./user-api");
      const { handleLogin } = copy.mod;
      const reserve = vi.spyOn(copy.store.prototype, "reserve").mockRejectedValue(new Error("store down"));
      const before = copy.stats.started;
      const res = await handleLogin(loginReq("not the password"));
      expect(res.status).toBe(429);
      expect(res.headers.get("retry-after")).toBe(String(FAIL_CLOSED_RETRY_AFTER_S));
      expect(copy.stats.started).toBe(before);
      expect(reserve).toHaveBeenCalled();
    });

    it("agent authentication: a store failure refuses unknown secrets, never an exempt one", async () => {
      const copy = await freshCopy<typeof import("./agent-api/handlers")>("./agent-api/handlers");
      const handlers = copy.mod;
      const auth = await enroll("rl-host");
      const poll = (secret: string) =>
        handlers.handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth: { agentId: auth.agentId, secret } }));
      expect((await poll(auth.secret)).status).toBe(204);
      for (const method of ["reserve", "check", "hit"] as const) {
        vi.spyOn(copy.store.prototype, method).mockRejectedValue(new Error("store down"));
      }
      const wrong = await poll(`${auth.secret.slice(0, -2)}xx`);
      expect(wrong.status).toBe(429);
      expect(wrong.headers.get("retry-after")).toBe(String(FAIL_CLOSED_RETRY_AFTER_S));
      // The secret verified less than 25 s ago is held by no failure limit: still authenticated.
      expect((await poll(auth.secret)).status).toBe(204);
    });
  });
});
