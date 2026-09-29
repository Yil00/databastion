import { and, eq, inArray, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb, type Database } from "@/db/client";
import * as schema from "@/db/schema";
import { agents, notificationChannels, notificationDeliveries, securityEvents, systemAlertBudgets } from "@/db/schema";
import type { AgentIntegrityPayload } from "@/lib/notification-render";
import { createRuntimeRole, hasDb, setupTestDatabase } from "@/test/db";

import {
  alertingWarnings,
  DEFAULT_SYSTEM_ALERTS_MAX_PER_HOUR,
  SYSTEM_ALERTS_MAX_PER_HOUR_VAR,
  systemAlertsMaxPerHour,
} from "./alerting-config";
import { drainDeliveries, enqueueSystemAlert, enqueueSystemAlertDigests, notificationClock, type Senders } from "./notifications";
import { checkSilentAgents } from "./system-alerts";

describe("DATABASTION_SYSTEM_ALERTS_MAX_PER_HOUR", () => {
  it("defaults to 20, accepts 1 to 10000, falls back (warned) otherwise", () => {
    expect(DEFAULT_SYSTEM_ALERTS_MAX_PER_HOUR).toBe(20);
    expect(systemAlertsMaxPerHour({})).toBe(20);
    expect(systemAlertsMaxPerHour({ [SYSTEM_ALERTS_MAX_PER_HOUR_VAR]: " " })).toBe(20);
    expect(systemAlertsMaxPerHour({ [SYSTEM_ALERTS_MAX_PER_HOUR_VAR]: "1" })).toBe(1);
    expect(systemAlertsMaxPerHour({ [SYSTEM_ALERTS_MAX_PER_HOUR_VAR]: "10000" })).toBe(10_000);
    for (const bad of ["0", "-3", "10001", "2.5", "abc", "1e3x"]) {
      expect(systemAlertsMaxPerHour({ [SYSTEM_ALERTS_MAX_PER_HOUR_VAR]: bad })).toBe(20);
      expect(alertingWarnings({ [SYSTEM_ALERTS_MAX_PER_HOUR_VAR]: bad }).join("\n")).toContain(SYSTEM_ALERTS_MAX_PER_HOUR_VAR);
    }
    expect(alertingWarnings({ [SYSTEM_ALERTS_MAX_PER_HOUR_VAR]: "20" })).toEqual([]);
    expect(alertingWarnings({ [SYSTEM_ALERTS_MAX_PER_HOUR_VAR]: "50" })).toEqual([]);
  });
});

const EMAIL_CONFIG = { host: "smtp.example.com", port: 587, tls: "starttls", from: "a@example.com", recipients: ["b@example.com"], username: null };

describe.skipIf(!hasDb)("global hourly budget of system alerts per channel (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  let ops = "";
  let noc = "";
  let soc = "";

  beforeAll(async () => {
    teardown = await setupTestDatabase();
  });
  afterAll(async () => {
    await teardown?.();
  });
  beforeEach(async () => {
    await getDb().delete(notificationChannels);
    const rows = await getDb()
      .insert(notificationChannels)
      .values([
        { slug: "ops-mail", type: "email", systemAlerts: true, config: EMAIL_CONFIG },
        { slug: "noc-mail", type: "email", systemAlerts: true, config: EMAIL_CONFIG },
        { slug: "soc-mail", type: "email", systemAlerts: false, config: EMAIL_CONFIG },
      ])
      .returning({ id: notificationChannels.id, slug: notificationChannels.slug });
    ops = rows.find((r) => r.slug === "ops-mail")?.id ?? "";
    noc = rows.find((r) => r.slug === "noc-mail")?.id ?? "";
    soc = rows.find((r) => r.slug === "soc-mail")?.id ?? "";
  });
  afterEach(() => {
    notificationClock.now = null;
    delete process.env[SYSTEM_ALERTS_MAX_PER_HOUR_VAR];
  });

  async function newAgents(n: number, prefix: string): Promise<string[]> {
    const rows = await getDb()
      .insert(agents)
      .values(Array.from({ length: n }, (_, i) => ({ name: `${prefix}-${i}`, hostname: `${prefix}-${i}.example`, version: "0.1.0" })))
      .returning({ id: agents.id });
    return rows.map((r) => r.id);
  }

  function integrityAlert(agentId: string, hour: string, kind = "agent.batch_rejected") {
    const payload: AgentIntegrityPayload = {
      event: "agent.integrity",
      occurred_at: `${hour}:05:00.000Z`,
      url: null,
      kind,
      severity: "high",
      agent_id: agentId,
      security_event_id: "00000000-0000-4000-8000-000000000000",
      details: { endpoint: "findings" },
    };
    return { subjectKey: `agent:${agentId}|integrity:${kind}|hour:${hour}`, agentId, securityEventId: null, payload };
  }

  const rowsOf = (agentIds: string[]) =>
    getDb()
      .select()
      .from(notificationDeliveries)
      .where(inArray(notificationDeliveries.agentId, agentIds));

  /** `{ "pending": n, "skipped:rate_limited": m }` of one channel. */
  const statusCount = (rows: { channelId: string | null; status: string; lastError: string | null }[], channel: string) =>
    rows
      .filter((r) => r.channelId === channel)
      .reduce<Record<string, number>>((acc, r) => {
        const k = `${r.status}${r.lastError ? `:${r.lastError}` : ""}`;
        acc[k] = (acc[k] ?? 0) + 1;
        return acc;
      }, {});

  it("N agents share one budget per channel and hour; over it: skipped (rate_limited); repeats cost nothing", async () => {
    process.env[SYSTEM_ALERTS_MAX_PER_HOUR_VAR] = "3";
    notificationClock.now = () => new Date("2026-09-27T10:15:00.000Z");
    const ids = await newAgents(5, "budget");
    let pending = 0;
    for (const id of ids) pending += await getDb().transaction((tx) => enqueueSystemAlert(tx, integrityAlert(id, "2026-09-27T10")));
    // 3 per system-alert channel (two channels), none to the channel without system alerts.
    expect(pending).toBe(6);
    // The same alerts again (same idempotency keys): nothing inserted, nothing charged.
    for (const id of ids) expect(await getDb().transaction((tx) => enqueueSystemAlert(tx, integrityAlert(id, "2026-09-27T10")))).toBe(0);
    const rows = await rowsOf(ids);
    expect(rows.filter((r) => r.channelId === soc)).toHaveLength(0);
    expect(statusCount(rows, ops)).toEqual({ pending: 3, "skipped:rate_limited": 2 });
    expect(statusCount(rows, noc)).toEqual({ pending: 3, "skipped:rate_limited": 2 });
    const budgets = await getDb().select().from(systemAlertBudgets).orderBy(systemAlertBudgets.channelId);
    expect(budgets.map((b) => [b.windowStart.toISOString(), b.sent])).toEqual([
      ["2026-09-27T10:00:00.000Z", 3],
      ["2026-09-27T10:00:00.000Z", 3],
    ]);

    // The next hour has a fresh budget.
    notificationClock.now = () => new Date("2026-09-27T11:00:00.000Z");
    const [late] = await newAgents(1, "budget-late");
    expect(await getDb().transaction((tx) => enqueueSystemAlert(tx, integrityAlert(String(late), "2026-09-27T11")))).toBe(2);
  });

  it("an aborted transaction gives its charge back", async () => {
    process.env[SYSTEM_ALERTS_MAX_PER_HOUR_VAR] = "1";
    notificationClock.now = () => new Date("2026-09-27T12:15:00.000Z");
    const [a, b] = await newAgents(2, "abort");
    await expect(
      getDb().transaction(async (tx) => {
        await enqueueSystemAlert(tx, integrityAlert(String(a), "2026-09-27T12"));
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    expect(await getDb().transaction((tx) => enqueueSystemAlert(tx, integrityAlert(String(b), "2026-09-27T12")))).toBe(2);
  });

  it("concurrent transactions from several processes never exceed the budget", async () => {
    process.env[SYSTEM_ALERTS_MAX_PER_HOUR_VAR] = "5";
    notificationClock.now = () => new Date("2026-09-27T13:20:00.000Z");
    const ids = await newAgents(40, "race");
    // Three pools stand for three console processes (web replicas and the worker).
    const url = String(process.env.DATABASE_URL);
    const pools = [0, 1, 2].map(() => new Pool({ connectionString: url, max: 8 }));
    try {
      const dbs = pools.map((p) => drizzle(p, { schema }) as unknown as Database);
      const results = await Promise.all(
        ids.map((id, i) => (dbs[i % dbs.length] as Database).transaction((tx) => enqueueSystemAlert(tx, integrityAlert(id, "2026-09-27T13")))),
      );
      expect(results.reduce((a, b) => a + b, 0)).toBe(10);
    } finally {
      await Promise.all(pools.map((p) => p.end()));
    }
    const rows = await rowsOf(ids);
    expect(rows).toHaveLength(80);
    expect(statusCount(rows, ops)).toEqual({ pending: 5, "skipped:rate_limited": 35 });
    expect(statusCount(rows, noc)).toEqual({ pending: 5, "skipped:rate_limited": 35 });
    const [budget] = await getDb()
      .select()
      .from(systemAlertBudgets)
      .where(and(eq(systemAlertBudgets.channelId, ops), eq(systemAlertBudgets.windowStart, new Date("2026-09-27T13:00:00.000Z"))));
    expect(budget?.sent).toBe(5);
  });

  it("silent agents: one digest per channel and closed hour (counts per event, agent count, no agent text)", async () => {
    process.env[SYSTEM_ALERTS_MAX_PER_HOUR_VAR] = "2";
    notificationClock.now = () => new Date("2026-09-27T14:10:00.000Z");
    const ids = await newAgents(4, "fleet-host");
    await getDb()
      .update(agents)
      .set({ status: "online", lastSeenAt: new Date("2026-09-27T13:00:00.000Z") })
      .where(inArray(agents.id, ids));
    // Also one integrity alert of one of them, in the same hour.
    await getDb().transaction((tx) => enqueueSystemAlert(tx, integrityAlert(String(ids[0]), "2026-09-27T14")));
    const stats = await checkSilentAgents(getDb(), { now: new Date("2026-09-27T14:10:00.000Z"), thresholdS: 300 });
    expect(stats.silent).toBe(4);
    // Every silence is recorded, notified or not.
    expect(await getDb().select().from(securityEvents).where(and(inArray(securityEvents.agentId, ids), eq(securityEvents.kind, "agent.silent")))).toHaveLength(4);
    const rows = await rowsOf(ids);
    expect(statusCount(rows, ops)).toEqual({ pending: 2, "skipped:rate_limited": 3 });

    // The hour is not over: no digest.
    notificationClock.now = () => new Date("2026-09-27T14:59:59.999Z");
    expect(await enqueueSystemAlertDigests(getDb())).toBe(0);
    // Closed: one digest per system-alert channel, never twice.
    notificationClock.now = () => new Date("2026-09-27T15:00:30.000Z");
    expect(await enqueueSystemAlertDigests(getDb())).toBe(2);
    expect(await enqueueSystemAlertDigests(getDb())).toBe(0);
    const digests = await getDb()
      .select()
      .from(notificationDeliveries)
      .where(and(eq(notificationDeliveries.event, "system_alerts.suppressed"), eq(notificationDeliveries.channelId, ops)));
    expect(digests).toHaveLength(1);
    const digest = digests[0];
    expect(digest).toMatchObject({ status: "pending", agentId: null, securityEventId: null, incidentId: null });
    // Limit 2: the integrity alert and one silence were sent, three silences were not.
    expect(digest?.payload).toEqual({
      event: "system_alerts.suppressed",
      occurred_at: "2026-09-27T15:00:00.000Z",
      url: null,
      channel: "ops-mail",
      window_start: "2026-09-27T14:00:00.000Z",
      window_end: "2026-09-27T15:00:00.000Z",
      suppressed: 3,
      by_event: { "agent.silent": 3 },
      agents: 3,
      limit_per_hour: 2,
    });
    const text = JSON.stringify(digest?.payload);
    for (const id of ids) expect(text).not.toContain(id);
    expect(text).not.toContain("fleet-host");
    // Past budget rows are pruned (more than 2 hours old).
    notificationClock.now = () => new Date("2026-09-27T18:00:00.000Z");
    await enqueueSystemAlertDigests(getDb());
    expect(
      await getDb().select().from(systemAlertBudgets).where(sql`${systemAlertBudgets.windowStart} < '2026-09-27T16:00:00Z'::timestamptz`),
    ).toHaveLength(0);

    // Digests are not charged to the budget and are sent like any delivery.
    const calls: string[] = [];
    const senders: Senders = {
      email: async (_c, _p, msg) => {
        calls.push(msg.subject);
        return { ok: true };
      },
      webhook: async () => ({ ok: true }),
    };
    await drainDeliveries(getDb(), { senders });
    expect(calls).toContain("[DataBastion] 3 system alerts suppressed");
  });

  it("the runtime role charges the budget, records overflows, queues digests and prunes (migration 0033)", async () => {
    const { url } = await createRuntimeRole();
    const pool = new Pool({ connectionString: url, max: 2 });
    try {
      const db = drizzle(pool, { schema }) as unknown as Database;
      process.env[SYSTEM_ALERTS_MAX_PER_HOUR_VAR] = "1";
      notificationClock.now = () => new Date("2026-09-28T09:30:00.000Z");
      const ids = await newAgents(2, "runtime");
      for (const id of ids) await db.transaction((tx) => enqueueSystemAlert(tx, integrityAlert(id, "2026-09-28T09")));
      expect(statusCount(await rowsOf(ids), ops)).toEqual({ pending: 1, "skipped:rate_limited": 1 });
      notificationClock.now = () => new Date("2026-09-28T12:00:00.000Z");
      expect(await enqueueSystemAlertDigests(db)).toBe(2);
      await expect(pool.query("truncate system_alert_budgets")).rejects.toThrow(/permission denied/);
    } finally {
      await pool.end();
    }
  });
});
