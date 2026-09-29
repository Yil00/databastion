import { and, eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { getDb } from "@/db/client";
import { agents, auditLog, notificationChannels, notificationDeliveries, securityEvents } from "@/db/schema";
import { renderEmail, type AgentBatchesDroppedPayload } from "@/lib/notification-render";
import { handleHeartbeat } from "@/server/agent-api/handlers";
import { hasDb, setupTestDatabase } from "@/test/db";
import { agentRequest, enroll } from "@/test/helpers";

import { DROPPED_BATCHES_ALERT_INTERVAL_S, droppedBatchesDelta, flushDroppedBatchAlerts } from "./dropped-batches";
import { setNotificationJobSender } from "./notification-queue";

describe("droppedBatchesDelta", () => {
  const prev = (dropped: number | undefined, uptimeS: number | null = 100) => ({
    spool: dropped === undefined ? { bytes: 0 } : { bytes: 0, dropped_batches: dropped },
    uptimeS,
  });
  const cur = (dropped: number | undefined, uptimeS = 130) => ({
    spool: dropped === undefined ? { bytes: 0 } : { bytes: 0, dropped_batches: dropped },
    uptimeS,
  });

  it("counts the rise of the counter between two heartbeats of the same run", () => {
    expect(droppedBatchesDelta(prev(3), cur(3))).toBe(0);
    expect(droppedBatchesDelta(prev(3), cur(10))).toBe(7);
    expect(droppedBatchesDelta(prev(0), cur(0))).toBe(0);
  });

  it("after a restart (lower uptime or lower counter) the whole current counter is new", () => {
    expect(droppedBatchesDelta(prev(50, 5000), cur(4, 30))).toBe(4);
    expect(droppedBatchesDelta(prev(50, 5000), cur(60, 30))).toBe(60);
    expect(droppedBatchesDelta(prev(50, 100), cur(2, 130))).toBe(2);
  });

  it("no previous counter: the current one counts since the agent started; absent now: 0", () => {
    expect(droppedBatchesDelta({ spool: null, uptimeS: null }, cur(5))).toBe(5);
    expect(droppedBatchesDelta(prev(undefined), cur(5))).toBe(5);
    expect(droppedBatchesDelta(prev(5), cur(undefined))).toBe(0);
    expect(droppedBatchesDelta({ spool: null, uptimeS: null }, cur(undefined))).toBe(0);
  });

  it("ignores non-counts and saturates at the integer bound", () => {
    expect(droppedBatchesDelta({ spool: { dropped_batches: "7" }, uptimeS: 100 }, cur(9))).toBe(9);
    expect(droppedBatchesDelta(prev(0), cur(Number.MAX_SAFE_INTEGER))).toBe(2_147_483_647);
  });
});

describe("agent.batches_dropped e-mail", () => {
  it("counts, timestamps and ids only", () => {
    const p: AgentBatchesDroppedPayload = {
      event: "agent.batches_dropped",
      occurred_at: "2026-09-29T10:00:00.000Z",
      url: "https://console.example/agents/a",
      agent_id: "0b5c3c1e-1111-4a4a-9b9b-000000000001",
      dropped_batches: 1,
      since: "2026-09-29T09:58:00.000Z",
      min_interval_s: 3600,
      security_event_id: "0b5c3c1e-1111-4a4a-9b9b-000000000002",
    };
    const mail = renderEmail(p);
    expect(mail.subject).toBe("[DataBastion] Agent dropped 1 batch: 0b5c3c1e-1111-4a4a-9b9b-000000000001");
    expect(mail.text).toContain("reported 1 batch dropped since 2026-09-29T09:58:00.000Z");
    expect(mail.text).toContain("every 60 minutes");
    expect(renderEmail({ ...p, dropped_batches: 12 }).subject).toContain("dropped 12 batches");
  });
});

const HOST = "dropper-host";

describe.skipIf(!hasDb)("dropped-batches alert (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  const wakeUps = vi.fn(async () => undefined);

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    setNotificationJobSender(wakeUps);
    await getDb().insert(notificationChannels).values([
      { slug: "ops-mail", type: "email", systemAlerts: true, config: { host: "smtp.example.com", port: 587, tls: "starttls", from: "a@example.com", recipients: ["b@example.com"], username: null } },
      { slug: "soc-mail", type: "email", systemAlerts: false, config: { host: "smtp.example.com", port: 587, tls: "starttls", from: "a@example.com", recipients: ["b@example.com"], username: null } },
    ]);
  });
  afterAll(async () => {
    setNotificationJobSender(null);
    await teardown?.();
  });

  async function heartbeat(auth: { agentId: string; secret: string }, dropped: number | undefined, uptimeS: number): Promise<void> {
    const spool: Record<string, number> = { bytes: 0, max_bytes: 1024, batches: 0 };
    if (dropped !== undefined) spool.dropped_batches = dropped;
    const body = {
      ts: new Date().toISOString(),
      agent_version: "0.1.0",
      uptime_s: uptimeS,
      connectors: ["postgres"],
      targets: [],
      detected_targets: [],
      spool,
    };
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }))).status).toBe(200);
  }

  const events = (agentId: string) =>
    getDb()
      .select()
      .from(securityEvents)
      .where(and(eq(securityEvents.agentId, agentId), eq(securityEvents.kind, "agent.batches_dropped")))
      .orderBy(securityEvents.at);
  const deliveries = (agentId: string) =>
    getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.agentId, agentId)).orderBy(notificationDeliveries.createdAt);
  const state = async (agentId: string) =>
    (
      await getDb()
        .select({ unalerted: agents.droppedBatchesUnalerted, since: agents.droppedBatchesSince, alertedAt: agents.droppedBatchesAlertedAt })
        .from(agents)
        .where(eq(agents.id, agentId))
    )[0];

  it("alerts on a rise, at most once per agent and hour, with the delta; later drops go in the next alert", async () => {
    const auth = await enroll(HOST);
    await heartbeat(auth, 0, 10);
    await heartbeat(auth, undefined, 20);
    expect(await events(auth.agentId)).toHaveLength(0);

    // A rise of 3: one security event, one audit entry, one delivery (system-alert channel only).
    await heartbeat(auth, 3, 30);
    let evs = await events(auth.agentId);
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ severity: "medium", details: { dropped_batches: 3, min_interval_s: DROPPED_BATCHES_ALERT_INTERVAL_S } });
    const rows = await deliveries(auth.agentId);
    expect(rows.map((r) => [r.event, r.channelSlug, r.securityEventId])).toEqual([["agent.batches_dropped", "ops-mail", evs[0]?.id]]);
    expect(rows[0]?.payload).toMatchObject({ event: "agent.batches_dropped", agent_id: auth.agentId, dropped_batches: 3, security_event_id: evs[0]?.id });
    // No agent-provided text in the event, the audit entry or the notification.
    const audit = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "agent.batches_dropped"), eq(auditLog.targetId, auth.agentId)));
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ actorType: "system", details: { dropped_batches: 3, security_event_id: evs[0]?.id } });
    expect(JSON.stringify([evs, rows, audit])).not.toContain("dropper");
    expect(wakeUps).toHaveBeenCalled();
    expect(await state(auth.agentId)).toMatchObject({ unalerted: 0, since: null });

    // Within the hour: counted, not alerted (unchanged counter adds nothing).
    await heartbeat(auth, 5, 40);
    await heartbeat(auth, 5, 50);
    // Restart: uptime back to 3 s, 1 batch dropped since.
    await heartbeat(auth, 1, 3);
    expect(await events(auth.agentId)).toHaveLength(1);
    const held = await state(auth.agentId);
    expect(held?.unalerted).toBe(3);
    expect(held?.since).toBeInstanceOf(Date);

    // The worker raises the held-back drops once the hour is over, not before.
    const alertedAt = held?.alertedAt as Date;
    expect(await flushDroppedBatchAlerts(getDb(), { now: new Date(alertedAt.getTime() + (DROPPED_BATCHES_ALERT_INTERVAL_S - 60) * 1000) })).toBe(0);
    expect(await flushDroppedBatchAlerts(getDb(), { now: new Date(alertedAt.getTime() + (DROPPED_BATCHES_ALERT_INTERVAL_S + 1) * 1000) })).toBe(1);
    expect(await flushDroppedBatchAlerts(getDb(), { now: new Date(alertedAt.getTime() + (DROPPED_BATCHES_ALERT_INTERVAL_S + 1) * 1000) })).toBe(0);
    evs = await events(auth.agentId);
    expect(evs.map((e) => (e.details as { dropped_batches: number }).dropped_batches)).toEqual([3, 3]);
    expect((evs[1]?.details as { since: string }).since).toBe(held?.since?.toISOString());
    expect((await deliveries(auth.agentId)).map((r) => r.event)).toEqual(["agent.batches_dropped", "agent.batches_dropped"]);

    // An hour after that alert, the next rise alerts from the heartbeat itself.
    await getDb().execute(sql`update agents set dropped_batches_alerted_at = now() - interval '61 minutes' where id = ${auth.agentId}`);
    await heartbeat(auth, 1, 13);
    expect(await events(auth.agentId)).toHaveLength(2);
    await heartbeat(auth, 9, 23);
    evs = await events(auth.agentId);
    expect(evs.map((e) => (e.details as { dropped_batches: number }).dropped_batches)).toEqual([3, 3, 8]);
  });

  it("the first heartbeat counts the drops since the agent started; revoked and locked agents are not alerted", async () => {
    const first = await enroll("first-host");
    await heartbeat(first, 4, 60);
    expect((await events(first.agentId)).map((e) => (e.details as { dropped_batches: number }).dropped_batches)).toEqual([4]);

    const revoked = await enroll("revoked-host");
    await heartbeat(revoked, 0, 10);
    await getDb().execute(sql`update agents set dropped_batches_unalerted = 2, dropped_batches_since = now(), locked_at = now() where id = ${revoked.agentId}`);
    await flushDroppedBatchAlerts(getDb(), { now: new Date(Date.now() + 10 * 3600_000) });
    expect(await events(revoked.agentId)).toHaveLength(0);
  });
});
