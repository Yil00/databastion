import { and, eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { getDb } from "@/db/client";
import { agents, auditLog, notificationChannels, notificationDeliveries, securityEvents } from "@/db/schema";
import { renderEmail, type AgentAuditStreamStoppedPayload } from "@/lib/notification-render";
import { handleHeartbeat } from "@/server/agent-api/handlers";
import { hasDb, setupTestDatabase } from "@/test/db";
import { agentRequest, enroll } from "@/test/helpers";

import { AUDIT_STREAM_ALERT_INTERVAL_S, flushAuditStreamStoppedAlerts, stoppedStreams, streamStopped } from "./audit-stream-alerts";
import { setNotificationJobSender } from "./notification-queue";

const STOPPED = { code: "audit.stream_stopped", count: 3 };

describe("stopped Audit streams in a heartbeat", () => {
  it("counts each target reporting audit.stream_stopped once", () => {
    expect(streamStopped(null)).toBe(false);
    expect(streamStopped([{ code: "audit.reads_not_logged" }])).toBe(false);
    expect(streamStopped([{ code: "audit.reads_not_logged" }, STOPPED])).toBe(true);
    expect(
      stoppedStreams([
        { target_id: "a", notes: [STOPPED] },
        { target_id: "a", notes: [STOPPED] },
        { target_id: "b" },
        { target_id: "c", notes: [{ code: "check.timed_out" }] },
        { target_id: "d", notes: [STOPPED] },
      ]),
    ).toBe(2);
  });

  it("e-mail: counts, timestamps and ids only", () => {
    const p: AgentAuditStreamStoppedPayload = {
      event: "agent.audit_stream_stopped",
      occurred_at: "2026-09-29T10:00:00.000Z",
      url: "https://console.example/agents/a",
      agent_id: "0b5c3c1e-1111-4a4a-9b9b-000000000001",
      stopped_streams: 1,
      since: "2026-09-29T09:58:00.000Z",
      min_interval_s: 3600,
      security_event_id: "0b5c3c1e-1111-4a4a-9b9b-000000000002",
    };
    const mail = renderEmail(p);
    expect(mail.subject).toBe("[DataBastion] Audit stopped on 1 target: agent 0b5c3c1e-1111-4a4a-9b9b-000000000001");
    expect(mail.text).toContain("reports the Audit stream of 1 target stopped after repeated internal errors, since 2026-09-29T09:58:00.000Z");
    expect(mail.text).toContain("repeated every 60 minutes while a stream stays stopped");
    expect(renderEmail({ ...p, stopped_streams: 3 }).subject).toContain("on 3 targets");
  });
});

describe.skipIf(!hasDb)("Audit stream stopped alert (PostgreSQL, ADR-0031 decision 3)", () => {
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

  /** One heartbeat; `stopped`: the target ids reporting a stopped stream. */
  async function heartbeat(auth: { agentId: string; secret: string }, stopped: string[], all = ["ldap-people", "pg-crm"]): Promise<void> {
    const body = {
      ts: new Date().toISOString(),
      agent_version: "0.1.0",
      uptime_s: 30,
      connectors: ["postgres", "openldap"],
      targets: all.map((id) => ({
        target_id: id,
        engine: id.startsWith("ldap") ? "openldap" : "postgres",
        reachable: true,
        audit_level: stopped.includes(id) ? "none" : "full",
        ...(stopped.includes(id) ? { notes: [STOPPED] } : {}),
      })),
      detected_targets: [],
      spool: { bytes: 0, max_bytes: 1024, batches: 0 },
    };
    expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }))).status).toBe(200);
  }

  const events = (agentId: string) =>
    getDb()
      .select()
      .from(securityEvents)
      .where(and(eq(securityEvents.agentId, agentId), eq(securityEvents.kind, "agent.audit_stream_stopped")))
      .orderBy(securityEvents.at);
  const deliveries = (agentId: string) =>
    getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.agentId, agentId)).orderBy(notificationDeliveries.createdAt);
  const state = async (agentId: string) =>
    (
      await getDb()
        .select({ unalerted: agents.auditStreamStopsUnalerted, since: agents.auditStreamStopsSince, alertedAt: agents.auditStreamStopsAlertedAt })
        .from(agents)
        .where(eq(agents.id, agentId))
    )[0];

  it("alerts when a target reports a stopped stream, at most once per agent and hour, and again every hour while it lasts", async () => {
    const auth = await enroll("stopper-host");
    await heartbeat(auth, []);
    expect(await events(auth.agentId)).toHaveLength(0);

    // A stopped stream: one security event (medium), one audit entry, one delivery.
    await heartbeat(auth, ["ldap-people"]);
    let evs = await events(auth.agentId);
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ severity: "medium", details: { stopped_streams: 1, min_interval_s: AUDIT_STREAM_ALERT_INTERVAL_S } });
    const rows = await deliveries(auth.agentId);
    expect(rows.map((r) => [r.event, r.channelSlug, r.securityEventId])).toEqual([["agent.audit_stream_stopped", "ops-mail", evs[0]?.id]]);
    expect(rows[0]?.payload).toMatchObject({ event: "agent.audit_stream_stopped", agent_id: auth.agentId, stopped_streams: 1, security_event_id: evs[0]?.id });
    const audit = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "agent.audit_stream_stopped"), eq(auditLog.targetId, auth.agentId)));
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ actorType: "system", details: { stopped_streams: 1, security_event_id: evs[0]?.id } });
    // No agent-provided text (target ids, host name) in the event, the audit entry or the notification.
    expect(JSON.stringify([evs, rows, audit])).not.toMatch(/ldap-people|pg-crm|stopper/);
    expect(wakeUps).toHaveBeenCalled();

    // Still stopped, and a second target stops, within the hour: recorded, not alerted.
    await heartbeat(auth, ["ldap-people"]);
    await heartbeat(auth, ["ldap-people", "pg-crm"]);
    await heartbeat(auth, ["ldap-people"]);
    expect(await events(auth.agentId)).toHaveLength(1);
    const held = await state(auth.agentId);
    expect(held?.unalerted).toBe(2);
    expect(held?.since).toBeInstanceOf(Date);

    // The worker raises it once the hour is over, not before.
    const alertedAt = held?.alertedAt as Date;
    expect(await flushAuditStreamStoppedAlerts(getDb(), { now: new Date(alertedAt.getTime() + (AUDIT_STREAM_ALERT_INTERVAL_S - 60) * 1000) })).toBe(0);
    expect(await flushAuditStreamStoppedAlerts(getDb(), { now: new Date(alertedAt.getTime() + (AUDIT_STREAM_ALERT_INTERVAL_S + 1) * 1000) })).toBe(1);
    expect(await flushAuditStreamStoppedAlerts(getDb(), { now: new Date(alertedAt.getTime() + (AUDIT_STREAM_ALERT_INTERVAL_S + 1) * 1000) })).toBe(0);
    evs = await events(auth.agentId);
    expect(evs.map((e) => (e.details as { stopped_streams: number }).stopped_streams)).toEqual([1, 2]);

    // An hour later the stream is still stopped: the next heartbeat alerts again (not only on the
    // transition).
    await getDb().execute(sql`update agents set audit_stream_stops_alerted_at = now() - interval '61 minutes' where id = ${auth.agentId}`);
    await heartbeat(auth, ["ldap-people"]);
    expect(await events(auth.agentId)).toHaveLength(3);
    // Recovered (restart or reconfiguration): nothing more, even after the hour.
    await heartbeat(auth, []);
    await getDb().execute(sql`update agents set audit_stream_stops_alerted_at = now() - interval '61 minutes' where id = ${auth.agentId}`);
    await heartbeat(auth, []);
    expect(await flushAuditStreamStoppedAlerts(getDb())).toBe(0);
    expect(await events(auth.agentId)).toHaveLength(3);
    expect((await deliveries(auth.agentId)).map((r) => r.event)).toEqual(Array(3).fill("agent.audit_stream_stopped"));
  });

  it("a heartbeat and the worker raising concurrently give exactly one alert", async () => {
    for (let round = 0; round < 5; round++) {
      const auth = await enroll(`race-stop-${round}`);
      await heartbeat(auth, []);
      await getDb().execute(
        sql`update agents set audit_stream_stops_unalerted = 1, audit_stream_stops_since = now(), audit_stream_stops_alerted_at = now() - interval '2 hours' where id = ${auth.agentId}`,
      );
      await Promise.all([heartbeat(auth, ["pg-crm"]), flushAuditStreamStoppedAlerts(getDb())]);
      expect(await events(auth.agentId)).toHaveLength(1);
    }
  });

  it("revoked and locked agents are not alerted", async () => {
    const locked = await enroll("locked-stop-host");
    await heartbeat(locked, []);
    await getDb().execute(sql`update agents set audit_stream_stops_unalerted = 1, audit_stream_stops_since = now(), locked_at = now() where id = ${locked.agentId}`);
    await flushAuditStreamStoppedAlerts(getDb(), { now: new Date(Date.now() + 10 * 3600_000) });
    expect(await events(locked.agentId)).toHaveLength(0);
  });

  it("is charged to the per-channel budget of system alerts like the others", async () => {
    process.env.DATABASTION_SYSTEM_ALERTS_MAX_PER_HOUR = "1";
    try {
      await getDb().execute(sql`delete from system_alert_budgets`);
      const a = await enroll("budget-stop-a");
      const b = await enroll("budget-stop-b");
      await heartbeat(a, ["pg-crm"]);
      await heartbeat(b, ["pg-crm"]);
      const all = [...(await deliveries(a.agentId)), ...(await deliveries(b.agentId))];
      expect(all.map((r) => [r.status, r.lastError]).sort()).toEqual([
        ["pending", null],
        ["skipped", "rate_limited"],
      ]);
      // Both security events are recorded.
      expect(await events(a.agentId)).toHaveLength(1);
      expect(await events(b.agentId)).toHaveLength(1);
    } finally {
      delete process.env.DATABASTION_SYSTEM_ALERTS_MAX_PER_HOUR;
    }
  });
});
