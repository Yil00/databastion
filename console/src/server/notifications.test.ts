import http from "node:http";
import type { AddressInfo } from "node:net";

import { and, eq, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { PgBoss } from "pg-boss";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { getDb } from "@/db/client";
import * as schema from "@/db/schema";
import { agents, auditLog, incidents, notificationChannels, notificationDeliveries, policies, securityEvents, users } from "@/db/schema";
import { handleFindings, handleHeartbeat, handlePollJobs } from "@/server/agent-api/handlers";
import { failuresPerAgent } from "@/server/agent-api/auth";
import { argon2Hash } from "@/server/crypto";
import { enqueueJob } from "@/server/jobs";
import { createRuntimeRole, hasDb, setupTestDatabase } from "@/test/db";
import { adminUser, agentRequest, enroll, uuidv7 } from "@/test/helpers";
import { logger } from "@/lib/logger";
import { pgBossOptions, registerNotificationQueue, registerPolicyQueue } from "@/worker/queues";

import { drainPolicyWork, getIncident } from "./incidents";
import { POLICY_QUEUE } from "./policy-queue";
import { recordIntegrityEvent } from "./integrity";
import { backoffSeconds, drainDeliveries, enqueueSuppressionDigests, listDeliveries, MAX_DELIVERY_ATTEMPTS, type Senders } from "./notifications";
import { verifyWebhookSignature } from "./senders/webhook";
import { checkSilentAgents } from "./system-alerts";
import {
  handleCreateChannel,
  handleCreatePolicy,
  handleDeleteChannel,
  handleIncidentTransition,
  handleListChannels,
  handleLogin,
  handleRotateChannelSecret,
  handleTestChannel,
  handleUpdateChannel,
  channelTestsPerChannel,
  channelTestsPerUser,
  loginFailuresPerIp,
  loginFailuresPerUser,
  loginFailuresPerUserGlobal,
  loginFailuresUnknownUser,
} from "./user-api";

const ORIGIN = "http://console.test";
const PASSWORD = "correct horse battery staple";
const SMTP_PASSWORD = "smtp-PASSWORD-canary-7f3e";
const URL_TOKEN = "T0-B0-urltokencanary";
/** Masked samples: must never appear in any notification (I2). */
const SAMPLES = ["j*******@e******.com", "m****@e******.org"];
type Who = { cookie: string; csrf: string };
type Auth = { agentId: string; secret: string };

function userReq(method: string, p: string, opts: { body?: unknown; who?: Who } = {}) {
  const headers: Record<string, string> = { "Content-Type": "application/json", Origin: ORIGIN };
  if (opts.who?.cookie) headers.Cookie = opts.who.cookie;
  if (opts.who?.csrf) headers["X-CSRF-Token"] = opts.who.csrf;
  return new Request(`${ORIGIN}${p}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
}

async function login(username: string): Promise<Who> {
  const res = await handleLogin(userReq("POST", "/api/auth/login", { body: { username, password: PASSWORD } }));
  expect(res.status).toBe(200);
  const cookie = (res.headers.getSetCookie().find((c) => c.startsWith("databastion_session=")) ?? "").split(";")[0] ?? "";
  const { csrf_token: csrf } = (await res.json()) as { csrf_token: string };
  return { cookie, csrf };
}

const HEARTBEAT = {
  agent_version: "0.1.0",
  uptime_s: 12,
  classifiers_version: "2026.09.1",
  connectors: ["postgres"],
  targets: [{ target_id: "pg-prod-1", engine: "postgres", reachable: true, audit_level: "limited" }],
  detected_targets: [],
  spool: { bytes: 0, max_bytes: 1024, batches: 0 },
};

async function heartbeat(auth: Auth): Promise<void> {
  const body = { ...HEARTBEAT, ts: new Date().toISOString() };
  expect((await handleHeartbeat(agentRequest("POST", "/heartbeat", { auth, body }))).status).toBe(200);
}

async function agentWithTargets(host = "db-host-1"): Promise<Auth> {
  const auth = await enroll(host);
  await heartbeat(auth);
  return auth;
}

const FINDING = {
  target_id: "pg-prod-1",
  location: { engine: "postgres", database: "crm", schema: "public", object: "clients", field: "email" },
  classifier: "pii.email",
  confidence: 0.97,
  sampled: 200,
  matched: 150,
  masked_samples: SAMPLES,
};

async function scan(auth: Auth): Promise<void> {
  const jobId = await enqueueJob(getDb(), {
    agentId: auth.agentId,
    type: "discovery.scan",
    targetId: "pg-prod-1",
    classifiersVersion: "2026.09.1",
    params: { sample_rows: 200, max_duration_s: 900 },
  });
  expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(200);
  const body = { batch_id: uuidv7(), job_id: jobId, classifiers_version: "2026.09.1", findings: [FINDING] };
  expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);
}

/** Local webhook receiver (plain HTTP on 127.0.0.1: the tests set the dev flag). */
function receiver() {
  const received: { headers: http.IncomingHttpHeaders; body: string }[] = [];
  let status = 204;
  const server = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (c: string) => (body += c));
    req.on("end", () => {
      received.push({ headers: req.headers, body });
      res.writeHead(status).end();
    });
  });
  return {
    received,
    setStatus: (s: number) => (status = s),
    start: async () => {
      await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
      return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    },
    stop: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}

/** Senders that record and answer as told (no network). */
function fakeSenders(answer: () => { ok: true } | { ok: false; code: string; retryable: boolean }) {
  const calls: { kind: "email" | "webhook"; body: string }[] = [];
  const senders: Senders = {
    email: async (_config, _password, msg) => {
      calls.push({ kind: "email", body: `${msg.subject}\n${msg.text}` });
      return answer();
    },
    webhook: async (_url, _secret, msg) => {
      calls.push({ kind: "webhook", body: msg.body });
      return answer();
    },
  };
  return { calls, senders };
}

/** Makes every waiting delivery due now (fake time for the backoff). */
const makeDue = () => getDb().execute(sql`update notification_deliveries set next_attempt_at = now() - interval '1 second' where status = 'pending'`);

describe.skipIf(!hasDb)("alerting (PostgreSQL)", () => {
  let teardown: () => Promise<void>;
  let admin: Who;
  let analyst: Who;
  const hook = receiver();
  let hookBase = "";

  beforeAll(async () => {
    teardown = await setupTestDatabase();
    await adminUser();
    await getDb().insert(users).values({ username: "analyst", passwordHash: await argon2Hash(PASSWORD), role: "analyst" });
    admin = await login("admin");
    analyst = await login("analyst");
    hookBase = await hook.start();
  });
  afterAll(async () => {
    await hook.stop();
    await teardown?.();
  });
  beforeEach(async () => {
    loginFailuresPerIp.clear();
    loginFailuresPerUser.clear();
    loginFailuresPerUserGlobal.clear();
    loginFailuresUnknownUser.clear();
    failuresPerAgent.clear();
    channelTestsPerUser.clear();
    channelTestsPerChannel.clear();
    process.env.DATABASTION_ALERTING_INSECURE_DEV = "1";
    process.env.DATABASTION_PUBLIC_URL = ORIGIN;
    await getDb().delete(policies);
    await getDb().delete(notificationChannels);
    await drainPolicyWork(getDb());
    // Deliveries of earlier tests are finished (the runtime role never deletes them).
    await getDb().execute(sql`update notification_deliveries set status = 'failed', last_error = 'internal' where status in ('pending', 'sending')`);
  });
  afterEach(() => {
    delete process.env.DATABASTION_NOTIFY_MAX_PER_HOUR;
    delete process.env.DATABASTION_ALERTING_INSECURE_DEV;
    delete process.env.DATABASTION_PUBLIC_URL;
  });

  const createChannel = (body: unknown, who: Who = admin) => handleCreateChannel(userReq("POST", "/api/notification-channels", { body, who }));
  const updateChannel = (id: string, body: unknown, who: Who = admin) =>
    handleUpdateChannel(userReq("PATCH", `/api/notification-channels/${id}`, { body, who }), id);

  async function webhookChannel(slug = "soc-hook", over: Record<string, unknown> = {}): Promise<{ id: string; secret: string }> {
    const res = await createChannel({ slug, type: "webhook", config: { url: `${hookBase}/hooks/${URL_TOKEN}` }, ...over });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; signing_secret: string };
    return { id: body.id, secret: body.signing_secret };
  }

  async function emailChannel(slug = "soc-mail", over: Record<string, unknown> = {}): Promise<string> {
    const res = await createChannel({
      slug,
      type: "email",
      config: { host: "smtp.example.com", port: 587, tls: "starttls", from: "dlp@example.com", recipients: ["soc@example.com"], username: "dlp" },
      password: SMTP_PASSWORD,
      ...over,
    });
    expect(res.status).toBe(201);
    return ((await res.json()) as { id: string }).id;
  }

  /** A policy on this agent's e-mail findings only (earlier tests' findings stay out of it). */
  async function policyNotifying(agentId: string, channels: string[]): Promise<string> {
    const res = await handleCreatePolicy(
      userReq("POST", "/api/policies", {
        who: admin,
        body: {
          name: `Emails ${uuidv7()}`,
          conditions: { classifiers: ["pii.email"], agent_ids: [agentId] },
          actions: [{ type: "create_incident", severity: "high" }, ...channels.map((channel) => ({ type: "notify", channel }))],
        },
      }),
    );
    expect(res.status).toBe(201);
    return ((await res.json()) as { id: string }).id;
  }

  async function deliveriesOf(incidentId: string) {
    return getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.incidentId, incidentId)).orderBy(notificationDeliveries.channelSlug);
  }

  describe("channels API: admin only, CSRF, secrets never returned, audited without secrets", () => {
    it("creates, lists, updates, rotates and deletes", async () => {
      const { id, secret } = await webhookChannel();
      expect(secret).toMatch(/^whsec_/);
      const mailId = await emailChannel();
      const list = await handleListChannels(userReq("GET", "/api/notification-channels", { who: admin }));
      const text = await list.text();
      expect(text).not.toContain(secret);
      expect(text).not.toContain(URL_TOKEN);
      expect(text).not.toContain(SMTP_PASSWORD);
      const channels = (JSON.parse(text) as { channels: { id: string; config: Record<string, unknown>; secret_set: boolean }[] }).channels;
      expect(channels.find((c) => c.id === id)?.config).toEqual({ origin: hookBase });
      expect(channels.find((c) => c.id === mailId)).toMatchObject({ secret_set: true });

      expect((await updateChannel(id, { enabled: false, system_alerts: true })).status).toBe(204);
      const rotated = await handleRotateChannelSecret(userReq("POST", `/api/notification-channels/${id}/rotate-secret`, { who: admin }), id);
      const next = ((await rotated.json()) as { signing_secret: string }).signing_secret;
      expect(next).toMatch(/^whsec_/);
      expect(next).not.toBe(secret);
      expect(await (await updateChannel(mailId, { config: { host: "smtp.example.com", port: 587, tls: "starttls", from: "dlp@example.com", recipients: ["soc@example.com"] }, password: "x" })).json()).toEqual({
        error: "invalid_channel",
        field: "password",
      });
      // M1: the stored password never follows the channel to another relay without being re-entered.
      const moved = { host: "attacker.example.net", port: 587, tls: "starttls", from: "dlp@example.com", recipients: ["soc@example.com"], username: "dlp" };
      for (const config of [
        moved,
        { ...moved, host: "smtp.example.com", port: 2525 },
        { ...moved, host: "smtp.example.com", tls: "implicit" },
        { ...moved, host: "smtp.example.com", username: "other" },
      ]) {
        const r = await updateChannel(mailId, { config });
        expect(r.status).toBe(400);
        expect(await r.json()).toEqual({ error: "password_required" });
      }
      // Same relay (recipients changed): the password is kept.
      expect((await updateChannel(mailId, { config: { ...moved, host: "smtp.example.com", recipients: ["x@example.com"] } })).status).toBe(204);
      expect((await updateChannel(mailId, { config: moved, password: "new-relay-password" })).status).toBe(204);
      expect((await updateChannel(mailId, { password: null })).status).toBe(204);
      // Without a stored password, moving is free.
      expect((await updateChannel(mailId, { config: { ...moved, host: "relay2.example.net" } })).status).toBe(204);
      expect((await createChannel({ slug: "soc-hook", type: "webhook", config: { url: "https://h.example.com/x" } })).status).toBe(409);
      expect(await (await createChannel({ slug: "x", type: "webhook", config: { url: "https://169.254.169.254/" } })).json()).toEqual({
        error: "invalid_channel",
        field: "config.url",
      });
      expect((await handleDeleteChannel(userReq("DELETE", `/api/notification-channels/${id}`, { who: admin }), id)).status).toBe(204);

      // Secrets are encrypted at rest; the audit log holds none of them (nor the URL).
      const dump = String(
        (
          await getDb().execute(sql`
            select coalesce(string_agg(t, ' '), '') as s from (
              select row_to_json(c)::text as t from notification_channels c
              union all select encode(secret, 'escape') from notification_channels where secret is not null
              union all select row_to_json(l)::text from audit_log l) x`)
        ).rows[0]?.s,
      );
      for (const s of [secret, next, URL_TOKEN, SMTP_PASSWORD]) expect(dump).not.toContain(s);
      const actions = (await getDb().select().from(auditLog).where(sql`${auditLog.action} like 'notification_channel.%'`)).map((a) => a.action);
      expect(actions).toEqual(
        expect.arrayContaining([
          "notification_channel.create",
          "notification_channel.update",
          "notification_channel.rotate_signing_key",
          "notification_channel.delete",
        ]),
      );
    });

    it("refuses analysts (audited), missing CSRF, and http:// URLs without the dev flag", async () => {
      const res = await createChannel({ slug: "x", type: "webhook", config: { url: "https://h.example.com/" } }, analyst);
      expect(res.status).toBe(403);
      expect((await handleListChannels(userReq("GET", "/api/notification-channels", { who: analyst }))).status).toBe(403);
      expect((await createChannel({ slug: "x", type: "webhook", config: { url: "https://h.example.com/" } }, { ...admin, csrf: "" })).status).toBe(403);
      const denied = await getDb().select().from(auditLog).where(eq(auditLog.action, "user.access_denied"));
      expect(denied.some((a) => (a.details as Record<string, unknown>).route === "notification_channel.create")).toBe(true);
      delete process.env.DATABASTION_ALERTING_INSECURE_DEV;
      expect(await (await createChannel({ slug: "x", type: "webhook", config: { url: `${hookBase}/x` } })).json()).toEqual({
        error: "invalid_channel",
        field: "config.url",
      });
    });

    it("without the server key, no secret can be stored", async () => {
      const saved = process.env.DATABASTION_ENCRYPTION_KEY;
      delete process.env.DATABASTION_ENCRYPTION_KEY;
      try {
        const res = await createChannel({ slug: "nokey", type: "webhook", config: { url: "https://h.example.com/" } });
        expect(res.status).toBe(409);
        expect(await res.json()).toEqual({ error: "encryption_key_unavailable" });
      } finally {
        process.env.DATABASTION_ENCRYPTION_KEY = saved;
      }
    });
  });

  describe("incident notifications", () => {
    it("one delivery per (incident, channel); unknown and disabled slugs are recorded as skipped", async () => {
      const { secret } = await webhookChannel("soc-hook");
      await emailChannel("off-mail", { enabled: false });
      const auth = await agentWithTargets();
      await policyNotifying(auth.agentId, ["soc-hook", "no-such-channel", "off-mail"]);
      await scan(auth);
      await drainPolicyWork(getDb());
      const [incident] = await getDb().select().from(incidents).where(eq(incidents.agentId, auth.agentId));
      if (!incident) throw new Error("no incident");
      let rows = await deliveriesOf(incident.id);
      expect(rows.map((r) => [r.channelSlug, r.status, r.lastError])).toEqual([
        ["no-such-channel", "skipped", "unknown_channel"],
        ["off-mail", "skipped", "channel_disabled"],
        ["soc-hook", "pending", null],
      ]);
      // Re-evaluations (a policy pass) never duplicate the deliveries.
      await getDb().update(policies).set({ changedAt: sql`now()` });
      await drainPolicyWork(getDb());
      expect(await deliveriesOf(incident.id)).toHaveLength(3);

      const n = hook.received.length;
      const stats = await drainDeliveries(getDb());
      expect(stats).toMatchObject({ attempted: 1, delivered: 1 });
      rows = await deliveriesOf(incident.id);
      expect(rows.find((r) => r.channelSlug === "soc-hook")).toMatchObject({ status: "delivered", attempts: 1, lastError: null });
      const got = hook.received.slice(n);
      expect(got).toHaveLength(1);
      const sent = got[0] as { headers: http.IncomingHttpHeaders; body: string };
      expect(verifyWebhookSignature(secret, String(sent.headers["x-databastion-signature"]), sent.body)).toBe(true);
      const payload = JSON.parse(sent.body) as Record<string, unknown>;
      expect(payload).toMatchObject({
        version: 1,
        event: "incident.opened",
        delivery_id: rows.find((r) => r.channelSlug === "soc-hook")?.id,
        url: `${ORIGIN}/incidents/${incident.id}`,
        incident: { id: incident.id, severity: "high", status: "open", reopened_from: null },
        agent_id: auth.agentId,
        target_id: "pg-prod-1",
        classifier: "pii.email",
        location: { engine: "postgres", database: "crm", schema: "public", object: "clients", field: "email" },
        counts: { sampled: 200, matched: 150, confidence: 0.97 },
      });
      // I2: no sample, masked or not, in what was sent or stored.
      for (const s of SAMPLES) expect(sent.body).not.toContain(s);
      expect(sent.body).not.toContain("e******");
      const stored = String((await getDb().execute(sql`select coalesce(string_agg(row_to_json(d)::text, ' '), '') as s from notification_deliveries d`)).rows[0]?.s);
      for (const s of SAMPLES) expect(stored).not.toContain(s);
      // Nothing left to send.
      expect(await drainDeliveries(getDb())).toMatchObject({ attempted: 0 });
      // The incident page lists them.
      expect((await listDeliveries(getDb(), { incidentId: incident.id })).map((d) => d.status).sort()).toEqual(["delivered", "skipped", "skipped"]);
    });

    it("a new incident after a resolution is flagged reopened_from", async () => {
      await webhookChannel("soc-hook");
      const auth = await agentWithTargets();
      await policyNotifying(auth.agentId, ["soc-hook"]);
      await scan(auth);
      await drainPolicyWork(getDb());
      const [first] = await getDb().select().from(incidents).where(eq(incidents.agentId, auth.agentId));
      const t = await handleIncidentTransition(
        userReq("POST", `/api/incidents/${first?.id}/transition`, { body: { status: "resolved" }, who: analyst }),
        String(first?.id),
      );
      expect(t.status).toBe(204);
      await scan(auth);
      await drainPolicyWork(getDb());
      const rows = await getDb().select().from(incidents).where(and(eq(incidents.agentId, auth.agentId), eq(incidents.status, "open")));
      const [delivery] = await deliveriesOf(String(rows[0]?.id));
      expect((delivery?.payload as { incident: { reopened_from: string } }).incident.reopened_from).toBe(first?.id);
    });

    it("retries with exponential backoff up to the cap, then fails; permanent errors fail at once", async () => {
      await webhookChannel("soc-hook");
      const auth = await agentWithTargets();
      await policyNotifying(auth.agentId, ["soc-hook"]);
      await scan(auth);
      await drainPolicyWork(getDb());
      const [incident] = await getDb().select().from(incidents).where(eq(incidents.agentId, auth.agentId));
      const id = String(incident?.id);
      const flaky = fakeSenders(() => ({ ok: false, code: "http_503", retryable: true }));
      const before = Date.now();
      expect(await drainDeliveries(getDb(), { senders: flaky.senders })).toMatchObject({ attempted: 1, retried: 1 });
      let [row] = await deliveriesOf(id);
      expect(row).toMatchObject({ status: "pending", attempts: 1, lastError: "http_503" });
      const delay = (row?.nextAttemptAt.getTime() ?? 0) - before;
      expect(delay).toBeGreaterThan(50_000);
      expect(delay).toBeLessThan(70_000);
      // Not due yet: nothing is attempted.
      expect(await drainDeliveries(getDb(), { senders: flaky.senders })).toMatchObject({ attempted: 0 });
      expect([1, 2, 3, 4, 5, 6, 7, 8, 9].map(backoffSeconds)).toEqual([60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]);
      for (let i = 2; i <= MAX_DELIVERY_ATTEMPTS; i++) {
        await makeDue();
        await drainDeliveries(getDb(), { senders: flaky.senders });
      }
      [row] = await deliveriesOf(id);
      expect(row).toMatchObject({ status: "failed", attempts: MAX_DELIVERY_ATTEMPTS, lastError: "http_503" });
      expect(flaky.calls).toHaveLength(MAX_DELIVERY_ATTEMPTS);
      await makeDue();
      expect(await drainDeliveries(getDb(), { senders: flaky.senders })).toMatchObject({ attempted: 0 });

      // A permanent failure (e.g. a refused address) fails at the first attempt.
      await scan(auth);
      await getDb().update(incidents).set({ status: "resolved", resolvedAt: sql`now() - interval '1 day'` }).where(eq(incidents.id, id));
      await drainPolicyWork(getDb());
      const permanent = fakeSenders(() => ({ ok: false, code: "address_internal", retryable: false }));
      expect(await drainDeliveries(getDb(), { senders: permanent.senders })).toMatchObject({ attempted: 1, failed: 1 });
    });

    it("the real sender refuses a loopback webhook without the dev flag (SSRF), recorded as failed", async () => {
      await webhookChannel("soc-hook");
      const auth = await agentWithTargets();
      await policyNotifying(auth.agentId, ["soc-hook"]);
      await scan(auth);
      await drainPolicyWork(getDb());
      delete process.env.DATABASTION_ALERTING_INSECURE_DEV;
      const n = hook.received.length;
      expect(await drainDeliveries(getDb())).toMatchObject({ attempted: 1, failed: 1 });
      const [incident] = await getDb().select().from(incidents).where(eq(incidents.agentId, auth.agentId));
      const [row] = await deliveriesOf(String(incident?.id));
      // http:// is refused first (no dev flag); nothing reached the receiver.
      expect(row).toMatchObject({ status: "failed", lastError: "insecure_refused" });
      expect(hook.received.length).toBe(n);
    });

    it("a crashed attempt (expired lease) is claimed again; a deleted channel fails its deliveries", async () => {
      const { id: channelId } = await webhookChannel("soc-hook");
      const auth = await agentWithTargets();
      await policyNotifying(auth.agentId, ["soc-hook"]);
      await scan(auth);
      await drainPolicyWork(getDb());
      const [incident] = await getDb().select().from(incidents).where(eq(incidents.agentId, auth.agentId));
      const incidentId = String(incident?.id);
      await getDb().execute(sql`update notification_deliveries set status = 'sending', attempts = 1, lease_until = now() - interval '1 second' where incident_id = ${incidentId}`);
      const ok = fakeSenders(() => ({ ok: true }));
      expect(await drainDeliveries(getDb(), { senders: ok.senders })).toMatchObject({ delivered: 1 });
      expect((await deliveriesOf(incidentId))[0]).toMatchObject({ status: "delivered", attempts: 2 });

      await getDb().execute(sql`update notification_deliveries set status = 'pending', delivered_at = null where incident_id = ${incidentId}`);
      expect((await handleDeleteChannel(userReq("DELETE", `/api/notification-channels/${channelId}`, { who: admin }), channelId)).status).toBe(204);
      expect(await drainDeliveries(getDb(), { senders: ok.senders })).toMatchObject({ failed: 1 });
      expect((await deliveriesOf(incidentId))[0]).toMatchObject({ status: "failed", lastError: "channel_deleted", channelSlug: "soc-hook", channelId: null });
    });

    it("an e-mail channel gets a plain-text alert without samples; a channel test is audited", async () => {
      const mailId = await emailChannel("soc-mail");
      const auth = await agentWithTargets();
      await policyNotifying(auth.agentId, ["soc-mail"]);
      await scan(auth);
      await drainPolicyWork(getDb());
      const rec = fakeSenders(() => ({ ok: true }));
      expect(await drainDeliveries(getDb(), { senders: rec.senders })).toMatchObject({ delivered: 1 });
      const mail = rec.calls[0]?.body ?? "";
      expect(mail).toMatch(/^\[DataBastion\] HIGH incident: Emails/);
      expect(mail).toContain("crm.public.clients.email");
      expect(mail).toContain("Matched:    150 of 200");
      for (const s of SAMPLES) expect(mail).not.toContain(s);

      const t = await handleTestChannel(userReq("POST", `/api/notification-channels/${mailId}/test`, { who: admin }), mailId);
      expect(t.status).toBe(202);
      expect(await drainDeliveries(getDb(), { senders: rec.senders })).toMatchObject({ delivered: 1 });
      expect(rec.calls.at(-1)?.body).toMatch(/Test notification/);
      expect((await getDb().select().from(auditLog).where(eq(auditLog.action, "notification_channel.test"))).length).toBeGreaterThanOrEqual(1);
    });

    it("L3: channel tests are rate limited per channel and per admin; connection errors are merged", async () => {
      const ids = [await emailChannel("m1"), await emailChannel("m2"), await emailChannel("m3"), await emailChannel("m4")];
      const test = (id: string) => handleTestChannel(userReq("POST", `/api/notification-channels/${id}/test`, { who: admin }), id);
      const first = ids[0] as string;
      for (let i = 0; i < 3; i++) expect((await test(first)).status).toBe(202);
      const limited = await test(first);
      expect(limited.status).toBe(429);
      expect(Number(limited.headers.get("Retry-After"))).toBeGreaterThanOrEqual(1);
      for (const id of ids.slice(1)) for (let i = 0; i < 3; i++) await test(id);
      // 3 + 3 x 3 = 12 > 10 per admin: the last ones are refused.
      expect(channelTestsPerUser.count((await getDb().select().from(users).where(eq(users.username, "admin")))[0]?.id ?? "")).toBe(10);
      const refusals = await getDb().select().from(auditLog).where(and(eq(auditLog.action, "notification_channel.test"), eq(auditLog.outcome, "failure")));
      expect(refusals.length).toBeGreaterThanOrEqual(3);
      // Refused and filtered connections look the same on a test delivery.
      const timeouts = fakeSenders(() => ({ ok: false, code: "connect_timeout", retryable: true }));
      await drainDeliveries(getDb(), { senders: timeouts.senders });
      const tests = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.event, "channel.test"));
      expect(tests.length).toBeGreaterThan(0);
      expect(tests.filter((t) => t.status === "pending").every((t) => t.lastError === "connect_failed")).toBe(true);
    });

    it("L6: over its hourly budget a channel skips incident notifications, then gets one digest (counts only)", async () => {
      process.env.DATABASTION_NOTIFY_MAX_PER_HOUR = "2";
      const { id: channelId } = await webhookChannel("burst-hook");
      const auth = await agentWithTargets();
      await policyNotifying(auth.agentId, ["burst-hook"]);
      // Three findings, three incidents in the same hour.
      const jobId = await enqueueJob(getDb(), {
        agentId: auth.agentId,
        type: "discovery.scan",
        targetId: "pg-prod-1",
        classifiersVersion: "2026.09.1",
        params: { sample_rows: 200, max_duration_s: 900 },
      });
      expect((await handlePollJobs(agentRequest("GET", "/jobs?wait=0", { auth }))).status).toBe(200);
      const items = ["email", "email2", "email3"].map((field) => ({ ...FINDING, location: { ...FINDING.location, field } }));
      const body = { batch_id: uuidv7(), job_id: jobId, classifiers_version: "2026.09.1", findings: items };
      expect((await handleFindings(agentRequest("POST", "/findings", { auth, body }))).status).toBe(202);
      await drainPolicyWork(getDb());
      const rows = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.channelId, channelId));
      expect(rows.map((r) => [r.status, r.lastError]).sort()).toEqual([
        ["pending", null],
        ["pending", null],
        ["skipped", "rate_limited"],
      ]);
      // The hour is not over: no digest yet.
      expect(await enqueueSuppressionDigests(getDb())).toBe(0);
      // Fake time: the suppressed row belongs to a closed hour.
      await getDb().execute(sql`update notification_deliveries set created_at = date_trunc('hour', now()) - interval '30 minutes' where channel_id = ${channelId} and last_error = 'rate_limited'`);
      expect(await enqueueSuppressionDigests(getDb())).toBe(1);
      expect(await enqueueSuppressionDigests(getDb())).toBe(0);
      const [digest] = await getDb().select().from(notificationDeliveries).where(and(eq(notificationDeliveries.channelId, channelId), eq(notificationDeliveries.event, "notifications.suppressed")));
      expect(digest?.payload).toMatchObject({ event: "notifications.suppressed", channel: "burst-hook", suppressed: 1, limit_per_hour: 2 });
      expect(JSON.stringify(digest?.payload)).not.toContain(auth.agentId);
      const rec = fakeSenders(() => ({ ok: true }));
      await drainDeliveries(getDb(), { senders: rec.senders });
      expect(rec.calls.some((c) => c.body.includes('"suppressed":1'))).toBe(true);
    });

    it("a secret sealed under another server key is unusable: secret_unavailable (retried)", async () => {
      await webhookChannel("soc-hook");
      const auth = await agentWithTargets();
      await policyNotifying(auth.agentId, ["soc-hook"]);
      await scan(auth);
      await drainPolicyWork(getDb());
      const saved = process.env.DATABASTION_ENCRYPTION_KEY;
      process.env.DATABASTION_ENCRYPTION_KEY = "rotated-server-key-0123456789abcdefghijklmnop";
      try {
        const rec = fakeSenders(() => ({ ok: true }));
        expect(await drainDeliveries(getDb(), { senders: rec.senders })).toMatchObject({ retried: 1 });
        expect(rec.calls).toHaveLength(0);
      } finally {
        process.env.DATABASTION_ENCRYPTION_KEY = saved;
      }
      const [incident] = await getDb().select().from(incidents).where(eq(incidents.agentId, auth.agentId));
      expect((await deliveriesOf(String(incident?.id)))[0]).toMatchObject({ status: "pending", lastError: "secret_unavailable" });
      expect(await getIncident(getDb(), String(incident?.id))).not.toBeNull();
    });
  });

  describe("silent agents (fake time)", () => {
    async function lastSeen(agentId: string): Promise<Date> {
      const [a] = await getDb().select({ at: agents.lastSeenAt }).from(agents).where(eq(agents.id, agentId));
      return a?.at as Date;
    }
    const silentRows = (agentId: string) =>
      getDb().select().from(notificationDeliveries).where(and(eq(notificationDeliveries.agentId, agentId))).orderBy(notificationDeliveries.createdAt);

    it("one alert per silence episode, a recovery notice, then a new episode", async () => {
      await webhookChannel("ops-hook", { system_alerts: true });
      await webhookChannel("soc-hook");
      const auth = await agentWithTargets("silent-host");
      const t0 = await lastSeen(auth.agentId);
      const at = (s: number) => new Date(t0.getTime() + s * 1000);

      const events = () =>
        getDb().select().from(securityEvents).where(and(eq(securityEvents.agentId, auth.agentId), eq(securityEvents.kind, "agent.silent")));
      // Just under the threshold: nothing (for this agent; agents of earlier tests may be silent).
      await checkSilentAgents(getDb(), { now: at(299), thresholdS: 300 });
      expect(await silentRows(auth.agentId)).toHaveLength(0);
      expect(await events()).toHaveLength(0);
      // Over it: one alert, to the system-alert channel only.
      expect((await checkSilentAgents(getDb(), { now: at(301), thresholdS: 300 })).silent).toBeGreaterThanOrEqual(1);
      // Later checks in the same episode: nothing more (no alert storm).
      await checkSilentAgents(getDb(), { now: at(900), thresholdS: 300 });
      await checkSilentAgents(getDb(), { now: at(86_400), thresholdS: 300 });
      let rows = await silentRows(auth.agentId);
      expect(rows.map((r) => [r.event, r.channelSlug])).toEqual([["agent.silent", "ops-hook"]]);
      const silent = await events();
      expect(silent).toHaveLength(1);
      expect(silent[0]).toMatchObject({ severity: "medium", details: { threshold_s: 300 } });
      expect(rows[0]?.securityEventId).toBe(silent[0]?.id);
      expect(await getDb().select().from(auditLog).where(and(eq(auditLog.action, "agent.silent"), eq(auditLog.targetId, auth.agentId)))).toHaveLength(1);
      const payload = rows[0]?.payload as Record<string, unknown>;
      expect(payload).toMatchObject({ event: "agent.silent", agent: { id: auth.agentId, hostname: "silent-host" }, threshold_s: 300 });

      // The agent reports again: a recovery notice, once.
      await heartbeat(auth);
      const t1 = await lastSeen(auth.agentId);
      const soon = new Date(t1.getTime() + 1000);
      expect((await checkSilentAgents(getDb(), { now: soon, thresholdS: 300 })).recovered).toBe(1);
      expect((await checkSilentAgents(getDb(), { now: soon, thresholdS: 300 })).recovered).toBe(0);
      rows = await silentRows(auth.agentId);
      expect(rows.map((r) => r.event)).toEqual(["agent.silent", "agent.recovered"]);
      expect(await getDb().select().from(auditLog).where(and(eq(auditLog.action, "agent.recovered"), eq(auditLog.targetId, auth.agentId)))).toHaveLength(1);

      // A later silence is a new episode: a new alert.
      await checkSilentAgents(getDb(), { now: new Date(t1.getTime() + 301_000), thresholdS: 300 });
      expect((await silentRows(auth.agentId)).map((r) => r.event)).toEqual(["agent.silent", "agent.recovered", "agent.silent"]);

      // Delivered through the real webhook sender (dev flag), signed.
      const n = hook.received.length;
      await drainDeliveries(getDb());
      const mine = hook.received
        .slice(n)
        .map((r) => JSON.parse(r.body) as { event: string; agent: { id: string } })
        .filter((b) => b.agent.id === auth.agentId);
      expect(mine.map((b) => b.event).sort()).toEqual(["agent.recovered", "agent.silent", "agent.silent"]);
      expect((await silentRows(auth.agentId)).every((r) => r.status === "delivered")).toBe(true);
    });

    it("revoked, locked and never-online agents are excluded; the startup grace holds new alerts", async () => {
      await webhookChannel("ops-hook", { system_alerts: true });
      const revoked = await agentWithTargets("revoked-host");
      const locked = await agentWithTargets("locked-host");
      const never = await enroll("never-host");
      const graced = await agentWithTargets("graced-host");
      await getDb().update(agents).set({ status: "revoked", revokedAt: sql`now()` }).where(eq(agents.id, revoked.agentId));
      await getDb().update(agents).set({ status: "locked", lockedAt: sql`now()` }).where(eq(agents.id, locked.agentId));
      const t0 = await lastSeen(graced.agentId);
      const later = new Date(t0.getTime() + 3600_000);
      // Grace: the worker started less than a threshold ago.
      expect(await checkSilentAgents(getDb(), { now: later, thresholdS: 300, notBefore: new Date(later.getTime() + 1) })).toMatchObject({ silent: 0 });
      const stats = await checkSilentAgents(getDb(), { now: later, thresholdS: 300, notBefore: later });
      expect(stats.silent).toBeGreaterThanOrEqual(1);
      for (const a of [revoked, locked, never]) expect(await silentRows(a.agentId)).toHaveLength(0);
      expect((await silentRows(graced.agentId)).map((r) => r.event)).toEqual(["agent.silent"]);
    });

    it("without a system-alert channel the security event is still recorded", async () => {
      const auth = await agentWithTargets("lonely-host");
      const t0 = await lastSeen(auth.agentId);
      // Other agents of earlier tests may be silent too at this fake time.
      await checkSilentAgents(getDb(), { now: new Date(t0.getTime() + 301_000), thresholdS: 300 });
      expect(await silentRows(auth.agentId)).toHaveLength(0);
      expect(await getDb().select().from(securityEvents).where(and(eq(securityEvents.agentId, auth.agentId), eq(securityEvents.kind, "agent.silent")))).toHaveLength(1);
    });
  });

  it("agent-integrity events notify the system-alert channels at most once per agent, kind and hour", async () => {
    await webhookChannel("ops-hook", { system_alerts: true });
    const auth = await agentWithTargets("integrity-host");
    for (let i = 0; i < 3; i++) {
      await recordIntegrityEvent(getDb(), { agentId: auth.agentId, kind: "batch_rejected", endpoint: "findings", status: 400, details: [{ pointer: "/findings/0/matched", keyword: "maximum" }], ip: null });
    }
    await recordIntegrityEvent(getDb(), { agentId: auth.agentId, kind: "batch_conflict", endpoint: "findings", status: 409, ip: null });
    const rows = await getDb().select().from(notificationDeliveries).where(eq(notificationDeliveries.agentId, auth.agentId));
    expect(rows.map((r) => (r.payload as { kind: string }).kind).sort()).toEqual(["agent.batch_conflict", "agent.batch_rejected"]);
    expect(await getDb().select().from(securityEvents).where(eq(securityEvents.agentId, auth.agentId))).toHaveLength(4);
  });

  it("delivers through real pg-boss queues run by the runtime role (policy engine -> notifications)", async () => {
    const { url } = await createRuntimeRole();
    const boss = new PgBoss(pgBossOptions(url));
    boss.on("error", () => undefined);
    await boss.start();
    try {
      const runtimeDb = drizzle(new Pool({ connectionString: url, max: 4 }), { schema });
      await registerPolicyQueue(boss, () => runtimeDb, logger, { pollingIntervalSeconds: 0.5 });
      await registerNotificationQueue(boss, () => runtimeDb, logger, { pollingIntervalSeconds: 0.5 });
      const { secret } = await webhookChannel("soc-hook");
      const auth = await agentWithTargets();
      await policyNotifying(auth.agentId, ["soc-hook"]);
      await scan(auth);
      const n = hook.received.length;
      // Only the policy wake-up is sent: the engine wakes the notification queue itself.
      await boss.send(POLICY_QUEUE, {});
      for (let i = 0; i < 150 && hook.received.length === n; i++) await new Promise((r) => setTimeout(r, 100));
      const got = hook.received.slice(n);
      expect(got).toHaveLength(1);
      expect(verifyWebhookSignature(secret, String(got[0]?.headers["x-databastion-signature"]), String(got[0]?.body))).toBe(true);
      await runtimeDb.$client.end();
    } finally {
      await boss.stop({ graceful: false, timeout: 2000 });
    }
  });

  it("the runtime role sends and records deliveries but cannot delete or rewrite them (migration 0019)", async () => {
    const { url } = await createRuntimeRole();
    await webhookChannel("soc-hook");
    const auth = await agentWithTargets();
    await policyNotifying(auth.agentId, ["soc-hook"]);
    await scan(auth);
    const pool = new Pool({ connectionString: url, max: 2 });
    try {
      const db = drizzle(pool, { schema });
      await drainPolicyWork(db);
      const ok = fakeSenders(() => ({ ok: false, code: "http_500", retryable: true }));
      expect(await drainDeliveries(db, { senders: ok.senders })).toMatchObject({ retried: 1 });
      await expect(pool.query("delete from notification_deliveries")).rejects.toThrow(/permission denied/);
      await expect(pool.query("update notification_deliveries set payload = '{}'::jsonb")).rejects.toThrow(/permission denied/);
      await expect(pool.query("update notification_deliveries set channel_slug = 'x'")).rejects.toThrow(/permission denied/);
      // Silent-agent check as the runtime role.
      await expect(checkSilentAgents(db, { now: new Date(Date.now() + 86_400_000), thresholdS: 300 })).resolves.toBeDefined();
    } finally {
      await pool.end();
    }
  });
});
