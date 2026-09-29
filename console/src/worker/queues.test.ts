import type { Job } from "pg-boss";
import { describe, expect, it, vi } from "vitest";

import type { Logger } from "@/lib/logger";

import * as auditStreamAlerts from "@/server/audit-stream-alerts";
import * as droppedBatches from "@/server/dropped-batches";
import * as events from "@/server/events";
import * as incidents from "@/server/incidents";
import * as notifications from "@/server/notifications";
import * as rateLimit from "@/server/rate-limit";
import * as systemAlerts from "@/server/system-alerts";
import type { Database } from "@/db/client";

import {
  createEventsPurgeHandler,
  createNoopHandler,
  createNotificationHandler,
  createPolicyHandler,
  createRateLimitsPruneHandler,
  NOOP_QUEUE,
  type NoopPayload,
} from "./queues";

describe("noop queue handler", () => {
  it("acknowledges every job of the batch without throwing", async () => {
    const debug = vi.fn();
    const handler = createNoopHandler({ debug } as unknown as Logger);
    const jobs = [{ id: "a" }, { id: "b" }] as unknown as Job<NoopPayload>[];

    await expect(handler(jobs)).resolves.toBeUndefined();
    expect(debug).toHaveBeenCalledTimes(2);
    expect(debug).toHaveBeenCalledWith({ queue: NOOP_QUEUE, jobId: "a" }, "noop job processed");
  });
});

const stats = (over: Partial<incidents.DrainStats> = {}): incidents.DrainStats => ({
  events: 0,
  findings: 0,
  policyPasses: 0,
  created: 0,
  more: false,
  ...over,
});

describe("policies.evaluate handler", () => {
  const log = { warn: vi.fn() } as unknown as Logger;
  const db = () => ({}) as Database;
  const jobs = [{ id: "a" }] as unknown as Job<Record<string, unknown>>[];

  it("drains once per batch and re-queues only when work remains", async () => {
    const run = vi
      .spyOn(incidents, "runPolicyEvaluation")
      .mockResolvedValueOnce(stats({ more: false }))
      .mockResolvedValueOnce(stats({ more: true }));
    const requeue = vi.fn(async () => "id");
    const notify = vi.fn(async () => "id");
    const handler = createPolicyHandler(db, log, requeue, 10, notify);
    await handler(jobs);
    expect(requeue).not.toHaveBeenCalled();
    await handler(jobs);
    expect(requeue).toHaveBeenCalledTimes(1);
    expect(notify).not.toHaveBeenCalled();
    expect(run).toHaveBeenCalledTimes(2);
    await handler([]);
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("wakes the notification delivery when incidents were created", async () => {
    vi.spyOn(incidents, "runPolicyEvaluation").mockResolvedValue(stats({ created: 2 }));
    const notify = vi.fn(async () => "id");
    await createPolicyHandler(db, log, async () => "id", 10, notify)(jobs);
    expect(notify).toHaveBeenCalledTimes(1);
  });

  it("a failed re-queue is logged, not thrown (the schedule catches up)", async () => {
    vi.spyOn(incidents, "runPolicyEvaluation").mockResolvedValue(stats({ more: true }));
    const handler = createPolicyHandler(db, log, async () => {
      throw new Error("down");
    });
    await expect(handler(jobs)).resolves.toBeUndefined();
    expect(log.warn).toHaveBeenCalled();
  });

  it("a failed drain fails the job (pg-boss retries it)", async () => {
    vi.spyOn(incidents, "runPolicyEvaluation").mockRejectedValue(new Error("db down"));
    await expect(createPolicyHandler(db, log, async () => "id")(jobs)).rejects.toThrow("db down");
  });
});

describe("notifications.deliver handler", () => {
  const log = { info: vi.fn(), warn: vi.fn() } as unknown as Logger;
  const db = () => ({}) as Database;
  const jobs = [{ id: "a" }] as unknown as Job<Record<string, unknown>>[];
  const delivery = (over: Partial<notifications.DeliveryStats> = {}): notifications.DeliveryStats => ({
    attempted: 0,
    delivered: 0,
    retried: 0,
    failed: 0,
    more: false,
    ...over,
  });

  it("checks silent agents with the startup grace, then drains; re-queues only when work remains", async () => {
    const check = vi.spyOn(systemAlerts, "checkSilentAgents").mockResolvedValue({ silent: 0, recovered: 0 });
    const flush = vi.spyOn(droppedBatches, "flushDroppedBatchAlerts").mockResolvedValue(0);
    const flushStops = vi.spyOn(auditStreamAlerts, "flushAuditStreamStoppedAlerts").mockResolvedValue(0);
    const digests = vi.spyOn(notifications, "enqueueSuppressionDigests").mockResolvedValue(0);
    const systemDigests = vi.spyOn(notifications, "enqueueSystemAlertDigests").mockResolvedValue(0);
    const drain = vi
      .spyOn(notifications, "drainDeliveries")
      .mockResolvedValueOnce(delivery({ attempted: 1, delivered: 1 }))
      .mockResolvedValueOnce(delivery({ attempted: 10, more: true }));
    const requeue = vi.fn(async () => "id");
    const startedAt = new Date("2026-09-28T12:00:00Z");
    const handler = createNotificationHandler(db, log, requeue, { startedAt });
    await handler(jobs);
    expect(check).toHaveBeenCalledWith(expect.anything(), { thresholdS: 300, notBefore: new Date("2026-09-28T12:05:00Z") });
    expect(requeue).not.toHaveBeenCalled();
    await handler(jobs);
    expect(requeue).toHaveBeenCalledTimes(1);
    await handler([]);
    expect(drain).toHaveBeenCalledTimes(2);
    expect(digests).toHaveBeenCalledTimes(2);
    expect(systemDigests).toHaveBeenCalledTimes(2);
    expect(flush).toHaveBeenCalledTimes(2);
    expect(flushStops).toHaveBeenCalledTimes(2);
  });

  it("a failed check fails the job (pg-boss retries it; the outbox keeps the work)", async () => {
    vi.spyOn(systemAlerts, "checkSilentAgents").mockRejectedValue(new Error("db down"));
    await expect(createNotificationHandler(db, log, async () => "id")(jobs)).rejects.toThrow("db down");
  });
});

describe("events.purge handler", () => {
  const log = { info: vi.fn(), warn: vi.fn() } as unknown as Logger;
  const db = () => ({}) as Database;
  const jobs = [{ id: "a" }] as unknown as Job<Record<string, unknown>>[];

  it("purges with the configured retention and re-queues only when rows remain", async () => {
    const purge = vi
      .spyOn(events, "purgeAccessEvents")
      .mockResolvedValueOnce({ deleted: 3, more: false })
      .mockResolvedValueOnce({ deleted: 10_000, more: true });
    const requeue = vi.fn(async () => "id");
    const handler = createEventsPurgeHandler(db, log, requeue, { retentionDays: () => 30, budgetMs: 5 });
    await handler(jobs);
    expect(purge).toHaveBeenCalledWith(expect.anything(), { retentionDays: 30, budgetMs: 5 });
    expect(requeue).not.toHaveBeenCalled();
    await handler(jobs);
    expect(requeue).toHaveBeenCalledTimes(1);
    await handler([]);
    expect(purge).toHaveBeenCalledTimes(2);
  });

  it("a failed purge fails the job (pg-boss retries it)", async () => {
    vi.spyOn(events, "purgeAccessEvents").mockRejectedValue(new Error("db down"));
    await expect(createEventsPurgeHandler(db, log, async () => "id")(jobs)).rejects.toThrow("db down");
  });
});

describe("rate_limits.prune handler", () => {
  const log = { warn: vi.fn(), debug: vi.fn() } as unknown as Logger;
  const db = () => ({}) as Database;
  const jobs = [{ id: "a" }] as unknown as Job<Record<string, unknown>>[];

  it("prunes once per batch and re-queues only when expired rows remain", async () => {
    const prune = vi
      .spyOn(rateLimit, "pruneRateLimitCounters")
      .mockResolvedValueOnce({ deleted: 3, more: false })
      .mockResolvedValueOnce({ deleted: rateLimit.PRUNE_CHUNK, more: true });
    const requeue = vi.fn(async () => "id");
    // Small statements: row locks held far below the limiters' 1.5 s lock_timeout (review L-2).
    expect(rateLimit.PRUNE_CHUNK).toBe(1_000);
    const handler = createRateLimitsPruneHandler(db, log, requeue, { budgetMs: 5 });
    await handler(jobs);
    expect(prune).toHaveBeenCalledWith(expect.anything(), { budgetMs: 5 });
    expect(requeue).not.toHaveBeenCalled();
    await handler(jobs);
    expect(requeue).toHaveBeenCalledTimes(1);
    await handler([]);
    expect(prune).toHaveBeenCalledTimes(2);
  });
});
