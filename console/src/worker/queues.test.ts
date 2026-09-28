import type { Job } from "pg-boss";
import { describe, expect, it, vi } from "vitest";

import type { Logger } from "@/lib/logger";

import * as incidents from "@/server/incidents";
import type { Database } from "@/db/client";

import { createNoopHandler, createPolicyHandler, NOOP_QUEUE, type NoopPayload } from "./queues";

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

describe("policies.evaluate handler", () => {
  const log = { warn: vi.fn() } as unknown as Logger;
  const db = () => ({}) as Database;
  const jobs = [{ id: "a" }] as unknown as Job<Record<string, unknown>>[];

  it("drains once per batch and re-queues only when work remains", async () => {
    const run = vi.spyOn(incidents, "runPolicyEvaluation").mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    const requeue = vi.fn(async () => "id");
    const handler = createPolicyHandler(db, log, requeue, 10);
    await handler(jobs);
    expect(requeue).not.toHaveBeenCalled();
    await handler(jobs);
    expect(requeue).toHaveBeenCalledTimes(1);
    expect(run).toHaveBeenCalledTimes(2);
    await handler([]);
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("a failed re-queue is logged, not thrown (the schedule catches up)", async () => {
    vi.spyOn(incidents, "runPolicyEvaluation").mockResolvedValue(true);
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
