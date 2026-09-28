import type { Job } from "pg-boss";
import { describe, expect, it, vi } from "vitest";

import type { Logger } from "@/lib/logger";

import { createNoopHandler, NOOP_QUEUE, type NoopPayload } from "./queues";

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
