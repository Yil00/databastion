import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { processGlobal } from "./process-global";
import { NO_SENDER_WARNING_INTERVAL_MS } from "./wake-up";

/**
 * `next build` gives the startup hook and the route handlers separate copies of the same server
 * module (P4-D E2E: `requestPolicyEvaluation` compiled to an empty function, the sender installed at
 * startup was never seen by the routes). `vi.resetModules()` + a fresh import reproduces two copies.
 */
async function freshCopy<T>(path: string): Promise<T> {
  vi.resetModules();
  return (await import(/* @vite-ignore */ path)) as T;
}

type PolicyQueue = typeof import("./policy-queue");
type NotificationQueue = typeof import("./notification-queue");

async function resetSenders(): Promise<void> {
  (await import("./policy-queue")).setPolicyJobSender(null);
  (await import("./notification-queue")).setNotificationJobSender(null);
  processGlobal("wakeUpNoSenderWarnedAt", () => new Map<string, number>()).clear();
}

describe("wake-ups across module copies", () => {
  beforeEach(resetSenders);
  afterEach(async () => {
    vi.unstubAllEnvs();
    vi.useRealTimers();
    vi.doUnmock("pg-boss");
    await resetSenders();
  });

  it("the policy sender installed by one copy is used by another copy", async () => {
    const startup = await freshCopy<PolicyQueue>("./policy-queue");
    const route = await freshCopy<PolicyQueue>("./policy-queue");
    expect(route.requestPolicyEvaluation).not.toBe(startup.requestPolicyEvaluation);
    const send = vi.fn(async () => undefined);
    startup.setPolicyJobSender(send);
    await route.requestPolicyEvaluation();
    expect(send).toHaveBeenCalledTimes(1);
    route.setPolicyJobSender(null);
    await startup.requestPolicyEvaluation();
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("the notification sender installed by one copy is used by another copy", async () => {
    const startup = await freshCopy<NotificationQueue>("./notification-queue");
    const route = await freshCopy<NotificationQueue>("./notification-queue");
    expect(route.requestNotificationDelivery).not.toBe(startup.requestNotificationDelivery);
    const send = vi.fn(async () => undefined);
    startup.setNotificationJobSender(send);
    await route.requestNotificationDelivery();
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("the pg-boss senders installed at startup reach the queues from the route copies", async () => {
    const sent: string[] = [];
    let instances = 0;
    vi.doMock("pg-boss", () => ({
      PgBoss: class {
        constructor() {
          instances++;
        }
        on() {}
        async start() {
          return this;
        }
        async send(queue: string) {
          sent.push(queue);
          return null;
        }
      },
    }));
    vi.stubEnv("DATABASE_URL", "postgres://wake-up-test.invalid/db");
    const startup = await freshCopy<typeof import("./policy-queue-boss")>("./policy-queue-boss");
    startup.installPgBossPolicySender();
    const policies = await freshCopy<PolicyQueue>("./policy-queue");
    const notifications = await freshCopy<NotificationQueue>("./notification-queue");
    await policies.requestPolicyEvaluation();
    await notifications.requestNotificationDelivery();
    await policies.requestPolicyEvaluation();
    expect(sent).toEqual(["policies.evaluate", "notifications.deliver", "policies.evaluate"]);
    // A second installation (another copy of the startup module) reuses the process's pg-boss.
    (await freshCopy<typeof import("./policy-queue-boss")>("./policy-queue-boss")).installPgBossPolicySender();
    await policies.requestPolicyEvaluation();
    expect(instances).toBe(1);
  });

  it("a failing sender is logged, never thrown", async () => {
    const queue = await freshCopy<PolicyQueue>("./policy-queue");
    const { logger } = await import("@/lib/logger");
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
    queue.setPolicyJobSender(async () => {
      throw new Error("queue down");
    });
    await expect(queue.requestPolicyEvaluation()).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.objectContaining({ queue: "policies.evaluate" }), "policy evaluation wake-up not sent");
  });

  it("warns, rate-limited, when a production process has no sender", async () => {
    vi.useFakeTimers({ now: new Date("2026-09-29T10:00:00Z") });
    vi.stubEnv("NODE_ENV", "production");
    // Every copy has its own logger too: record the warnings of all of them.
    const calls: unknown[][] = [];
    const spyLogger = async () => {
      const { logger } = await import("@/lib/logger");
      vi.spyOn(logger, "warn").mockImplementation((...args: unknown[]) => {
        calls.push(args);
      });
    };
    const first = await freshCopy<PolicyQueue>("./policy-queue");
    await spyLogger();
    const second = await freshCopy<PolicyQueue>("./policy-queue");
    await spyLogger();
    const notifications = await freshCopy<NotificationQueue>("./notification-queue");
    await spyLogger();
    const warnings = () => calls.filter(([, msg]) => typeof msg === "string" && msg.startsWith("wake-up not sent"));

    await first.requestPolicyEvaluation();
    await second.requestPolicyEvaluation();
    await first.requestPolicyEvaluation();
    // Once per queue and process, whichever copy asks.
    expect(warnings()).toHaveLength(1);
    expect(warnings()[0]?.[0]).toEqual({ queue: "policies.evaluate" });
    await notifications.requestNotificationDelivery();
    expect(warnings()).toHaveLength(2);

    vi.advanceTimersByTime(NO_SENDER_WARNING_INTERVAL_MS - 1);
    await second.requestPolicyEvaluation();
    expect(warnings()).toHaveLength(2);
    vi.advanceTimersByTime(1);
    await second.requestPolicyEvaluation();
    expect(warnings()).toHaveLength(3);
  });

  it("stays silent without a sender outside production (tests, CLIs)", async () => {
    vi.stubEnv("NODE_ENV", "test");
    const queue = await freshCopy<PolicyQueue>("./policy-queue");
    const { logger } = await import("@/lib/logger");
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
    await queue.requestPolicyEvaluation();
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("process counters across module copies", () => {
  it("the /events counters incremented by a route copy are read by another copy", async () => {
    const route = await freshCopy<typeof import("./events")>("./events");
    const listener = await freshCopy<typeof import("./events")>("./events");
    const before = listener.eventStats.backpressure;
    route.eventStats.backpressure++;
    expect(listener.eventStats.backpressure).toBe(before + 1);
    route.eventStats.backpressure--;
  });

  it("the argon2 counters counted by a route copy are read by another copy", async () => {
    const route = await freshCopy<typeof import("./crypto")>("./crypto");
    const listener = await freshCopy<typeof import("./crypto")>("./crypto");
    const before = listener.argon2Stats.started;
    await route.argon2Hash("wake-up-test-not-a-secret");
    expect(listener.argon2Stats.started).toBe(before + 1);
  });

  it("the database pool is shared by every copy of the client", async () => {
    vi.stubEnv("DATABASE_URL", "postgres://wake-up-test.invalid/db");
    const a = await freshCopy<typeof import("@/db/client")>("@/db/client");
    const b = await freshCopy<typeof import("@/db/client")>("@/db/client");
    try {
      expect(b.getPool()).toBe(a.getPool());
      expect(b.getDb()).not.toBe(a.getDb());
    } finally {
      await a.closeDb();
      vi.unstubAllEnvs();
    }
    // A closed pool is replaced for every copy.
    vi.stubEnv("DATABASE_URL", "postgres://wake-up-test.invalid/db");
    try {
      const again = b.getPool();
      expect(a.getPool()).toBe(again);
    } finally {
      await b.closeDb();
      vi.unstubAllEnvs();
    }
  });
});
