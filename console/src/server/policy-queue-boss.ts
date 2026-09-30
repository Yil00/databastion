import { PgBoss } from "pg-boss";

import { getDatabaseUrl } from "@/config/env";
import { errorSummary, logger } from "@/lib/logger";
import { pgBossOptions } from "@/worker/queues";

import { NOTIFICATION_QUEUE, setNotificationJobSender } from "./notification-queue";
import { POLICY_QUEUE, setPolicyJobSender } from "./policy-queue";
import { processGlobal } from "./process-global";

/**
 * pg-boss sender of the web process: send only (no maintenance, no schedule, no migration: the
 * worker installs and maintains pg-boss). Started lazily on the first send; a failed start is
 * retried on the next send. One per process (globalThis, see process-global.ts), whichever bundled
 * copy of this module installs the senders.
 */
const shared = processGlobal<{ starting: Promise<PgBoss> | null }>("pgBossSender", () => ({ starting: null }));

function boss(): Promise<PgBoss> {
  if (!shared.starting) {
    const b = new PgBoss({
      ...pgBossOptions(getDatabaseUrl()),
      application_name: "databastion-web",
      max: 2,
      migrate: false,
      supervise: false,
      schedule: false,
    });
    b.on("error", (err: unknown) => logger.warn({ error: errorSummary(err) }, "pg-boss sender error"));
    const starting = b.start().catch((err: unknown) => {
      if (shared.starting === starting) shared.starting = null;
      throw err;
    });
    shared.starting = starting;
  }
  return shared.starting;
}

/** Installs the web process senders: policy engine and notification delivery wake-ups. */
export function installPgBossPolicySender(): void {
  setPolicyJobSender(async () => {
    await (await boss()).send(POLICY_QUEUE, {});
  });
  setNotificationJobSender(async () => {
    await (await boss()).send(NOTIFICATION_QUEUE, {});
  });
}
