import { PgBoss } from "pg-boss";

import { getDatabaseUrl } from "@/config/env";
import { errorSummary, logger } from "@/lib/logger";
import { pgBossOptions } from "@/worker/queues";

import { POLICY_QUEUE, setPolicyJobSender } from "./policy-queue";

/**
 * pg-boss sender of the web process: send only (no maintenance, no schedule, no migration: the
 * worker installs and maintains pg-boss). Started lazily on the first send; a failed start is
 * retried on the next send.
 */
let starting: Promise<PgBoss> | null = null;

function boss(): Promise<PgBoss> {
  if (!starting) {
    const b = new PgBoss({
      ...pgBossOptions(getDatabaseUrl()),
      application_name: "databastion-web",
      max: 2,
      migrate: false,
      supervise: false,
      schedule: false,
    });
    b.on("error", (err: unknown) => logger.warn({ error: errorSummary(err) }, "pg-boss sender error"));
    starting = b.start().catch((err: unknown) => {
      starting = null;
      throw err;
    });
  }
  return starting;
}

export function installPgBossPolicySender(): void {
  setPolicyJobSender(async () => {
    await (await boss()).send(POLICY_QUEUE, {});
  });
}
