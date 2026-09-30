import { sql } from "drizzle-orm";

import type { Database } from "@/db/client";

type Tx = Parameters<Parameters<Database["transaction"]>[0]>[0];

/**
 * Serializes the transactions that write several jobs of one agent: the job claim (`claimJobs`),
 * revocation, the rotation-conflict lock, scan requests and Audit settings. Transaction-scoped
 * advisory lock, released at commit / rollback.
 *
 * Lock order (no cycle, security review L1 of #98): a caller that locks the agent's `agents` row
 * (`UPDATE` or `SELECT ... FOR UPDATE`) does so BEFORE this lock, and every caller takes this lock
 * BEFORE writing the agent's `jobs` rows. The claim takes no `agents` row lock at all (it only
 * reads the row), so it never waits for a transaction that holds this lock's successors.
 */
export async function lockAgentJobs(tx: Tx, agentId: string): Promise<void> {
  await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${`jobs.claim:${agentId}`}, 0))`);
}
