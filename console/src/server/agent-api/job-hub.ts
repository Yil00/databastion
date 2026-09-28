import { Client } from "pg";

import { getDatabaseUrl } from "@/config/env";
import { errorSummary, logger } from "@/lib/logger";

/**
 * Wake-ups for held `GET /jobs` long-polls.
 *
 * Mechanism: PostgreSQL LISTEN/NOTIFY on ONE dedicated connection per console process (not one
 * per held request), plus an in-memory registry of waiters. A held poll holds no database
 * connection while it waits. Chosen over pg-boss (a queue for worker jobs, not a push channel to
 * HTTP requests) and over pure polling (one query per agent per second). NOTIFY is transactional,
 * so a job becomes visible to the agent exactly when its insert commits.
 *
 * Channels (payload: agent id):
 * - `databastion_jobs`: a job was queued for this agent;
 * - `databastion_agent_revoked`: the agent was revoked or locked; its held polls are closed.
 *
 * If the listener connection is down, waiters still re-check the database every
 * `FALLBACK_RECHECK_MS`, so jobs are delayed at most by that amount.
 */

export const JOBS_CHANNEL = "databastion_jobs";
export const REVOKED_CHANNEL = "databastion_agent_revoked";
export const FALLBACK_RECHECK_MS = 5_000;
/** Held polls allowed at the same time for one agent (a conforming agent holds one). */
export const MAX_HELD_POLLS_PER_AGENT = 2;

export type WakeReason = "job" | "revoked" | "timeout" | "aborted" | "recheck";

interface Waiter {
  wake: (reason: WakeReason) => void;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

class JobHub {
  private readonly waiters = new Map<string, Set<Waiter>>();
  private listener: Client | undefined;
  private connecting: Promise<void> | undefined;

  heldPolls(agentId: string): number {
    return this.waiters.get(agentId)?.size ?? 0;
  }

  private dispatch(agentId: string, reason: WakeReason): void {
    for (const waiter of [...(this.waiters.get(agentId) ?? [])]) waiter.wake(reason);
  }

  /** Wakes this process's held polls of `agentId` (a job is available). */
  notifyJob(agentId: string): void {
    this.dispatch(agentId, "job");
  }

  /** Closes this process's held polls of `agentId`. */
  closeAgent(agentId: string): void {
    this.dispatch(agentId, "revoked");
  }

  /**
   * Waits until a job notification, a revocation, `ms` elapsing, the request being aborted, or the
   * fallback re-check period. Holds no database connection.
   */
  wait(agentId: string, ms: number, signal?: AbortSignal): Promise<WakeReason> {
    void this.ensureListener();
    return new Promise<WakeReason>((resolve) => {
      let set = this.waiters.get(agentId);
      if (!set) {
        set = new Set();
        this.waiters.set(agentId, set);
      }
      const timer = setTimeout(() => waiter.wake("timeout"), ms);
      const recheck = setTimeout(() => waiter.wake("recheck"), Math.min(ms, FALLBACK_RECHECK_MS) + 1);
      const onAbort = () => waiter.wake("aborted");
      const waiter: Waiter = {
        wake: (reason) => {
          clearTimeout(timer);
          clearTimeout(recheck);
          signal?.removeEventListener("abort", onAbort);
          const current = this.waiters.get(agentId);
          current?.delete(waiter);
          if (current?.size === 0) this.waiters.delete(agentId);
          resolve(reason);
        },
      };
      set.add(waiter);
      if (signal?.aborted) waiter.wake("aborted");
      else signal?.addEventListener("abort", onAbort, { once: true });
    });
  }

  private ensureListener(): Promise<void> {
    if (this.listener) return Promise.resolve();
    this.connecting ??= this.connect().finally(() => {
      this.connecting = undefined;
    });
    return this.connecting;
  }

  private async connect(): Promise<void> {
    const client = new Client({
      connectionString: getDatabaseUrl(),
      application_name: "databastion-console-jobhub",
    });
    const drop = () => {
      if (this.listener === client) this.listener = undefined;
      void client.end().catch(() => undefined);
    };
    client.on("error", (err) => {
      logger.warn({ error: errorSummary(err) }, "job hub listener error");
      drop();
    });
    client.on("end", drop);
    client.on("notification", (msg) => {
      if (!msg.payload || !UUID.test(msg.payload)) return;
      if (msg.channel === JOBS_CHANNEL) this.notifyJob(msg.payload);
      else if (msg.channel === REVOKED_CHANNEL) this.closeAgent(msg.payload);
    });
    try {
      await client.connect();
      await client.query(`LISTEN ${JOBS_CHANNEL}`);
      await client.query(`LISTEN ${REVOKED_CHANNEL}`);
      this.listener = client;
    } catch (err) {
      logger.warn({ error: errorSummary(err) }, "job hub listener unavailable, polling fallback");
      drop();
    }
  }

  /** Stops the listener (tests, graceful shutdown). */
  async close(): Promise<void> {
    await this.connecting;
    const client = this.listener;
    this.listener = undefined;
    await client?.end().catch(() => undefined);
  }

  /** Test helper: resolves once the listener is connected. */
  ready(): Promise<void> {
    return this.ensureListener();
  }
}

export const jobHub = new JobHub();
