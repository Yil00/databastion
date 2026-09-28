import { eq } from "drizzle-orm";

import { getDb } from "@/db/client";
import { agents } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import { enrollAgent, recordHeartbeat } from "@/server/agents";
import { applyJobStatus, claimJobs } from "@/server/jobs";
import { RateLimiter } from "@/server/rate-limit";
import { clientIp } from "@/server/request";

import { authenticateAgent } from "./auth";
import { agentError, invalidRequest, NO_STORE, rateLimited, unauthorized, unavailable } from "./errors";
import { jobHub } from "./job-hub";
import {
  checkProtocolHeaders,
  conformingJson,
  CONSOLE_MIN_PROTOCOL,
  guarded,
  HEARTBEAT_INTERVAL_S,
  readValidBody,
} from "./pipeline";

/**
 * Agent API v1 handlers (contract: shared/protocol/openapi.yaml). Every body goes through
 * `readValidBody` (4 MiB cap, `validateSchema` then `checkSemantics`). No handler logs a request
 * body; `/enroll` bodies and responses are never logged at all.
 */

/** `/enroll` attempts per source IP (successful or not). */
export const enrollPerIp = new RateLimiter(20, 10 * 60_000);

export function handleEnroll(req: Request): Promise<Response> {
  return guarded("enroll", async () => {
    const headers = checkProtocolHeaders(req);
    if (headers) return headers;
    const ip = clientIp(req);
    if (ip) {
      const limit = enrollPerIp.hit(ip);
      if (limit.limited) return rateLimited(limit.retryAfterS);
    }
    const body = await readValidBody(req, "EnrollRequest");
    if (!body.ok) return body.response;
    const enrolled = await enrollAgent(getDb(), body.value, ip);
    if (!enrolled) return unauthorized();
    return conformingJson("EnrollResponse", {
      agent_id: enrolled.agentId,
      agent_secret: enrolled.secret,
      console_min_protocol: CONSOLE_MIN_PROTOCOL,
      heartbeat_interval_s: HEARTBEAT_INTERVAL_S,
    });
  });
}

async function preamble(req: Request) {
  const headers = checkProtocolHeaders(req);
  if (headers) return { ok: false as const, response: headers };
  return authenticateAgent(req);
}

export function handleHeartbeat(req: Request): Promise<Response> {
  return guarded("heartbeat", async () => {
    const auth = await preamble(req);
    if (!auth.ok) return auth.response;
    const body = await readValidBody(req, "HeartbeatRequest");
    if (!body.ok) return body.response;
    await recordHeartbeat(getDb(), auth.agent.id, body.value);
    return conformingJson("HeartbeatResponse", {
      console_min_protocol: CONSOLE_MIN_PROTOCOL,
      heartbeat_interval_s: HEARTBEAT_INTERVAL_S,
      server_time: new Date().toISOString(),
    });
  });
}

export const MAX_WAIT_S = 25;
const WAIT = /^(0|[1-9][0-9]?)$/;

/** Parses the query string: only `wait` (integer 0..25, default 25) is allowed. */
export function parseWait(url: URL): number | null {
  let wait = MAX_WAIT_S;
  for (const [key, value] of url.searchParams) {
    if (key !== "wait" || !WAIT.test(value) || Number(value) > MAX_WAIT_S) return null;
    wait = Number(value);
  }
  return url.searchParams.getAll("wait").length > 1 ? null : wait;
}

/** Test hook: shortens the long-poll unit (seconds) so tests do not wait 25 s. */
export const pollClock = { msPerSecond: 1000 };

export function handlePollJobs(req: Request): Promise<Response> {
  return guarded("jobs", async () => {
    const auth = await preamble(req);
    if (!auth.ok) return auth.response;
    const wait = parseWait(new URL(req.url));
    if (wait === null) return invalidRequest();
    const agentId = auth.agent.id;
    if (wait === 0) {
      const jobs = await claimJobs(getDb(), agentId);
      return jobs.length > 0 ? conformingJson("JobList", { jobs }) : noContent();
    }
    // Reserved synchronously, before any await, released in `finally` (M2).
    const slot = jobHub.reserveSlot(agentId);
    if (slot === "agent") return rateLimited(1);
    if (slot === "process") return unavailable();
    try {
      const deadline = Date.now() + wait * pollClock.msPerSecond;
      let claim = true;
      for (;;) {
        const seq = jobHub.seq(agentId);
        if (claim) {
          const jobs = await claimJobs(getDb(), agentId);
          if (jobs.length > 0) return conformingJson("JobList", { jobs });
        }
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;
        // No database connection is held while waiting.
        const reason = await jobHub.wait(agentId, remaining, req.signal, seq);
        if (reason === "revoked") return unauthorized();
        if (reason === "aborted") break;
        // Revocation / lock may have come from a console process whose NOTIFY we missed.
        if (!(await stillActive(agentId))) return unauthorized();
        if (reason === "timeout") break;
        // M3: claim only on a job wake-up, or when the listener is down (polling fallback).
        claim = reason === "job" || !jobHub.listening;
      }
      return noContent();
    } finally {
      slot();
    }
  });
}

const noContent = () => new Response(null, { status: 204, headers: NO_STORE });

async function stillActive(agentId: string): Promise<boolean> {
  const [row] = await getDb()
    .select({ revokedAt: agents.revokedAt, lockedAt: agents.lockedAt, hash: agents.currentSecretHash })
    .from(agents)
    .where(eq(agents.id, agentId))
    .limit(1);
  return !!row && row.revokedAt === null && row.lockedAt === null && row.hash !== null;
}

/** Console-side clock skew tolerance on agent timestamps (contract: 5 min). */
export const MAX_FUTURE_SKEW_MS = 5 * 60_000;

export function handleJobStatus(req: Request, jobId: string): Promise<Response> {
  return guarded("job_status", async () => {
    const auth = await preamble(req);
    if (!auth.ok) return auth.response;
    if (!validateSchema("Uuid", jobId).ok) return invalidRequest();
    const body = await readValidBody(req, "JobStatusUpdate");
    if (!body.ok) return body.response;
    if (Date.parse(body.value.ts) > Date.now() + MAX_FUTURE_SKEW_MS) {
      return invalidRequest([{ pointer: "/ts", keyword: "formatMaximum" }]);
    }
    const outcome = await applyJobStatus(getDb(), auth.agent.id, jobId, body.value);
    if (outcome === "not_found") return agentError(404, "not_found");
    if (outcome === "conflict") return agentError(409, "conflict");
    return noContent();
  });
}
