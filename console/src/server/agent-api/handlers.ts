import { eq } from "drizzle-orm";

import { getDb } from "@/db/client";
import { agents } from "@/db/schema";
import { validateSchema } from "@/lib/protocol/validate";
import { enrollAgent, recordHeartbeat } from "@/server/agents";
import { applyJobStatus, claimJobs } from "@/server/jobs";
import { RateLimiter } from "@/server/rate-limit";
import {
  lockAgentForConflict,
  rotatePerAgent,
  rotateSecret,
  staleRotateRetry,
  type RotateOutcome,
} from "@/server/rotation";
import { AGENT_SECRET_FORMAT, isLowEntropySecret } from "@/server/crypto";
import { BODY_READ_DEADLINE_MS, clientIp, ipBucket, readJsonBody, type BodyResult } from "@/server/request";

import { authenticateAgent, authPrecheck, type AuthOptions, type AuthResult } from "./auth";
import { agentError, invalidRequest, NO_STORE, rateLimited, unauthorized, unavailable } from "./errors";
import { jobHub } from "./job-hub";
import {
  checkProtocolHeaders,
  conformingJson,
  CONSOLE_MIN_PROTOCOL,
  guarded,
  HEARTBEAT_INTERVAL_S,
  readValidBody,
  validateBody,
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
      const limit = enrollPerIp.hit(ipBucket(ip));
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

type Preamble = Extract<AuthResult, { ok: true }> | { ok: false; response: Response };

async function preamble(req: Request, opts: AuthOptions = {}): Promise<Preamble> {
  const headers = checkProtocolHeaders(req);
  if (headers) return { ok: false, response: headers };
  const auth = await authenticateAgent(req, opts);
  if (auth.ok) return auth;
  if (auth.staleSecret) {
    // `S0` used after the tolerance window (ADR-0008 / ADR-0010): treated like rotation_conflict.
    await lockAgentForConflict(getDb(), auth.agentId, "stale_secret", clientIp(req));
    return { ok: false, response: agentError(409, "rotation_conflict") };
  }
  return { ok: false, response: auth.response };
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
    // Reserved synchronously (also for wait=0: L-a), before any await, released in `finally` (M2).
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
        if (reason === "aborted") break;
        // Revocation, lock or promotion (L2: the poll is bound to the secret it was opened with),
        // possibly from a console process whose NOTIFY we missed.
        if (!(await stillActive(agentId, auth.matchedHash))) return unauthorized();
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

/** The agent is active AND the secret that authenticated the poll is still its current one. */
async function stillActive(agentId: string, matchedHash: string): Promise<boolean> {
  const [row] = await getDb()
    .select({ revokedAt: agents.revokedAt, lockedAt: agents.lockedAt, hash: agents.currentSecretHash })
    .from(agents)
    .where(eq(agents.id, agentId))
    .limit(1);
  return !!row && row.revokedAt === null && row.lockedAt === null && row.hash === matchedHash;
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

/**
 * `/rotate` bodies are read BEFORE the argon2id authentication, but after its cheap checks
 * (`authPrecheck`: headers, secret format, failure limits; L1), so that the late-retry check of a
 * stale `S0` runs under the argon2id pool slot of the authentication itself (P1-D). 64 KiB cap
 * (`413` after authentication beyond); 10 s read deadline (`400` before any argon2id work). Apart
 * from that deadline, nothing about the body is answered before the caller is authenticated.
 */
export const MAX_ROTATE_BODY_BYTES = 64 * 1024;
/** Read deadline of the `/rotate` body (test hook: tests shorten it). */
export const rotateBodyDeadline = { ms: BODY_READ_DEADLINE_MS };

/** A well-formed `new_secret` of a body not validated yet, for `AuthOptions.staleCandidate`. */
function rotateCandidate(body: BodyResult): string | undefined {
  if (!body.ok || typeof body.value !== "object" || body.value === null || Array.isArray(body.value)) {
    return undefined;
  }
  const candidate = (body.value as Record<string, unknown>).new_secret;
  if (typeof candidate !== "string" || !AGENT_SECRET_FORMAT.test(candidate) || isLowEntropySecret(candidate)) {
    return undefined;
  }
  return candidate;
}

/**
 * `POST /rotate` (ADR-0008, ADR-0010). The body carries a secret: it is never logged, and an error
 * never echoes it. A new secret that fails the `AgentSecret` format is answered `invalid_secret`.
 */
export function handleRotate(req: Request): Promise<Response> {
  return guarded("rotate", async () => {
    const headers = checkProtocolHeaders(req);
    if (headers) return headers;
    // L1: cheap rejections (headers, secret format, failure limits) before buffering the body.
    const pre = await authPrecheck(req);
    if (!pre.ok) return pre.response;
    const raw = await readJsonBody(req, { maxBytes: MAX_ROTATE_BODY_BYTES, deadlineMs: rotateBodyDeadline.ms });
    // A body not received within the deadline is answered before any argon2id work: no pool slot,
    // no counted attempt, and never a lock (a slow network is not a rotation conflict).
    if (!raw.ok && raw.timedOut) return invalidRequest();
    const auth = await preamble(req, { allowPrevious: true, staleCandidate: rotateCandidate(raw) });
    if (!auth.ok) return auth.response;
    if (auth.via === "previous" && auth.stale) {
      // N1: stale S0. Handled before any other check: duplicate or lock, never another answer.
      const body = validateBody(raw, "RotateRequest");
      const outcome = await staleRotateRetry(
        getDb(),
        {
          agentId: auth.agent.id,
          matchedHash: auth.matchedHash,
          verifiedCurrentHash: auth.agent.currentSecretHash,
          staleDuplicate: auth.staleDuplicate,
        },
        body.ok ? body.value : null,
        clientIp(req),
      );
      if (outcome.kind === "duplicate") auth.refundAttempt?.();
      return rotateResponse(outcome);
    }
    const limit = rotatePerAgent.hit(auth.agent.id);
    if (limit.limited) return rateLimited(limit.retryAfterS);
    const body = validateBody(raw, "RotateRequest");
    if (!body.ok) {
      const details = await errorDetails(body.response);
      if (details.length > 0 && details.every((d) => d.pointer === "/new_secret")) {
        return agentError(400, "invalid_secret");
      }
      return body.response;
    }
    const presented = /^Bearer (\S+)$/.exec(req.headers.get("authorization") ?? "")?.[1] ?? "";
    const outcome = await rotateSecret(
      getDb(),
      { agentId: auth.agent.id, via: auth.via, presented, matchedHash: auth.matchedHash },
      body.value,
      clientIp(req),
    );
    // S0 inside the window: the attempt counted by authentication is given back on a duplicate.
    if (outcome.kind === "duplicate") auth.refundAttempt?.();
    return rotateResponse(outcome);
  });
}

function rotateResponse(outcome: RotateOutcome): Response {
  switch (outcome.kind) {
    case "registered":
    case "duplicate":
      return conformingJson("RotateResponse", {
        grace_expires_at: outcome.graceExpiresAt.toISOString(),
        duplicate: outcome.kind === "duplicate",
      });
    case "invalid_secret":
      return agentError(400, "invalid_secret");
    case "not_found":
      return agentError(404, "not_found");
    case "conflict":
      return agentError(409, "rotation_conflict");
    case "busy":
      return unavailable();
    case "unauthorized":
      return unauthorized();
  }
}

async function errorDetails(res: Response): Promise<{ pointer: string }[]> {
  try {
    const body = (await res.clone().json()) as { details?: { pointer: string }[] };
    return body.details ?? [];
  } catch {
    return [];
  }
}
