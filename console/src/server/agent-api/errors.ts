import { randomUUID } from "node:crypto";

import type { Schemas, ValidationDetail } from "@/lib/protocol/validate";

export type ErrorCode = Schemas["Error"]["code"];

/** Fixed, generic messages: an error body never echoes a submitted value (contract `Error`). */
const MESSAGES: Record<ErrorCode, string> = {
  invalid_request: "The request does not conform to the protocol.",
  unauthorized: "Authentication failed.",
  not_found: "The referenced resource was not found.",
  conflict: "The request conflicts with the current state.",
  batch_conflict: "This batch was already received with a different content.",
  rotation_conflict: "Secret rotation conflict: the agent has been locked.",
  invalid_secret: "The new secret was rejected.",
  payload_too_large: "The request body is too large.",
  protocol_unsupported: "The protocol version is not supported.",
  rate_limited: "Too many requests.",
  unavailable: "The console is temporarily unavailable.",
  internal: "Internal error.",
};

/** Headers of every agent API response: nothing is cacheable (some responses carry a secret). */
export const NO_STORE = { "Cache-Control": "no-store" } as const;

export interface ErrorOptions {
  details?: ValidationDetail[];
  minProtocol?: number;
  retryAfterS?: number;
}

export function agentError(status: number, code: ErrorCode, opts: ErrorOptions = {}): Response {
  const body: Schemas["Error"] = { code, message: MESSAGES[code], request_id: randomUUID() };
  if (opts.minProtocol !== undefined) body.min_protocol = opts.minProtocol;
  if (opts.details && opts.details.length > 0) body.details = opts.details;
  const headers: Record<string, string> = { ...NO_STORE };
  if (opts.retryAfterS !== undefined) headers["Retry-After"] = String(opts.retryAfterS);
  return Response.json(body, { status, headers });
}

export const invalidRequest = (details?: ValidationDetail[]) =>
  agentError(400, "invalid_request", { details });
export const unauthorized = () => agentError(401, "unauthorized");
export const rateLimited = (retryAfterS: number) =>
  agentError(429, "rate_limited", { retryAfterS });
export const unavailable = () => agentError(503, "unavailable", { retryAfterS: 5 });
