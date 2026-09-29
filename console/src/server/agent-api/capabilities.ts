/**
 * Capability negotiation (ADR-0022, contract `HeartbeatResponse.accepts`).
 *
 * Every contract schema is closed: an agent that sends an optional request field this console does
 * not know gets `400` (for a heartbeat, the whole heartbeat is lost). The console therefore lists,
 * in every heartbeat response, the optional request fields introduced after protocol 0.1.0 that
 * it accepts, and a conforming agent sends such a field only when the latest list names it.
 *
 * Rule: a token is listed here in the same change that makes the console accept the field (its
 * schema regenerated). "Accepts" means schema-valid and not rejected; the console may still
 * ignore the value (e.g. `access_event.bytes` is not stored yet).
 */
export const CONSOLE_ACCEPTS = ["access_event.bytes", "job_progress.coverage", "target_status.notes"] as const;

export type ConsoleCapability = (typeof CONSOLE_ACCEPTS)[number];
