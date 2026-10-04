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
 * ignore the value. Today `access_event.bytes` is stored and shown (not scored),
 * `target_status.notes` is stored for the latest heartbeat and rendered, and the
 * `job_progress.coverage` counters are stored with the job's progress and shown with the target's
 * latest scan (src/lib/scan-coverage.ts).
 *
 * Engines added after protocol 0.1.0 are tokens too (`engine.<value>`, ADR-0039 decision 8): until
 * the console lists one, a conforming agent sends no `Engine`, `Connector` or `AuditSource` value of
 * that engine (no target, detected target, finding or event). `engine.cas` (ADR-0041 decision 12):
 * `cas` targets, connectors, findings (service registry and audit log locations) and `cas_audit_log`
 * events are validated, stored and rendered like those of any engine.
 */
export const CONSOLE_ACCEPTS = ["access_event.bytes", "engine.cas", "job_progress.coverage", "target_status.notes"] as const;

export type ConsoleCapability = (typeof CONSOLE_ACCEPTS)[number];
