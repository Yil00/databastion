import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

/**
 * Console internal schema. Changes go through `pnpm db:generate`, which
 * writes a versioned SQL migration under drizzle/ (never edit the DB by hand).
 *
 * Sensitive columns plan (see console/README.md, "Data at rest"):
 * - secrets are never stored in clear: user passwords and agent secrets as argon2id hashes,
 *   enrollment tokens and session tokens as SHA-256 hashes (256-bit random inputs, so a fast hash
 *   is enough);
 * - no column holds a database credential or connection string (invariant I3);
 * - agent-provided strings stored here (hostname, target ids, versions) are bounded by the protocol
 *   schema and are escaped on display;
 * - AES-256-GCM encryption at rest (`DATABASTION_ENCRYPTION_KEY`) comes with the first column that
 *   needs it: masked samples (P2-D), then webhook / SMTP settings.
 */

const tsz = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

/**
 * `meta` is a small key/value table for console-level metadata
 * (e.g. installation id, schema bootstrap markers). It must never hold
 * secrets or sensitive values.
 */
export const meta = pgTable("meta", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
  updatedAt: tsz("updated_at").notNull().defaultNow(),
});

// ------------------------------------------------------------------ users and sessions

export const userRole = pgEnum("user_role", ["admin", "analyst"]);

export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /** Lowercased login name. */
    username: text("username").notNull(),
    /** argon2id PHC string. */
    passwordHash: text("password_hash").notNull(),
    role: userRole("role").notNull().default("analyst"),
    createdAt: tsz("created_at").notNull().defaultNow(),
    disabledAt: tsz("disabled_at"),
    lastLoginAt: tsz("last_login_at"),
  },
  (t) => [
    uniqueIndex("users_username_key").on(t.username),
    check("users_username_len", sql`char_length(${t.username}) between 1 and 64`),
  ],
);

export const sessions = pgTable(
  "sessions",
  {
    /** SHA-256 (hex) of the session cookie value; the cookie value itself is never stored. */
    tokenHash: text("token_hash").primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    createdAt: tsz("created_at").notNull().defaultNow(),
    lastSeenAt: tsz("last_seen_at").notNull().defaultNow(),
    expiresAt: tsz("expires_at").notNull(),
  },
  (t) => [index("sessions_user_id_idx").on(t.userId)],
);

// --------------------------------------------------------------------------- agents

export const agentStatus = pgEnum("agent_status", ["enrolled", "online", "revoked", "locked"]);

export const agents = pgTable(
  "agents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /** Display name, defaults to the hostname reported at enrollment. */
    name: text("name").notNull(),
    hostname: text("hostname").notNull(),
    version: text("version").notNull(),
    os: text("os"),
    arch: text("arch"),
    connectors: jsonb("connectors").$type<string[]>().notNull().default([]),
    classifiersVersion: text("classifiers_version"),
    status: agentStatus("status").notNull().default("enrolled"),
    enrolledAt: tsz("enrolled_at").notNull().defaultNow(),
    lastSeenAt: tsz("last_seen_at"),
    uptimeS: integer("uptime_s"),
    /** Agent clock minus console clock at the last heartbeat, in milliseconds. */
    clockSkewMs: integer("clock_skew_ms"),
    spool: jsonb("spool").$type<Record<string, number>>(),
    metrics: jsonb("metrics").$type<Record<string, number>>(),
    detectedTargets: jsonb("detected_targets").$type<unknown[]>(),
    /** argon2id PHC string of the current secret; NULL once revoked or locked. */
    currentSecretHash: text("current_secret_hash"),
    /** argon2id PHC string of the pending secret during a rotation (ADR-0008, `/rotate`). */
    pendingSecretHash: text("pending_secret_hash"),
    graceExpiresAt: tsz("grace_expires_at"),
    /** Previous secret hash, kept for the 60 s tolerance window after promotion (ADR-0008). */
    previousSecretHash: text("previous_secret_hash"),
    promotedAt: tsz("promoted_at"),
    lockedAt: tsz("locked_at"),
    revokedAt: tsz("revoked_at"),
    revokedBy: uuid("revoked_by").references(() => users.id, { onDelete: "set null" }),
  },
  (t) => [index("agents_status_idx").on(t.status)],
);

export const auditLevel = pgEnum("audit_level", ["full", "partial", "limited", "none"]);

/** Targets reported by an agent in its heartbeats (declared in its local agent.yaml). */
export const agentTargets = pgTable(
  "agent_targets",
  {
    agentId: uuid("agent_id")
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    targetId: text("target_id").notNull(),
    engine: text("engine").notNull(),
    edition: text("edition"),
    serverVersion: text("server_version"),
    reachable: boolean("reachable").notNull(),
    auditLevel: auditLevel("audit_level").notNull(),
    auditSource: text("audit_source"),
    lastError: text("last_error"),
    metrics: jsonb("metrics").$type<Record<string, number>>(),
    /** false when the target was absent from the last heartbeat (removed from agent.yaml). */
    present: boolean("present").notNull().default(true),
    firstSeenAt: tsz("first_seen_at").notNull().defaultNow(),
    lastReportedAt: tsz("last_reported_at").notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.agentId, t.targetId] })],
);

export const enrollmentTokens = pgTable(
  "enrollment_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /** SHA-256 (hex) of the `dbe_…` token; the token is shown once and never stored. */
    tokenHash: text("token_hash").notNull(),
    /** Optional admin note (e.g. intended host). Never the token. */
    label: text("label"),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
    createdAt: tsz("created_at").notNull().defaultNow(),
    expiresAt: tsz("expires_at").notNull(),
    consumedAt: tsz("consumed_at"),
    consumedByAgentId: uuid("consumed_by_agent_id").references(() => agents.id, {
      onDelete: "set null",
    }),
    revokedAt: tsz("revoked_at"),
  },
  (t) => [uniqueIndex("enrollment_tokens_token_hash_key").on(t.tokenHash)],
);

// ----------------------------------------------------------------------------- jobs

export const jobStatus = pgEnum("job_status", [
  "pending",
  "delivered",
  "running",
  "succeeded",
  "failed",
  "expired",
  "cancelled",
]);

export const jobs = pgTable(
  "jobs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    agentId: uuid("agent_id")
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    type: text("type").notNull(),
    targetId: text("target_id"),
    classifiersVersion: text("classifiers_version"),
    /** Job parameters as sent to the agent (contract `*Params`): never a secret or credential. */
    params: jsonb("params").$type<Record<string, unknown>>().notNull(),
    status: jobStatus("status").notNull().default("pending"),
    createdAt: tsz("created_at").notNull().defaultNow(),
    expiresAt: tsz("expires_at"),
    /** At-least-once delivery: a delivered job without status is redelivered after this instant. */
    leaseUntil: tsz("lease_until"),
    attempts: integer("attempts").notNull().default(0),
    deliveredAt: tsz("delivered_at"),
    /** Agent `ts` of the last status update (older updates are ignored). */
    lastStatusAt: tsz("last_status_at"),
    progress: jsonb("progress").$type<Record<string, number>>(),
    /** Closed failure code (+ engine code), contract `JobError`. */
    error: jsonb("error").$type<{ code: string; engine_code?: string }>(),
    finishedAt: tsz("finished_at"),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
  },
  (t) => [index("jobs_agent_status_idx").on(t.agentId, t.status, t.createdAt)],
);

// ------------------------------------------------------------------------ audit log

/**
 * Console audit log. Append-only: the application only ever inserts (see src/server/audit.ts).
 * `details` never holds a secret, a token or an agent-provided free-text value.
 */
export const auditLog = pgTable(
  "audit_log",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    at: tsz("at").notNull().defaultNow(),
    /** `user`, `agent` or `system`. */
    actorType: text("actor_type").notNull(),
    actorId: text("actor_id"),
    action: text("action").notNull(),
    outcome: text("outcome").notNull().default("success"),
    targetType: text("target_type"),
    targetId: text("target_id"),
    sourceIp: text("source_ip"),
    details: jsonb("details").$type<Record<string, unknown>>(),
  },
  (t) => [index("audit_log_at_idx").on(t.at), index("audit_log_action_idx").on(t.action)],
);

// ------------------------------------------------------------------ security events

/**
 * Agent-integrity security events (placeholder for the P3 `incidents` model): `rotation_conflict`
 * today, rejected batches and `batch_conflict` with P2-D. Raised by the console itself, never from
 * agent-provided text: `details` only holds console-computed scalars (no secret, no hash).
 */
export const securityEvents = pgTable(
  "security_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    at: tsz("at").notNull().defaultNow(),
    /** Closed set, e.g. `agent.rotation_conflict`. */
    kind: text("kind").notNull(),
    severity: text("severity").notNull(),
    agentId: uuid("agent_id").references(() => agents.id, { onDelete: "set null" }),
    details: jsonb("details").$type<Record<string, string | number | boolean | null>>(),
    acknowledgedAt: tsz("acknowledged_at"),
    acknowledgedBy: uuid("acknowledged_by").references(() => users.id, { onDelete: "set null" }),
  },
  (t) => [index("security_events_at_idx").on(t.at), index("security_events_agent_idx").on(t.agentId)],
);
