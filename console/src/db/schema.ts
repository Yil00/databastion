import { sql } from "drizzle-orm";
import {
  type AnyPgColumn,
  bigint,
  boolean,
  check,
  customType,
  doublePrecision,
  foreignKey,
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
 * - AES-256-GCM encryption at rest (`DATABASTION_ENCRYPTION_KEY`, HKDF subkey per domain):
 *   `findings.masked_samples` (P2-D, domain `masked-samples.v1`), `notification_channels.secret`
 *   (P3-C, domain `notification-channels.v1`: SMTP password, webhook signing secret).
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
    /**
     * `grace_expires_at` of the rotation that produced the current secret, copied at promotion: the
     * deadline answered to a late `S0 + S1` retry, even after a newer rotation started (ADR-0011).
     */
    promotedGraceExpiresAt: tsz("promoted_grace_expires_at"),
    /**
     * "Known good" fingerprint of the last verified secret (P1-D): hex HMAC-SHA256, keyed by a
     * subkey of `DATABASTION_ENCRYPTION_KEY`, over the current hash and the 256-bit secret (see
     * `knownGoodFingerprint`). Never authenticates: it only exempts that secret from the per-agent
     * failure limit, across console restarts. Bound to the current hash; cleared on lock and
     * revocation, replaced by the pending one at promotion.
     */
    knownGoodFingerprint: text("known_good_fingerprint"),
    /** When `known_good_fingerprint` was last confirmed by a full verification (24 h TTL). */
    knownGoodAt: tsz("known_good_at"),
    /**
     * Same fingerprint for the pending secret `S1`, bound to `pending_secret_hash`, written when a
     * `/rotate` authenticated with the current secret registers it (P1-D L2): `S1` is exempt from
     * the per-agent failure limit while pending, and becomes `known_good_fingerprint` at promotion.
     */
    knownGoodPendingFingerprint: text("known_good_pending_fingerprint"),
    lockedAt: tsz("locked_at"),
    /**
     * P3-C "silent agent" alert: `last_seen_at` of the silence episode already alerted (one alert
     * per episode). Set by the worker when it raises the alert, cleared when a later heartbeat ends
     * the episode (recovery).
     */
    silenceAlertedFor: tsz("silence_alerted_for"),
    /**
     * P7 "dropped batches" alert (end-of-phase-4 review M2): batches the agent reported dropped
     * (increase of `spool.dropped_batches` between heartbeats, a counter since agent start) and not
     * alerted yet; when the first of them was seen; when the last alert was raised (at most one per
     * agent and hour, see `src/server/dropped-batches.ts`).
     */
    droppedBatchesUnalerted: integer("dropped_batches_unalerted").notNull().default(0),
    droppedBatchesSince: tsz("dropped_batches_since"),
    droppedBatchesAlertedAt: tsz("dropped_batches_alerted_at"),
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
    /**
     * Contract `TargetStatus.notes` of the latest heartbeat (P4-D): closed codes with a bounded
     * count and closed labels, never free text; null when that heartbeat carried none. Bounded
     * (at most 16 notes, 16 KiB serialized; see src/lib/target-notes.ts).
     */
    notes: jsonb("notes").$type<{ code: string; count?: number; labels?: string[] }[]>(),
    metrics: jsonb("metrics").$type<Record<string, number>>(),
    /** false when the target was absent from the last heartbeat (removed from agent.yaml). */
    present: boolean("present").notNull().default(true),
    firstSeenAt: tsz("first_seen_at").notNull().defaultNow(),
    lastReportedAt: tsz("last_reported_at").notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.agentId, t.targetId] }),
    check(
      "agent_targets_notes_bounded",
      sql`${t.notes} is null or (jsonb_typeof(${t.notes}) = 'array' and jsonb_array_length(${t.notes}) <= 16 and octet_length(${t.notes}::text) <= 16384)`,
    ),
  ],
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
    /**
     * First delivery (console clock, never changed by a redelivery): no data of the job can have
     * been read before this instant. The policy engine compares it with `resolved_at` (N1).
     */
    firstDeliveredAt: tsz("first_delivered_at"),
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

// ------------------------------------------------------------------------- findings

/** Raw bytes (`bytea`): used for AES-256-GCM ciphertexts only. */
const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return "bytea";
  },
});

/**
 * Findings batches received from agents (`POST /findings`), for idempotency on
 * (`agent_id`, `batch_id`): `body_sha256` is the SHA-256 of the validated batch serialized as JSON.
 * Same pair + same hash: `202 duplicate: true`; same pair + another hash: `409 batch_conflict`.
 * Only accepted batches are recorded; the body itself is never stored here.
 */
export const findingsBatches = pgTable(
  "findings_batches",
  {
    agentId: uuid("agent_id")
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    batchId: uuid("batch_id").notNull(),
    bodySha256: text("body_sha256").notNull(),
    jobId: uuid("job_id").references(() => jobs.id, { onDelete: "set null" }),
    findingsCount: integer("findings_count").notNull(),
    receivedAt: tsz("received_at").notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.agentId, t.batchId] }),
    index("findings_batches_job_idx").on(t.jobId),
    check("findings_batches_sha256_format", sql`${t.bodySha256} ~ '^[0-9a-f]{64}$'`),
  ],
);

/**
 * Discovery findings: one row per (agent, target, location, classifier), updated by later scans.
 * `location_key` is the SHA-256 of that key (see `findingLocationKey`), unique per agent.
 * Names are normalized by the agent (ADR-0009) and escaped on display.
 * - `masked_samples`: AES-256-GCM ciphertext (subkey `masked-samples.v1` of
 *   `DATABASTION_ENCRYPTION_KEY`, random 96-bit nonce, AAD bound to the finding id) of the JSON
 *   array of masked samples; NULL when the batch carried none or when the server key is unavailable
 *   (fail closed: the finding is stored, its samples are not).
 * - `fingerprints`: `hmac-sha256:` values as sent (keyed by the agent-local key, never leaves it).
 * - False positives are an admin decision on the location + classifier: kept across rescans unless
 *   `matched` rises above its value at marking time or the classifier set changes.
 */
export const findings = pgTable(
  "findings",
  {
    id: uuid("id").primaryKey(),
    agentId: uuid("agent_id").notNull(),
    targetId: text("target_id").notNull(),
    locationKey: text("location_key").notNull(),
    engine: text("engine").notNull(),
    databaseName: text("database_name").notNull(),
    schemaName: text("schema_name"),
    objectName: text("object_name").notNull(),
    fieldName: text("field_name").notNull(),
    classifier: text("classifier").notNull(),
    classifiersVersion: text("classifiers_version").notNull(),
    confidence: doublePrecision("confidence").notNull(),
    sampled: integer("sampled").notNull(),
    matched: integer("matched").notNull(),
    estimatedRows: bigint("estimated_rows", { mode: "number" }),
    maskedSamples: bytea("masked_samples"),
    fingerprints: jsonb("fingerprints").$type<string[]>().notNull().default([]),
    firstJobId: uuid("first_job_id").references(() => jobs.id, { onDelete: "set null" }),
    lastJobId: uuid("last_job_id").references(() => jobs.id, { onDelete: "set null" }),
    lastBatchId: uuid("last_batch_id").notNull(),
    firstSeenAt: tsz("first_seen_at").notNull().defaultNow(),
    lastSeenAt: tsz("last_seen_at").notNull().defaultNow(),
    falsePositiveAt: tsz("false_positive_at"),
    falsePositiveBy: uuid("false_positive_by").references(() => users.id, { onDelete: "set null" }),
    /**
     * `matched` and `classifiers_version` when the false positive was marked: a later scan that
     * matches more values or runs another classifier set resets the mark (audited).
     */
    falsePositiveMatched: integer("false_positive_matched"),
    falsePositiveClassifiersVersion: text("false_positive_classifiers_version"),
    /**
     * `last_seen_at` of the revision last evaluated by the policy engine (P3-A). The finding is
     * pending evaluation while it differs from `last_seen_at` (set by the worker with a
     * compare-and-set on `last_seen_at`, so a rescan during an evaluation is never lost).
     */
    policyEvaluatedAt: tsz("policy_evaluated_at"),
  },
  (t) => [
    foreignKey({
      name: "findings_agent_target_fk",
      columns: [t.agentId, t.targetId],
      foreignColumns: [agentTargets.agentId, agentTargets.targetId],
    }).onDelete("cascade"),
    uniqueIndex("findings_location_key").on(t.agentId, t.locationKey),
    index("findings_target_classifier_idx").on(t.agentId, t.targetId, t.classifier),
    index("findings_classifier_idx").on(t.classifier),
    check("findings_confidence_range", sql`${t.confidence} >= 0 and ${t.confidence} <= 1`),
    check("findings_counts", sql`${t.matched} >= 0 and ${t.matched} <= ${t.sampled} and ${t.sampled} <= 10000`),
    check("findings_location_key_format", sql`${t.locationKey} ~ '^[0-9a-f]{64}$'`),
    index("findings_policy_pending_idx")
      .on(t.id)
      .where(sql`${t.policyEvaluatedAt} is distinct from ${t.lastSeenAt}`),
  ],
);

// ------------------------------------------------------------------- policies (P3-A)

/**
 * What a policy evaluates: Discovery findings (P3-A) or Audit access events (P4-C, added with
 * `ALTER TYPE ... ADD VALUE`, a compatible change). The condition document is validated per source
 * (src/lib/policy-model.ts, src/lib/event-model.ts), so a source brings its own keys without
 * changing this table.
 */
export const policySource = pgEnum("policy_source", ["finding", "access_event"]);

export const incidentSeverity = pgEnum("incident_severity", ["low", "medium", "high", "critical"]);

/**
 * Condition -> action rules applied by the worker. `conditions` and `actions` are JSON documents
 * validated by `parsePolicyConditions` / `parsePolicyActions` (unknown keys rejected); they only
 * hold identifiers, globs on normalized names and thresholds, never a sampled value.
 * - `revision` grows on every edit (incidents record the revision that created them);
 * - `changed_at` / `evaluated_at`: the policy needs a full pass over the existing findings while
 *   `evaluated_at` is null or older than `changed_at` (or than an exception expiry, see the worker).
 */
export const policies = pgTable(
  "policies",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    name: text("name").notNull(),
    description: text("description"),
    enabled: boolean("enabled").notNull().default(true),
    source: policySource("source").notNull().default("finding"),
    conditions: jsonb("conditions").$type<Record<string, unknown>>().notNull(),
    actions: jsonb("actions").$type<Record<string, unknown>[]>().notNull(),
    revision: integer("revision").notNull().default(1),
    createdAt: tsz("created_at").notNull().defaultNow(),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
    updatedAt: tsz("updated_at").notNull().defaultNow(),
    updatedBy: uuid("updated_by").references(() => users.id, { onDelete: "set null" }),
    changedAt: tsz("changed_at").notNull().defaultNow(),
    evaluatedAt: tsz("evaluated_at"),
  },
  (t) => [
    uniqueIndex("policies_name_key").on(sql`lower(${t.name})`),
    check("policies_name_len", sql`char_length(${t.name}) between 1 and 100`),
    check("policies_description_len", sql`char_length(${t.description}) <= 500`),
    check("policies_revision_positive", sql`${t.revision} >= 1`),
  ],
);

/**
 * Exceptions: a finding matching one is never turned into an incident by the policy (or by every
 * policy when `policy_id` is null). At least one scope column is set, so an exception can never
 * silence everything. `location` holds globs on normalized names, like the conditions. Expired
 * exceptions are kept (listed as expired) until an administrator deletes them.
 */
export const policyExceptions = pgTable(
  "policy_exceptions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    policyId: uuid("policy_id").references(() => policies.id, { onDelete: "cascade" }),
    agentId: uuid("agent_id").references(() => agents.id, { onDelete: "cascade" }),
    targetId: text("target_id"),
    classifier: text("classifier"),
    location: jsonb("location").$type<Record<string, string>>(),
    reason: text("reason").notNull(),
    expiresAt: tsz("expires_at"),
    createdAt: tsz("created_at").notNull().defaultNow(),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
  },
  (t) => [
    index("policy_exceptions_policy_idx").on(t.policyId),
    check(
      "policy_exceptions_scope",
      sql`${t.agentId} is not null or ${t.targetId} is not null or ${t.classifier} is not null or ${t.location} is not null`,
    ),
    check("policy_exceptions_reason_len", sql`char_length(${t.reason}) between 1 and 500`),
  ],
);

// ------------------------------------------------------------------ incidents (P3-B)

export const incidentStatus = pgEnum("incident_status", ["open", "acknowledged", "resolved", "false_positive"]);

/**
 * Incidents created by policies. One row per (policy, subject) occurrence: `dedup_key` identifies
 * the pair (`policy:<id>|finding:<id>`) and a partial unique index allows at most one open or
 * acknowledged incident per key, so re-evaluations (retries, rescans) never duplicate one.
 * Snapshots (`policy_name`, target, classifier, `finding_matched`, `finding_classifiers_version`)
 * keep the incident readable when the policy or the finding goes away; no sampled value is ever
 * stored here (masked samples stay encrypted on the finding row). Never deleted by the runtime
 * role (migration 0015).
 */
export const incidents = pgTable(
  "incidents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    dedupKey: text("dedup_key").notNull(),
    source: policySource("source").notNull(),
    policyId: uuid("policy_id").references(() => policies.id, { onDelete: "set null" }),
    policyName: text("policy_name").notNull(),
    policyRevision: integer("policy_revision").notNull(),
    severity: incidentSeverity("severity").notNull(),
    status: incidentStatus("status").notNull().default("open"),
    /** Channel references of the policy's `notify` actions at creation time (delivery: P3-C). */
    notifyChannels: jsonb("notify_channels").$type<string[]>().notNull().default([]),
    findingId: uuid("finding_id").references(() => findings.id, { onDelete: "set null" }),
    agentId: uuid("agent_id").references(() => agents.id, { onDelete: "set null" }),
    targetId: text("target_id"),
    classifier: text("classifier"),
    findingMatched: integer("finding_matched"),
    findingClassifiersVersion: text("finding_classifiers_version"),
    /** `last_seen_at` of the latest finding revision that matched (idempotent re-matches). */
    lastFindingSeenAt: tsz("last_finding_seen_at"),
    matchCount: integer("match_count").notNull().default(1),
    createdAt: tsz("created_at").notNull().defaultNow(),
    updatedAt: tsz("updated_at").notNull().defaultNow(),
    acknowledgedAt: tsz("acknowledged_at"),
    acknowledgedBy: uuid("acknowledged_by").references(() => users.id, { onDelete: "set null" }),
    resolvedAt: tsz("resolved_at"),
    resolvedBy: uuid("resolved_by").references(() => users.id, { onDelete: "set null" }),
    falsePositiveAt: tsz("false_positive_at"),
    falsePositiveBy: uuid("false_positive_by").references(() => users.id, { onDelete: "set null" }),
    // ---- source `access_event` (P4-C); null for finding incidents.
    /** First access event that matched (the others are in `incident_events`). */
    accessEventId: uuid("access_event_id").references((): AnyPgColumn => accessEvents.id, { onDelete: "set null" }),
    /** Principal as sent by the agent: `db_user`, or its `hmac-sha256:` fingerprint. Escaped on display. */
    principal: text("principal"),
    /** Database of the dedup scope (normalized name; null for an event without object). */
    eventDatabase: text("event_database"),
    /** Start of the UTC hour of the dedup scope (event `ts`, agent clock). */
    eventBucket: tsz("event_bucket"),
    /** Highest event score seen, total rows, union of the signals (at most 16), latest event `ts`. */
    eventScore: doublePrecision("event_score"),
    eventRows: doublePrecision("event_rows"),
    eventSignals: jsonb("event_signals").$type<string[]>(),
    lastEventAt: tsz("last_event_at"),
    /** An event of the incident was above its principal's baseline. */
    eventAnomaly: boolean("event_anomaly"),
    /**
     * Per-policy overflow incident: the policy reached its hourly cap of new incidents, and the
     * further matches of that hour are counted here (P4-C security review H1).
     */
    eventOverflow: boolean("event_overflow").notNull().default(false),
  },
  (t) => [
    uniqueIndex("incidents_active_dedup_key")
      .on(t.dedupKey)
      .where(sql`${t.status} in ('open', 'acknowledged')`),
    index("incidents_dedup_key_idx").on(t.dedupKey, t.createdAt),
    index("incidents_status_idx").on(t.status, t.createdAt),
    index("incidents_finding_idx").on(t.findingId),
    check("incidents_policy_name_len", sql`char_length(${t.policyName}) between 1 and 100`),
    check("incidents_match_count", sql`${t.matchCount} >= 1`),
  ],
);

// --------------------------------------------------------------- alerting (P3-C)

export const notificationChannelType = pgEnum("notification_channel_type", ["email", "webhook"]);

/**
 * Notification channels, referenced by `slug` from the policies' `notify` actions (copied to
 * `incidents.notify_channels`). `config` holds the non-secret settings only (SMTP host, port, TLS
 * mode, sender, recipients, username; webhook URL), validated by `src/lib/notification-model.ts`.
 * `secret` is the only secret (SMTP password or webhook signing secret): AES-256-GCM under the
 * subkey `notification-channels.v1`, AAD bound to the channel id; never returned by the API.
 * `system_alerts`: the channel also receives the console's own alerts (silent agents,
 * agent-integrity events, dropped batches).
 */
export const notificationChannels = pgTable(
  "notification_channels",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    slug: text("slug").notNull(),
    type: notificationChannelType("type").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    systemAlerts: boolean("system_alerts").notNull().default(false),
    config: jsonb("config").$type<Record<string, unknown>>().notNull(),
    secret: bytea("secret"),
    createdAt: tsz("created_at").notNull().defaultNow(),
    createdBy: uuid("created_by").references(() => users.id, { onDelete: "set null" }),
    updatedAt: tsz("updated_at").notNull().defaultNow(),
    updatedBy: uuid("updated_by").references(() => users.id, { onDelete: "set null" }),
  },
  (t) => [
    uniqueIndex("notification_channels_slug_key").on(t.slug),
    check("notification_channels_slug_format", sql`${t.slug} ~ '^[a-z0-9][a-z0-9_.-]{0,62}$'`),
  ],
);

export const notificationDeliveryStatus = pgEnum("notification_delivery_status", [
  "pending",
  "sending",
  "delivered",
  "failed",
  "skipped",
]);

/**
 * Transactional outbox of notifications. A row is written in the same transaction as the event it
 * reports (incident creation, silent agent, agent-integrity event), one per (subject, event,
 * channel): `idempotency_key` is unique, so a retried evaluation never notifies twice. The worker
 * claims due rows (`SKIP LOCKED`, lease), sends them and records the outcome: attempts, next
 * attempt (exponential backoff, capped), `last_error` (a closed error code, never a server
 * response). `payload` holds identifiers, counts, names and the console URL only: never a sampled
 * value, masked or not (I2). The runtime role cannot delete rows nor rewrite the key, subject or
 * payload (migration 0019).
 */
export const notificationDeliveries = pgTable(
  "notification_deliveries",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    idempotencyKey: text("idempotency_key").notNull(),
    event: text("event").notNull(),
    channelId: uuid("channel_id").references(() => notificationChannels.id, { onDelete: "set null" }),
    /** Slug as referenced (kept when the channel is deleted or was never found). */
    channelSlug: text("channel_slug").notNull(),
    incidentId: uuid("incident_id").references(() => incidents.id, { onDelete: "set null" }),
    agentId: uuid("agent_id").references(() => agents.id, { onDelete: "set null" }),
    securityEventId: uuid("security_event_id").references(() => securityEvents.id, { onDelete: "set null" }),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
    status: notificationDeliveryStatus("status").notNull().default("pending"),
    attempts: integer("attempts").notNull().default(0),
    nextAttemptAt: tsz("next_attempt_at").notNull().defaultNow(),
    leaseUntil: tsz("lease_until"),
    lastAttemptAt: tsz("last_attempt_at"),
    deliveredAt: tsz("delivered_at"),
    lastError: text("last_error"),
    createdAt: tsz("created_at").notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("notification_deliveries_idempotency_key").on(t.idempotencyKey),
    index("notification_deliveries_due_idx")
      .on(t.nextAttemptAt)
      .where(sql`${t.status} in ('pending', 'sending')`),
    index("notification_deliveries_incident_idx").on(t.incidentId),
    // L6: per-channel hourly budget of incident notifications, and the suppression digests.
    index("notification_deliveries_channel_created_idx").on(t.channelId, t.createdAt),
    index("notification_deliveries_rate_limited_idx")
      .on(t.createdAt)
      .where(sql`${t.lastError} = 'rate_limited'`),
    check("notification_deliveries_attempts", sql`${t.attempts} >= 0`),
    check("notification_deliveries_last_error_format", sql`${t.lastError} ~ '^[a-z0-9_]{1,64}$'`),
  ],
);

// ------------------------------------------------------------------- Audit (P4-C)

/**
 * Events batches received from agents (`POST /events`): idempotency on (`agent_id`, `batch_id`),
 * exactly like `findings_batches` (SHA-256 of the validated batch in canonical JSON, never the
 * body). Insert-only for the runtime role; purged with the events past the retention bound by the
 * owner-defined function `databastion_purge_access_events` (migration 0022).
 */
export const eventsBatches = pgTable(
  "events_batches",
  {
    agentId: uuid("agent_id")
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    batchId: uuid("batch_id").notNull(),
    bodySha256: text("body_sha256").notNull(),
    eventsCount: integer("events_count").notNull(),
    receivedAt: tsz("received_at").notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.agentId, t.batchId] }),
    index("events_batches_received_idx").on(t.receivedAt),
    check("events_batches_sha256_format", sql`${t.bodySha256} ~ '^[0-9a-f]{64}$'`),
  ],
);

/**
 * Normalized Audit access events (contract `AccessEvent`), masked by the agent before the uplink
 * (ADR-0007): no query text, no bound parameter, no returned value can be stored here, because the
 * contract has no field for them and the console rejects unknown fields. Columns hold the principal
 * (`db_user` or its fingerprint, client address, application), the action, the normalized object
 * names, counts, signals and the source, all bounded by the contract and escaped on display.
 * `principal_key` = SHA-256 of `u\0<db_user>` or `f\0<fingerprint>`: the grouping key of baselines
 * and dedup keys, so agent-provided text never appears in a key.
 *
 * The runtime role may only INSERT and SELECT, plus UPDATE of the evaluation columns
 * (`evaluated_at`, `sensitivity`, `score`, `anomaly`, `baseline_rows`) written by the worker:
 * what the agent reported can never be rewritten nor deleted by the console process (migration
 * 0022). Rows older than the retention bound are deleted by `databastion_purge_access_events`.
 */
export const accessEvents = pgTable(
  "access_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    agentId: uuid("agent_id").notNull(),
    targetId: text("target_id").notNull(),
    batchId: uuid("batch_id").notNull(),
    /** Index of the event in its batch. */
    itemIndex: integer("item_index").notNull(),
    ts: tsz("ts").notNull(),
    tsLast: tsz("ts_last"),
    receivedAt: tsz("received_at").notNull().defaultNow(),
    principalKey: text("principal_key").notNull(),
    dbUser: text("db_user"),
    dbUserFingerprint: text("db_user_fingerprint"),
    clientAddr: text("client_addr"),
    application: text("application"),
    action: text("action").notNull(),
    /** Contract `ObjectRef[]` (normalized names), at most 16. */
    objects: jsonb("objects").$type<{ database: string; schema?: string; object: string }[]>().notNull(),
    rows: bigint("rows", { mode: "number" }),
    /**
     * Contract `AccessEvent.bytes` (P4-D): size of the result returned or of the data affected, when
     * the source reports it (the total for a pre-aggregated event); null otherwise. Stored and
     * shown, not used by the score (ADR-0021: volume is rows only).
     */
    bytes: bigint("bytes", { mode: "number" }),
    signals: jsonb("signals").$type<string[]>().notNull().default([]),
    source: text("source").notNull(),
    aggregatedCount: integer("aggregated_count").notNull(),
    /**
     * At ingestion, the target was no longer reported by the agent (removed from its agent.yaml)
     * or its Audit settings were disabled: a conforming agent should not report such events
     * (security review L4). Stored and counted; the event is still evaluated.
     */
    unexpectedTarget: boolean("unexpected_target").notNull().default(false),
    // ---- evaluation (worker)
    evaluatedAt: tsz("evaluated_at"),
    /** Sensitivity of the most sensitive object reached (see src/lib/event-model.ts). */
    sensitivity: doublePrecision("sensitivity"),
    /** Volume x sensitivity score. */
    score: doublePrecision("score"),
    /** Volume above the principal's baseline (after its warm-up). */
    anomaly: boolean("anomaly"),
    /** Baseline volume (rows) of the principal when the event was evaluated; null during warm-up. */
    baselineRows: doublePrecision("baseline_rows"),
  },
  (t) => [
    foreignKey({
      name: "access_events_agent_target_fk",
      columns: [t.agentId, t.targetId],
      foreignColumns: [agentTargets.agentId, agentTargets.targetId],
    }).onDelete("cascade"),
    index("access_events_ts_idx").on(t.ts),
    index("access_events_target_ts_idx").on(t.agentId, t.targetId, t.ts),
    index("access_events_principal_ts_idx").on(t.agentId, t.targetId, t.principalKey, t.ts),
    index("access_events_signals_idx").using("gin", t.signals),
    index("access_events_pending_idx")
      .on(t.agentId, t.receivedAt, t.itemIndex, t.id)
      .where(sql`${t.evaluatedAt} is null`),
    check("access_events_principal", sql`(${t.dbUser} is null) <> (${t.dbUserFingerprint} is null)`),
    check("access_events_principal_key_format", sql`${t.principalKey} ~ '^[0-9a-f]{64}$'`),
    check("access_events_action", sql`${t.action} in ('connect', 'auth_failure', 'read', 'write', 'ddl', 'dcl')`),
    check("access_events_counts", sql`${t.aggregatedCount} >= 1 and (${t.rows} is null or ${t.rows} >= 0)`),
    check("access_events_bytes", sql`${t.bytes} is null or ${t.bytes} >= 0`),
  ],
);

/**
 * Link between an incident raised from access events and every event that matched it (the first
 * one is also `incidents.access_event_id`). Insert-only for the runtime role; the links of a purged
 * event go with it (`ON DELETE CASCADE`).
 */
export const incidentEvents = pgTable(
  "incident_events",
  {
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidents.id, { onDelete: "cascade" }),
    eventId: uuid("event_id")
      .notNull()
      .references(() => accessEvents.id, { onDelete: "cascade" }),
    createdAt: tsz("created_at").notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.incidentId, t.eventId] }), index("incident_events_event_idx").on(t.eventId)],
);

/**
 * Per-principal baselines (P4-C): exponentially weighted mean and variance of `ln(1 + rows)` and of
 * `ln(1 + score)` per event of a (agent, target, principal), with counters. Aggregates only: no
 * event, no object name, no value. `db_user` / `db_user_fingerprint` are kept for display. Not
 * deleted by the runtime role; they outlive the events they summarize.
 */
export const principalBaselines = pgTable(
  "principal_baselines",
  {
    agentId: uuid("agent_id").notNull(),
    targetId: text("target_id").notNull(),
    principalKey: text("principal_key").notNull(),
    dbUser: text("db_user"),
    dbUserFingerprint: text("db_user_fingerprint"),
    events: bigint("events", { mode: "number" }).notNull().default(0),
    meanLogRows: doublePrecision("mean_log_rows").notNull().default(0),
    varLogRows: doublePrecision("var_log_rows").notNull().default(0),
    meanLogScore: doublePrecision("mean_log_score").notNull().default(0),
    varLogScore: doublePrecision("var_log_score").notNull().default(0),
    rowsTotal: doublePrecision("rows_total").notNull().default(0),
    maxScore: doublePrecision("max_score").notNull().default(0),
    anomalies: bigint("anomalies", { mode: "number" }).notNull().default(0),
    firstEventAt: tsz("first_event_at"),
    lastEventAt: tsz("last_event_at"),
    updatedAt: tsz("updated_at").notNull().defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.agentId, t.targetId, t.principalKey] }),
    foreignKey({
      name: "principal_baselines_agent_target_fk",
      columns: [t.agentId, t.targetId],
      foreignColumns: [agentTargets.agentId, agentTargets.targetId],
    }).onDelete("cascade"),
    check("principal_baselines_principal_key_format", sql`${t.principalKey} ~ '^[0-9a-f]{64}$'`),
    check("principal_baselines_counts", sql`${t.events} >= 0 and ${t.anomalies} >= 0 and ${t.varLogRows} >= 0 and ${t.varLogScore} >= 0`),
  ],
);

/**
 * Audit settings per target (P4-C `audit.configure`), as last sent to the agent. `manual_objects`
 * are the objects an administrator added by hand (contract `SensitiveObject`); the objects derived
 * from findings are recomputed at each change. `sent_objects` is the `sensitive_objects` list of
 * the last job (to compute what a change removes); `warning` (closed code `emptied` / `shrunk` /
 * `disabled`) is set when the last change emptied the list, removed many objects or disabled Audit,
 * and cleared by a later change that does not.
 */
export const auditConfigs = pgTable(
  "audit_configs",
  {
    agentId: uuid("agent_id").notNull(),
    targetId: text("target_id").notNull(),
    enabled: boolean("enabled").notNull(),
    aggregationWindowS: integer("aggregation_window_s").notNull(),
    pollIntervalS: integer("poll_interval_s").notNull(),
    minRows: bigint("min_rows", { mode: "number" }),
    deriveFromFindings: boolean("derive_from_findings").notNull().default(true),
    manualObjects: jsonb("manual_objects").$type<Record<string, unknown>[]>().notNull().default([]),
    sentObjects: jsonb("sent_objects").$type<Record<string, unknown>[]>().notNull().default([]),
    lastJobId: uuid("last_job_id").references(() => jobs.id, { onDelete: "set null" }),
    warning: text("warning"),
    warningRemoved: integer("warning_removed"),
    updatedAt: tsz("updated_at").notNull().defaultNow(),
    updatedBy: uuid("updated_by").references(() => users.id, { onDelete: "set null" }),
  },
  (t) => [
    primaryKey({ columns: [t.agentId, t.targetId] }),
    foreignKey({
      name: "audit_configs_agent_target_fk",
      columns: [t.agentId, t.targetId],
      foreignColumns: [agentTargets.agentId, agentTargets.targetId],
    }).onDelete("cascade"),
    check("audit_configs_warning", sql`${t.warning} is null or ${t.warning} in ('emptied', 'shrunk', 'disabled')`),
  ],
);

/**
 * Shared rate-limit counters (P4-D): one fixed window per (limiter, key), anchored at the first hit
 * of the window like the in-memory limiter it backs (`src/server/rate-limit.ts`), so the limits
 * hold across web processes. `key_hash` is an HMAC-SHA256 (server-key subkey `rate-limit-keys.v1`;
 * plain SHA-256 without the server key) of the limiter key: source IPs, usernames as typed (possibly
 * a password), device-cookie nonces and agent ids are never stored in clear. Rows past `expires_at`
 * are dead (reset in place by the next hit) and pruned by the worker. The runtime role reads, inserts,
 * updates and deletes them (migration `0030`).
 */
export const rateLimitCounters = pgTable(
  "rate_limit_counters",
  {
    limiter: text("limiter").notNull(),
    keyHash: text("key_hash").notNull(),
    windowStart: tsz("window_start").notNull(),
    expiresAt: tsz("expires_at").notNull(),
    count: integer("count").notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.limiter, t.keyHash] }),
    index("rate_limit_counters_expires_idx").on(t.expiresAt),
    check("rate_limit_counters_limiter_format", sql`${t.limiter} ~ '^[a-z0-9_.]{1,64}$'`),
    check("rate_limit_counters_key_hash_format", sql`${t.keyHash} ~ '^[0-9a-f]{64}$'`),
    check("rate_limit_counters_count", sql`${t.count} >= 0`),
    check("rate_limit_counters_window", sql`${t.expiresAt} > ${t.windowStart}`),
  ],
);
