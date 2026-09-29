// GENERATED FILE, DO NOT EDIT. Source: shared/protocol/openapi.yaml.
// Regenerate with `pnpm protocol:generate` (from console/).

export interface paths {
    "/enroll": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Exchange a single-use enrollment token for an agent identity
         * @description The token is created by an administrator in the console (single use, valid 24 h) and copied
         *     manually into the agent configuration. The console stores only a hash (SHA-256) of the token and
         *     consumes it **atomically** (a single conditional update: unused and not expired -> used), so two
         *     concurrent enrollments with the same token cannot both succeed. It creates the agent and returns
         *     its `agent_id` and `agent_secret`. The agent stores them in a `0600` file, then generates its
         *     local HMAC key, which is **never transmitted**. This is the only unauthenticated endpoint; it
         *     carries no `Authorization` nor `X-DataBastion-Agent-Id` header, and it is rate limited per
         *     source IP (IPv6 bucketed by /56). Its request and response bodies are excluded from every request, APM and error log on
         *     both sides.
         */
        post: operations["enrollAgent"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/heartbeat": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Report agent status, target status, local detections and metrics
         * @description Sent every `heartbeat_interval_s` seconds (30 s by default). Carries the agent version, uptime,
         *     enabled connectors, the status and honest audit level of each declared target, the engines
         *     detected on the local host but not configured (ADR-0006), the spool state and internal
         *     metrics (ADR-0004), which the console re-exposes on its own `/metrics` endpoint.
         *     The targets reported here are the targets of this agent: results referencing another
         *     `target_id` are rejected with `404`. The agent sends a heartbeat before the first result of a
         *     newly declared target.
         */
        post: operations["sendHeartbeat"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/jobs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Long-poll pending jobs
         * @description The console holds the request for up to `wait` seconds and returns as soon as at least one job
         *     is pending for this agent, or `204` when `wait` elapses. The agent's HTTP client timeout must be
         *     at least `wait + 10` s; behind a proxy with a shorter idle timeout, the agent lowers `wait`.
         *     Revoking an agent closes its held long-poll.
         *
         *     Delivery is **at least once**: a delivered job is leased to the agent, which acknowledges it by
         *     posting a `running` (or terminal) status. A job with no status after 120 s is delivered again.
         *     The agent deduplicates jobs by `job_id`.
         */
        get: operations["pollJobs"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/jobs/{job_id}/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Report the progress or outcome of a job
         * @description Status transitions: `running` -> `running` (progress) -> `succeeded` | `failed`. A job may also go
         *     straight to `failed` (rejected: expired, unknown target, unsupported parameters). The console
         *     ignores updates older than the last one received (`ts`) and answers `409` to any update after a
         *     terminal status. A failure carries a closed error code, never a driver message (which could
         *     contain sampled values or query text).
         */
        post: operations["reportJobStatus"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/findings": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Submit a batch of Discovery findings
         * @description Idempotent on (`agent_id`, `batch_id`). The whole batch is rejected with `400` if any item does
         *     not conform to the schema (in particular any unknown field, which could carry a raw value); the
         *     error `details` let the agent drop only the offending items and resend the rest. `404` when
         *     `job_id` is unknown, not assigned to this agent or not a `discovery.scan` job (pointer
         *     `/job_id`), or when a `target_id` does not belong to this agent (pointer
         *     `/findings/<i>/target_id`, per-item handling). `409` (`batch_conflict`) when the `batch_id` was
         *     already received with a different content.
         *
         *     The job must still accept findings (`delivered` / `running`, or at most 24 h after
         *     `succeeded` / `failed`), the batch's `classifiers_version` and `target_id`s must be the job's,
         *     classifier ids must be registered for that version (`classifiers.json`), and a job accepts at
         *     most 50 000 findings over all its batches: see "Console-side checks" in the description of
         *     this contract for the order of the checks and the exact `pointer` / `keyword` of each answer.
         */
        post: operations["submitFindings"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/events": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Submit a batch of normalized Audit access events
         * @description Same envelope and idempotency rules as `POST /findings` (`batch_id`, UUIDv7, deduplicated on
         *     (`agent_id`, `batch_id`)). Events are pre-aggregated by the agent (same principal, object set and
         *     action within the aggregation window, 60 s by default) and carry no query text. `404` when a
         *     `target_id` does not belong to this agent (`details[].pointer` designates the items).
         *
         *     Time bounds (`400`, item pointers): `ts_last` earlier than `ts` (`formatMinimum` on
         *     `/events/<i>/ts_last`), `ts` or `ts_last` more than 5 min in the future (`formatMaximum`),
         *     `ts` older than the console's event retention (`formatMinimum` on `/events/<i>/ts`; not an
         *     agent-integrity event). `429` for back-pressure (`Retry-After: 30`) and rate limits,
         *     **before** the duplicate check: a batch answered `429` was not recorded, and its retry
         *     under the same `batch_id` is processed as new. See "Console-side checks" in the
         *     description of this contract for the order and the exact answers.
         *
         *     A console that does not implement Audit yet (before phase 4) answers `501`
         *     (`NotImplemented`) without reading the body. The agent then parks `POST /events` only;
         *     `POST /findings` and every other endpoint keep working (see `NotImplemented`).
         */
        post: operations["submitEvents"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/rotate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Register a new agent-generated secret
         * @description Secret rotation. The **agent generates** the new secret; the console never sends one after
         *     enrollment.
         *     1. Trigger: an `agent.rotate_secret` job (which carries no secret), or a local operator command.
         *     2. The agent generates `S1` locally (same format as `AgentSecret`, 256 bits from a CSPRNG) and
         *        persists it as *pending* next to its current secret `S0` (`0600` file, fsync) **before** any
         *        network call.
         *     3. The agent calls `POST /rotate` with `{new_secret: S1}`, authenticated with `S0`.
         *     4. The console stores the argon2id hash of `S1` as pending and answers `200` with
         *        `grace_expires_at` (at most 3600 s later, 300 s by default).
         *     5. The agent switches to `S1` for every subsequent request. **Promotion**: the first successful
         *        request authenticated with `S1`, or `grace_expires_at`, whichever comes first, makes `S1`
         *        current and revokes `S0`. When the rotation was requested by a job, the agent reports it as
         *        `succeeded` with `S1`.
         *
         *     **Retries are idempotent**: after a network error the agent resends the **same** `S1` with `S0`;
         *     the console compares it with the pending hash and answers `200` with `duplicate: true` and the
         *     unchanged deadline. The agent **never generates a new secret while one is pending**: it reuses
         *     the pending `S1`, including when a rotate job is redelivered. After a restart with a pending `S1`,
         *     the agent authenticates with `S1` first and falls back to `S0` only on `401` (then `S1` was never
         *     registered, and it retries step 3). Conversely, any `401` received while a pending `S1` exists
         *     makes the agent retry with `S1` before any other `401` handling.
         *
         *     Unless `S0` is stale (see below), a body that fails validation, or a `new_secret` equal to the
         *     authenticating secret or obviously low-entropy (see `AgentSecret`), is rejected with `400`
         *     (`invalid_request` / `invalid_secret`) before any duplicate or conflict check.
         *
         *     **Terminology.** `S0` is the secret that authenticated the rotation and `S1` the new one. While
         *     `S1` is pending, `S0` is still the current secret. Once `S1` is promoted, `S0` is the
         *     *previous* secret. **Tolerance window** (ADR-0010): the **60 s** that follow the promotion of
         *     `S1`. A *stale* `S0` is `S0` used **after** that window.
         *
         *     **Takeover detection** (someone else holds `S0`, ADR-0010, ADR-0011). The console decides from
         *     the secret that authenticates the request:
         *     - `/rotate` authenticated with `S0` whose `new_secret` is the **same** as the pending `S1`, or
         *       as the promoted (current) `S1`: idempotent retry, answered `200` with `duplicate: true` and
         *       the original `grace_expires_at` of that rotation. For the promoted `S1` this holds **at any
         *       time** after promotion, not only within the 60 s window (late retry, ADR-0011); it carries no
         *       secret and changes no state. Only the holder of `S1` can produce it;
         *     - `/rotate` authenticated with `S0` whose well-formed, non-low-entropy `new_secret` **differs**
         *       from the pending `S1`, or from the promoted `S1`: `409` `rotation_conflict`. While `S1` is
         *       pending or inside the 60 s window, the usual `400`, `404`, `429` and `503` answers of
         *       `/rotate` still apply to `S0` before this check;
         *     - once the console has recognized a **stale** `S0`, a `/rotate` has exactly two outcomes: the
         *       late-retry `duplicate` above, or `409` `rotation_conflict`. Anything else (body that fails
         *       validation, low-entropy or other `new_secret`, unknown `job_id`) is a `rotation_conflict`:
         *       this path never answers `400`, `404`, `429` or `503`. Late retries are bounded: more than
         *       **10** within a 5-minute window (the 11th locks). Answers given before the secret is
         *       recognized (protocol headers, authentication rate limit, verification capacity) are the
         *       same as for any secret; a stale `S0` that was replaced meanwhile, or of a revoked agent, gets
         *       `401`;
         *     - any request to another endpoint authenticated with `S0` within the 60 s tolerance window
         *       (requests in flight during the switch): plain `401`, no incident;
         *     - any request to another endpoint authenticated with a stale `S0`: `409` `rotation_conflict`.
         *
         *     A `/rotate` authenticated with the current secret while no secret is pending (in particular
         *     `S1` right after its promotion) always starts a new rotation and is **never** a
         *     `rotation_conflict`; the `invalid_secret` checks above still apply. The stale `S0` of the
         *     previous rotation is then forgotten once the new one is promoted.
         *
         *     On `rotation_conflict` (every case) the console **locks the agent, revokes every secret
         *     (current and pending), closes its long-polls and raises a security incident**. The agent that
         *     receives `rotation_conflict` stops all activity, logs a critical error and requires
         *     re-enrollment. A conforming agent never triggers it: the console never issues an
         *     `agent.rotate_secret` job while a secret is pending or within 60 s of a promotion, and the agent
         *     defers an `agent.rotate_secret` job received within 60 s of a promotion, so it never starts a
         *     rotation inside the window.
         *
         *     Suspected compromise is not handled by rotation: the administrator revokes the agent and
         *     re-enrolls it. The endpoint is rate limited (`429`). Its request body is excluded from every
         *     request, APM and error log on both sides.
         */
        post: operations["rotateSecret"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /**
         * Format: uuid
         * @description Canonical lowercase UUID.
         */
        Uuid: string;
        /**
         * Format: uuid
         * @description Canonical lowercase UUID version 7 (time ordered), generated by the agent.
         */
        UuidV7: string;
        /**
         * Format: date-time
         * @description RFC 3339 date-time, UTC recommended.
         */
        Timestamp: string;
        /** @description Semantic version of the agent binary. */
        AgentVersion: string;
        /** @description Protocol major version. */
        ProtocolMajor: number;
        /** @description Interval, in seconds, between two heartbeats. */
        HeartbeatIntervalSeconds: number;
        /**
         * @description Single-use enrollment token created in the console (valid 24 h): `dbe_` + 43 base64url chars
         *     (256 random bits). Stored hashed by the console.
         */
        EnrollmentToken: string;
        /**
         * @description Agent secret: `dbs_` + 43 base64url chars (256 random bits from a CSPRNG). Issued by the console
         *     in the `/enroll` response, generated by the agent for `/rotate`. Sent only in the
         *     `Authorization` header afterwards. Never logged by either side. The console rejects obviously
         *     low-entropy values (e.g. fewer than 16 distinct characters in the 43-character body, such as a
         *     single repeated character) with `400` `invalid_secret`.
         */
        AgentSecret: string;
        /** @description Host name of the agent host (RFC 1123), informational. */
        Hostname: string;
        /**
         * @description Identifier of a target, as declared in `agent.yaml` (ADR-0006). Unique per agent. A slug: it
         *     cannot contain a host name, address or credential.
         */
        TargetId: string;
        /**
         * @description Classifier identifier, e.g. `pii.email`, `pii.iban`, `secret.aws_key`. The valid ids of each
         *     `classifiers_version` are listed in the classifier registry `shared/protocol/classifiers.json`;
         *     the console rejects an id that is not registered for the batch's version (`enum`). An id is
         *     never renamed: a change of meaning is a new id in a new classifier set version.
         */
        ClassifierId: string;
        /**
         * @description Version of the classifier set, `YYYY.MM.N`, e.g. `2026.09.1`. Findings are accepted only for a
         *     version listed in the classifier registry `shared/protocol/classifiers.json` (`enum` otherwise).
         */
        ClassifiersVersion: string;
        /**
         * @description Exfiltration indicator computed by the agent from the raw audit data (ADR-0007). The
         *     vocabulary is the **signal registry** `shared/protocol/signals.json` (next to this file,
         *     schema `signals.schema.json`), which describes each id: a conforming agent emits only
         *     registered ids. Registered: `signature.pg_dump`, `signature.copy_to_file`,
         *     `signature.copy_to_program`, `signature.mysqldump`, `signature.into_outfile`,
         *     `signature.mongodump`, `signature.mongoexport`, `shape.full_table_copy`,
         *     `shape.full_table_read`, `shape.bulk_search`, `volume.large_result`. Families: `signature.*` a dump or export
         *     tool or command (the console treats it as severe), `shape.*` a query shape (heuristic,
         *     evadable), `volume.*` a volume threshold of the agent. The registry is **append-only**: a
         *     new signal is a new entry added by a compatible contract change; an id is never removed,
         *     renamed or given another meaning.
         *
         *     The name after the family is 1 to 6 words of 1 to 16 lowercase letters joined by `_`: no
         *     digit, so an id cannot carry a number (an account, card or phone number). This schema
         *     checks the **form** only (pattern), not registration, so that a console
         *     accepts a signal registered after it was built; it stores such a signal and matches it by
         *     exact id or family (`signature.*`). The console computes its own baseline verdict and
         *     does not rely on any `volume.*` signal for it (ADR-0021).
         */
        Signal: string;
        /**
         * @description `HMAC-SHA256(agent_local_key, "databastion/fp/v1" 0x00 classifier_id 0x00 normalized_value)`,
         *     lowercase hex, with `db_user` in place of the classifier id for `db_user_fingerprint`. The
         *     domain separation keeps the same string under two classifiers, or as an account name, from
         *     correlating. The key never leaves the agent, so fingerprints only correlate values seen by the
         *     same agent.
         *
         *     The normalization of the value is **agent-local and not part of this contract**: it belongs to
         *     the agent's classifier implementation and may change with its classifier set version. The
         *     console treats fingerprints as opaque, compares them only for equality, and must not assume
         *     that fingerprints of different agents, classifiers or `classifiers_version`s correlate.
         */
        Fingerprint: string;
        /**
         * @description Sample masked by `classifiers::masking` (e.g. `j***@e***.com`,
         *     `FR** **** **** **** **** ***0 189`). Schema rules: contains at least one `*`, no run of more than
         *     4 consecutive letters or digits, no combining mark, no control / format / private-use / line
         *     separator character. The console additionally requires at least 50 % of the non-separator characters (letters, digits
         *     and `*`; spaces and punctuation ignored) to be `*`: `06 ** ** ** 78` passes (6 of 10).
         */
        MaskedSample: string;
        /**
         * @description **Normalized** name of a database object: database, schema, table, collection, column, field
         *     path, LDAP suffix, container or attribute. Never a value, never a record identifier.
         *
         *     Normalization rules (`x-databastion-normalized-name`), applied by the agent before the uplink:
         *     - array indices in a path become `[]` (`orders.3.email` -> `orders[].email`);
         *     - dynamic keys (map keys, keys that look like identifiers or values) and any name segment
         *       matched by a classifier become `*` (`contacts.jane@example.com.phone` -> `contacts.*.phone`);
         *     - an LDAP entry DN is reduced to its parent container (`uid=jdoe,ou=people,dc=example,dc=com`
         *       -> `ou=people,dc=example,dc=com`); attribute types are lowercased;
         *     - a name that still does not match this schema is replaced by `*`.
         *
         *     Pattern: either a plain name, which excludes `@ = : ; / \ ' "`, backquote, `< > ( ) ,` and
         *     control / format characters (so no e-mail address, `key=value`, URL or SQL fragment), or an LDAP
         *     container DN made only of `ou=`, `dc=`, `o=`, `c=`, `l=`, `st=` RDNs (never `uid=` / `cn=`).
         */
        Identifier: string;
        /**
         * @description Console-provided filter on object names: an exact name, or a glob with `*` and `?`. The agent
         *     treats it as a name filter only and never interpolates it into a query.
         */
        IdentifierPattern: string;
        /** @description Non-negative integer counter, bounded to the JavaScript safe integer range. */
        Count: number;
        /**
         * @description Absolute path of a local Unix socket under a well-known runtime directory (`/run`, `/var/run`,
         *     `/tmp`, `/var/lib/mysql`), e.g. `/var/run/postgresql/.s.PGSQL.5432`. No segment starting with
         *     `..`. The agent only reports sockets from its fixed probe list.
         */
        UnixSocketPath: string;
        /**
         * @description IPv4 or IPv6 literal of the database client as logged by the engine, or `local` for a Unix socket
         *     connection. Never a host name.
         */
        ClientAddress: string | "local";
        /**
         * @description Database or directory engine.
         * @enum {string}
         */
        Engine: "postgres" | "mysql" | "mariadb" | "mongodb" | "openldap";
        /**
         * @description Agent connector (Cargo feature). `mysql` covers MySQL and MariaDB.
         * @enum {string}
         */
        Connector: "postgres" | "mysql" | "mongodb" | "openldap";
        /** @description Connectors compiled in and enabled in this agent. */
        ConnectorList: components["schemas"]["Connector"][];
        /**
         * @description Audit level actually reached for a target (docs/08-engine-capabilities.md). Reported honestly:
         *     e.g. PostgreSQL without pgaudit is `limited`, MySQL Community `partial`, MongoDB Community
         *     `limited` (or `partial` with profiler level 2), a target with audit disabled `none`.
         * @enum {string}
         */
        AuditLevel: "full" | "partial" | "limited" | "none";
        /**
         * @description Native source used for Audit on a target.
         * @enum {string}
         */
        AuditSource: "pgaudit" | "pg_stat_statements" | "pg_stat_activity" | "mariadb_server_audit" | "mysql_audit_log" | "performance_schema" | "mongodb_audit_log" | "mongodb_profiler" | "mongodb_log" | "openldap_accesslog";
        /**
         * @description Engine edition or distribution, when the agent can tell.
         * @enum {string}
         */
        Edition: "community" | "enterprise" | "percona";
        /**
         * @description Closed set of failure causes. Driver or engine messages are never sent (they can contain values
         *     or query text); `engine_code` may carry the engine's numeric / SQLSTATE code.
         * @enum {string}
         */
        FailureCode: "target_unreachable" | "authentication_failed" | "permission_denied" | "timeout" | "cancelled" | "expired" | "unknown_target" | "unsupported" | "invalid_params" | "resource_limit" | "internal";
        /** @description Engine error code (SQLSTATE, MySQL / MongoDB numeric code, LDAP result code). No text. */
        EngineCode: string;
        /**
         * @description Common error body for every non-2xx response. `message` is a fixed, generic English sentence chosen
         *     by the console; it **never echoes submitted values**. Validation `details` point to the offending
         *     location with a JSON pointer that the console builds **only from property names known to this
         *     schema** and array indices: an unknown property is reported on its parent object, never by its
         *     (possibly sensitive) name.
         */
        Error: {
            /**
             * @description Closed set. Agents decode it strictly, so adding a value is an incompatible change (new
             *     ADR and protocol version); a new situation reuses an existing code (e.g. `unavailable`
             *     for `501`, see `NotImplemented`).
             * @enum {string}
             */
            code: "invalid_request" | "unauthorized" | "not_found" | "conflict" | "batch_conflict" | "rotation_conflict" | "invalid_secret" | "payload_too_large" | "protocol_unsupported" | "rate_limited" | "unavailable" | "internal";
            message: string;
            request_id?: components["schemas"]["Uuid"];
            /** @description Present on `426`; minimum protocol major version accepted by the console. */
            min_protocol?: components["schemas"]["ProtocolMajor"];
            details?: components["schemas"]["ErrorDetail"][];
        };
        ErrorDetail: {
            /** @description JSON pointer into the submitted body (e.g. `/findings/3/confidence`); `""` for the root. */
            pointer: string;
            /**
             * @description Violated JSON Schema keyword (e.g. `additionalProperties`, `maximum`, `pattern`), or the
             *     keyword of a console-side check (see "Console-side checks" in the description of this
             *     contract):
             *     - `const`: a value that must equal the job's (`/classifiers_version`,
             *       `/findings/<i>/target_id`) or the target's (`/findings/<i>/location/engine`);
             *     - `notFound`: unknown job or target, or one not assigned to the calling agent (`/job_id`,
             *       `/findings/<i>/target_id`, `/events/<i>/target_id`), with `404`;
             *     - `maximum`: `matched > sampled`, or `sampled` above the job's `params.sample_rows`;
             *     - `enum`: `classifiers_version` not in the classifier registry (`/classifiers_version`),
             *       or a classifier id not registered for the batch's version or outside the job's
             *       `params.classifiers` (`/findings/<i>/classifier`);
             *     - `maxItems`: the per-job findings cap would be exceeded (`/findings`);
             *     - `formatMaximum`: a timestamp more than 5 min in the future (`/ts` of a status
             *       update, `/events/<i>/ts`, `/events/<i>/ts_last`);
             *     - `formatMinimum`: an access event's `ts_last` earlier than its `ts`
             *       (`/events/<i>/ts_last`), or its `ts` older than the console's event retention
             *       (`/events/<i>/ts`);
             *     - `maxBytes`, `maskRatio`, `falseSchema`, `invalid`: see `shared/protocol/README.md`.
             */
            keyword: string;
        };
        EnrollRequest: {
            token: components["schemas"]["EnrollmentToken"];
            hostname: components["schemas"]["Hostname"];
            agent_version: components["schemas"]["AgentVersion"];
            connectors: components["schemas"]["ConnectorList"];
            /** @enum {string} */
            os?: "linux";
            /** @enum {string} */
            arch?: "x86_64" | "aarch64";
        };
        /**
         * @description The agent identity. The agent's HMAC key is generated locally after enrollment and never
         *     appears in this protocol.
         */
        EnrollResponse: {
            agent_id: components["schemas"]["Uuid"];
            agent_secret: components["schemas"]["AgentSecret"];
            console_min_protocol: components["schemas"]["ProtocolMajor"];
            heartbeat_interval_s: components["schemas"]["HeartbeatIntervalSeconds"];
        };
        /**
         * @description Body of `POST /rotate`. A new rotation is authenticated with the current secret while no secret
         *     is pending (`S0`); a retry is authenticated with the same `S0` and resends the same
         *     `new_secret` (`S1`), which is answered `duplicate` while `S1` is pending and, after its
         *     promotion, at any time within the late-retry bound (see `POST /rotate`). `new_secret` is
         *     generated by the agent and persisted as pending before the call. Unless `S0` is stale, a body
         *     that fails validation, or a `new_secret` equal to the authenticating secret or obviously
         *     low-entropy, is rejected with `400` (`invalid_request` / `invalid_secret`) before any duplicate
         *     or conflict check; with a stale `S0` (recognized after the 60 s tolerance window), any request
         *     other than a late retry is a `409` `rotation_conflict`.
         */
        RotateRequest: {
            new_secret: components["schemas"]["AgentSecret"];
            /** @description The `agent.rotate_secret` job that requested this rotation, if any. */
            job_id?: components["schemas"]["Uuid"];
        };
        /**
         * @description Answer to an accepted `POST /rotate`: a new pending secret, or an idempotent retry (`duplicate`).
         *     Carries no secret.
         */
        RotateResponse: {
            /**
             * @description Deadline at which the pending secret is promoted and the previous one revoked, if the new
             *     secret has not been used before. At most 3600 s after the first registration; never extended
             *     by a retry.
             */
            grace_expires_at: components["schemas"]["Timestamp"];
            /**
             * @description `true` when the request was authenticated with `S0` and this exact secret is already pending,
             *     or is the current secret promoted from it (idempotent or late retry). `grace_expires_at` is
             *     then the original deadline.
             */
            duplicate: boolean;
        };
        /**
         * @description Internal metrics as a bounded `name -> number` map (counters, gauges, durations in seconds).
         *     The only open-keyed object of the protocol: names are restricted to `^[a-z][a-z0-9_]{0,63}$`
         *     and values to numbers, so it cannot carry text.
         *
         *     The console re-exposes them on `/metrics` under the distinct prefix `databastion_agent_reported_`
         *     with labels `agent_id` (and `target_id` for target metrics), so an agent can never shadow a
         *     console-computed metric such as `databastion_agent_last_seen_seconds`. Names on the console's
         *     reserved list (e.g. `last_seen_seconds`, `up`, `revoked`) are ignored.
         */
        MetricsMap: {
            [key: string]: number;
        };
        HeartbeatRequest: {
            /** @description Agent clock when the heartbeat was built (lets the console detect clock skew). */
            ts: components["schemas"]["Timestamp"];
            agent_version: components["schemas"]["AgentVersion"];
            uptime_s: components["schemas"]["Count"];
            classifiers_version?: components["schemas"]["ClassifiersVersion"];
            connectors: components["schemas"]["ConnectorList"];
            /** @description Status of every target declared in `agent.yaml`. */
            targets: components["schemas"]["TargetStatus"][];
            /**
             * @description Engines detected on the **local host** but not configured (ADR-0006), as suggestions for the
             *     console's configuration wizard. Never a target network address, never a process command line.
             */
            detected_targets: components["schemas"]["DetectedTarget"][];
            /** @description Jobs currently executing, so the console can detect lost jobs. */
            running_jobs?: components["schemas"]["Uuid"][];
            spool: components["schemas"]["SpoolStatus"];
            metrics?: components["schemas"]["MetricsMap"];
            /**
             * @description Optional **response and job** fields and features this agent build accepts
             *     (ADR-0022). Agents reject unknown fields in every console -> agent body, so the
             *     console sends a console -> agent field introduced after protocol 0.1.0 (in a response
             *     or in a job) only when the agent's latest heartbeat listed it. None exists yet: the
             *     agent omits the list. Unknown tokens are ignored by the console.
             */
            accepts?: components["schemas"]["CapabilityList"];
        };
        TargetStatus: {
            target_id: components["schemas"]["TargetId"];
            engine: components["schemas"]["Engine"];
            edition?: components["schemas"]["Edition"];
            /**
             * @description Engine version as reported by the server (e.g. `16.4`, `11.4.3`, `7.0.12`, `2.6.8`). Omitted
             *     when the reported string does not match this pattern.
             */
            server_version?: string;
            /** @description Whether the last connection attempt with the configured read-only account succeeded. */
            reachable: boolean;
            audit_level: components["schemas"]["AuditLevel"];
            audit_source?: components["schemas"]["AuditSource"];
            /** @description Cause of the last failed `check()` or connection, if any. */
            last_error?: components["schemas"]["FailureCode"];
            /**
             * @description Explanations of the target's status from the last `check()`: why the audit level is
             *     degraded, what is not covered, over-privilege, an insecure setting. Closed codes with
             *     bounded parameters, never free text; the console renders them (see `TargetNote`).
             *     Sent only when the latest `HeartbeatResponse.accepts` lists `target_status.notes`.
             */
            notes?: components["schemas"]["TargetNote"][];
            metrics?: components["schemas"]["MetricsMap"];
        };
        /**
         * @description One explanation of a target's status: a registered `code`, an optional `count` and
         *     optional closed `labels`. No free text, so no field can carry a sampled value, a
         *     credential, a connection string, a host name or address, query text or a driver
         *     message. The console renders a phrase for each code from its catalog, filling in `count`
         *     and `labels`; a code it does not know is shown as the raw code (with its count and
         *     labels), never rejected. E.g. `{"code": "audit.pgaudit_read_class_missing"}`,
         *     `{"code": "coverage.relations_rls_skipped", "count": 5}`,
         *     `{"code": "privilege.over_privileged", "labels": ["bypassrls", "pg_write_all_data"]}`.
         */
        TargetNote: {
            code: components["schemas"]["TargetNoteCode"];
            /** @description The number the note is about (relations, schemas, records, roles…), when it has one. */
            count?: components["schemas"]["Count"];
            /** @description Closed labels the note is about (privileges, role attributes, predefined roles…). */
            labels?: components["schemas"]["TargetNoteLabel"][];
        };
        /**
         * @description Code of a target note. The vocabulary is the registry `shared/protocol/target-notes.json`
         *     (append-only, like `signals.json`): a conforming agent sends only registered codes; the
         *     schema checks the form only, so an older console accepts a code registered later and
         *     shows it raw. Families: `audit.*` audit collection, `coverage.*` Discovery coverage,
         *     `privilege.*` privileges of the agent's account, `security.*` insecure settings,
         *     `check.*` the check itself. The name after the family is 1 to 6 words of 1 to 16
         *     lowercase letters joined by `_`: no digit, so a code cannot carry a number.
         */
        TargetNoteCode: string;
        /**
         * @description Closed label of a target note, in lower snake case: PostgreSQL role attributes and
         *     predefined roles; MySQL / MariaDB privilege names lowercased with spaces replaced by `_`
         *     (so MariaDB `BINLOG ADMIN` and MySQL `BINLOG_ADMIN` are both `binlog_admin`); audit
         *     collection states; check stages (`stage_*`). Anything the agent cannot map to this list
         *     is sent as `other`. A new value is a
         *     change of this enum: the agent sends it only when the latest `HeartbeatResponse.accepts`
         *     lists `target_status.note_labels.<revision>` for a revision that includes it (see
         *     ADR-0022), and sends `other` otherwise.
         * @enum {string}
         */
        TargetNoteLabel: "other" | "superuser" | "bypassrls" | "replication" | "createrole" | "createdb" | "pg_checkpoint" | "pg_create_subscription" | "pg_database_owner" | "pg_execute_server_program" | "pg_maintain" | "pg_monitor" | "pg_read_all_data" | "pg_read_all_settings" | "pg_read_all_stats" | "pg_read_server_files" | "pg_signal_autovacuum_worker" | "pg_signal_backend" | "pg_stat_scan_tables" | "pg_use_reserved_connections" | "pg_write_all_data" | "pg_write_server_files" | "alter" | "alter_routine" | "binlog_admin" | "binlog_monitor" | "binlog_replay" | "connection_admin" | "create" | "create_role" | "create_routine" | "create_tablespace" | "create_temporary_tables" | "create_user" | "create_view" | "delete" | "delete_history" | "drop" | "drop_role" | "event" | "execute" | "federated_admin" | "file" | "index" | "insert" | "lock_tables" | "process" | "read_only_admin" | "references" | "reload" | "replica_monitor" | "replication_client" | "replication_master_admin" | "replication_slave" | "replication_slave_admin" | "select" | "set_user" | "show_create_routine" | "show_databases" | "show_view" | "shutdown" | "slave_monitor" | "super" | "trigger" | "update" | "application_password_admin" | "audit_abort_exempt" | "audit_admin" | "authentication_policy_admin" | "backup_admin" | "binlog_encryption_admin" | "clone_admin" | "encryption_key_admin" | "firewall_admin" | "flush_optimizer_costs" | "flush_status" | "flush_tables" | "flush_user_resources" | "group_replication_admin" | "innodb_redo_log_archive" | "passwordless_user_admin" | "persist_ro_variables_admin" | "replication_applier" | "resource_group_admin" | "resource_group_user" | "role_admin" | "sensitive_variables_observer" | "session_variables_admin" | "set_any_definer" | "set_user_id" | "show_routine" | "system_user" | "system_variables_admin" | "table_encryption_admin" | "xa_recover_admin" | "logging_on" | "logging_off" | "file_output" | "non_file_output" | "stage_secret" | "stage_tls" | "stage_connect" | "stage_auth" | "stage_session_setup" | "stage_begin" | "stage_commit" | "stage_introspection" | "stage_columns" | "stage_sample" | "stage_check" | "stage_audit" | "stage_kill";
        /**
         * @description A local engine spotted by a Unix socket, a local listening port or a process name. At least one
         *     of `unix_socket`, `port`, `process` is present. The agent never connects to a detected target.
         */
        DetectedTarget: {
            engine: components["schemas"]["Engine"];
            unix_socket?: components["schemas"]["UnixSocketPath"];
            /** @description Local listening TCP port. The listening address is not reported. */
            port?: number;
            /**
             * @description Process name only (the command line may contain secrets and is never read or sent).
             * @enum {string}
             */
            process?: "postgres" | "mysqld" | "mariadbd" | "mongod" | "slapd";
        };
        SpoolStatus: {
            bytes: components["schemas"]["Count"];
            max_bytes: components["schemas"]["Count"];
            batches: components["schemas"]["Count"];
            /** @description Age, in seconds, of the oldest spooled batch. */
            oldest_age_s?: components["schemas"]["Count"];
            /** @description Batches dropped since start (spool full, or rejected with a non-retryable 4xx). */
            dropped_batches?: components["schemas"]["Count"];
            /** @description Individual findings / events dropped since start after a `400` or `404` pointing at them. */
            dropped_items?: components["schemas"]["Count"];
        };
        /**
         * @description Name of an optional field or feature (ADR-0022): `<object>.<field>` in snake case, e.g.
         *     `access_event.bytes`, with up to two more segments for a revision
         *     (`target_status.note_labels.2026_10`). Form only: a party ignores tokens it does not know.
         */
        Capability: string;
        /** @description Capability tokens (ADR-0022). */
        CapabilityList: components["schemas"]["Capability"][];
        HeartbeatResponse: {
            console_min_protocol: components["schemas"]["ProtocolMajor"];
            heartbeat_interval_s: components["schemas"]["HeartbeatIntervalSeconds"];
            server_time: components["schemas"]["Timestamp"];
            /**
             * @description Optional **request** fields and features this console accepts (ADR-0022), e.g.
             *     `target_status.notes`, `access_event.bytes`, `job_progress.coverage`. The agent keeps
             *     the list of the latest heartbeat response and sends an optional request field
             *     introduced after protocol 0.1.0 only when that list names it; before its first
             *     heartbeat response, and when the list is absent, it sends none of them. The console
             *     lists everything it accepts. Unknown tokens are ignored by the agent.
             */
            accepts?: components["schemas"]["CapabilityList"];
        };
        JobList: {
            jobs: components["schemas"]["Job"][];
        };
        /**
         * @description A console order, discriminated by `type`. Jobs never carry a secret, a credential, a connection
         *     string or configuration content: targets and credentials live in the agent's local `agent.yaml`.
         */
        Job: components["schemas"]["DiscoveryScanJob"] | components["schemas"]["AuditConfigureJob"] | components["schemas"]["AgentConfigReloadJob"] | components["schemas"]["AgentRotateSecretJob"];
        /**
         * @description A Discovery scan of one target. The console issues it only with the `classifiers_version` of
         *     the agent's latest heartbeat, registered in `classifiers.json`. The agent refuses a job whose
         *     `classifiers_version` is not its compiled one (or whose `params.classifiers` holds ids unknown
         *     to that set) **before touching the target**, reporting `failed` with `unsupported`. Findings
         *     of the job: see "Console-side checks" in the description of this contract.
         */
        DiscoveryScanJob: {
            job_id: components["schemas"]["Uuid"];
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "discovery.scan";
            created_at: components["schemas"]["Timestamp"];
            /** @description The agent must not start the job after this instant (reports `failed` / `expired`). */
            expires_at?: components["schemas"]["Timestamp"];
            target_id: components["schemas"]["TargetId"];
            /**
             * @description Classifier set the scan must use: the version from the agent's latest heartbeat, always
             *     registered in `classifiers.json`. Findings batches of this job must carry the same
             *     version. An agent whose compiled classifier set version differs refuses the job before
             *     touching the target and reports `failed` / `unsupported`.
             */
            classifiers_version: components["schemas"]["ClassifiersVersion"];
            params: components["schemas"]["DiscoveryScanParams"];
        };
        /**
         * @description Bounds of a Discovery scan (invariant I4). The agent also applies its own local hard limits and
         *     a per-statement timeout on every query.
         */
        DiscoveryScanParams: {
            /**
             * @description Maximum rows (documents, entries) sampled per object.
             * @default 200
             */
            sample_rows: number;
            /**
             * @description Wall-clock budget of the whole scan.
             * @default 900
             */
            max_duration_s: number;
            /**
             * @description Timeout applied to each query against the target.
             * @default 30000
             */
            statement_timeout_ms: number;
            /**
             * @description Databases (or LDAP suffixes) to include. Absent = all visible to the account. An empty list is
             *     rejected (`minItems: 1`) so that a "none selected" bug can never widen a scan to everything.
             */
            databases?: components["schemas"]["IdentifierPattern"][];
            /** @description Schemas to include (PostgreSQL). Absent = all. An empty list is rejected (`minItems: 1`). */
            schemas?: components["schemas"]["IdentifierPattern"][];
            /**
             * @description Tables / collections / objectClasses to include. Absent = all. An empty list is rejected
             *     (`minItems: 1`).
             */
            include_objects?: components["schemas"]["IdentifierPattern"][];
            /**
             * @description Tables / collections / objectClasses to skip. Absent or empty = nothing skipped (an empty list
             *     cannot widen the scan beyond the include filters, so it is accepted).
             */
            exclude_objects?: components["schemas"]["IdentifierPattern"][];
            /**
             * @description Restrict the scan to these classifiers. Absent = all classifiers of `classifiers_version`
             *     (as listed in `classifiers.json`); present = ids of that version only.
             *     An empty list is rejected (`minItems: 1`): it never means "no classifiers" nor "all".
             */
            classifiers?: components["schemas"]["ClassifierId"][];
        };
        AuditConfigureJob: {
            job_id: components["schemas"]["Uuid"];
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "audit.configure";
            created_at: components["schemas"]["Timestamp"];
            expires_at?: components["schemas"]["Timestamp"];
            target_id: components["schemas"]["TargetId"];
            params: components["schemas"]["AuditConfigureParams"];
        };
        /**
         * @description Audit settings for one target. Replaces the previous settings as a whole. Detection thresholds
         *     and scoring are applied by the console's worker; these settings only drive collection and
         *     pre-aggregation on the agent.
         */
        AuditConfigureParams: {
            enabled: boolean;
            /**
             * @description Pre-aggregation window (same principal, object set and action).
             * @default 60
             */
            aggregation_window_s: number;
            /**
             * @description Polling interval for polled sources (`performance_schema`, `pg_stat_activity`, `cn=accesslog`, profiler).
             * @default 10
             */
            poll_interval_s: number;
            /**
             * @description Events on objects that are not listed in `sensitive_objects` and carry no signal are only
             *     reported when they return at least this many rows.
             */
            min_rows?: components["schemas"]["Count"];
            /**
             * @description Objects classified as sensitive by Discovery, whose accesses are always reported. Absent or
             *     empty = no object is flagged sensitive: the settings replace the previous ones as a whole, so
             *     an empty list legitimately clears them. An empty list narrows reporting to events that carry
             *     a signal or reach `min_rows`; it can never widen what is reported.
             */
            sensitive_objects?: components["schemas"]["SensitiveObject"][];
        };
        SensitiveObject: {
            database: components["schemas"]["Identifier"];
            schema?: components["schemas"]["Identifier"];
            object: components["schemas"]["Identifier"];
            classifiers: components["schemas"]["ClassifierId"][];
        };
        /**
         * @description Asks the agent to re-read its **local** `agent.yaml`. The job carries no configuration: targets and
         *     credentials never transit through the console (invariant I3).
         */
        AgentConfigReloadJob: {
            job_id: components["schemas"]["Uuid"];
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "agent.config.reload";
            created_at: components["schemas"]["Timestamp"];
            expires_at?: components["schemas"]["Timestamp"];
            params: components["schemas"]["EmptyParams"];
        };
        /**
         * @description Asks the agent to rotate its secret. **Carries no secret**: the agent generates the new secret and
         *     registers it with `POST /rotate`. Suspected compromise is handled by revocation and
         *     re-enrollment, not by this job. The console never issues it while a secret is pending, nor within
         *     60 s of a promotion; the agent defers such a job received within 60 s of a promotion
         *     (ADR-0010).
         */
        AgentRotateSecretJob: {
            job_id: components["schemas"]["Uuid"];
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "agent.rotate_secret";
            created_at: components["schemas"]["Timestamp"];
            expires_at?: components["schemas"]["Timestamp"];
            params: components["schemas"]["RotateSecretParams"];
        };
        RotateSecretParams: {
            /** @enum {string} */
            reason?: "scheduled" | "manual";
        };
        /** @description No parameters. */
        EmptyParams: Record<string, never>;
        /** @description `error` is required when `status` is `failed`, and forbidden otherwise. */
        JobStatusUpdate: {
            /** @enum {string} */
            status: "running" | "succeeded" | "failed";
            ts: components["schemas"]["Timestamp"];
            progress?: components["schemas"]["JobProgress"];
            error?: components["schemas"]["JobError"];
        };
        JobProgress: {
            /** @description Estimated completion, from 0 to 1. */
            ratio?: number;
            /** @description Objects processed so far (sampled or skipped). */
            objects_done?: components["schemas"]["Count"];
            /**
             * @description Objects in the job's scope (`discovery.scan`: after its filters, across all databases
             *     of the target).
             */
            objects_total?: components["schemas"]["Count"];
            /** @description Findings reported so far for this job. */
            findings?: components["schemas"]["Count"];
            /**
             * @description Findings batches sent so far for this job. On `succeeded`, lets the console check that it
             *     received all of them.
             */
            batches?: components["schemas"]["Count"];
            /**
             * @description `discovery.scan` coverage: objects (tables, collections, LDAP object classes) actually
             *     sampled so far. With the `skipped_*` counters below, `objects_total` (the objects
             *     listed in the job's scope, after its filters, across all databases of the target) and
             *     `objects_done` (the objects processed, sampled or skipped), it tells how much of the
             *     scope a scan covered: `objects_total - objects_done` objects were not reached (scan
             *     stopped by its deadline, cancellation or the findings cap). Coverage counters are
             *     counts only, never a name; each is optional (absent: not reported; a `skipped_*`
             *     reason absent counts 0) and none is checked by the console. A new skip reason is a new
             *     optional `skipped_*` counter (compatible change, negotiated like any new request
             *     field). `objects_sampled` and the `skipped_*` counters are sent only when the latest
             *     `HeartbeatResponse.accepts` lists `job_progress.coverage` (ADR-0022).
             */
            objects_sampled?: components["schemas"]["Count"];
            /** @description Objects not sampled because the agent's account cannot read them (e.g. no `SELECT` on any column). */
            skipped_not_readable?: components["schemas"]["Count"];
            /**
             * @description Objects not sampled because of row-level security (PostgreSQL: a policy depending on
             *     user code or on another relation, or a row-level security ancestor; ADR-0012).
             */
            skipped_row_level_security?: components["schemas"]["Count"];
            /** @description Objects whose data is held outside the target (foreign tables, remote-access engines); never read (I5). */
            skipped_remote?: components["schemas"]["Count"];
            /**
             * @description Objects of a kind the connector does not sample (views, merge tables, sequences,
             *     storage engines outside the connector's allow-list).
             */
            skipped_unsupported?: components["schemas"]["Count"];
            /**
             * @description Objects beyond a structural bound of the connector (partition leaves over the per-root
             *     cap, a truncated catalog listing).
             */
            skipped_limit?: components["schemas"]["Count"];
            /**
             * @description Objects whose sampling failed (e.g. statement timeout, a privilege error at query
             *     time), after which the scan went on with the next object.
             */
            skipped_error?: components["schemas"]["Count"];
        };
        JobError: {
            code: components["schemas"]["FailureCode"];
            engine_code?: components["schemas"]["EngineCode"];
        };
        BatchAck: {
            batch_id: components["schemas"]["UuidV7"];
            /** @description `true` when this (`agent_id`, `batch_id`) had already been received with the same content; the batch was not processed again. */
            duplicate: boolean;
        };
        /** @description Serialized size at most 1 MiB (agent-side bound, `x-databastion-max-bytes`). */
        FindingsBatch: {
            batch_id: components["schemas"]["UuidV7"];
            /** @description The `discovery.scan` job that produced these findings. */
            job_id: components["schemas"]["Uuid"];
            /** @description Must equal the job's `classifiers_version` (`const`) and be registered (`enum`). */
            classifiers_version: components["schemas"]["ClassifiersVersion"];
            findings: components["schemas"]["Finding"][];
        };
        /**
         * @description A location contains a sensitive data type. `matched <= sampled` (checked by the console).
         *     No raw value: only masked samples and HMAC fingerprints.
         */
        Finding: {
            target_id: components["schemas"]["TargetId"];
            location: components["schemas"]["Location"];
            classifier: components["schemas"]["ClassifierId"];
            confidence: number;
            /** @description Values examined. */
            sampled: number;
            /** @description Values matching the classifier. */
            matched: number;
            /** @description Estimated size of the object (rows, documents, entries), from engine statistics. */
            estimated_rows?: components["schemas"]["Count"];
            masked_samples?: components["schemas"]["MaskedSample"][];
            fingerprints?: components["schemas"]["Fingerprint"][];
        };
        /**
         * @description Where the data lives, down to the column / field / attribute; never a record. All names are
         *     normalized (see `Identifier`).
         *     PostgreSQL: database, schema, table, column. MySQL / MariaDB: database, table, column (no schema).
         *     MongoDB: database, collection, normalized field path. OpenLDAP: naming context (as
         *     `database`), the entry's container reduced to `ou`/`dc`/`o`/`c`/`l`/`st` RDNs (as `schema`,
         *     never an entry DN), structural objectClass (as `object`), attribute (ADR-0029).
         */
        Location: {
            engine: components["schemas"]["Engine"];
            database: components["schemas"]["Identifier"];
            schema?: components["schemas"]["Identifier"];
            object: components["schemas"]["Identifier"];
            field: components["schemas"]["Identifier"];
        };
        /** @description Serialized size at most 1 MiB (agent-side bound, `x-databastion-max-bytes`). */
        EventsBatch: {
            batch_id: components["schemas"]["UuidV7"];
            events: components["schemas"]["AccessEvent"][];
        };
        /**
         * @description Normalized access event, pre-aggregated by the agent. Contains no query text, no bound parameter
         *     and no returned value: only who, what object, which action, how many rows, and signals.
         *     `read` and `write` events name at least one object: when the agent cannot tell which
         *     objects a read or write reached, it reports the object `*` rather than dropping the
         *     event (see `ObjectRef`).
         */
        AccessEvent: {
            target_id: components["schemas"]["TargetId"];
            /** @description First occurrence. */
            ts: components["schemas"]["Timestamp"];
            /** @description Last occurrence, when `aggregated_count > 1`. */
            ts_last?: components["schemas"]["Timestamp"];
            principal: components["schemas"]["Principal"];
            /**
             * @description `auth_failure`: failed authentication (the account name is then usually fingerprinted).
             * @enum {string}
             */
            action: "connect" | "auth_failure" | "read" | "write" | "ddl" | "dcl";
            objects: components["schemas"]["ObjectRef"][];
            /** @description Rows (documents, entries) returned or affected, when the source provides it. */
            rows?: components["schemas"]["Count"];
            /**
             * @description Size in bytes of the result returned (or of the data affected), when the source
             *     reports it; absent otherwise, never estimated. For a pre-aggregated event, the total
             *     of the merged events, as for `rows`. Not produced by the PostgreSQL connector:
             *     neither pgaudit nor `pg_stat_statements` reports a result size. Sent only when the
             *     latest `HeartbeatResponse.accepts` lists `access_event.bytes` (ADR-0022).
             */
            bytes?: components["schemas"]["Count"];
            /** @description Signal ids of the registry `signals.json` (see `Signal`). */
            signals?: components["schemas"]["Signal"][];
            source: components["schemas"]["AuditSource"];
            /** @description Number of raw events merged into this one. */
            aggregated_count: number;
        };
        /**
         * @description Who accessed. Exactly one of `db_user` / `db_user_fingerprint`. For a failed authentication with
         *     an account that does not exist on the target (the attempted name may be a mistyped password), and
         *     for any account name that does not match the `db_user` pattern, the agent sends
         *     `db_user_fingerprint` instead of the name. The console escapes `db_user` and `application` on
         *     display.
         */
        Principal: {
            /** @description Database account (or LDAP bind DN) as logged by the engine. */
            db_user?: string;
            db_user_fingerprint?: components["schemas"]["Fingerprint"];
            client_addr?: components["schemas"]["ClientAddress"];
            /**
             * @description Client-declared application name (`application_name`, `appName`). The agent replaces every
             *     character outside `[A-Za-z0-9 ._:/+-]` with `_` and truncates to 64 characters.
             */
            application?: string;
        } & (unknown | unknown);
        /**
         * @description Object reached by an access. Names are normalized (see `Identifier`); never an LDAP entry DN.
         *
         *     **The name `*`.** An `object` equal to `*` means the agent does not name the object, for
         *     one of two reasons:
         *     - **unknown object**: the source does not say which objects were reached and the agent
         *       cannot tell from the statement (dynamic SQL, a function or procedure body, a statement
         *       it cannot parse). `database` is the session's database and `schema` is absent. Such a
         *       read or write is reported against `*`, never dropped; the event may also list, next to
         *       `*`, the objects the agent could tell;
         *     - **masked name**: normalization replaced the name (a name matched by a classifier, or
         *       one that does not conform to `Identifier`). This also applies to `database` and
         *       `schema`.
         *
         *     In both cases `*` is a **literal name, not a wildcard**: it never means "every object".
         *     The console compares it as the string `*` (ADR-0021): an `objects` condition or a
         *     location exception selects it only when its glob matches the string `*` (the glob `*`,
         *     or `\*` for that name only); a glob such as `clients` or `crm_*` does not. Its
         *     sensitivity is that of the findings recorded under the same normalized name (any
         *     schema when `schema` is absent), usually none, so its score is usually 0; the event
         *     still matches conditions that do not depend on objects (signals, principals, rows,
         *     anomaly), and the dedup scope uses its `database`. A policy scoped to named objects
         *     therefore does not see such accesses: signal, volume and anomaly conditions do.
         */
        ObjectRef: {
            database: components["schemas"]["Identifier"];
            schema?: components["schemas"]["Identifier"];
            object: components["schemas"]["Identifier"];
        };
    };
    responses: {
        /**
         * @description Batch accepted for asynchronous processing, or already received with the same content
         *     (`duplicate: true`). Either way the agent removes it from its spool.
         */
        BatchAccepted: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["BatchAck"];
            };
        };
        /**
         * @description Body or parameters do not conform to this contract (unknown field, bound exceeded, bad format).
         *     Not retryable as is: see "Retries and error handling" for the per-item handling of batches.
         */
        BadRequest: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Error"];
            };
        };
        /**
         * @description Missing, invalid, superseded (after a rotation) or revoked secret.
         *     - If a pending secret exists (rotation in progress), the agent first retries with it.
         *     - If the request was sent with a secret that is no longer the agent's current one (e.g. `S0`
         *       in flight while switching to `S1`), the agent retries once with its current secret. The
         *       console answers such a request with a plain `401`, without incident, only within the 60 s
         *       tolerance window that follows promotion; after it, the request is a `409` `rotation_conflict`
         *       (see `POST /rotate`).
         *     - If it was sent with the current secret, the agent stops normal operation (no job polling, no
         *       uploads), keeps spooling within its bounds, logs an error, and retries a single heartbeat every
         *       15 min with jitter, so that it recovers if the console restores it. It never loops aggressively.
         */
        Unauthorized: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Error"];
            };
        };
        /**
         * @description Referenced job unknown or not assigned to this agent (the two cases are not distinguished), or
         *     `target_id` not belonging to this agent.
         */
        NotFound: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Error"];
            };
        };
        /**
         * @description `conflict`: invalid job status transition (the job is already in a terminal state).
         *     `batch_conflict`: `batch_id` already received with a different content (alert raised).
         */
        Conflict: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Error"];
            };
        };
        /** @description Body larger than 4 MiB. The agent splits the batch in two and resends each half under a new `batch_id`. */
        PayloadTooLarge: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Error"];
            };
        };
        /**
         * @description `X-DataBastion-Protocol` is below the minimum accepted by the console (`min_protocol` in the body).
         *     The agent logs it and keeps spooling results to disk until it is upgraded.
         */
        UpgradeRequired: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Error"];
            };
        };
        /** @description Rate limited. Exponential backoff with jitter, honoring `Retry-After`. */
        TooManyRequests: {
            headers: {
                "Retry-After": components["headers"]["RetryAfter"];
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Error"];
            };
        };
        /**
         * @description The endpoint is part of this contract but not implemented by this console version (e.g.
         *     `POST /events` before Audit, phase 4). The body is not read. `code` is `unavailable`: there is
         *     no dedicated `not_implemented` code because `Error.code` is a closed enum decoded strictly by
         *     v1 agents, and a new value would make a deployed agent fail to decode the whole error body.
         *     The console may send `Retry-After` (typically 3600 s). A `501` concerns **that endpoint
         *     only** and must not block any other: the agent parks the endpoint until `Retry-After` (or its
         *     own backoff) has elapsed, with per-endpoint queues or by skipping the parked endpoint's
         *     batches, keeps its spooled batches within its bounds (never dropped because of a `501`), and
         *     stops producing new batches for it while it is parked.
         */
        NotImplemented: {
            headers: {
                "Retry-After": components["headers"]["RetryAfter"];
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Error"];
            };
        };
        /** @description Console temporarily unavailable. Exponential backoff with jitter, honoring `Retry-After`. */
        ServiceUnavailable: {
            headers: {
                "Retry-After": components["headers"]["RetryAfter"];
                [name: string]: unknown;
            };
            content: {
                "application/json": components["schemas"]["Error"];
            };
        };
    };
    parameters: {
        /** @description Agent identifier returned by `POST /enroll`. */
        AgentId: components["schemas"]["Uuid"];
        /** @description Protocol major version spoken by the agent. `1` for this contract. */
        ProtocolVersion: number;
        /** @description `databastion-agent/<version>`, e.g. `databastion-agent/0.1.0`. */
        UserAgent: string;
    };
    requestBodies: never;
    headers: {
        /** @description Delay, in seconds, before the agent may retry. The agent adds jitter. */
        RetryAfter: number;
        /** @description Responses carrying a secret must not be cached by any intermediary. */
        CacheControlNoStore: "no-store";
    };
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    enrollAgent: {
        parameters: {
            query?: never;
            header: {
                /** @description Protocol major version spoken by the agent. `1` for this contract. */
                "X-DataBastion-Protocol": components["parameters"]["ProtocolVersion"];
                /** @description `databastion-agent/<version>`, e.g. `databastion-agent/0.1.0`. */
                "User-Agent": components["parameters"]["UserAgent"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["EnrollRequest"];
            };
        };
        responses: {
            /** @description Agent enrolled. The response carries a secret and is sent with `Cache-Control: no-store`. */
            200: {
                headers: {
                    "Cache-Control": components["headers"]["CacheControlNoStore"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrollResponse"];
                };
            };
            400: components["responses"]["BadRequest"];
            /** @description Unknown, expired or already consumed enrollment token. The agent does not retry. */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Error"];
                };
            };
            413: components["responses"]["PayloadTooLarge"];
            426: components["responses"]["UpgradeRequired"];
            429: components["responses"]["TooManyRequests"];
            503: components["responses"]["ServiceUnavailable"];
        };
    };
    sendHeartbeat: {
        parameters: {
            query?: never;
            header: {
                /** @description Agent identifier returned by `POST /enroll`. */
                "X-DataBastion-Agent-Id": components["parameters"]["AgentId"];
                /** @description Protocol major version spoken by the agent. `1` for this contract. */
                "X-DataBastion-Protocol": components["parameters"]["ProtocolVersion"];
                /** @description `databastion-agent/<version>`, e.g. `databastion-agent/0.1.0`. */
                "User-Agent": components["parameters"]["UserAgent"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["HeartbeatRequest"];
            };
        };
        responses: {
            /** @description Heartbeat recorded. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HeartbeatResponse"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthorized"];
            413: components["responses"]["PayloadTooLarge"];
            426: components["responses"]["UpgradeRequired"];
            429: components["responses"]["TooManyRequests"];
            503: components["responses"]["ServiceUnavailable"];
        };
    };
    pollJobs: {
        parameters: {
            query?: {
                /** @description Maximum time, in seconds, the console holds the request. `0` returns immediately. */
                wait?: number;
            };
            header: {
                /** @description Agent identifier returned by `POST /enroll`. */
                "X-DataBastion-Agent-Id": components["parameters"]["AgentId"];
                /** @description Protocol major version spoken by the agent. `1` for this contract. */
                "X-DataBastion-Protocol": components["parameters"]["ProtocolVersion"];
                /** @description `databastion-agent/<version>`, e.g. `databastion-agent/0.1.0`. */
                "User-Agent": components["parameters"]["UserAgent"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description At least one job is pending. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["JobList"];
                };
            };
            /** @description No job became available within `wait` seconds. The agent polls again immediately. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthorized"];
            426: components["responses"]["UpgradeRequired"];
            429: components["responses"]["TooManyRequests"];
            503: components["responses"]["ServiceUnavailable"];
        };
    };
    reportJobStatus: {
        parameters: {
            query?: never;
            header: {
                /** @description Agent identifier returned by `POST /enroll`. */
                "X-DataBastion-Agent-Id": components["parameters"]["AgentId"];
                /** @description Protocol major version spoken by the agent. `1` for this contract. */
                "X-DataBastion-Protocol": components["parameters"]["ProtocolVersion"];
                /** @description `databastion-agent/<version>`, e.g. `databastion-agent/0.1.0`. */
                "User-Agent": components["parameters"]["UserAgent"];
            };
            path: {
                /** @description Identifier of the job, as received from `GET /jobs`. */
                job_id: components["schemas"]["Uuid"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["JobStatusUpdate"];
            };
        };
        responses: {
            /** @description Status recorded. */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthorized"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            426: components["responses"]["UpgradeRequired"];
            429: components["responses"]["TooManyRequests"];
            503: components["responses"]["ServiceUnavailable"];
        };
    };
    submitFindings: {
        parameters: {
            query?: never;
            header: {
                /** @description Agent identifier returned by `POST /enroll`. */
                "X-DataBastion-Agent-Id": components["parameters"]["AgentId"];
                /** @description Protocol major version spoken by the agent. `1` for this contract. */
                "X-DataBastion-Protocol": components["parameters"]["ProtocolVersion"];
                /** @description `databastion-agent/<version>`, e.g. `databastion-agent/0.1.0`. */
                "User-Agent": components["parameters"]["UserAgent"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["FindingsBatch"];
            };
        };
        responses: {
            202: components["responses"]["BatchAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthorized"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            426: components["responses"]["UpgradeRequired"];
            429: components["responses"]["TooManyRequests"];
            503: components["responses"]["ServiceUnavailable"];
        };
    };
    submitEvents: {
        parameters: {
            query?: never;
            header: {
                /** @description Agent identifier returned by `POST /enroll`. */
                "X-DataBastion-Agent-Id": components["parameters"]["AgentId"];
                /** @description Protocol major version spoken by the agent. `1` for this contract. */
                "X-DataBastion-Protocol": components["parameters"]["ProtocolVersion"];
                /** @description `databastion-agent/<version>`, e.g. `databastion-agent/0.1.0`. */
                "User-Agent": components["parameters"]["UserAgent"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["EventsBatch"];
            };
        };
        responses: {
            202: components["responses"]["BatchAccepted"];
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthorized"];
            404: components["responses"]["NotFound"];
            409: components["responses"]["Conflict"];
            413: components["responses"]["PayloadTooLarge"];
            426: components["responses"]["UpgradeRequired"];
            /**
             * @description `rate_limited`, with `Retry-After` (seconds): back-pressure while more than 20 000 events
             *     of the agent are not evaluated yet (`Retry-After: 30`), or a per-agent rate limit (300
             *     requests or 60 stored batches per minute; the rest of the window, 1 to 60 s). Nothing
             *     was recorded: the agent keeps the batch spooled and resends it unchanged, under the
             *     same `batch_id`, after `Retry-After` plus jitter. Answered before the duplicate check.
             */
            429: {
                headers: {
                    "Retry-After": components["headers"]["RetryAfter"];
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Error"];
                };
            };
            501: components["responses"]["NotImplemented"];
            503: components["responses"]["ServiceUnavailable"];
        };
    };
    rotateSecret: {
        parameters: {
            query?: never;
            header: {
                /** @description Agent identifier returned by `POST /enroll`. */
                "X-DataBastion-Agent-Id": components["parameters"]["AgentId"];
                /** @description Protocol major version spoken by the agent. `1` for this contract. */
                "X-DataBastion-Protocol": components["parameters"]["ProtocolVersion"];
                /** @description `databastion-agent/<version>`, e.g. `databastion-agent/0.1.0`. */
                "User-Agent": components["parameters"]["UserAgent"];
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RotateRequest"];
            };
        };
        responses: {
            /** @description New secret registered as pending (or already registered: `duplicate: true`). Carries no secret. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RotateResponse"];
                };
            };
            400: components["responses"]["BadRequest"];
            401: components["responses"]["Unauthorized"];
            404: components["responses"]["NotFound"];
            /**
             * @description `rotation_conflict`: the request was authenticated with `S0` and either (a) its well-formed,
             *     non-low-entropy `new_secret` differs from the pending `S1` or from the promoted `S1`, or
             *     (b) the console has recognized a stale `S0` (after the 60 s tolerance window) and the
             *     request is anything other than a late retry resending the promoted `S1` (invalid body,
             *     low-entropy secret, unknown `job_id`), or (c) it is the 11th late retry within a 5-minute
             *     window. Never returned to a `/rotate` authenticated with
             *     the current secret while no secret is pending. The agent has been locked and all its secrets
             *     revoked; the agent stops and requires re-enrollment.
             */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Error"];
                };
            };
            413: components["responses"]["PayloadTooLarge"];
            426: components["responses"]["UpgradeRequired"];
            429: components["responses"]["TooManyRequests"];
            503: components["responses"]["ServiceUnavailable"];
        };
    };
}
