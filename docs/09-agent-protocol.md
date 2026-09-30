# Agent ↔ console protocol (v1)

> **Source of truth: [`shared/protocol/openapi.yaml`](../shared/protocol/openapi.yaml)** (OpenAPI 3.1, see [its README](../shared/protocol/README.md)). This page is an overview. When it differs from the contract, the contract wins. Any protocol change goes through the contract; an incompatible change also needs an ADR and a new version (`/api/agent/v2`).

## Principles
- The agent is **always the client**. The console never initiates a connection and agents open no listening port ([ADR-0001](adr/0001-transport-https-outbound.md)).
- HTTPS (TLS 1.3 only), JSON (UTF-8), prefix `/api/agent/v1`
- Headers on every request:
  - `X-DataBastion-Protocol: 1`
  - `User-Agent: databastion-agent/<version>`
  - except on `POST /enroll`: `Authorization: Bearer <agent_secret>` and `X-DataBastion-Agent-Id: <uuid>`
- **Closed schemas**: every object has `additionalProperties: false`. The console rejects any body with an unknown field, at any depth, with `400` and stores no part of it. The only exception is the heartbeat metrics map (numeric values only, restricted key pattern).
- **Bounded everything**: every string, array and number has a bound. Free-text strings exclude control, format, private-use and line/paragraph separator characters.
- **Size limits**: the console rejects bodies larger than **4 MiB** with `413`. The agent keeps every serialized findings or events batch under **1 MiB**, so a conforming agent never reaches the console limit.

### Compatible changes and capability negotiation
A compatible contract change adds **optional** fields. Every schema is closed, in both directions:
- a console built before a request field was added answers `400` (`invalid_request`, keyword `additionalProperties`) to any body that carries it;
- an agent built before a response or job field was added cannot decode the reply.

Optional fields added after protocol 0.1.0 are therefore **negotiated** ([ADR-0022](adr/0022-protocol-capability-negotiation.md)). "Upgrade the console first" is not relied on; it would only ever hold for request fields.
- **Request fields (agent → console).** Every heartbeat response carries `accepts`, the list of optional request fields the console accepts (`Capability` tokens such as `target_status.notes`, `access_event.bytes`, `job_progress.coverage`). The agent sends such a field only when its **latest** heartbeat response listed it:
  - never before its first response, nor when the list is absent;
  - after a heartbeat rejected with `400` (e.g. a console rolled back), it forgets the list, so its next heartbeat carries none of these fields.

  In the agent, `ConsoleCapabilities::console_accepts(token)` is the only way a producer decides to send a gated field. The console lists every such field it accepts (a tested constant). "Accepts" means "does not reject": `access_event.bytes` is accepted but not stored yet.
- **Response and job fields (console → agent).** The agent lists the ones it accepts in `HeartbeatRequest.accepts`. The console sends a console → agent field introduced after 0.1.0, in any response or job, only when the agent's latest heartbeat named it. None exists yet, so the agent omits the list.
- **New enum values** in a request field (e.g. a new `TargetNoteLabel`) are negotiated with a revision token; until then the agent sends the fallback value (`other`).
- **Form-only registries** (`signals.json`, `target-notes.json`) need no negotiation: an older console accepts a well-formed id it does not know.
- **Multi-replica consoles** list a token only once **every** replica accepts the field. During a rolling upgrade, the build that accepts a field ships first without listing it; the listing follows once no older replica remains.
- **The agent keeps at most 64 tokens** of a list, the contract bound.
- **Obligations of the first gated producer** (met by the PostgreSQL and MySQL / MariaDB connectors; [ADR-0022](adr/0022-protocol-capability-negotiation.md) decision 9):
  - clear the capabilities on a `400` from `/events` or `/jobs/{id}/status` whose body carried a gated field and whose `details` report an unknown field (keyword `additionalProperties`); a `400` with any other keyword keeps the ordinary rules and the capabilities. The heartbeat still clears them on any `400`. `/findings` carries no gated field;
  - resend the items pointed at with the gated fields stripped, rather than dropping them, once (the stripped body carries no gated field, so it is never stripped again; each strip is counted in `gated_fields_stripped_total`); the stripped batch goes under a new `batch_id`, so after a console rollback it may duplicate a batch the console already accepted whose `202` was lost;
  - hold note codes as a closed Rust enum (`NoteCode::ALL`) with a contract test against `target-notes.json`, never built with `format!`.

The agent populates `TargetStatus.notes` (from `check()`) and the `objects_sampled` / `skipped_*` counters (on the terminal status of a scan) of the PostgreSQL and MySQL / MariaDB connectors, only while the console lists their tokens. No connector sets `AccessEvent.bytes` yet; it is always absent.

**Without negotiation** (a field sent that the console does not accept), today's behavior is as follows; it is why a producer must check `console_accepts`:
- **Heartbeat.** The whole heartbeat is rejected, not only the new field. The agent treats the `400` as a non-retryable rejection: it logs a warning, counts it in `heartbeat_failures_total`, forgets the console's capabilities and sends the next heartbeat at the normal interval (30 s). It stays active: job polling and result uploads go on. On the console side:
  - `last_seen_at` stops moving while heartbeats fail, so the agent is displayed **silent** after 90 s. An `agent.silent` alert is raised after `DATABASTION_SILENT_AGENT_INTERVALS` intervals (10 by default, i.e. 5 min) and notified.
  - The agent is **not** revoked or locked automatically: revocation is an administrator action.
  - Target status, audit level, spool state and metrics stay frozen at the last accepted heartbeat. A target declared meanwhile is not registered, so its findings and events get `404` (`notFound`, item pointers) and the agent drops them.
  - The rejected heartbeat raises no agent-integrity event, and its failure counter never reaches the console (it travels in the heartbeat).
- **Findings and events.** An unknown field inside an item is reported on the item (`/events/<i>`), so the agent drops every item that carries it and resends the rest. If every item carries it, every item is dropped. Each rejection also raises an agent-integrity alert.
- **Job status.** A status update carrying an unaccepted `progress` counter is rejected with `400` and not retried. The job keeps its previous status until its own timeouts apply.

## Endpoints

| Method | Path | Purpose |
|---------|--------|------|
| `POST` | `/enroll` | Exchanges a single-use enrollment token for `agent_id` + `agent_secret`. The only unauthenticated endpoint |
| `POST` | `/heartbeat` | Agent and target status, local detections, spool state, metrics. Every `heartbeat_interval_s` (30 s by default) |
| `GET` | `/jobs?wait=25` | **Long-poll**: returns pending jobs, or `204` after `wait` seconds (max 25) |
| `POST` | `/jobs/{job_id}/status` | `running` / `succeeded` / `failed` + progress |
| `POST` | `/findings` | Batch of Discovery findings |
| `POST` | `/events` | Batch of normalized access events (Audit) |
| `POST` | `/rotate` | Registers a new, **agent-generated** secret |

## Errors
Every non-2xx response carries a common body: a fixed `code`, a generic `message` chosen by the console, an optional `request_id`, and optional validation `details` (`pointer`, `keyword`). The message **never echoes submitted values**, and a pointer is built only from property names known to the schema (an unknown property is reported on its parent object).

Codes: `invalid_request`, `unauthorized`, `not_found`, `conflict`, `batch_conflict`, `rotation_conflict`, `invalid_secret`, `payload_too_large`, `protocol_unsupported`, `rate_limited`, `unavailable`, `internal`.

**The `Error.code` values are frozen for v1** ([ADR-0013](adr/0013-frozen-error-codes.md)). v1 agents decode `code` strictly: a new value would make a deployed agent fail to decode the whole error body, and lose its `details` and `min_protocol`. A new situation reuses an existing code and is told apart by the HTTP status, `details[].pointer` and `details[].keyword` (for example `unavailable` with `501`, below). Adding a code needs a new protocol version (`/api/agent/v2`).

`details[].keyword` is either a JSON Schema keyword (`additionalProperties`, `maximum`, `pattern`…) or the keyword of a console-side check. Console-side checks reuse JSON Schema keyword names where they fit:

| Keyword | Meaning (console-side) |
|---------|------------------------|
| `const` | A value must equal the job's (`/classifiers_version`, `/findings/<i>/target_id`) or the target's (`/findings/<i>/location/engine`) |
| `notFound` | Unknown job or target, or one not assigned to the calling agent (`/job_id`, `/findings/<i>/target_id`, `/events/<i>/target_id`), with `404` |
| `maximum` | `matched > sampled`, or `sampled` above the job's `params.sample_rows` |
| `enum` | `classifiers_version` not in the classifier registry, or a classifier id not registered for the batch's version or outside the job's `params.classifiers` |
| `maxItems` | The per-job findings cap would be exceeded (`/findings`) |
| `formatMaximum` | A timestamp more than 5 min in the future (`/ts` of a status update, `/events/<i>/ts`, `/events/<i>/ts_last`) |
| `formatMinimum` | An access event's `ts_last` earlier than its `ts`, or its `ts` older than the console's event retention |
| `maxBytes`, `maskRatio`, `falseSchema`, `invalid` | Size above `x-databastion-max-bytes`, masked sample under 50 % `*`, Ajv false schema, fallback ([shared/protocol/README.md](../shared/protocol/README.md#consumers)) |

```json
{
  "code": "invalid_request",
  "message": "The request body does not conform to the protocol schema.",
  "request_id": "0192a1b3-0000-7000-8000-000000000001",
  "details": [
    { "pointer": "/findings/0", "keyword": "additionalProperties" },
    { "pointer": "/findings/3/confidence", "keyword": "maximum" }
  ]
}
```

### Agent handling
| Response | Agent behavior |
|----------|----------------|
| `401` | If a secret is pending (rotation in progress), retry with it first. If the request was sent with a secret that is no longer current, retry once with the current one. A `401` on `S1` received for a request sent before the last `/rotate` answer is stale and does not put `S0` first again (#30). Only a `401` on the **current** secret is fatal: the agent stops normal operation (no polling, no uploads), keeps spooling within its bounds, logs an error, and retries a single heartbeat every 15 min with jitter. Never an aggressive loop |
| `400` / `404` on `/findings`, `/events` | If every `details[].pointer` designates an item (`/findings/<i>/…`, `/events/<i>/…`, including `404` on `/…/<i>/target_id`), the agent drops those items and resends the rest under a **new** `batch_id`. Otherwise (including `404` on `job_id`) it drops the batch |
| `413` | Split the batch in two halves, each under a new `batch_id`; a single item still rejected is dropped |
| `426` | Protocol too old (`min_protocol` in the body): log it and keep spooling to disk |
| `429` / `503` | Exponential backoff with jitter, honoring `Retry-After`. On `/findings` and `/events`, a `429` records nothing: the batch stays spooled and is resent unchanged under the **same** `batch_id` (see [Console-side checks on events](#console-side-checks-on-events)). With a pending `S1`, the retry uses `S1` again, **never** `S0`: the console answers `429` / `503` before recognizing the secret, so `S1` may already be promoted and `S0` past the 60 s window, where using it locks the agent ([ADR-0010](adr/0010-rotation-conflict-window.md), [ADR-0011](adr/0011-late-rotation-retry.md); #30). The console's rate limits are shared by its processes; while that shared store is unavailable, it answers `429` + `Retry-After: 5` to agent authentications it cannot exempt, `/enroll` and `/rotate` (fail closed, [ADR-0024](adr/0024-shared-rate-limits.md)), except the late-retry limit of `/rotate`, which falls back to per-process counters |
| Other `400`, `404`, `409` | Not retryable: drop the request, increment a metric, log `code`, `pointer` and `keyword`, never the payload |
| `501` | The endpoint is not implemented by this console (e.g. `POST /events` on a console older than P4-C, #54, which implements it; `code` is `unavailable`). The agent **parks that endpoint** until `Retry-After` (or its own backoff) has elapsed, and stops producing new batches for it while parked. It never blocks the other endpoints (per-endpoint queues, or skipping the parked endpoint's batches) and never drops the parked batches because of a `501`: they stay spooled within the spool bounds. The agent (#42): a `501` on `/findings` or `/events` parks only that endpoint, for `Retry-After` (clamped to 1..=3600 s) plus jitter, or for the spool backoff of consecutive `501`s when the header is absent. The batch stays spooled and is resent later under the **same** `batch_id`; each endpoint stays FIFO, and the other endpoint's batches are still sent. While `/findings` is parked, no new scan starts, and a running scan is back-pressured (see [Agent-side handling of job parameters](#agent-side-handling-of-job-parameters)). Counted in the `batches_parked_total` metric. A `501` on any other path is a plain server error, retried within that request's normal interval, not a `Retry-After` throttle: a long `Retry-After` cannot silence heartbeats or job polls |
| Network errors, other `5xx` | Retry with backoff; batches are idempotent thanks to `batch_id` |

On the console side, a rejected (`400`) findings or events batch, a `batch_conflict` or a `rotation_conflict` cannot come from a conforming agent: the console records it in its audit log and raises an agent-integrity alert.

## Enrollment
```
Admin (console)            Agent                               Console
     │  creates a token       │                                    │
     │  (single use, 24 h)    │                                    │
     │───────────────────────▶│  POST /enroll {token, hostname,    │
     │   (manual copy)        │    agent_version, connectors}      │
     │                        │───────────────────────────────────▶│
     │                        │◀── {agent_id, agent_secret,        │
     │                        │     console_min_protocol,          │
     │                        │     heartbeat_interval_s}          │
     │                        │  stores them in a 0600 file,       │
     │                        │  generates its local HMAC key      │
     │                        │  (never transmitted)               │
```
The console stores only a SHA-256 hash of the token and consumes it atomically. `/enroll` is rate limited per source IP (IPv6 bucketed by /56), with a limit shared by every console process ([ADR-0024](adr/0024-shared-rate-limits.md)), and its bodies are never logged. See [05-security.md](05-security.md#agent-secret-management).

## Secret rotation
The **agent generates** the new secret; after enrollment the console never sends a secret ([ADR-0008](adr/0008-agent-generated-secret-rotation.md)).

1. Trigger: an `agent.rotate_secret` job (which carries no secret) or a local operator command.
2. The agent generates `S1` (256 bits, CSPRNG) and persists it as *pending* next to its current secret `S0` (`0600` file, fsync) before any network call.
3. `POST /rotate` with `{"new_secret": S1}` (the `RotateRequest`), authenticated with `S0`.
4. The console stores the argon2id hash of `S1` as pending and answers `200` with `grace_expires_at` (300 s by default, at most 3600 s).
5. The agent switches to `S1`. The `/rotate` reply counts as a success only if it is a contract answer (`200`, JSON media type, a valid `RotateResponse`); any other reply (e.g. a middlebox page) leaves the outcome unknown, as after a network error (#30). The first successful request with `S1`, or `grace_expires_at`, makes `S1` current and revokes `S0`.

```json
{ "new_secret": "dbs_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1",
  "job_id": "01920f5f-1d40-7f70-b154-3c4d5e6f7081" }
```
```json
{ "grace_expires_at": "2026-09-28T14:07:11Z", "duplicate": false }
```

- **Idempotent retry**: after a network error the agent resends the **same** `S1` with `S0`; the console answers `200` with `duplicate: true` and the unchanged deadline. The agent never generates a new secret while one is pending.
- **Rejected secrets**: a `new_secret` equal to the current one, or obviously low-entropy, is rejected with `400` `invalid_secret`. (The fixture secret above is low-entropy on purpose: schema-valid, rejected by the console.)
- **Conflict lock** ([ADR-0010](adr/0010-rotation-conflict-window.md)): a `/rotate` authenticated with `S0` whose `new_secret` differs from the pending `S1` or from the `S1` promoted less than 60 s ago, or any request with `S0` after the **60 s tolerance window** that follows promotion, is a `rotation_conflict` (`409`). The console locks the agent, revokes every secret, closes its long-polls and raises a security incident; the agent stops and requires **re-enrollment**. Within the 60 s window, a `/rotate` with `S0` carrying the same `S1` is a `duplicate`, and other requests with `S0` get a plain `401`. A `/rotate` authenticated with the current secret while no secret is pending always starts a new rotation and is never a conflict. The console issues no `agent.rotate_secret` job while a secret is pending or within 60 s of a promotion, and the agent defers such a job received within that window. `openapi.yaml` states the same rules.
- **Late retry** ([ADR-0011](adr/0011-late-rotation-retry.md), refines ADR-0010): a `/rotate` authenticated with `S0` whose `new_secret` matches the current (promoted) `S1` is a `duplicate` at any time, with that rotation's original deadline, and never a conflict (at most 10 per agent per 5 min; the 11th locks). Any other `/rotate` with `S0` after the window locks the agent. When a `/rotate` outcome is unknown, the agent probes `S1` with a heartbeat before re-sending `/rotate` with `S0`. `openapi.yaml` states the same rule (#24).
- **Suspected compromise** is not handled by rotation: the administrator revokes the agent and re-enrolls it.

## Jobs (console → agent, via long-poll)
Delivery is at least once: a job with no status after 120 s is delivered again, and the agent deduplicates on `job_id`. The console gives a job up (`failed`, `timeout`) after 5 deliveries without any status, with one exception since #94: a queued `discovery.scan` of an online agent (last heartbeat less than 90 s ago) is still delivered again every 120 s but not given up while `now < first_delivered_at + max_duration_s + 600 s`, because the agent acknowledges a scan only when it starts it (see [Scan worker](#agent-side-handling-of-job-parameters)). Every scan deadline on the console (this one, the dead-scan sweep at `first_delivered_at + max_duration_s + 1 h` and the findings window) is anchored on the job's **first** delivery, which a redelivery never moves; a stored `max_duration_s` that is not a plain integer counts as 900 s. Jobs never carry a secret, a credential, a connection string or configuration content.

```json
{
  "jobs": [
    {
      "job_id": "01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a",
      "type": "discovery.scan",
      "created_at": "2026-09-28T14:00:00Z",
      "expires_at": "2026-09-28T20:00:00Z",
      "target_id": "pg-prod-1",
      "classifiers_version": "2026.09.1",
      "params": {
        "sample_rows": 200,
        "max_duration_s": 3600,
        "statement_timeout_ms": 30000,
        "databases": ["crm"],
        "schemas": ["public"],
        "exclude_objects": ["audit_*"],
        "classifiers": ["pii.email", "pii.iban", "secret.aws_key"]
      }
    }
  ]
}
```
**Default scan budget.** The contract default of `max_duration_s` is 900 s. Since #94 the console makes the three bounds explicit in every scan job and uses 3600 s for `max_duration_s`, because Discovery is paced ([ADR-0035](adr/0035-discovery-pacing.md), proposed); the contract is unchanged, and the agent clamps the value to `limits.max_scan_duration_s`.

**Classifier version of a scan job.** The console issues a `discovery.scan` job only with the `classifiers_version` reported in the agent's **latest heartbeat**, and only if that version is registered (with `params.classifiers` ids of that version); otherwise it issues no job (#41). The agent refuses a job whose `classifiers_version` is not its compiled one, or whose `params.classifiers` holds ids unknown to that set, **before touching the target** (no connection, no query), and reports it `failed` with `unsupported`: a capability mismatch of the agent build, not invalid parameters. The check runs first, before the parameter gate and any target access, and is counted in `jobs_unsupported_classifiers_total` (#42). A pending `discovery.scan` whose `classifiers_version` is no longer in the console registry (for example after a console downgrade) is marked `failed` with `internal` when it is claimed, and never served (#41).

MVP types: `discovery.scan`, `audit.configure` (collection settings and sensitive objects to monitor; thresholds and scoring stay in the console worker), `agent.config.reload` (re-read the local `agent.yaml`; the job carries no configuration), `agent.rotate_secret`.

Empty lists in job parameters never widen what the agent does:
- `discovery.scan` filters `databases`, `schemas`, `include_objects` and `classifiers` mean "all" when absent, and must be **non-empty** when present (`minItems: 1`): an empty list is rejected by the schema, so a "nothing selected" bug cannot turn into a scan of everything;
- `exclude_objects` absent or empty means nothing is excluded;
- `audit.configure` replaces the previous settings as a whole, so an empty `sensitive_objects` is accepted and clears the list: it narrows Audit reporting to events that carry a signal or reach `min_rows`, and never widens it.

### Agent-side handling of job parameters
*Implemented in `agent/crates/core` (`job.rs`, `runtime.rs`, `config.rs`; #39, #42).* Connectors never see the generated protocol types; job parameters reach them through these steps:
0. **Classifier set** (#42): for a `discovery.scan`, a `classifiers_version` other than the compiled one, or an unknown id in `params.classifiers`, ends the job `failed` with `unsupported` first (see [Classifier version of a scan job](#jobs-console--agent-via-long-poll)).
1. **Contract gate.** `TryFrom<&DiscoveryScanParams>` and `TryFrom<&AuditConfigureParams>` check the contract ranges and the keywords serde does not enforce (`minItems`, `maxItems`, `uniqueItems`, the `Identifier` `not` rule), and map classifier ids through the compiled classifier set. A duplicate classifier id, an out-of-range value or an empty filter list (`Some([])`) ends the job `failed` with `invalid_params`, before any connection to the target. Duplicate name patterns in the filters are removed. `max_duration_s` and `statement_timeout_ms` equal to `0` are read as "no bound requested".
2. **Local clamp.** The checked values are then clamped to the `limits` of `agent.yaml`, which the console cannot raise: `sample_rows` to `max_sample_rows`, `max_duration_s` to `max_scan_duration_s` (`0` becomes that cap), `statement_timeout_ms` to `statement_timeout_ms` (`0` becomes the local cap: a statement timeout of `0`, unlimited on PostgreSQL / MySQL, is never used), and the audit `poll_interval_s` is raised to at least `min_audit_poll_interval_s`.

The internal job types have private fields and no other constructor, so a connector always gets clamped values.

`agent.yaml` settings involved:

| Key | Range (default) | Effect |
|-----|-----------------|--------|
| `limits.max_sample_rows` | 1..=10000 (1000) | Rows sampled per object |
| `limits.statement_timeout_ms` | 100..=600000 (30000), never `0` | Cap of every query |
| `limits.max_scan_duration_s` | 60..=86400 (3600) | Cap of a whole scan |
| `limits.min_audit_poll_interval_s` | 1..=3600 (5) | Floor of audit polling: a lower console `poll_interval_s` is raised to it |
| `limits.discovery_duty_cycle_percent` | 1..=100 (1) | Discovery pacing: after each unit of work against the target, a pause of `busy × (100 − d) / d`; `100` disables it (#93, [ADR-0035](adr/0035-discovery-pacing.md), proposed; [08-engine-capabilities.md](08-engine-capabilities.md#discovery-load-on-the-monitored-database-every-engine)) |
| `targets[].phone_region` | `fr`, or absent | Per target: region of national phone numbers written without `+`, so that `06 12 34 56 78` and `+33 6 12 34 56 78` get the same fingerprint. Absent: unknown, the digits are fingerprinted as they are |

Unknown keys and unknown `phone_region` values are rejected when the file is loaded. `agent.config.reload` re-reads the file; a scan already queued keeps the values it was clamped with.

**Scan worker.** A `discovery.scan` that passes the gate is queued (at most 16 queued; beyond, the job is left without a status and delivered again later) and run by a worker separate from the jobs loop, one scan at a time, so `agent.rotate_secret` and `agent.config.reload` never wait behind a scan. Since #93 the worker sends a `running` status for a scan before starting it, so a long paced scan is not delivered again after the 120 s lease nor given up by the console after 5 deliveries; a queued scan is acknowledged only when it starts (the console keeps it, see [Jobs](#jobs-console--agent-via-long-poll)). When the console answers that status with `404` or `409` (the job was cancelled, expired or timed out meanwhile, or is not the agent's), the scan does not run and nothing more is reported for it. A paced scan that would reach its deadline stops before the next unit instead: the objects left are counted in `skipped_limit` and the scan succeeds ([08-engine-capabilities.md](08-engine-capabilities.md#discovery-load-on-the-monitored-database-every-engine)). Queued scans wait while `/findings` is parked after a `501` (#42). A job for an undeclared target ends `failed` with `unknown_target`, and one for an engine whose connector is still a stub with `unsupported`. A scan's clamped `max_duration_s` counts from when the agent received the job, queue time included (#42): a queued scan whose window has elapsed ends `failed` with `timeout` without touching the target; otherwise its deadline is the remaining window. The running scan is stopped (its connector future dropped) at that deadline (`failed`, `timeout`), when the agent stops being active after a fatal `401` (revocation; `failed`, `cancelled`) and on agent shutdown (`failed`, `cancelled`). The findings already produced are spooled first; findings that cannot be spooled are counted as lost, and a scan that would otherwise succeed but lost findings ends `failed` with `resource_limit`, as does a scan stopped at the per-job cap (see [Console-side checks](#console-side-checks-on-findings)). While `/findings` is parked, a running scan holds its current chunk in memory (at most 500 findings, plus the 64-slot channel from the connector) and the connector is back-pressured on `FindingSink::submit()` until the park ends; the deadline, revocation and shutdown still apply. A connector that finishes while its findings are held is not reported `timeout` because of the park: the held findings go to the bounded spool. Connectors must therefore not hold database resources across `submit()` (see [05-security.md](05-security.md#connector-obligations)). **Terminal status after the findings** (P2-G, #70, [ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md) decision 10). When a scan ends, the agent holds its terminal status until the console has answered every findings batch spooled for that job (`BatchAck`, or a contract rejection that drops the batch), for at most 120 s. There is no hold for a `cancelled` scan, when no spool worker runs, while `/findings` is parked after a `501`, while the spool worker is in a retry backoff (console unreachable, `5xx`, `429`), once the agent stops being active, or on shutdown. A status sent while batches of its job are still spooled is counted in the `scan_status_before_flush_total` metric. Those batches are sent later: the console accepts findings for 24 h after the terminal status (see [Console-side checks](#console-side-checks-on-findings)). The scan counts as in flight during the hold, so the next queued scan starts up to 120 s later, and its `max_duration_s` window, which counts queue time, shrinks by as much. Dropping the future does not by itself stop a query on the database server, so the connectors cancel it server-side: a cancel request on PostgreSQL (#47, [ADR-0015](adr/0015-postgresql-connector-decisions.md)), `KILL QUERY` from a separate connection on MySQL / MariaDB (#52, [ADR-0018](adr/0018-mysql-mariadb-grants-and-connector.md)); the statement timeout stays the last bound. `audit.configure` is gated the same way; a job for an undeclared target ends `failed` with `unknown_target`, and one for a connector without Audit support with `unsupported`.

### Scan coverage
A `discovery.scan` status update can report how much of its scope the scan covered, in `progress` (all optional counters, counts only, never a name; not checked by the console):
- `objects_total`: objects (tables, collections, LDAP object classes) in the job's scope after its filters, across all databases of the target; `objects_done`: objects processed (sampled or skipped); `objects_sampled`: objects actually sampled;
- `skipped_not_readable`, `skipped_row_level_security`, `skipped_remote`, `skipped_unsupported`, `skipped_limit`, `skipped_error`: objects not sampled, by reason (no read privilege; row-level security, ADR-0012; data held outside the target, I5; a kind the connector does not sample, such as views or merge tables; a structural bound such as the partition-leaf cap, or, since #93, the scan's deadline under Discovery pacing; a sampling failure after which the scan went on). An absent reason counts 0; a new reason is a new optional `skipped_*` counter.

`objects_total - objects_done` objects were not reached (deadline, cancellation, findings cap). The counters are flat numbers so that the console stores `progress` as a numeric map. `objects_sampled` and `skipped_*` are sent only when the console accepts `job_progress.coverage` ([negotiation](#compatible-changes-and-capability-negotiation)). The agent sends `objects_sampled` and the non-zero `skipped_*` counters of the PostgreSQL and MySQL / MariaDB connectors on the terminal status of a scan (#68), each clamped to the contract bound; it does not send `objects_total` nor `objects_done` yet. If a status carrying them is answered `400` for an unknown field, the agent forgets the console's capabilities and sends the status once more without the counters (counted in `gated_fields_stripped_total`).

## Result batches and idempotency
`POST /findings` and `POST /events` share the same envelope rules:
- a `batch_id` (UUIDv7) generated by the agent before spooling;
- at most 1 MiB serialized (agent side), plus `maxItems` (200 findings, 500 events);
- the console deduplicates on **(`agent_id`, `batch_id`)** and keeps a SHA-256 of the batch. Same pair, same content: `202` with `duplicate: true`, not processed again. Same pair, different content: `409` `batch_conflict`, and an alert;
- **same content** means the same parsed JSON value, not the same bytes: the hash covers a canonical serialization of the validated body (object keys sorted recursively, no insignificant whitespace, numbers compared by value). Key order and formatting may change between two sends; array order and every value are significant;
- the duplicate check runs **after** authentication, the size checks and schema validation, and **before** every other console-side check, so the replay of an accepted batch is acknowledged even after its job stopped accepting findings;
- only **accepted** batches are recorded: a rejected batch (any `4xx`) leaves no (`agent_id`, `batch_id`) record and can never cause a `batch_conflict`;
- a batch is accepted or rejected as a whole; the response is a `BatchAck`:

```json
{ "batch_id": "01920f60-3c1a-7b2e-9f00-5a1b2c3d4e5f", "duplicate": false }
```

### Names are normalized
Object and field names are engine metadata that can embed values (MongoDB dynamic keys, LDAP entry DNs, generated table names). The schema alone cannot prove that a name is free of values, so the agent normalizes every name before the uplink ([ADR-0009](adr/0009-name-normalization-and-item-sanitization.md)):
- array indices become `[]` (`orders.3.email` → `orders[].email`);
- dynamic keys and any name segment matched by a classifier become `*` (`contacts.jane@example.com.phone` → `contacts.*.phone`);
- an LDAP entry DN is reduced to its parent container (`uid=jdoe,ou=people,dc=example,dc=com` → `ou=people,dc=example,dc=com`), and a container value that looks like data becomes `*` (`ou=Oliver O'Connor,ou=teams,…` → `ou=*,ou=teams,…`);
- a name that still does not match the `Identifier` schema is replaced by `*`.

The `Identifier` pattern rejects e-mail addresses, `key=value` forms other than LDAP container RDNs (`ou=`, `dc=`, `o=`, `c=`, `l=`, `st=`; never `uid=` or `cn=`), URLs, SQL fragments, and names or path segments made only of 9 or more digits and separators. It remains a safety net: a person name used as a key (`ou=Jane Doe`) passes the pattern and is only caught by the agent's normalization.

Before spooling, the agent validates **each item** and sanitizes it rather than dropping it (control characters stripped, strings truncated, non-conforming name segment → `*`, non-conforming account name → fingerprint, non-conforming optional field omitted). A single hostile name cannot get a whole batch rejected.

## Finding (agent → console)
```json
{
  "batch_id": "01920f60-3c1a-7b2e-9f00-5a1b2c3d4e5f",
  "job_id": "01920f5e-8a10-7c4d-8e21-0f1e2d3c4b5a",
  "classifiers_version": "2026.09.1",
  "findings": [
    {
      "target_id": "pg-prod-1",
      "location": { "engine": "postgres", "database": "crm", "schema": "public",
                    "object": "clients", "field": "email" },
      "classifier": "pii.email",
      "confidence": 0.97,
      "sampled": 200,
      "matched": 194,
      "estimated_rows": 1250000,
      "masked_samples": ["j***@e***.com", "m***@e***.org"],
      "fingerprints": [
        "hmac-sha256:9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f",
        "hmac-sha256:4141414141414141414141414141414141414141414141414141414141414141"
      ]
    }
  ]
}
```
- A location identifies a column / field / attribute, never a record.
- **Fingerprints** are `hmac-sha256:` + 64 lowercase hex characters: `HMAC-SHA256(agent_local_key, "databastion/fp/v1" 0x00 classifier_id 0x00 normalized_value)` (see [05-security.md](05-security.md#masking-and-fingerprints)). They are **opaque and agent-local**: the key never leaves the agent, and the value normalization belongs to the agent's classifier implementation, not to the contract. The console compares fingerprints for equality only and must not assume that fingerprints of different agents, classifiers or `classifiers_version`s correlate.
- **Masked samples** must contain at least one `*` and no run of more than 4 letters or digits; the console also requires at least 50 % of the non-separator characters to be `*`.
- **Forbidden**: any field containing a raw value. The console rejects non-conforming batches.

### Location mapping per engine
| Engine | `database` | `schema` | `object` | `field` |
|--------|------------|----------|----------|---------|
| PostgreSQL | database | schema | table (or partitioned root) | column |
| MySQL / MariaDB | database | absent | table | column |
| MongoDB | database | absent | collection | normalized field path |
| OpenLDAP | naming context (`dc=example,dc=org`) | the entry's container: its parent DN reduced to `ou` / `dc` / `o` / `c` / `l` / `st` RDNs, values that look like data replaced by `*` | structural object class (canonical schema name) | attribute type (canonical name, lowercased, options such as `;lang-fr` dropped) |

For OpenLDAP ([ADR-0029](adr/0029-openldap-connector.md) decision 6), **an entry DN never appears in a location**: `uid=jdoe,ou=people,dc=example,dc=org` gives `database` `dc=example,dc=org`, `schema` `ou=people,dc=example,dc=org`, and for instance `object` `inetOrgPerson`, `field` `mail`. Entries of containers with the same normalized name are pooled. Using `schema` for the container is a clarification of the `Location` description (compatible change). In access events, the log does not give the object class of the entries a search returned: `objects[]` names the console's `sensitive_objects` reachable from the search base and scope, else `*` with the container as `schema` ([08-engine-capabilities.md](08-engine-capabilities.md#openldap-audit)).

### Console-side checks on findings
The full list, pointers and order are in `openapi.yaml` ("Console-side checks not expressible in this schema"). In short, after the duplicate check:
1. **Job window.** `job_id` must be a `discovery.scan` job of the calling agent that still accepts findings (`404`, `/job_id`, `notFound`; the agent drops the batch). A scan job accepts findings while it is `delivered` (the first batch may overtake the `running` status) or `running`, until `first_delivered_at + params.max_duration_s + 1 h` (the first delivery, since #94), and for **24 h** after it reached `succeeded` or `failed` (counted from that deadline at the latest, so a late final status does not reopen the window), so late spooled batches still land. After that, late batches get `404` and the agent drops them. A job never delivered, expired or cancelled accepts none.
2. **Targets.** Every `target_id` belongs to the calling agent (`404`, `notFound`).
3. **Cross-field checks** (`400`): `classifiers_version` registered and equal to the job's; each finding's `target_id` equal to the job's; `location.engine` equal to the engine reported for the target; `matched <= sampled <= params.sample_rows`; `classifier` registered for the batch's version and within the job's `params.classifiers` when present.
4. **Per-job cap.** At most **50 000** findings per job, over all its batches. A batch that would exceed it is rejected as a whole (`400`, `/findings`, `maxItems`); the console serializes the batches of one agent so concurrent batches cannot jointly exceed it. The agent counts the findings it emits per job (`MAX_FINDINGS_PER_JOB` = 50 000, #42): the finding past the cap stops the scan, the findings kept so far are flushed, and the job ends `failed` with `resource_limit` (counted in `scans_findings_capped_total`), so a conforming agent never hits the `400`. The agent counter is in memory: after an agent restart and a redelivery of the job the count starts again, so the console cap stays authoritative.

### Classifier registry
[`shared/protocol/classifiers.json`](../shared/protocol/classifiers.json) lists the valid classifier ids of each `classifiers_version` (today `2026.09.1`, ten ids). The console rejects findings whose version is not registered or whose classifier is not listed for it (`enum`) (#41). A published version is **never modified**: a new or changed classifier is a new version, added by a compatible contract change. `classifiers.lock.json` pins the SHA-256 of each published version's sorted id list; the protocol tests fail if a locked version changes or disappears, and CI rejects a pull request that edits or removes an existing lock entry (only new keys are allowed). The agent's compiled classifier set must equal the entry of its version (contract test in `agent/crates/classifiers`).

## Access event (agent → console)
Access events are masked in the agent before the uplink ([ADR-0007](adr/0007-mask-access-events.md)): no query text, no bound parameter, no returned value.

```json
{
  "batch_id": "01920f60-3c1a-7b2e-9f00-5a1b2c3d4e5f",
  "events": [
    {
      "target_id": "pg-prod-1",
      "ts": "2026-09-28T14:02:11Z",
      "principal": { "db_user": "backup", "client_addr": "192.0.2.14", "application": "pg_dump" },
      "action": "read",
      "objects": [{ "database": "crm", "schema": "public", "object": "clients" }],
      "rows": 1250000,
      "signals": ["signature.pg_dump", "shape.full_table_copy", "volume.large_result"],
      "source": "pgaudit",
      "aggregated_count": 1
    }
  ]
}
```
- `principal` carries **exactly one** of `db_user` (account or LDAP bind DN as logged by the engine) or `db_user_fingerprint` (`hmac-sha256:…`). The agent sends the fingerprint for a failed authentication with an account that does not exist on the target (the attempted name may be a mistyped password), and for any account name that does not match the `db_user` pattern. On OpenLDAP, where a principal is an entry DN that usually names a person, `db_user` is sent only for `anonymous`, the agent's own DN and the DNs listed in the target's `openldap.clear_principals`; every other principal is a fingerprint ([ADR-0029](adr/0029-openldap-connector.md) decision 7).
- `client_addr` is an IP literal or `local`, never a host name. `application` is reduced to `[A-Za-z0-9 ._:/+-]` and 64 characters by the agent. The console escapes `db_user` and `application` on display.
- `action`: `connect`, `auth_failure`, `read`, `write`, `ddl`, `dcl`. `read` and `write` events name at least one object.
- The agent **pre-aggregates** repetitive events (same principal, object set and action within the aggregation window, 60 s by default); `ts_last` and `aggregated_count` describe the merged events.
- `signals` are computed by the agent from the raw data (ADR-0007), from the [signal registry](#signal-registry). The console does not rely on any `volume.*` signal for its baseline verdict: it computes its own per-principal baseline ([ADR-0021](adr/0021-access-event-correlation.md)).
- `bytes` (optional): size of the result returned or of the data affected, when the source reports it; the total for a pre-aggregated event, as `rows`. Never estimated. The PostgreSQL connector does not produce it (neither pgaudit nor `pg_stat_statements` reports a result size), and the console does not use it yet (the score uses `rows`). Sent only when the console accepts `access_event.bytes`.

### The object `*`
An `objects[]` entry whose `object` is `*` means the agent does not name the object:
- **unknown object**: the source does not say which objects a read or write reached and the agent cannot tell from the statement (dynamic SQL, a function or procedure body, a statement it cannot parse). `database` is the session's database and `schema` is absent. The event is reported against `*` rather than dropped (the contract requires one object for `read` / `write`); it may also list, next to `*`, the objects the agent could tell (PostgreSQL connector, P4-A);
- **masked name**: normalization replaced the name ([Names are normalized](#names-are-normalized)); this can also happen to `database` or `schema`.

`*` is a **literal name, not a wildcard**: it never means "every object". The console compares it as the string `*` ([ADR-0021](adr/0021-access-event-correlation.md), residual risks): an `objects` policy condition or a location exception selects it only when its glob matches the string `*` (the glob `*`, or `\*` for that name only), never through a glob such as `clients` or `crm_*`. Its sensitivity is that of findings recorded under the same normalized name (any schema when `schema` is absent), usually none, so its score is usually 0. The event still matches conditions that do not depend on objects (signals, principals, `min_rows`, anomaly), and its `database` is used in the dedup scope. A policy scoped to named objects therefore does not see such accesses; signal, volume and anomaly conditions do.

### Signal registry
[`shared/protocol/signals.json`](../shared/protocol/signals.json) lists the signal ids a conforming agent emits, with their meaning and the engines whose connector emits them:

| Signal | Meaning (PostgreSQL connector P4-A, MySQL / MariaDB connector P4-B) |
|--------|---------|
| `signature.pg_dump` | A `pg_dump` / `pg_dumpall` run: that application name on a whole-relation read or copy, or one session copying several whole relations to the client |
| `signature.copy_to_file` | Server-side export to a file (`COPY … TO '<file>'`), also from dynamic SQL |
| `signature.copy_to_program` | Server-side export to a program (`COPY … TO PROGRAM`) |
| `signature.mysqldump` | A `mysqldump`, `mariadb-dump`, `mysqlpump` or `mydumper` run (MySQL / MariaDB; heuristic) |
| `signature.into_outfile` | Server-side export to a file on the database server (`SELECT … INTO OUTFILE` / `INTO DUMPFILE`), also when refused (MySQL / MariaDB) |
| `shape.full_table_copy` | `COPY` out of a whole relation, or of an unfiltered query (heuristic) |
| `shape.full_table_read` | Read of whole relations: no filter, no aggregation, no or a large limit (heuristic) |
| `volume.large_result` | Rows returned or affected above the agent's large-result threshold |

The registry is **append-only**: an id is never removed, renamed or given another meaning, and a new signal (as `signature.mysqldump` and `signature.into_outfile` were for the MySQL / MariaDB Audit connector, #64) is a new entry added by a compatible contract change. The `Signal` schema checks the form only (`^(signature|shape|volume)\.[a-z]{1,16}(_[a-z]{1,16}){0,5}$`, no digit), not registration, so a console accepts a signal registered after it was built, stores it and matches it by exact id or family (`signature.*`); every `signature.*` signal makes an event severe (it bypasses the hourly incident cap). The protocol tests check the registry and that valid fixtures only use registered ids; CI (every push and pull request) compares the registry with `dev`, `main` and, on push, the previous tip, and rejects the removal or renaming of an id, or the loss of one of its engines; the agent contract test `contract_signals.rs` checks that every signal the agent can emit is registered and that every registered signal of an engine with an Audit connector can be emitted.

### Console-side checks on events
*Implemented by the console in P4-C (#54); listed in `openapi.yaml` ("Console-side checks", `POST /events`).* In this order:
1. **Request rate** (`429`): at most 300 authenticated requests per minute per agent, whatever their outcome, checked after authentication and before the body is read.
2. **Body**: `413` above 4 MiB, then schema validation (`400` with the first schema error only; the checks below then do not run), then the batch-level checks (`400`, reported together): serialized size above 1 MiB (pointer `""`, `maxBytes`) and `ts_last` earlier than `ts` (`/events/<i>/ts_last`, `formatMinimum`).
3. **Back-pressure** (`429` + `Retry-After: 30`): while more than 20 000 events of the agent are not evaluated yet by the console.
4. **Stored-batch rate** (`429`): at most 60 stored batches per minute per agent; a batch that turns out to be a duplicate or is rejected later does not count.
5. **Duplicate check** on (`agent_id`, `batch_id`), as for findings (`202` `duplicate: true`, or `409` `batch_conflict`).
6. **Targets.** Every `target_id` belongs to the calling agent (`404`, `/events/<i>/target_id`, `notFound`).
7. **Future timestamps** (`400`): `ts` or `ts_last` more than 5 min ahead of the console clock (`/events/<i>/ts` or `/events/<i>/ts_last`, `formatMaximum`).
8. **Retention** (`400`), only when step 7 found nothing: `ts` older than the console's event retention (`DATABASTION_EVENTS_RETENTION_DAYS`, default 90 days, accepted 7 to 3650; `/events/<i>/ts`, `formatMinimum`). A conforming agent with an old spool can hit it: the console counts it and raises no integrity alert; the agent drops those items (item pointers) and resends the rest.

**`429` on `/events`**: code `rate_limited`, no `details`, `Retry-After` always set: `30` for back-pressure, the rest of the one-minute window (1 to 60 s) for the rate limits. Steps 1, 3 and 4 run **before** the duplicate check, so a batch answered `429` was never recorded: the agent keeps it spooled and resends it unchanged, under the same `batch_id`, after `Retry-After` plus jitter, and the console then processes it as a new batch (`duplicate: false`), not as a duplicate. While an agent is throttled, even the replay of an already accepted batch (a lost `202`) is answered `429`, then `duplicate: true` once the throttle ends. The rate limits of steps 1 and 4 are shared by every console process through the console database ([ADR-0024](adr/0024-shared-rate-limits.md)); if that shared store fails, each process applies its own counters, with the same `Retry-After` range. The back-pressure threshold is read from the database ([ADR-0021](adr/0021-access-event-correlation.md)).

A batch rejected with `400` for any other reason, a `batch_conflict`, a foreign target or a future timestamp is an agent-integrity event. `formatMinimum` is an `ErrorDetail.keyword` value; `keyword` is not frozen by [ADR-0013](adr/0013-frozen-error-codes.md), which covers `Error.code`.

## Heartbeat
Request: `ts`, `agent_version`, `uptime_s`, `classifiers_version`, enabled `connectors`, the status of each declared target (`reachable`, honest `audit_level` and `audit_source`, `server_version`, `last_error` as a closed failure code, e.g. `unsupported` for a connector that is still a stub or `timeout` when `check()` does not finish within the heartbeat's 10 s deadline (see below), optional `notes`, target metrics), `detected_targets` found on the local host only ([ADR-0006](adr/0006-target-discovery.md)), `running_jobs`, `spool` state (including dropped batches and items), and a numeric `metrics` map. Agent counters in that map include `batches_parked_total` (batches answered `501`), `jobs_unsupported_classifiers_total` (scans refused for their classifier set) and `scans_findings_capped_total` (scans stopped at the per-job cap) (#42), and `scan_status_before_flush_total` (scan statuses sent before all of the scan's findings batches were answered; #70). Since #88: `checks_timed_out_total` (target checks still running at the heartbeat deadline), `checks_account_busy_total` (targets whose turn on a shared account did not come before the deadline; both reported `timeout` in the target status), `auth_failures_overflowed_total` (failed logins beyond the 100 named groups of the failed-login cap, folded into overflow events, [05-security.md](05-security.md#access-events-ingestion-and-correlation)) and `spool_rejected_batches_total` (new batches dropped on arrival by the priority eviction of a full spool, also counted in `dropped_batches`). Since #93: `audit_pending_evicted_total` (MySQL / MariaDB audit-log statements reported before their statement record because the bounded grouping state was full, [08-engine-capabilities.md](08-engine-capabilities.md#one-event-per-statement-audit-log-files)); the `metrics` map is open-keyed, so this needs no protocol change.

**Target checks** (P2-G, #70, [ADR-0025](adr/0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md) decision 9). The agent runs the targets' `check()` concurrently under one 10 s deadline from the start of the heartbeat, so a heartbeat waits at most 10 s for all of its targets. Targets that reach the same account (engine family, host or socket, port, account) take turns, one check at a time, so an account has at most one check next to one scan. The turns cover checks only: Audit streams hold their own connections, and the per-account limits in [05-security.md](05-security.md#recommended-database-accounts-read-only) count them (ADR-0025 decision 11). Since #88 the account key recognizes aliases: an omitted port and the engine's default one, host names in any case or with a trailing dot, IP literal forms (`[::1]`, `::ffff:127.0.0.1`), `localhost` and the loopback addresses, a socket path through symlinks, and host names that resolve to a shared address. Under I5, only declared target names are resolved, and only when two targets of one engine family, account and port name different hosts: through the system resolver, with a 1 s timeout, results cached 5 minutes and timed-out lookups cached 60 s (the name then keeps its literal key). A check still running, or still waiting for its turn, at the deadline is dropped and cancelled server-side. Its target is reported `reachable: false`, `audit_level: None`, `last_error: timeout`, with the note `check.timed_out` when notes are sent. A timed-out check takes the last turn of its account at the next heartbeats, so the other targets rotate ahead of it; a target whose turn never came before the deadline is reported the same way (the contract has no other status) and counted as busy (`checks_account_busy_total`, apart from `checks_timed_out_total`).

**`notes`** (optional, at most 16): explanations of the target's status from the last `check()`, as **closed codes with bounded parameters, never free text**. Each note is `{code, count?, labels?}`:
- `code` is a `TargetNoteCode`, registered in [`shared/protocol/target-notes.json`](../shared/protocol/target-notes.json) (append-only, like the signal registry);
- `count` is a `Count`;
- `labels` holds up to 16 closed `TargetNoteLabel` values: PostgreSQL role attributes and predefined roles, MySQL / MariaDB privilege names in lower snake case, audit collection states, `check()` stages; anything else is sent as `other`.

No field can carry a sampled value, a credential, a connection string, a host name or address, query text or a driver message. The registry is seeded with the codes of today's `check()` messages, for example:

```json
"notes": [
  { "code": "audit.pgaudit_log_not_configured" },
  { "code": "coverage.relations_rls_skipped", "count": 5 },
  { "code": "privilege.role_attributes", "labels": ["bypassrls", "createrole"] },
  { "code": "security.tls_disabled" }
]
```

**Rendering rule:** the console renders each note from a phrase catalog keyed by code (the registry's descriptions, with `{count}` and `{labels}` placeholders), escaping the labels. A code missing from the catalog, e.g. registered after the console was built, is shown as the raw code with its count and labels, never rejected; the schema checks its form only (`^(audit|coverage|privilege|security|check)\.[a-z]{1,16}(_[a-z]{1,16}){0,5}$`, no digit). The console never derives a decision from notes: `reachable`, `audit_level` and `last_error` are the machine-readable status.

Notes are sent only when the console accepts `target_status.notes`. The PostgreSQL and MySQL / MariaDB connectors produce them from `check()` (#68): codes from a closed Rust enum checked against the registry by a contract test, one note per code, at most 16 per target (insecure settings, check failures and privileges kept first when there are more), counts clamped to the contract bound, labels sorted, deduplicated and capped at 16 (the most severe kept). Dropped audit records (not parsable, oversized or damaged) are reported as `audit.records_dropped` with their count over the last 24 h.

The targets reported in heartbeats are the agent's targets: results referencing another `target_id` are rejected with `404`. The agent sends a heartbeat before the first result of a newly declared target.

Response:
```json
{
  "console_min_protocol": 1,
  "heartbeat_interval_s": 30,
  "server_time": "2026-09-28T14:02:00.412Z",
  "accepts": ["access_event.bytes", "job_progress.coverage", "target_status.notes"]
}
```
`accepts` lists the optional request fields the console accepts ([ADR-0022](adr/0022-protocol-capability-negotiation.md)).

Metrics are a bounded `name → number` map (max 128 entries, names `^[a-z][a-z0-9_]{0,63}$`). The console re-exposes them on its own `/metrics` endpoint under the prefix `databastion_agent_reported_`, with an `agent_id` label (and `target_id` for target metrics), so an agent can never shadow a console-computed metric; names on the console's reserved list (e.g. `last_seen_seconds`, `up`, `revoked`) are ignored ([ADR-0004](adr/0004-observability-via-console.md)).
