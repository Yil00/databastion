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
| `formatMaximum` | A timestamp more than 5 min in the future |
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
| `429` / `503` | Exponential backoff with jitter, honoring `Retry-After`. With a pending `S1`, the retry uses `S1` again, **never** `S0`: the console answers `429` / `503` before recognizing the secret, so `S1` may already be promoted and `S0` past the 60 s window, where using it locks the agent ([ADR-0010](adr/0010-rotation-conflict-window.md), [ADR-0011](adr/0011-late-rotation-retry.md); #30) |
| Other `400`, `404`, `409` | Not retryable: drop the request, increment a metric, log `code`, `pointer` and `keyword`, never the payload |
| `501` | The endpoint is not implemented by this console (e.g. `POST /events` before Audit, phase 4; `code` is `unavailable`). The agent **parks that endpoint** until `Retry-After` (or its own backoff) has elapsed, and stops producing new batches for it while parked. It never blocks the other endpoints (per-endpoint queues, or skipping the parked endpoint's batches) and never drops the parked batches because of a `501`: they stay spooled within the spool bounds |
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
The console stores only a SHA-256 hash of the token and consumes it atomically. `/enroll` is rate limited per source IP, and its bodies are never logged. See [05-security.md](05-security.md#agent-secret-management).

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
Delivery is at least once: a job with no status after 120 s is delivered again, and the agent deduplicates on `job_id`. Jobs never carry a secret, a credential, a connection string or configuration content.

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
        "max_duration_s": 900,
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
**Classifier version of a scan job.** The console issues a `discovery.scan` job only with the `classifiers_version` reported in the agent's **latest heartbeat**, and only if that version is registered (with `params.classifiers` ids of that version); otherwise it issues no job. The agent refuses a job whose `classifiers_version` is not its compiled one, or whose `params.classifiers` holds ids unknown to that set, **before touching the target** (no connection, no query), and reports it `failed` with `unsupported`: a capability mismatch of the agent build, not invalid parameters.

MVP types: `discovery.scan`, `audit.configure` (collection settings and sensitive objects to monitor; thresholds and scoring stay in the console worker), `agent.config.reload` (re-read the local `agent.yaml`; the job carries no configuration), `agent.rotate_secret`.

Empty lists in job parameters never widen what the agent does:
- `discovery.scan` filters `databases`, `schemas`, `include_objects` and `classifiers` mean "all" when absent, and must be **non-empty** when present (`minItems: 1`): an empty list is rejected by the schema, so a "nothing selected" bug cannot turn into a scan of everything;
- `exclude_objects` absent or empty means nothing is excluded;
- `audit.configure` replaces the previous settings as a whole, so an empty `sensitive_objects` is accepted and clears the list: it narrows Audit reporting to events that carry a signal or reach `min_rows`, and never widens it.

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
- an LDAP entry DN is reduced to its parent container (`uid=jdoe,ou=people,dc=example,dc=com` → `ou=people,dc=example,dc=com`);
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

### Console-side checks on findings
The full list, pointers and order are in `openapi.yaml` ("Console-side checks not expressible in this schema"). In short, after the duplicate check:
1. **Job window.** `job_id` must be a `discovery.scan` job of the calling agent that still accepts findings (`404`, `/job_id`, `notFound`; the agent drops the batch). A scan job accepts findings while it is `delivered` (the first batch may overtake the `running` status) or `running`, until `delivered_at + params.max_duration_s + 1 h`, and for **24 h** after it reached `succeeded` or `failed` (counted from that deadline at the latest, so a late final status does not reopen the window), so late spooled batches still land. After that, late batches get `404` and the agent drops them. A job never delivered, expired or cancelled accepts none.
2. **Targets.** Every `target_id` belongs to the calling agent (`404`, `notFound`).
3. **Cross-field checks** (`400`): `classifiers_version` registered and equal to the job's; each finding's `target_id` equal to the job's; `location.engine` equal to the engine reported for the target; `matched <= sampled <= params.sample_rows`; `classifier` registered for the batch's version and within the job's `params.classifiers` when present.
4. **Per-job cap.** At most **50 000** findings per job, over all its batches. A batch that would exceed it is rejected as a whole (`400`, `/findings`, `maxItems`); the console serializes the batches of one agent so concurrent batches cannot jointly exceed it. The agent counts the findings it emits per job, stops at the bound and ends the job `failed` with `resource_limit` (the findings already accepted are kept), so a conforming agent never hits the `400`.

### Classifier registry
[`shared/protocol/classifiers.json`](../shared/protocol/classifiers.json) lists the valid classifier ids of each `classifiers_version` (today `2026.09.1`, ten ids). The console rejects findings whose version is not registered or whose classifier is not listed for it (`enum`). A published version is **never modified**: a new or changed classifier is a new version, added by a compatible contract change. `classifiers.lock.json` pins the SHA-256 of each published version's sorted id list; the protocol tests fail if a locked version changes or disappears, and CI rejects a pull request that edits or removes an existing lock entry (only new keys are allowed). The agent's compiled classifier set must equal the entry of its version (contract test in `agent/crates/classifiers`).

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
      "signals": ["signature.pg_dump", "shape.full_table_copy", "volume.above_baseline"],
      "source": "pgaudit",
      "aggregated_count": 1
    }
  ]
}
```
- `principal` carries **exactly one** of `db_user` (account or LDAP bind DN as logged by the engine) or `db_user_fingerprint` (`hmac-sha256:…`). The agent sends the fingerprint for a failed authentication with an account that does not exist on the target (the attempted name may be a mistyped password), and for any account name that does not match the `db_user` pattern.
- `client_addr` is an IP literal or `local`, never a host name. `application` is reduced to `[A-Za-z0-9 ._:/+-]` and 64 characters by the agent. The console escapes `db_user` and `application` on display.
- `action`: `connect`, `auth_failure`, `read`, `write`, `ddl`, `dcl`. `read` and `write` events name at least one object.
- The agent **pre-aggregates** repetitive events (same principal, object set and action within the aggregation window, 60 s by default); `ts_last` and `aggregated_count` describe the merged events.

## Heartbeat
Request: `ts`, `agent_version`, `uptime_s`, `classifiers_version`, enabled `connectors`, the status of each declared target (`reachable`, honest `audit_level` and `audit_source`, `server_version`, `last_error` as a closed failure code, e.g. `unsupported` for a connector that is still a stub or `timeout` when `check()` exceeds 10 s, target metrics), `detected_targets` found on the local host only ([ADR-0006](adr/0006-target-discovery.md)), `running_jobs`, `spool` state (including dropped batches and items), and a numeric `metrics` map.

The targets reported in heartbeats are the agent's targets: results referencing another `target_id` are rejected with `404`. The agent sends a heartbeat before the first result of a newly declared target.

Response:
```json
{
  "console_min_protocol": 1,
  "heartbeat_interval_s": 30,
  "server_time": "2026-09-28T14:02:00.412Z"
}
```

Metrics are a bounded `name → number` map (max 128 entries, names `^[a-z][a-z0-9_]{0,63}$`). The console re-exposes them on its own `/metrics` endpoint under the prefix `databastion_agent_reported_`, with an `agent_id` label (and `target_id` for target metrics), so an agent can never shadow a console-computed metric; names on the console's reserved list (e.g. `last_seen_seconds`, `up`, `revoked`) are ignored ([ADR-0004](adr/0004-observability-via-console.md)).
