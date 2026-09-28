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
| `401` | If a secret is pending (rotation in progress), retry with it first. If the request was sent with a secret that is no longer current, retry once with the current one. Only a `401` on the **current** secret is fatal: the agent stops normal operation (no polling, no uploads), keeps spooling within its bounds, logs an error, and retries a single heartbeat every 15 min with jitter. Never an aggressive loop |
| `400` / `404` on `/findings`, `/events` | If every `details[].pointer` designates an item (`/findings/<i>/…`, `/events/<i>/…`, including `404` on `/…/<i>/target_id`), the agent drops those items and resends the rest under a **new** `batch_id`. Otherwise (including `404` on `job_id`) it drops the batch |
| `413` | Split the batch in two halves, each under a new `batch_id`; a single item still rejected is dropped |
| `426` | Protocol too old (`min_protocol` in the body): log it and keep spooling to disk |
| `429` / `503` | Exponential backoff with jitter, honoring `Retry-After` |
| Other `400`, `404`, `409` | Not retryable: drop the request, increment a metric, log `code`, `pointer` and `keyword`, never the payload |
| Network errors, `5xx` | Retry with backoff; batches are idempotent thanks to `batch_id` |

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
5. The agent switches to `S1`. The first successful request with `S1`, or `grace_expires_at`, makes `S1` current and revokes `S0`.

```json
{ "new_secret": "dbs_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE1",
  "job_id": "01920f5f-1d40-7f70-b154-3c4d5e6f7081" }
```
```json
{ "grace_expires_at": "2026-09-28T14:07:11Z", "duplicate": false }
```

- **Idempotent retry**: after a network error the agent resends the **same** `S1` with `S0`; the console answers `200` with `duplicate: true` and the unchanged deadline. The agent never generates a new secret while one is pending.
- **Rejected secrets**: a `new_secret` equal to the current one, or obviously low-entropy, is rejected with `400` `invalid_secret`. (The fixture secret above is low-entropy on purpose: schema-valid, rejected by the console.)
- **Conflict lock**: a different `new_secret` while one is pending (or just promoted), or a request with `S0` after the **60 s tolerance window** that follows promotion, is a `rotation_conflict` (`409`). The console locks the agent, revokes every secret, closes its long-polls and raises a security incident; the agent stops and requires **re-enrollment**. Within the 60 s window, requests with `S0` get a plain `401`.
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
MVP types: `discovery.scan`, `audit.configure` (collection settings and sensitive objects to monitor; thresholds and scoring stay in the console worker), `agent.config.reload` (re-read the local `agent.yaml`; the job carries no configuration), `agent.rotate_secret`.

Empty lists in job parameters never widen what the agent does:
- `discovery.scan` filters `databases`, `schemas`, `include_objects` and `classifiers` mean "all" when absent, and must be **non-empty** when present (`minItems: 1`): an empty list is rejected by the schema, so a "nothing selected" bug cannot turn into a scan of everything;
- `exclude_objects` absent or empty means nothing is excluded;
- `audit.configure` replaces the previous settings as a whole, so an empty `sensitive_objects` is accepted and clears the list: it narrows Audit reporting to events that carry a signal or reach `min_rows`, and never widens it.

## Result batches and idempotency
`POST /findings` and `POST /events` share the same envelope rules:
- a `batch_id` (UUIDv7) generated by the agent before spooling;
- at most 1 MiB serialized (agent side), plus `maxItems` (200 findings, 500 events);
- the console deduplicates on **(`agent_id`, `batch_id`)** and keeps a SHA-256 of the body. Same pair, same content: `202` with `duplicate: true`, not processed again. Same pair, different content: `409` `batch_conflict`, and an alert;
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
      "masked_samples": ["j*******@e******.com", "m****@e******.org"],
      "fingerprints": [
        "hmac-sha256:9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f",
        "hmac-sha256:4141414141414141414141414141414141414141414141414141414141414141"
      ]
    }
  ]
}
```
- A location identifies a column / field / attribute, never a record.
- **Fingerprints** are `hmac-sha256:` + 64 lowercase hex characters: `HMAC-SHA256(agent_local_key, normalized_value)`. The key never leaves the agent, so fingerprints only correlate values seen by the same agent.
- **Masked samples** must contain at least one `*` and no run of more than 4 letters or digits; the console also requires at least 50 % of the non-separator characters to be `*`.
- **Forbidden**: any field containing a raw value. The console rejects non-conforming batches; it also checks that `job_id` is a `discovery.scan` job of the calling agent, that each `target_id` belongs to the agent, and that `matched <= sampled <= sample_rows`.

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
Request: `ts`, `agent_version`, `uptime_s`, `classifiers_version`, enabled `connectors`, the status of each declared target (`reachable`, honest `audit_level` and `audit_source`, `server_version`, `last_error` as a closed failure code, target metrics), `detected_targets` found on the local host only ([ADR-0006](adr/0006-target-discovery.md)), `running_jobs`, `spool` state (including dropped batches and items), and a numeric `metrics` map.

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
