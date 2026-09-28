# Agent ↔ console protocol (v1, draft)

> Design draft. The source of truth will be `shared/protocol/openapi.yaml` (phase 0). Any protocol change goes through this contract and, if it breaks compatibility, through an ADR.

## Principles
- The agent is **always the client**. The console never initiates a connection.
- HTTPS (TLS 1.3), JSON, prefix `/api/agent/v1`
- Headers on every request:
  - `Authorization: Bearer <agent_secret>` (except enrollment)
  - `X-DataBastion-Agent-Id: <uuid>`
  - `X-DataBastion-Protocol: 1`
  - `User-Agent: databastion-agent/<version>`
- Idempotency: every submission carries a `batch_id` (UUIDv7). The console ignores a batch it has already received, so the agent can safely resend after an outage.

## Endpoints

| Method | Path | Purpose |
|---------|--------|------|
| `POST` | `/enroll` | Exchanges the enrollment token for `agent_id` + `agent_secret` |
| `POST` | `/heartbeat` | Status, detected targets, metrics, version. Every 30 s |
| `GET` | `/jobs?wait=25` | **Long-poll**: returns pending jobs, or `204` after 25 s |
| `POST` | `/jobs/{job_id}/status` | `running` / `succeeded` / `failed` + progress |
| `POST` | `/findings` | Batch of Discovery findings |
| `POST` | `/events` | Batch of normalized access events (Audit) |
| `POST` | `/rotate` | Acknowledges that a new secret has been applied |

### Special responses
- `401`: invalid or revoked secret → the agent stops and logs it (no aggressive retry loop)
- `426`: protocol version too old → the agent reports it in its logs and continues in spool mode
- `429` / `503`: exponential backoff with *jitter*, honoring `Retry-After`

## Enrollment
```
Admin (console)            Agent                               Console
     │  creates a token       │                                    │
     │  (single use, 24 h)    │                                    │
     │───────────────────────▶│  POST /enroll {token, hostname,    │
     │   (manual copy)        │        version, connectors}        │
     │                        │───────────────────────────────────▶│
     │                        │◀── {agent_id, agent_secret,        │
     │                        │     console_min_protocol}          │
     │                        │  generates its local HMAC key      │
     │                        │  (never transmitted)               │
```

## Jobs (console → agent, via long-poll)
```json
{
  "job_id": "01920f5e-…",
  "type": "discovery.scan",
  "target_id": "pg-prod-1",
  "params": { "sample_rows": 200, "max_duration_s": 900, "schemas": ["public"] },
  "classifiers_version": "2026.09.1"
}
```
MVP types: `discovery.scan`, `audit.configure` (thresholds, sensitive locations to monitor), `agent.config.reload`, `agent.rotate_secret`.

## Finding (agent → console)
```json
{
  "batch_id": "01920f60-…",
  "job_id": "01920f5e-…",
  "findings": [{
    "target_id": "pg-prod-1",
    "location": { "engine": "postgres", "database": "crm", "schema": "public",
                  "object": "clients", "field": "email" },
    "classifier": "pii.email",
    "confidence": 0.97,
    "sampled": 200,
    "matched": 194,
    "estimated_rows": 1250000,
    "masked_samples": ["j*********@e******.fr", "m****@g****.com"],
    "fingerprints": ["hmac:9f2c…", "hmac:41ab…"]
  }]
}
```
**Forbidden**: any field containing a raw value. The console rejects batches that do not conform to the schema (`additionalProperties: false`).

## Access event (agent → console)
```json
{
  "target_id": "pg-prod-1",
  "ts": "2026-09-28T14:02:11Z",
  "principal": { "db_user": "backup", "client_addr": "10.0.3.14", "application": "pg_dump" },
  "action": "read",
  "objects": [{ "database": "crm", "schema": "public", "object": "clients" }],
  "rows": 1250000,
  "signals": ["signature.pg_dump", "shape.full_table_copy"],
  "source": "pgaudit",
  "aggregated_count": 1
}
```
The agent **pre-aggregates** repetitive events (same principal, same object, same action within a 60 s window) to limit volume.

## Heartbeat
Contains: version, uptime, active connectors, status of each target (`reachable`, `audit_level`), spool size, and internal metrics (counters, durations). The console re-exposes them on `/metrics`.
