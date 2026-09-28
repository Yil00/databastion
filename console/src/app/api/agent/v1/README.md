# Agent API v1 (`/api/agent/v1/*`)

Server side of the agent ↔ console protocol.

| Route | Status | Handler |
|-------|--------|---------|
| `POST /enroll` | implemented (P1-A) | `src/server/agent-api/handlers.ts` `handleEnroll` |
| `POST /heartbeat` | implemented (P1-A) | `handleHeartbeat` |
| `GET /jobs?wait=` | implemented (P1-A), long-poll | `handlePollJobs` |
| `POST /jobs/{job_id}/status` | implemented (P1-A) | `handleJobStatus` |
| `POST /rotate` | implemented (P1-A part 2), ADR-0008 + ADR-0010 | `handleRotate`, logic in `src/server/rotation.ts` |
| `POST /findings`, `POST /events` | `501` (catch-all `[...path]/route.ts`, body never read) | later phases (P2-D, P3) |

Route files are thin: the logic lives in `src/server/agent-api/` (pipeline, auth, long-poll hub)
and `src/server/{agents,jobs,enrollment}.ts`.

Request pipeline (every endpoint): required headers (`X-DataBastion-Protocol`, `User-Agent`;
`426` with `min_protocol` below the console minimum) → agent authentication (except `/enroll`) →
body read with a hard 4 MiB cap (`413`) → `validateSchema` → `checkSemantics` → handler. Errors use
the contract `Error` body with a fixed message per code and never echo submitted values. Every
response is `Cache-Control: no-store`. Outgoing bodies (`EnrollResponse`, `HeartbeatResponse`,
`JobList`) are validated against the contract before being sent; each job is validated
individually and a non-conforming job is marked `failed` and never served.

Authentication: every attempt that needs an argon2id verification is counted before it runs
(refunded on success), per (agent id, source IP) (10 / 5 min) and per source IP (50 / 5 min); the
per-IP limit only applies when the IP is known (trusted proxy), and the per-agent key falls back to
the agent id alone otherwise. At most 8 argon2id verifications of unrecognized secrets run at once per process (`503` +
`Retry-After` beyond); secrets matching the last verified fingerprint use a separate reserved pool
of 4, and logins have their own pool, so neither floods of wrong secrets nor login floods can block
a legitimate agent. Verified secrets are cached 25 s, bound to the stored hash and purged on
revocation; the agent row is read on every request, so a revocation from any console process is
effective immediately. A 24 h "known good" fingerprint of the last verified secret only exempts it
from the per-agent failure limit (an attacker cannot lock the agent out); it never authenticates.
It is persisted in the agent row (hash-bound SHA-256, no secret), so it survives console restarts.

Rotation: `authenticateAgent` also matches the pending secret (promoting it on first use) and the
previous one (`401` inside the 60 s window, `/rotate` only gets it through; after the window the
handler locks the agent, `409 rotation_conflict`). A use of the previous secret stays counted as a
failed attempt (a `/rotate` duplicate gives it back), and the late-retry check of `/rotate` runs
under the authentication's pool slot: `S0` checks never run argon2id outside the bounded pools. See the console README, "Agent secret rotation".

Long-poll: one `LISTEN` connection per process (`databastion_jobs`, `databastion_agent_revoked`),
no database connection held while waiting. While the listener is up, a held poll re-reads only the
agent's revocation state every 30 s and claims jobs on a job wake-up; when it is down, it claims
every 5 s. Held-poll slots are reserved before any await, also for `wait=0`: at most 2 per agent
(`429`) and 2000 per process (`503`). Revocation closes held polls with `401`. A job delivered 5 times without any
status is marked `failed` (`timeout`).

Rules for the endpoints to come (see [docs/09-agent-protocol.md](../../../../../../docs/09-agent-protocol.md)):

- The contract is `shared/protocol/openapi.yaml` (invariant I6). Types and the
  JSON Schema bundle are **generated** into `src/generated/protocol/`; no hand-written
  protocol types.
- Every request body is validated with `src/lib/protocol/validate.ts`
  (`validateHeartbeatRequest(body)`…, Ajv 2020 on the generated schema bundle) and
  rejected on unknown fields (`additionalProperties: false`). On failure it returns
  `{pointer, keyword}` details (at most 20) built only from contract property names
  and array indices: they never echo a submitted value or an unknown field name, so
  they can be returned to the agent and logged. Pointers are truncated at the first
  segment that cannot be disclosed, so they always match the contract's `ErrorDetail`.
- `ok: true` from `validateSchema` is **schema-only**. Every endpoint (P1-A, P2-D…) must
  then call `checkSemantics(name, value)`, which enforces the rules JSON Schema cannot
  express: `x-databastion-max-bytes` (keyword `maxBytes`) and the 50 % `*` rule of
  `MaskedSample` (keyword `maskRatio`). Reserved metric names are ignored by the
  `/metrics` exporter, not rejected.
- The console never initiates a connection to an agent (I1) and never stores
  target database credentials (I3).
- Agent secrets are stored hashed (argon2id).
- Each endpoint is a sibling route (e.g. `heartbeat/route.ts`), which takes
  precedence over the catch-all placeholder.
- Tests: `src/server/agent-api/agent-api.test.ts` runs every endpoint against the fixtures of
  `shared/protocol/fixtures/` on a throwaway PostgreSQL cluster.
