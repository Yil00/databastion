# ADR-0008: Agent-generated secret rotation with conflict lock

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
The initial design ([09-agent-protocol.md](../09-agent-protocol.md)) had the console issue a new agent secret, which the agent "retrieved on its next call". That puts a live secret in a console response after enrollment, makes a lost response unrecoverable (the console has switched, the agent has not), and gives anyone who stole the current secret a way to obtain the next one. The protocol v1 contract (`shared/protocol/openapi.yaml`, `POST /rotate`) needed a rotation that survives network errors and restarts and that surfaces a stolen secret instead of rewarding it.

## Decision
- **The agent generates the new secret** (`S1`, 256 bits from a CSPRNG, `AgentSecret` format) and persists it as *pending* next to the current secret `S0` (`0600` file, fsync) **before** any network call. After enrollment, the console never sends a secret.
- The agent registers `S1` with `POST /rotate` (`RotateRequest {new_secret, job_id?}`), authenticated with `S0`. Trigger: an `agent.rotate_secret` job (which carries no secret) or a local operator command.
- The console stores the argon2id hash of `S1` as pending and returns `grace_expires_at` (300 s by default, at most 3600 s, never extended by a retry). The first successful request with `S1`, or the deadline, promotes `S1` and revokes `S0`.
- **Idempotent retries**: the same `S1` resent with `S0` gets `200` with `duplicate: true`. The agent never generates a new secret while one is pending, including after a restart or a redelivered job.
- The console rejects a `new_secret` equal to the current secret or obviously low-entropy (`400` `invalid_secret`).
- **Conflict lock**: a different `new_secret` while one is pending or just promoted, or a request with `S0` more than **60 s** after promotion, is a `rotation_conflict`. The console locks the agent, revokes every secret (current and pending), closes its long-polls and raises a security incident. The agent stops and requires re-enrollment. Requests with `S0` within the 60 s tolerance window get a plain `401`.
- Rotation is maintenance, not incident response: **suspected compromise = revoke + re-enroll**.

## Consequences
- No secret travels from the console to the agent after enrollment; a lost `/rotate` response is recovered by retrying with the same pending secret.
- Two parties holding `S0` cannot both rotate silently: the second one triggers a lock and an incident. The cost is that a buggy agent that generates a second secret also gets locked and must be re-enrolled; a conforming agent never triggers the lock.
- The agent needs atomic storage of the pending secret (P1-B); the console needs a pending-hash column, the promotion logic, the 60 s window and the lock (P1-A).
- `/rotate` bodies are excluded from all logs on both sides, like `/enroll`.

## Rejected alternatives
- **Console-issued secret in a response**: a lost response desynchronizes the agent, and the thief of `S0` receives `S1`.
- **Accepting `S0` indefinitely after rotation**: hides a stolen secret.
- **Rotation as the answer to a suspected compromise**: whoever holds the secret can race the rotation; revocation and re-enrollment do not depend on the secret.
