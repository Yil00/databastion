# ADR-0010: Rotation conflict window and "just promoted" definition

- **Status**: Accepted
- **Date**: 2026-09-28
- **Refines**: [ADR-0008](0008-agent-generated-secret-rotation.md) (which stays Accepted)

## Context
[ADR-0008](0008-agent-generated-secret-rotation.md) makes a different `new_secret` "while one is pending or just promoted" a `rotation_conflict`, and a request with the previous secret more than 60 s after promotion a conflict too. It does not define "just promoted", and it does not say which secret authenticates the `/rotate` request that counts as a conflict. Read literally, a legitimate agent that has already switched to its new secret and starts the next rotation shortly after a promotion could be locked. Both the console `/rotate` implementation (P1-A part 2) and the contract text of `POST /rotate` in `shared/protocol/openapi.yaml` need one unambiguous rule.

Notation: `S0` is the previous secret, `S1` the new secret registered by `/rotate` (pending, then current after promotion).

## Decision
- **"Just promoted"** means: within the **60 s tolerance window** that starts when `S1` becomes the current secret (first successful request with `S1`, or the `grace_expires_at` deadline).
- A `rotation_conflict` applies **only** to a `/rotate` authenticated with `S0` whose `new_secret` differs from:
  - the pending `S1`, or
  - the `S1` promoted less than 60 s ago.
- A `/rotate` authenticated with `S0` that carries the **same** `S1` (pending, or promoted less than 60 s ago) gets `200` with `duplicate: true`. This is the idempotent retry of ADR-0008, extended to the tolerance window.
- A `/rotate` authenticated with the **current** secret always starts a new rotation and is **never** a `rotation_conflict`. The usual checks still apply (`invalid_secret` for a secret equal to the current one or obviously low-entropy).
- Any use of `S0` **after** the 60 s window is a `rotation_conflict`, as in ADR-0008: the console locks the agent, revokes every secret (current and pending), closes its long-polls and raises a security incident.
- **Console**: it never issues an `agent.rotate_secret` job while a secret is pending, nor within 60 s after a promotion.
- **Agent**: it defers an `agent.rotate_secret` job received within 60 s of a promotion (implemented in P1-B, #16), so a conforming agent never starts a rotation inside the window.

## Consequences
- A conforming agent cannot trigger the lock: retries with `S0` inside the window are duplicates, and a new rotation authenticated with the current secret is never a conflict.
- Two parties holding `S0` still cannot both rotate silently: the second one, sending a different `new_secret` with `S0`, triggers the lock and an incident.
- The contract text of `POST /rotate` in `shared/protocol/openapi.yaml` must be aligned with this ADR. Follow-up task owned by `agent-engineer`, with a `security-reviewer` review (P1 follow-ups in the [ROADMAP](../ROADMAP.md)).
- The console `/rotate` implementation (P1-A part 2) follows this ADR.
- The console needs, in addition to what ADR-0008 lists, the promotion timestamp of the current secret and the hash of the previous secret `S0`, to tell a retry inside the window from a conflict.

## Rejected alternatives
- **Treating any `/rotate` within 60 s of a promotion as a conflict, whatever secret authenticates it**: locks a legitimate agent that rotates again right after a promotion, and punishes the console's own scheduling.
- **Answering a same-`S1` retry with `S0` inside the window with `401`** (literal reading of ADR-0008): forces a conforming agent whose `/rotate` response was lost into an error path, although the request is a harmless retry.
- **No tolerance window for `S0`**: in-flight requests sent with `S0` just before promotion would be treated as theft.
