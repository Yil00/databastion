# ADR-0011: Late rotation retry with the previous secret

- **Status**: Accepted
- **Date**: 2026-09-28
- **Refines**: [ADR-0010](0010-rotation-conflict-window.md) (which stays Accepted)

## Context
[ADR-0010](0010-rotation-conflict-window.md) treats a `/rotate` authenticated with the previous secret `S0` and carrying the same new secret `S1` as an idempotent `duplicate` only while `S1` is pending or promoted less than 60 s ago. After the window, any use of `S0` is a `rotation_conflict` and locks the agent.

The security review of the console `/rotate` implementation (P1-A part 2, #21) found a case where a conforming agent is locked: the agent sends `/rotate`, the console registers `S1`, the response is lost, and the agent then stays offline longer than the grace period. `S1` is promoted at `grace_expires_at`; when the agent comes back and retries `/rotate` with `S0` and the same `S1`, ADR-0010 locks it although the request is a harmless retry.

Notation as in ADR-0010: `S0` is the previous secret, `S1` the new secret registered by `/rotate` (pending, then current after promotion).

## Decision
- **Late retry**: a `/rotate` authenticated with `S0` whose `new_secret` matches the **current** (promoted) secret is an idempotent retry **at any time**, not only inside the 60 s window. The console answers `200` with `duplicate: true` and the deadline of that rotation (`grace_expires_at` as originally set), and never locks the agent. Only the holder of `S1` can send it, so it reveals nothing and grants nothing.
- **Every other outcome of a `/rotate` authenticated with `S0` after the window locks the agent** (`409 rotation_conflict` + security event): invalid body, low-entropy or any other `new_secret`, unknown `job_id`. This path has exactly two outcomes, the late-retry duplicate or a lock; it never answers `400`, `404`, `429` or `503`.
- **Other endpoints**: a request authenticated with `S0` after the window on any endpoint other than `/rotate` is a `rotation_conflict`, unchanged from ADR-0010.
- **Bound**: late retries are limited to 10 per agent per 5 minutes; the 11th locks the agent.
- **Agent**: when the outcome of a `/rotate` is unknown, the agent first tries its pending `S1` (a heartbeat used as a probe) and re-sends `/rotate` with `S0` only if `S1` is refused. Implemented in P1-B (#20).

### Errata to ADR-0010
ADR-0010 states that "a `/rotate` authenticated with the **current** secret always starts a new rotation and is **never** a `rotation_conflict`". This applies **while no secret is pending**. The specific rules for `S0` in ADR-0010 and in this ADR take precedence. ADR-0010 is not edited; this section is the reference for that reading.

## Consequences
- A conforming agent whose `/rotate` response was lost is not locked, however long its outage.
- A party holding only `S0` still cannot rotate silently: any `new_secret` other than the current secret, and any use of `S0` outside `/rotate` after the window, locks the agent and raises a security event.
- The console keeps the hash of `S0` and the deadline of the rotation that promoted the current secret, even when a newer rotation has started, so it can recognize a late retry.
- The contract text of `POST /rotate` in `shared/protocol/openapi.yaml` must reflect this rule (409 wording: "authenticated with `S0`" / "while no secret is pending" instead of "the current secret"). Follow-up owned by `agent-engineer`, with a `security-reviewer` review (P1-D in the [ROADMAP](../ROADMAP.md)).
- The console `/rotate` implementation (P1-A part 2, #21) follows this ADR.

## Rejected alternatives
- **Keeping the 60 s window as the only tolerance** (ADR-0010 as written): locks a conforming agent after a lost response and a long outage.
- **Extending the tolerance window to the whole grace period or longer**: widens the period during which `S0` is accepted for every request, instead of accepting only the one request that proves possession of `S1`.
- **Answering stale-`S0` errors with `400` / `404`**: gives a party holding `S0` a way to probe the console without consequence; the lock is the only answer apart from the proven retry.
