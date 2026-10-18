# ADR-0053: Tell the console that an event's `*` may hide objects past the 15-object bound

- **Status**: Proposed
- **Date**: 2026-10-18
- **Refines**: [ADR-0021](0021-access-event-correlation.md) (which stays Accepted), decisions 3 (score), 5 (conditions and exceptions) and 6 (dedup scope), for events whose objects overflowed; uses [ADR-0022](0022-protocol-capability-negotiation.md) (capability negotiation) without changing it
- **Context references**: ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups), "Contract, after G7"; [08-engine-capabilities.md, Objects per event and sensitive objects](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine); [09-agent-protocol.md, the object `*`](../09-agent-protocol.md#the-object-); `MaskedEvent` in `agent/crates/classifiers/src/masking.rs`; `console/src/lib/event-model.ts` and `console/src/server/event-engine.ts` (read at `72e87d5`, `dev`)

## Context

Since gate G7 of the end-of-phase-9 security review (#262, released in 0.8.0), the agent core keeps at most 15 named objects per access event and reserves the 16th slot of `AccessEvent.objects` (`maxItems: 16`) for `*`. When a statement reaches more objects, the ones past the 15th are not listed: the event names `(<database>, -, *)`, or `(*, -, *)` once objects of another database are left out too, and `MaskedEvent` sets two agent-side flags, `always_report` and `objects_overflowed`.

What each flag does today:

- **`always_report`** is used by the agent only. It exempts the event from the `audit.configure` filters (`min_rows`, `sensitive_objects`), so an overflowed event always reaches the console. It is not in the contract and the console never sees it.
- **`objects_overflowed`** is used by the agent only: by the own-read budget (an overflowed event of the agent's identity is never left out, since the objects it does not name were not charged), by the aggregation (merged with OR) and by tests and fuzz oracles. It is not in the contract either.

What the console does with such an event (the rule of the contract's "the name `*`" and ADR-0021):

- The `*` is a literal name. Its sensitivity is that of the findings recorded under the name `*`, usually none, so the event's sensitivity comes from the 15 named objects only, and its score (`sensitivity × log10(1 + rows)`) is usually that of the most sensitive listed object, or 0.
- An `objects` condition retains the `*` only when its glob matches the string `*`. A policy written for `crm.customers` does not see an event that reached `crm.customers` as its 16th object.
- `min_sensitivity` and `min_score` conditions miss it in the same way. Signal, principal, `min_rows` and anomaly conditions still see the event.
- A location exception covers the event when its globs cover every retained object, the literal `*` included only when the glob matches `*`.

So the agent no longer drops these events, but on the console they look like an access to an unknown object (dynamic SQL, a statement the agent could not analyse) or to a masked name, and the policies most likely to be written for sensitive data (scoped to named objects, or to a sensitivity) do not fire. A statement that names 15 harmless tables before a sensitive one still evades them; only the agent-side drop was closed by G7.

Constraints:

- **ADR-0013 and ADR-0022.** Every schema is closed on both sides: a console rejects an unknown field (`400`). Adding an optional field is compatible only when negotiated with a capability token; narrowing a pattern (for example forbidding a name in `Identifier`) is incompatible.
- **I2.** Whatever is added must carry no value and no name the event does not already carry.
- **I6.** The change is made in `shared/protocol/openapi.yaml`; the TypeScript and Rust types are regenerated, never edited.
- **Old parties.** 0.8.0 agents set the flag internally but cannot send it; 0.1.x to 0.7.x agents cut their object lists at 16 without a sign (documented in docs/08). 0.8.0 and older consoles do not know the field.

## Options

### (a) An optional `AccessEvent.objects_overflowed` field, negotiated

A boolean `objects_overflowed`, sent only as `true`, when the agent core left objects of the event out under the 15-object bound (`MaskedEvent::objects_overflowed`), and only while the console's latest `HeartbeatResponse.accepts` lists `access_event.objects_overflowed`. The event still names `*` as today. The console gives the `*` objects of a flagged event a meaning: "one or more objects of this database (of this target, for database `*`) that the event does not name".

### (b) A reserved object form

A distinct object name, such as `**` or `*+`, for the overflow `*`. No new field. But:

- `**` and `*+` are valid `Identifier` values and valid Redis / Valkey `KeyPattern` values, so a real name can collide with them unless the patterns forbid them, which is a narrowing (incompatible, ADR-0013, ADR-0022 decision 6).
- An older console accepts the form and treats it as an ordinary literal name: no fail-closed effect, and a policy glob `*` already matches it.
- ADR-0009 normalization, the agent sanitizer, the console's rendering and the `KeyPattern` rendering rule would all need a special case for a name that is not a name.

### (c) Do nothing

The agent's always-report flag does not reach policies: it acts only on the agent's `audit.configure` filter, and nothing in the event tells the console about it. Policies with signal, principal, volume or anomaly conditions see these events; policies scoped to objects or to a sensitivity do not. The limit would be documented in docs/08 and the user guide (it partly is: "a policy scoped to named objects does not see such accesses").

### (d) A new signal in `signals.json`

A form-only registry id, for example `shape.objects_overflowed`, needs no negotiation (ADR-0022 decision 5): 0.8.0 consoles would store and show it, and a policy with `signals: ["shape.*"]` would select it at once. But:

- Signals are exfiltration indicators. An overflow is a property of the object list, not of the access: a reporting query over 20 tables is not suspicious in itself.
- Being a new signal, it makes a later event "worse" than a resolved incident without it (ADR-0021 decision 7), so it would reopen incidents for a reason that is not about the access.
- Object-scoped and sensitivity-scoped policies, the actual gap, still need the console code of option (a) to see the event.

## Decision (proposed)

Option (a).

### 1. Contract (`shared/protocol/`, `security-reviewer` review)

1. `AccessEvent.objects_overflowed`: optional boolean, `const: true` (the field is absent otherwise), described as: "the agent left objects of this event out under the bound of 15 named objects; the event's `*` objects stand for them (see `ObjectRef`, the name `*`)". It carries no value, no name and no count (I2).
2. Capability token `access_event.objects_overflowed`. The agent sends the field only when the console's latest heartbeat response lists the token, under the ADR-0022 decision 9 obligations already met for `access_event.bytes` (capabilities cleared on a `400` whose body carried a gated field, the items resent with the field stripped). A console running several replicas lists it only once every replica accepts it (ADR-0022 decision 8).
3. The contract requires at least one object `*` in an event that carries the field. If the code generators support `contains` in the `if` / `then` form already used by `AccessEvent`, the rule is in the schema; otherwise it is a console-side check listed in "Console-side checks not expressible in this schema", with an existing `ErrorDetail.keyword`. Either way a rejected item is resent without the field (decision 9), so the event is never lost. The agent core cannot produce the field without `*` (`MaskedEvent` invariant, covered by the existing property tests).
4. The "name `*`" text of `ObjectRef` gains a third case, "overflowed objects", next to "unknown object" and "masked name".
5. No new `Error.code`, no new enum value, no removed or renamed field: a compatible change (ADR-0013).

### 2. Agent (`agent-engineer`)

1. The uplink serializer sets the field from `MaskedEvent::objects_overflowed()` when `console_accepts("access_event.objects_overflowed")`. Aggregation keeps merging the flag with OR, so an aggregated event is flagged when any merged event was.
2. Nothing else changes on the agent: the event is still always reported, still names `*` with the same database rule, and the `audit.configure` filter is unchanged.

### 3. Console (`console-engineer`): every `*` object of a flagged event is an overflow `*`

Fail closed: the console cannot know which objects were left out, so it treats the overflow `*` as possibly any object of its database, for every rule that could otherwise let the event through.

1. **Storage.** A nullable boolean column on `access_events` (ADR-0021 decision 1: the table holds the contract fields), true only when the field was sent; a Drizzle migration with no constraint to validate.
2. **Sensitivity and score (refines ADR-0021 decision 3).** The sensitivity of an overflow `*` is the highest object sensitivity among the target's findings (false positives excluded) in its database, compared with `foldName` as for named objects; for the database `*`, among all the target's findings. The event's sensitivity stays the maximum over its objects, so the overflow can only raise it; the score formula is unchanged. The bound is an upper bound: the event's `rows` is the statement's, not the sensitive object's.
3. **Baselines.** A principal's baseline is fed with the score computed from the named objects only, so an upper bound does not raise the baseline's recorded maximum score; the anomaly verdict, from `rows`, is unchanged.
4. **`objects` conditions (refines ADR-0021 decision 5).** An overflow `*` is retained by an `objects` pattern when the pattern's `database` glob, if any, matches its database; its `schema` and `object` globs are not applied to it (it may be any object of that database). An overflow `*` with the database `*` is retained by every `objects` pattern. `min_sensitivity` and `min_score` apply to the sensitivity and score of item 2.
5. **Exceptions (refines ADR-0021 decision 5).** A location exception covers an overflow `*` only when it would cover every object of its database: its `schema` and `object` globs are absent or exactly `*`, and its `database` glob, if any, matches the database (for the database `*`: absent or exactly `*`). The glob `\*`, which selects the literal name `*` only, does not cover an overflow `*`. Exceptions scoped to an agent or a target only apply as today.
6. **Dedup (ADR-0021 decision 6).** Unchanged rule: the dedup database is the one of the most sensitive retained object, which can now be the overflow `*` and its database (or `*`).
7. **Display and notifications.** The event view and incident page say that the event reached more objects than it lists. The `incident.opened` access-event payload (ADR-0021 decision 10) gains an `objects_overflowed` key, with the e-mail and chat renderings; it is an added key, and the webhook documentation states it.
8. **Without the field** (an agent up to 0.8.0, or a console that did not list the token): every `*` is treated as today. The console does not guess an overflow from 16 objects or from a `*`: an absent field means "not known", and the docs say so.

### 4. Compatibility

| Agent | Console | Behaviour |
|---|---|---|
| 0.8.0 or older | this change | No field; as today. 0.1.x to 0.7.x lists were cut at 16 without a sign (docs/08). |
| this change | 0.8.0 or older | Token not listed, so no field; the event still names `*` and is always reported, as with 0.8.0. |
| this change | this change | Field sent; console rules of decision 3. |
| this change | console rolled back | A `400` on the field clears the capabilities and the items are resent without it (ADR-0022 decision 9). |

The CI job "E2E compatibility (console N, agent N-1)" covers the first row; the agent's strip-and-resend tests cover the last.

### 5. Documentation (`docs-keeper`)

When implemented: docs/08 "Objects per event and sensitive objects" (what the console does with the flag, and that agents up to 0.8.0 and consoles that do not list the token keep today's behaviour), docs/09 "the object `*`", the user guide's policy section, and the upgrade notes of the release that ships it.

## Consequences

- Object-scoped and sensitivity-scoped policies see an event that reached a sensitive object past the 15th; a statement can no longer hide one behind 15 harmless names from those policies.
- More incidents: a flagged event on a database with any sensitive finding scores like an access to its most sensitive object, and every object-scoped policy whose database glob matches retains it. Statements naming 16 objects or more are uncommon in application traffic (a `pg_dump` gives one event per table), but reporting jobs and ORMs that join many tables will raise incidents they did not raise before. The per-target hourly cap and the dedup (ADR-0021 decisions 6 and 8) bound the volume; an exception scoped as in decision 3 item 5, or to a principal through `exclude_principals`, silences a known job.
- One aggregate per target and database for the sensitivity of item 2, computed per evaluation chunk; its cost is bounded like the per-object lookup.
- The score of a flagged event is an upper bound and is shown as such.
- Nothing changes for events without the flag, nor for old agents and consoles.

### Residual risks

- Until both sides run this change, the gap of the context stays. Release notes should say so.
- An unknown-object `*` (dynamic SQL, a function body, a statement the agent could not parse) may also hide a sensitive object and keeps the "literal `*`" rule. Extending the flag to it is open question 1.

## Rejected alternatives

- **(b) A reserved object form**: it collides with real `Identifier` and `KeyPattern` values unless the patterns are narrowed (incompatible), and older consoles would treat it as an ordinary name, with no fail-closed effect.
- **(c) Do nothing**: the gap stays for exactly the policies written for sensitive data; G7 then fixes only the agent-side drop.
- **(d) A signal**: it reaches 0.8.0 consoles without negotiation, but it mixes a property of the object list with exfiltration indicators, reopens resolved incidents (ADR-0021 decision 7) for a reason unrelated to the access, and does not by itself make object- or sensitivity-scoped policies see the event.
- **A per-object flag in `ObjectRef`**: the core merges overflowed objects into one `*` per event (one per database, then `(*, -, *)`), so an event-level flag says the same thing; a per-object field would also apply to `KeyPattern` objects through the duplicated Redis / Valkey `ObjectRef` form in `AccessEvent`.
- **A count of the objects left out**: it tells the console nothing it can act on, and a count of distinct objects is engine text the agent would have to bound and the console to trust.
- **Sensitivity of the whole target for an overflow `*` with a named database**: the core keeps the database whenever every left-out object shares it, so the database bound is already fail closed and the target bound would only add noise.

## Open questions (for the maintainer)

1. Should the agent also set the flag (or a sibling field, `objects_unknown`) for an unknown-object `*`? Proposed answer: not in this change. Unknown-object `*` events are much more frequent (every dynamic SQL, user function or unparsable text on every engine), and scoring each of them like the database's most sensitive object would raise incidents on most application traffic; decide after measuring how often they occur in the load and end-to-end runs.
2. Should the sensitivity bound of an overflow `*` be the database's highest object sensitivity (proposed) or the sum over the database's objects capped at 30? Proposed answer: the highest, as ADR-0021 decision 3 takes the event's most sensitive object, not a sum.
3. Should a flagged event bypass the per-target hourly cap as a severe event (ADR-0021 decision 8)? Proposed answer: no. It bypasses the cap only through the existing rule (a score above the overflow incident's highest), which the higher score of decision 3 item 2 already makes likely.
