# ADR-0053: Tell the console that an event's `*` may hide objects past the 15-object bound

- **Status**: Proposed (revised on 2026-10-18 after its security review, "sound after changes": H1, M1 to M3, L1 to L3)
- **Date**: 2026-10-18
- **Refines**: [ADR-0021](0021-access-event-correlation.md) (which stays Accepted), decisions 3 (score), 5 (conditions and exceptions), 6 (dedup scope) and 10 (notifications), for events whose objects overflowed; uses [ADR-0022](0022-protocol-capability-negotiation.md) (capability negotiation) without changing it
- **Context references**: ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups), "Contract, after G7"; [08-engine-capabilities.md, Objects per event and sensitive objects](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine); [09-agent-protocol.md, the object `*`](../09-agent-protocol.md#the-object-); `MaskedEvent` in `agent/crates/classifiers/src/masking.rs`; `to_batches` and `stripped` in `agent/crates/core/src/uplink.rs`; `console/src/lib/event-model.ts` and `console/src/server/event-engine.ts` (read at `72e87d5`, `dev`)

## Context

Since gate G7 of the end-of-phase-9 security review (#262, released in 0.8.0), the agent core keeps at most 15 named objects per access event and reserves the 16th slot of `AccessEvent.objects` (`maxItems: 16`) for `*`. When a statement reaches more objects, the ones past the 15th are not listed and the event names a `*` object instead. Objects a connector drops under a bound of its own (SQL Server Audit keeps 64 per statement, Redis / Valkey 17 patterns per entry) reach the same rule through `MaskedEvent::with_unlisted_objects`. In both cases `MaskedEvent` sets two agent-side flags, `always_report` and `objects_overflowed`.

The `*` that stands for the left-out objects has no fixed shape. It is `(<database>, -, *)` when they share a database, `(*, -, *)` once objects of another database are left out too, and none is added when a `*` object already in the event covers them: that `*` can be one with a schema, from an unknown object of the same database. An event can also hold several `*` objects (one per database while there is room).

What each flag does today:

- **`always_report`** is used by the agent only. It exempts the event from the `audit.configure` filters (`min_rows`, `sensitive_objects`), so an overflowed event always reaches the console. It is not in the contract and the console never sees it.
- **`objects_overflowed`** is used by the agent only: by the own-read budget (an overflowed event of the agent's identity is never left out, since the objects it does not name were not charged), by the aggregation (merged with OR) and by tests and fuzz oracles. It is not in the contract either.

What the console does with such an event (the rule of the contract's "the name `*`" and ADR-0021):

- The `*` is a literal name. Its sensitivity is that of the findings recorded under the name `*`, usually none, so the event's sensitivity comes from the named objects only, and its score (`sensitivity × log10(1 + rows)`) is usually that of the most sensitive listed object, or 0.
- An `objects` condition retains the `*` only when its glob matches the string `*`. A policy written for `crm.customers` does not see an event that reached `crm.customers` as its 16th object.
- `min_sensitivity` and `min_score` conditions miss it in the same way. Signal, principal, `min_rows` and anomaly conditions still see the event.
- A location exception covers the event when its globs cover every retained object, the literal `*` included only when the glob matches `*`.

So the agent no longer drops these events, but on the console they look like an access to an unknown object (dynamic SQL, a statement the agent could not analyse) or to a masked name, and the policies most likely to be written for sensitive data (scoped to named objects, or to a sensitivity) do not fire. A statement that names 15 harmless tables before a sensitive one still evades them; only the agent-side drop was closed by G7.

How gated fields reach the console today: the agent decides at conversion time. `to_batches` (`agent/crates/core/src/uplink.rs`) builds the protocol batches from the masked events with `accept_bytes` taken from the capability set at that moment, and the batches are spooled as built. The capability set (`ConsoleCapabilities`) is not persisted: it is empty from the start of the agent until the first heartbeat answer, and it is cleared on a `400` whose body carried a gated field, after which `stripped()` resends the items without it. An event converted while the set is empty or cleared therefore loses its gated fields for good, even when the console accepts them a few seconds later.

Constraints:

- **ADR-0013 and ADR-0022.** Every schema is closed on both sides: a console rejects an unknown field (`400`). Adding an optional field is compatible only when negotiated with a capability token; narrowing a pattern (for example forbidding a name in `Identifier`) is incompatible.
- **I2.** Whatever is added must carry no value and no name the event does not already carry.
- **I6.** The change is made in `shared/protocol/openapi.yaml`; the TypeScript and Rust types are regenerated, never edited.
- **Old parties.** 0.8.0 agents set the flag internally but cannot send it; 0.1.x to 0.7.x agents cut their object lists at 16 without a sign (documented in docs/08). 0.8.0 and older consoles do not know the field.

## Options

### (a) An optional `AccessEvent.objects_overflowed` field, negotiated

A boolean `objects_overflowed`, sent only as `true`, when objects of the event were left out under a bound (the core's or a connector's), and only to a console whose latest `HeartbeatResponse.accepts` lists `access_event.objects_overflowed`. The event still names `*` as today. The console gives the `*` objects of a flagged event a meaning: "one or more objects of this database (of this target, for database `*`) that the event does not name".

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

Option (a), under the precondition of decision 6 (measure first).

### 1. Contract (`shared/protocol/`, `security-reviewer` review)

1. `AccessEvent.objects_overflowed`: optional boolean, `const: true` (the field is absent otherwise), described as: "objects of this event were left out under a bound (the agent core's 15 named objects, or a connector's own bound); the event's `*` objects stand for them (see `ObjectRef`, the name `*`)". It carries no value, no name and no count (I2).
2. Capability token `access_event.objects_overflowed`, under the ADR-0022 decision 9 obligations already met for `access_event.bytes` (capabilities cleared on a `400` whose body carried a gated field, the items resent with the field stripped). A console running several replicas lists it only once every replica accepts it (ADR-0022 decision 8).
3. The contract requires at least one object `*` in an event that carries the field. If the code generators support `contains` in the `if` / `then` form already used by `AccessEvent`, the rule is in the schema; otherwise it is a console-side check listed in "Console-side checks not expressible in this schema", with an existing `ErrorDetail.keyword`. Either way a rejected item is resent without the field (decision 9), so the event is never lost. The agent core cannot produce the field without `*` (`MaskedEvent` invariant, covered by the existing property tests).
4. The "name `*`" text of `ObjectRef` gains a third case, "overflowed objects", next to "unknown object" and "masked name".
5. No new `Error.code`, no new enum value, no removed or renamed field: a compatible change (ADR-0013).

### 2. Agent (`agent-engineer`): the flag is spooled and stripped at send time

The gating moves from conversion time to send time, so that an event converted before the first heartbeat answer, or while the capabilities are cleared, keeps its flag.

1. **Spool the full form.** The conversion (`to_batches`) always writes `objects_overflowed` into the event batches it spools, whatever the capability set holds at that moment.
2. **Strip at send time.** Before a batch is sent, the uplink checks the current capability set: when `access_event.objects_overflowed` is not listed, the batch is sent through the existing `stripped()` path (decode, drop the field, re-encode under a new `batch_id`), as on a `400` today. Today `stripped()` drops every gated field; at send time it drops only those whose tokens the current set does not list (a per-token form), so `bytes` is kept for a console that lists `access_event.bytes`. After a `400`, every gated field is still dropped, as decision 9 requires, and a batch stripped that way is never stripped twice. When the token is listed, the spooled batch is sent as it is.
3. **Why this option.** Holding flagged events until the token is listed (the ADR-0042 precedent for unlisted engines) would hold them forever with a console that never lists it (0.8.0 or older), and these events are always reported because they matter; persisting the capability set would send the field to a console rolled back since the last run, before its first answer, and relies on the `400` path for correctness anyway. Stripping at send time loses nothing in either case: an old console gets the event without the flag, a new one with it.
4. **Test obligations.** (1) Restart: events flagged and spooled before the first heartbeat answer, agent restarted, then a console that lists the token receives them with the flag, and one that does not receives them without it, none dropped. (2) After a `400` clears the capabilities, events converted before the next heartbeat answer are sent with the flag once the token is listed again. (3) A batch stripped at send time is byte-for-byte the batch the conversion would have built without the flag (apart from `batch_id`).
5. Aggregation keeps merging the flag with OR, so an aggregated event is flagged when any merged event was. Nothing else changes on the agent: the event is still always reported, still names `*` with the same database rule, and the `audit.configure` filter is unchanged.
6. The same send-time path could serve `access_event.bytes`, which has the same loss today; moving it is outside this ADR and left to the implementation PR or a follow-up.

### 3. Console (`console-engineer`): every `*` object of a flagged event is an overflow `*`

Fail closed for selection: the console cannot know which objects were left out, so it treats the overflow `*` as possibly any object of its database for every rule that decides whether the event is retained. Not for comparison between incidents: an upper bound must not make later events look less severe than they are.

1. **Which objects.** Every object named `*` in a flagged event is an overflow `*`, whatever its shape: `(<database>, -, *)`, `(*, -, *)`, or a `*` with a schema that absorbed the overflow (Context). The console does not infer the bound from the shape. On Redis / Valkey, a real `*` key pattern in a flagged event (the pattern of a key the agent could not attribute) is treated as an overflow too; this is fail closed and is documented in docs/08.
2. **Storage.** A nullable boolean column on `access_events` (ADR-0021 decision 1: the table holds the contract fields), true only when the field was sent, and the bound sensitivity and score of item 3 next to the existing `sensitivity` and `score`; a Drizzle migration with no constraint to validate.
3. **Two scores (refines ADR-0021 decision 3).**
   - The **named score** is today's score, computed from the named objects only (the `*` objects keep their literal-name sensitivity).
   - The **bound score** gives each overflow `*` the highest object sensitivity among the target's findings (false positives excluded) in its database, or among all the target's findings for the database `*`; the event's bound sensitivity is the maximum over its objects, and the formula is unchanged. It is an upper bound: the event's `rows` is the statement's, not the sensitive object's. For an event without the flag, both scores are the same.
   - The per-database lookup uses the same fold as `objectKey` (`foldName` on the database name), filters on `target_id` (as well as the agent), and has the JavaScript fallback the per-object lookup has on a `C` / `POSIX`-ctype console database.
4. **Where each score is used.**
   - **Bound score and bound sensitivity:** `min_score` and `min_sensitivity` conditions, the choice of the dedup object (ADR-0021 decision 6: the most sensitive retained object, which can now be the overflow `*` and its database, or `*`), and display.
   - **Named score:** `incidents.event_score` (the incident's highest score), the overflow incident's highest score, the baseline's `maxScore`, `worseThanResolved` and `worseThanFalsePositive` (ADR-0021 decision 7, ADR-0031 decision 2), and `severeEvent` (the cap bypass, ADR-0021 decision 8). Without this, a flagged event would raise an incident's or the overflow incident's highest score to a bound, and a later event that names the sensitive object, with a lower true score, would be linked to a resolved or false-positive incident instead of opening one, or would no longer bypass the cap.
   - **On the incident**, the console records that it holds a flagged event (`objects_overflowed`, true once any linked event was flagged) and the highest bound score of its events, for display as an upper bound ("up to …"). Neither is compared with later events.
5. **`objects` conditions (refines ADR-0021 decision 5).** An overflow `*` is retained by an `objects` pattern when the pattern's `database` glob, if any, matches its database; its `schema` and `object` globs are not applied to it (it may be any object of that database). An overflow `*` with the database `*` is retained by every `objects` pattern.
6. **Exceptions (refines ADR-0021 decision 5).** A location exception covers an overflow `*` only when it would cover every object of its database: its `schema` and `object` globs are absent or exactly `*`, and its `database` glob, if any, matches the database (for the database `*`: absent or exactly `*`). The glob `\*`, which selects the literal name `*` only, does not cover an overflow `*`. Exceptions scoped to an agent or a target only apply as today. This states what an exception covers; it is not a recommended way to silence a job (Consequences).
7. **Display and notifications (refines ADR-0021 decision 10).** The event view and incident page say that the event reached more objects than it lists, and show the bound score as an upper bound. The `incident.opened` access-event payload gains an `objects_overflowed` key, with the e-mail and chat renderings. The upgrade notes of the release that ships it say that this added key can break webhook receivers that validate the payload strictly (reject unknown keys), so they must be updated first.
8. **Without the field** (an agent up to 0.8.0, or a console that did not list the token): every `*` is treated as today. The console does not guess an overflow from 16 objects or from a `*`: an absent field means "not known", and the docs say so.
9. **Test obligations.** (1) A resolved and a false-positive incident opened by a flagged event do not hide a later event of the same scope and hour that names the sensitive object: it opens a new incident when its named score is higher than the incident's (which is the named score of the flagged event, not its bound). (2) The cap bypass is not made harder: after a flagged event joins the overflow incident of a policy and target, a later event whose named score is above the overflow incident's highest named score still bypasses the cap. (3) The per-database lookup matches folded database names, never reads findings of another target, and gives the same result through the `C`-ctype fallback.

### 4. Compatibility

| Agent | Console | Behaviour |
|---|---|---|
| 0.8.0 or older | this change | No field; as today. 0.1.x to 0.7.x lists were cut at 16 without a sign (docs/08). |
| this change | 0.8.0 or older | Token never listed, so every batch is stripped at send time; the event still names `*` and is always reported, as with 0.8.0. |
| this change | this change | Field sent, including for events spooled before the first heartbeat answer; console rules of decision 3. |
| this change | console rolled back | A `400` on the field clears the capabilities and the items are resent without it (ADR-0022 decision 9); later batches are stripped at send time until the token is listed again. |

The CI job "E2E compatibility (console N, agent N-1)" covers the first row; the agent tests of decision 2 cover the others.

### 5. Documentation (`docs-keeper`)

When implemented: docs/08 "Objects per event and sensitive objects" (what the console does with the flag, the Redis / Valkey `*` pattern treated as an overflow, and that agents up to 0.8.0 and consoles that do not list the token keep today's behaviour), docs/09 "the object `*`", the user guide's policy section (the bound score, and `exclude_principals` for known jobs), and the upgrade notes (the webhook key of decision 3 item 7).

### 6. Precondition of acceptance: measure the flagged-event rate

Before this ADR is accepted, the rate of flagged events is measured and recorded (in the ADR or in `docs/measurements/`): on the `load` and end-to-end runs of every engine, and on an ORM-style workload (generated joins and eager loading over many tables, and reporting queries over 16 tables or more). If the rate makes the extra incidents of the Consequences unacceptable, the maintainer picks one or more mitigations before acceptance:

- **`min_sensitivity` with rows.** A flagged event is kept by `min_sensitivity` through its bound only when it reports `rows > 0` or no `rows` at all; a flagged event that reports 0 rows uses its named sensitivity there.
- **A per-policy opt-out.** A policy condition that makes the policy use the named score and the literal-`*` rule for flagged events, for policies whose author accepts the gap (audited like any policy change).

**Measurement note (2026-10-20).** A first measurement is recorded in [docs/measurements/adr-0053-flagged-event-rate.md](../measurements/adr-0053-flagged-event-rate.md): load run 39453966277, a 600 s soak with an ORM-style principal next to the regular load on PostgreSQL, MariaDB and SQL Server, plus Valkey and CAS. Overflowed events: 5.18 % of events (0.47 % of statements) on PostgreSQL, 4.80 % (0.48 %) on MariaDB, 12.93 % (0.47 %) on SQL Server, of which 74 of 120 are the agent's own reads (under investigation), none on Valkey and CAS; none from the regular application principal. Unknown-object `*` events without overflow: 8.26 % on PostgreSQL, 1.60 % on MariaDB, every event on Valkey. Not yet covered: the end-to-end runs, MongoDB Audit, and engines other than those five. This note records data only; the decision above and the choice of a mitigation are unchanged and remain the maintainer's.

## Consequences

- Object-scoped and sensitivity-scoped policies see an event that reached a sensitive object past the 15th, or one a connector dropped under its own bound; a statement can no longer hide one behind 15 harmless names from those policies.
- More incidents: a flagged event on a database with any sensitive finding selects like an access to its most sensitive object, and every object-scoped policy whose database glob matches retains it. Statements naming 16 objects or more are uncommon in application traffic (a `pg_dump` gives one event per table), but reporting jobs and ORMs that join many tables can raise incidents they did not raise before; decision 6 measures how many. The per-target hourly cap and the dedup (ADR-0021 decisions 6 and 8) bound the volume. A known job is best silenced with `exclude_principals` on the policy concerned, which keeps every other principal's accesses visible; a location exception that covers a whole database (decision 3 item 6) would also silence every other access to it and is not recommended for this. A narrower exception scope (for example by principal) is a possible later change, in its own ADR.
- Incident comparisons stay on named scores, so the bound never makes a later event look less severe; the incident shows the bound for information.
- One aggregate per target and database for the bound sensitivity, computed per evaluation chunk; its cost is bounded like the per-object lookup.
- The agent's spooled batches carry the flag and are stripped at send time when needed: one decode and re-encode per batch sent to a console without the token.
- Nothing changes for events without the flag, nor for old agents and consoles.

### Residual risks

- Until both sides run this change, the gap of the context stays. Release notes should say so.
- An unknown-object `*` (dynamic SQL, a function body, a statement the agent could not parse) may also hide a sensitive object and keeps the "literal `*`" rule, except where it absorbed an overflow (decision 3 item 1). Extending the flag to it is open question 1.
- A real `*` key pattern on Redis / Valkey in a flagged event is scored and selected as an overflow: more incidents, never fewer.

## Rejected alternatives

- **(b) A reserved object form**: it collides with real `Identifier` and `KeyPattern` values unless the patterns are narrowed (incompatible), and older consoles would treat it as an ordinary name, with no fail-closed effect.
- **(c) Do nothing**: the gap stays for exactly the policies written for sensitive data; G7 then fixes only the agent-side drop.
- **(d) A signal**: it reaches 0.8.0 consoles without negotiation, but it mixes a property of the object list with exfiltration indicators, reopens resolved incidents (ADR-0021 decision 7) for a reason unrelated to the access, and does not by itself make object- or sensitivity-scoped policies see the event.
- **One score, the bound, everywhere**: it raises incidents' and the overflow incident's highest scores to an upper bound, so a later event naming the sensitive object can be linked to a resolved or false-positive incident, or fail to bypass the cap (security review H1).
- **Gating at conversion time, as for `bytes` today**: events converted before the first heartbeat answer or after a strip lose the flag for good (security review M1).
- **Holding flagged events until the token is listed**: with a console that never lists it, always-reported events would never be sent.
- **Persisting the capability set**: it can send the field to a rolled-back console and still depends on the `400` path; stripping at send time needs no stored state.
- **A per-object flag in `ObjectRef`**: the console treats every `*` of a flagged event as an overflow anyway (decision 3 item 1), so an event-level flag says what the console can act on; a per-object field would also apply to `KeyPattern` objects through the duplicated Redis / Valkey `ObjectRef` form in `AccessEvent`.
- **A count of the objects left out**: it tells the console nothing it can act on, and a count of distinct objects is engine text the agent would have to bound and the console to trust.
- **Sensitivity of the whole target for an overflow `*` with a named database**: the core keeps the database whenever every left-out object shares it, so the database bound is already fail closed and the target bound would only add noise.

## Open questions (for the maintainer)

1. Should the agent also set the flag (or a sibling field, `objects_unknown`) for an unknown-object `*`? Proposed answer: not in this change. Unknown-object `*` events are much more frequent (every dynamic SQL, user function or unparsable text on every engine), and selecting each of them like the database's most sensitive object would raise incidents on most application traffic; decide after measuring how often they occur, with the measurement of decision 6.
2. Should the bound sensitivity of an overflow `*` be the database's highest object sensitivity (proposed) or the sum over the database's objects capped at 30? Proposed answer: the highest, as ADR-0021 decision 3 takes the event's most sensitive object, not a sum.
3. Should a flagged event bypass the per-target hourly cap as a severe event (ADR-0021 decision 8)? Proposed answer: no. It bypasses the cap through the existing rule only, on its named score. Using the bound there would not help: once a bound entered the overflow incident's highest score, later events would need a higher score to bypass the cap, so bypasses would become less likely, not more; this is why decision 3 item 4 keeps the overflow incident's highest score on named scores.
4. Which mitigation of decision 6, if any, once the rate is measured? Proposed answer: decided on the measurement; `min_sensitivity` with rows first, since it needs no new policy key.
