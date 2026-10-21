# ADR-0056: A marker on names altered by ADR-0009 normalization, which location exceptions refuse to cover

- **Status**: Proposed (2026-10-21), for the maintainer's decision
- **Security review (2026-10-21)**: sound after changes, revised (H1: findings stored per location; H2: the inline `ObjectRef` copies of `AccessEvent`; M1: the first gated field on findings; L1 to L4)
- **Date**: 2026-10-21
- **Refines** (on acceptance): [ADR-0009](0009-name-normalization-and-item-sanitization.md) (which stays Accepted), its normalized names, which would carry a negotiated marker when normalization changed them; [ADR-0054](0054-case-sensitive-location-exceptions.md) (which stays Accepted), decision 4 and its residual risk "Normalization merges names"; [ADR-0021](0021-access-event-correlation.md) (which stays Accepted), decision 5 (exceptions on access events), and [ADR-0014](0014-policy-and-incident-model.md) (which stays Accepted), decision 1, for location exceptions only. Uses [ADR-0022](0022-protocol-capability-negotiation.md) (capability negotiation) and the send-time stripping of [ADR-0053](0053-overflowed-event-objects-flag.md) decision 2 without changing them; interacts with [ADR-0025](0025-mysql-mariadb-role-privileges-and-heartbeat-checks.md) (a scan's terminal status waits up to 120 s for its findings batches)
- **Context references**: ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups), "Contract: a marker on names altered by ADR-0009 normalization"; ADR-0054 open question 4 (decided on 2026-10-20: a follow-up with its own ADR and a `security-reviewer` review); ADR-0054 implementation note of 2026-10-20 (`connector-postgres/src/it_names.rs` pins the residual); [08-engine-capabilities.md, Objects per event and sensitive objects](../08-engine-capabilities.md#objects-per-event-and-sensitive-objects-every-engine); `shared/protocol/openapi.yaml` (`Identifier`, `KeyPattern`, `Location`, `ObjectRef`, the inline `ObjectRef` copies in `AccessEvent.allOf`); `shared/protocol/scripts/inline-objectref.test.mjs`; `agent/crates/classifiers/src/names.rs` (`NormalizedName`), `agent/crates/classifiers/src/keys.rs` (key patterns); `agent/crates/connector-cas/src/registry.rs` (`snake()`); `agent/crates/core/src/uplink.rs` (`carries_gated`), `agent/crates/core/src/runtime.rs` (`resend_unflagged`); `console/src/server/findings.ts` (findings upsert), `console/src/lib/policy-model.ts` (`exceptionCovers`), `console/src/lib/event-model.ts` (`exceptionCoversEvent`) (read at `c2ae105`, `dev`)

## Context

ADR-0009 normalization runs on every name before the uplink. Its first step strips control and format characters (zero-width characters such as U+200B, the soft hyphen U+00AD, bidirectional controls) and applies NFKC, so compatibility forms (fullwidth letters, ligatures) become their plain forms. The later steps turn value-like segments into `*`, array indices into `[]`, and LDAP entry DNs into their parent container. Redis / Valkey key patterns go through their own normalizer (`classifiers/src/keys.rs`), which applies NFKC to the key name before splitting it into segments and masks forbidden characters per segment.

The first step can merge two names the engine keeps apart. A table `"customers<U+200B>"` and a fullwidth `ｃｕｓｔｏｍｅｒｓ` both reach the console as `customers`, next to the real `customers` (`it_names.rs` pins this). The engine holds three objects; the console sees one name. ADR-0054 made location exceptions compare with case on PostgreSQL, MongoDB, Redis, Valkey, CAS and unknown engines (and, with ADR-0055, on MySQL / MariaDB and SQL Server databases reported case-sensitive), but an exception written for `customers` still covers the two look-alikes. Anyone who can create an object in a covered schema can therefore place data under a name the exception covers by accident: an exception is the console's only durable suppression besides false positives (ADR-0014 decisions 3 and 4). ADR-0054 recorded this as a residual risk and a follow-up.

A related case is the CAS `field`: the agent converts definition keys to snake_case and lowercases their ASCII capitals while doing so (`snake()`), so `userName`, `UserName` and `user_name` all arrive as `user_name` (ADR-0054 residual risks).

Not every change made by normalization merges distinct objects in a way that matters for exceptions:

- A name or segment replaced by `*` (classifier match, value-like segment, non-conforming name) is already the literal name `*`: an exception covers it only when its glob matches `*` (contract, "the name `*`").
- Array indices as `[]`, and dynamic keys as `*`, are field-path rules: they merge elements of one logical field on purpose.
- LDAP attribute types lowercased, and an entry DN reduced to its container: LDAP compares those without case, and the container is the location by design (ADR-0029).
- SQL Server and MySQL / MariaDB trailing spaces: the engines compare names that way, and N1 already handles them per engine.

What is left is the first step (stripping and NFKC, in `names.rs` and `keys.rs`) and the CAS key conversion: changes after which the name sent is a different string from the engine's, and another engine object may be sent under the same string.

How the console stores what would carry the marker:

- **Findings** are stored one row per (agent, location key) (`console/src/server/findings.ts`): within a batch the last item of a location wins, and across scans the row is updated in place (`onConflictDoUpdate`). The look-alikes and the plain table share one location key. A marker stored "as sent" on that row would be whatever the last item said: a scan that reports the altered look-alike and then the plain table would leave the row unmarked, and an exception would cover the look-alike's finding again.
- **Access events** are stored per event, with their objects.

How the contract would carry it:

- `ObjectRef` is a component, but `AccessEvent.allOf` holds three inline copies of its shape, each with `additionalProperties: false` (kept in step by hand; `shared/protocol/scripts/inline-objectref.test.mjs` checks the two source branches): the `then` branch for the Redis / Valkey sources (`object` as a `KeyPattern`), the `else` branch for every other source (`object` as an `Identifier`), and the `contains` item of the ADR-0053 rule that a flagged event names a `*`.
- Findings carry no gated field today: `carries_gated()` in `agent/crates/core/src/uplink.rs` is `false` for findings by design, pinned by the runtime test `findings_carry_no_gated_field_so_a_400_keeps_the_capabilities`. `Location.altered` would be the first.

Constraints:

- **ADR-0013 and ADR-0022.** Every schema is closed. A new optional field is compatible only when negotiated with a capability token; changing `Identifier` or `KeyPattern` to carry the mark inside the name would be a narrowing (incompatible, ADR-0022 decision 6).
- **I2.** The marker must carry no value, no removed character and no original spelling: only that the name was changed.
- **I6.** The change is made in `shared/protocol/openapi.yaml`, and the types are regenerated.
- **Old parties.** Agents up to this change cannot send the marker; consoles up to this change do not know it.

## Options

### (A) One boolean per item: `Finding.names_altered`, `AccessEvent.names_altered`

Set when any name of the item was altered. Simple, one token per schema. A finding has one location, so for findings this is per location. An access event lists up to 16 objects: one altered object would make every object of the event uncoverable by an exception that names a part, which raises incidents for the other 15.

### (B) A closed list of altered parts on each location and object: `Location.altered`, `ObjectRef.altered`

An optional array of unique values from a closed enum, present only when non-empty, naming the parts whose names normalization altered. The console refuses to cover an altered part with a glob that names it; a glob that is absent or exactly `*` for that part still covers it, as for an overflow `*` (ADR-0053 decision 3 item 6). Per object, so the other objects of an event are unaffected, and per part, so an exception that covers a whole database still covers an altered table name in it. The finding row shares its location key with the look-alikes; the marker is merged on the row (decision 3 item 2).

### (B') As (B), with the marker in the finding's location key

The console makes the altered parts part of the location key, so the look-alikes and the plain table become two finding rows. No merge rule is needed, and each row keeps its own marker. But all altered look-alikes of one location still share one row (the agent sends no original spelling), the key changes for existing rows whose next scan reports them altered (a new row and a stale one), and every consumer of the location key (dedup, sensitivity lookups, the per-object sensitivity of events, false positives) gains a component that is not a name.

### (C) Replace altered names by `*` in the agent

No protocol change: the agent treats an altered name like a non-conforming one. But `*` is a literal name for policy conditions too: an `objects` condition for `crm.customers` would no longer retain a read of the fullwidth twin, and its sensitivity would come from findings under `*`. Exceptions would stop covering the look-alike, but conditions would stop selecting it as well, and every name with a ligature, a fullwidth form or an invisible character (common in names created by copy and paste) would lose its detail in the console.

### (D) A target note

A registered note code (`coverage.names_altered`) needs no negotiation (ADR-0022 decision 5), but notes carry no location: the console could not tell which exception to restrict, and notes are a human-facing registry, not a matching input (ADR-0055 rejected alternative (4)).

### (E) Keep as is and document

The residual is documented in docs/08 and the user guide since ADR-0054. No change; exceptions keep covering look-alikes.

## Decision (proposed)

Option (B).

### 1. Contract (`shared/protocol/`, `security-reviewer` review)

1. **Two closed enums.** `LocationPart`: `database`, `schema`, `object`, `field`. `ObjectRefPart`: `database`, `schema`, `object` (an event object names no field). `Location.altered` is an array of 1 to 4 unique `LocationPart` values; `ObjectRef.altered` an array of 1 to 3 unique `ObjectRefPart` values. Both optional.
2. **Every copy of the `ObjectRef` shape.** `altered` is added to the `ObjectRef` component **and** to its three inline copies in `AccessEvent.allOf`, each closed with `additionalProperties: false`: the `then` branch (Redis / Valkey, `object` as a `KeyPattern`), the `else` branch (`object` as an `Identifier`), and the `contains` item of the ADR-0053 rule (`object` `const: "*"`). Missing it from the `contains` item would fail silently: a flagged event whose `*` carries `altered` would match no `contains` item, the console would answer `400` with the keyword `contains`, and the agent's overflow-rule handling (`resend_unflagged`, ADR-0053 implementation note) would resend the event once without `objects_overflowed`, keeping the capabilities; the event would reach the console unflagged, with the literal `*` rule, and nothing would show it. `shared/protocol/scripts/inline-objectref.test.mjs` is extended to the `contains` shape (today it checks the two branches), so every copy must list the same properties as the component.
3. **Fixtures.** Valid: a finding with `altered` (PostgreSQL), an event with an altered object on each branch (an `Identifier` source and a Redis source), and a flagged event (`objects_overflowed`) whose `*` carries `altered`. Invalid: `field` in an `ObjectRef.altered`, an unknown part, a repeated part, an empty list.
4. **Description**: "the agent's name normalization (ADR-0009: control and format characters stripped, NFKC; on Redis / Valkey the same steps of the key-pattern normalizer; on CAS, definition keys converted to snake_case) changed these parts, so another object of the engine may be sent under the same name. Never set for a part sent as `*`." It carries no value, no character and no count (I2).
5. **Tokens** `location.altered` and `object_ref.altered`, under the ADR-0022 decision 9 obligations (capabilities cleared on a `400` whose body carried a gated field, the items resent with the field stripped). A console lists both or neither, and lists them only once every replica accepts them (ADR-0022 decision 8).
6. No new `Error.code`, no new value in an existing enum, no removed or renamed field: a compatible change (ADR-0013).

### 2. Agent (`agent-engineer`)

1. **Where the marker comes from.**
   - `Identifier` names: `NormalizedName` (`names.rs`) records whether the stripping and NFKC step changed the input (compared on the input as read from the engine, before any other rule), and whether the result is `*` (then not altered).
   - Redis / Valkey key patterns: `keys.rs` records whether NFKC or its per-segment stripping changed a segment that is kept in the pattern (a segment turned into `*` is not altered). Discovery findings carry the marker of the pattern learned from the scanned keys. Audit keys are mapped to scan-learned patterns: an event object carries the marker of the learned pattern it maps to, OR the marker of its own key name when that name was changed by NFKC or stripping; a key mapped to `*` (no learned pattern) is not marked.
   - CAS: the registry marks a `field` whose snake_case conversion changed the key.
2. **Events.** The marker is spooled in full and stripped per token at send time, through the ADR-0053 decision 2 path (#297), with the hold while the capability set is not known, as for `objects_overflowed`. Aggregation merges the parts of objects merged together (union).
3. **Findings: the first gated field on `/findings`.** The findings path becomes part of the gating:
   - `carries_gated()` returns `true` for a findings batch with any `Location.altered`; the test `findings_carry_no_gated_field_so_a_400_keeps_the_capabilities` is inverted for such a batch (a `400` with `additionalProperties` on it clears the capabilities and resends the items once without the field) and kept for a findings batch without the field;
   - findings batches are spooled in full and stripped per token at send time, as event batches;
   - **no hold for findings**: when the capability set is not known, a findings batch is sent stripped at once rather than held, so the ADR-0025 wait (a scan's terminal status waits up to 120 s for its findings batches) is never spent waiting on a heartbeat answer; the marker of those findings is lost until the next scan (residual risks).
4. The agent's `sensitive_objects` filter is unchanged: it matches looser only.
5. **Test obligations.** The `it_names.rs` relations whose names differ by U+200B and a fullwidth letter reach the console with `object` in `altered`, and the plain relation without it; a property test that a name is marked if and only if the first step changed it and the result is not `*`, for `names.rs` and `keys.rs`; a Redis key with a fullwidth segment marked in Discovery and in Audit; the CAS `userName` key marked, `user_name` not; the findings tests of item 3.

### 3. Console (`console-engineer`)

1. **Events.** The parts as sent, stored with each event object; nullable, a Drizzle migration with no constraint to validate, never updatable by the runtime role (agent-reported, like `objects_overflowed`).
2. **Findings: merged per location and job.** The finding row's `altered` column holds the union (OR) of the altered parts of every item of that location within one job: within a batch (instead of the last item winning for this column) and across that job's batches. The first batch of a new job for the location replaces it. This column is the one exception to "agent-reported columns are not updatable by the runtime role": it is updated under these rules only. So a job that reports the plain table and an altered look-alike under one location keeps the row marked whatever the order, and a later scan that no longer finds the look-alike clears it.
3. **False positives.** A false positive (ADR-0014 decision 4) marked while the row was not altered does not carry over to the row once it is altered: the finding is evaluated again as not a false positive, and an administrator marks it again if it still is one. The audit log keeps the earlier mark.
4. **Exceptions (refines ADR-0054 decision 1 and ADR-0021 decision 5).** For an altered part, an exception covers the name only when its glob for that part is absent or exactly `*`. For the parts not altered, today's rules apply (with ADR-0054's case rules). The glob `\*` does not cover an altered part. This applies to finding exceptions (`exceptionCovers`) and access-event exceptions (`exceptionCoversEvent`).
5. **Unchanged.** Policy conditions, per-object sensitivity and scores, the dedup key, and the bound of an overflow `*`: they keep matching the name as sent, which can only report more.
6. **Display.** The finding and event views say that the name was altered by normalization, so the administrator checks the database for look-alike names. Notifications are unchanged.
7. **Without the field** (an older agent, or a console that does not list the tokens): today's behaviour. The console does not guess an alteration from the name.
8. **Test obligations.** For every glob and name, a cover of an altered part implies a glob absent or exactly `*` for that part; an unaltered object of the same event keeps today's result. Findings: plain, altered, then plain again for one location, in one batch and across batches of one job, leave the row altered, and an exception naming the object never covers it; the first batch of the next job without the look-alike clears it; a false positive marked on the unaltered row does not apply to the altered one.

### 4. Compatibility

| Agent | Console | Behaviour |
|---|---|---|
| older | this change | No field; as today. |
| this change | older | Tokens never listed, so the field is stripped at send time; as today. |
| this change | this change | Field sent; altered parts are covered only by `*` or absent globs. |
| this change | console rolled back | A `400` on the field clears the capabilities, and the items (events and findings) are resent without it (ADR-0022 decision 9). |

### 5. Documentation (`docs-keeper`)

When implemented: docs/08 "Objects per event and sensitive objects" and the user guide's policy section (what an altered name is and what exceptions do with it, the SQL Server width-insensitive case below), docs/09, the ADR-0054 residual updated, and the upgrade notes (findings and events from upgraded agents may reopen incidents an exception suppressed through an altered name; false positives on such rows must be marked again).

## Consequences

- An exception written for `customers` no longer suppresses `"customers<U+200B>"` or `ｃｕｓｔｏｍｅｒｓ` reported by an upgraded agent; an exception that covers the whole schema or database still does.
- More incidents where legitimate names contain invisible characters or compatibility forms and are covered by named exceptions; bounded by the dedup and the per-target hourly cap (ADR-0021 decisions 6 and 8). An administrator who accepts them can write an exception on the enclosing database or schema, which also covers every other object there.
- **SQL Server width-insensitive collations** (`_WS` absent from the collation name, the default): the server compares `ｃｕｓｔｏｍｅｒｓ` and `customers` as one name, but the statement text keeps the client's spelling, so an event naming the object in fullwidth form is marked altered and no named exception covers it. This fails safe (more incidents, never fewer) and is noise; documented in docs/08.
- On CAS, every definition key in camelCase becomes an altered `field`: CAS exceptions naming a field cover those findings no longer. This may be noisy; open question 2.
- Findings in one location key share one marker, merged per job, and false positives on altered rows must be marked again.
- One more optional field in two schemas and the three inline copies, two tokens, a column on findings and on event objects, and the first gated field on `/findings`. Stored rows from before the change have no marker forever.

### Residual risks

- Until both sides run this change, the residual of ADR-0054 stays.
- Findings sent while the capability set is not known (no hold, decision 2 item 3) lose the marker until the next scan of the location.
- Names changed by other rules (a segment turned into `*`, array indices) are not marked; they are covered by the literal `*` rule or are field-path merges by design.
- A name that differs only by case on a case-insensitive engine, or only by trailing spaces where the engine ignores them, is not an alteration and is not marked.

## Rejected alternatives

- **(A) One boolean per item**: on access events, one altered object would make every object of the event uncoverable by named exceptions, and an exception covering the whole database would still have to be special-cased; per object and per part says what exceptions can act on.
- **(B') The marker in the location key**: possible, but it changes the key of existing rows, still merges all look-alikes into one row, and adds a non-name component to every lookup by location; the per-job merge of decision 3 item 2 gives the same exception result on one row. Open question 4.
- **"As sent" storage on the finding row**: the last item of a location wins, so the plain table reported after its look-alike would clear the marker (security review H1).
- **(C) Altered names as `*`**: conditions would stop selecting the look-alike and the console would lose the name's detail; exceptions are the only rule that must be stricter.
- **(D) A target note**: no location, and a rendering registry used as a matching input.
- **(E) Keep and document**: leaves a suppression any account with `CREATE` can exploit; ADR-0054 chose the stricter rule for case with the same argument.
- **A hold for findings while the capabilities are not known**: it would compete with the ADR-0025 120 s wait for a scan's terminal status.
- **A marker inside the name** (a reserved suffix or prefix): collides with real names unless `Identifier` and `KeyPattern` are narrowed (incompatible), and older consoles would read it as part of the name.
- **Sending the original spelling, or a fingerprint of it**: the console needs only to know that the name changed; the stripped characters could carry a value (I2), and a fingerprint would be a new keyed identifier with nothing to compare it to.

## Open questions (for the maintainer)

1. Option (B) per part (proposed), or (A) per item for simplicity? Proposed answer: (B); (A) makes events with one altered object uncoverable as a whole.
2. CAS `field` keys converted to snake_case: marked (proposed, the rule is the same: two keys may arrive as one), or left out because CAS definitions are written by administrators? Proposed answer: marked; measure on the dev registry how many findings it affects before the implementation.
3. Should the console offer an inventory of the exceptions whose effect changes, as ADR-0054 decision 6 did? Proposed answer: no. Stored rows have no marker, so there is nothing to compare at upgrade; the change shows only as agents are upgraded, and the upgrade notes say so.
4. Findings: the per-job merge on one row (proposed) or the marker in the location key (B')? Proposed answer: the per-job merge; it keeps the location key a tuple of names.
