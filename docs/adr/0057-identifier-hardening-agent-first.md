# ADR-0057: `Identifier` hardening, agent first: the `KeyPattern` digit-run, address and escape rules for every normalized name

- **Status**: Accepted (2026-10-22). **Accepted by the maintainer on 2026-10-22, option (B), agent first**, as revised after its security review of 2026-10-21 (open question 1 answered by that choice; questions 2 and 3 answered the same day with their proposed answers; see [Open questions](#open-questions-for-the-maintainer)). History: proposed on 2026-10-21. Implementation: the agent first, then the console mask in a later release; the narrowing of `Identifier` later, in `/api/agent/v2` only (ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups))
- **Security review (2026-10-21)**: sound after changes, revised (M1: the agent's current masking stated from the code; L1 to L6)
- **Date**: 2026-10-21
- **Refines** (on acceptance): [ADR-0009](0009-name-normalization-and-item-sanitization.md) (which stays Accepted), its normalized names, with stricter producer rules; uses [ADR-0013](0013-frozen-error-codes.md) and [ADR-0022](0022-protocol-capability-negotiation.md) decision 6 (narrowing a pattern is incompatible) without changing them
- **Context references**: ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups), "Contract: `Identifier` hardening"; [ADR-0052](0052-redis-valkey-connector.md) decision 7 (`KeyPattern`); `shared/protocol/openapi.yaml` (`Identifier`, `KeyPattern`, `ObjectName`, `SensitiveObject`); `agent/crates/classifiers/src/names.rs` (`NormalizedName`, `normalize_path`, `normalize_field_path`, `segment_looks_like_value`, `MAX_INDEX_DIGITS`, `MAX_TOTAL_DIGITS`, `has_percent_escape`), `agent/crates/core/src/sanitize.rs`; `shared/protocol/redocly.yaml` (`recommended-strict`); `console/src/db/schema.ts` (per-agent share of the system-alert budget) (read at `c2ae105`, `dev`)

## Context

`KeyPattern` (Redis / Valkey key patterns, phase 9) was written after `Identifier` and has stricter `not` rules: no segment of 9 or more digits, spaces, `_`, `+` or `-`; no digit-to-digit run of 9 or more digits and separators across segments (`06.12.34.56.78`); no IPv4 address as whole segments; no percent-encoded byte; no IPv6 or MAC address; no first segment naming a URL scheme. Digits and spaces are any Unicode decimal digit and space separator. `Identifier`, the schema of every other name (database, schema, table, collection, column, field path, LDAP container), has only one such rule: no name or `.`-separated segment made only of 9 or more digits and separators. Its pattern already forbids `:`, `/` and `@`: a name holding no `:` cannot hold a URL scheme followed by its `:`, nor an IPv6 or `:`-separated MAC address, so those three rules have nothing to add; the others can.

The contract schema is the console's check, not the agent's only defense: the agent normalizer (`names.rs`) is already stricter, and masks most of what the `KeyPattern` rules refuse. Its actual gate on every name it builds:

- no run of more than 6 numeric characters (`MAX_INDEX_DIGITS`), and no more than 8 numeric characters in total (`MAX_TOTAL_DIGITS`), counted in any script (`is_numeric_like`); a segment with more than 6 digits, consecutive or in total, is a value (`cust_12345678`, `events_2026_10_21`);
- no percent-encoded byte (`%XX`) and no `%uXXXX` escape (`has_percent_escape`);
- in dotted paths (`normalize_path`), a segment made only of digits and of at most 6 of them becomes `[]` after the previous segment, or `*` when it is the first: `10.0.0.1` becomes `*[][][]`, and `1.2.3.4.5` the same way;
- in field paths with real keys (`normalize_field_path`), any key holding a `.` is a dynamic key and becomes `*`;
- a long hexadecimal segment (16 or more hexadecimal characters once `-` is removed, with at least one digit: UUIDs, ObjectIds, hashes) is a value, which catches the dashed MAC form `00-1a-2b-3c-4d-5e` as one segment.

What survives today: the dotted MAC form (`001a.2b3c.4d5e`: three 4-character segments, none digit-only, none long enough for the hexadecimal rule) and short runs separated by `_`, `+` or `-` inside one segment that stay below both bounds (`1_2_3_4_5`, 5 digits in 9 characters).

Narrowing `Identifier` in the contract is incompatible (ADR-0022 decision 6), in both directions:

- **Agent -> console.** A console with a narrowed `Identifier` refuses an item from an older agent whose name passes today's rule but not the new one, with a per-item `400`. Under ADR-0009 the agent drops refused items and resends the rest: a finding or event is lost, which ADR-0009 rejected ("dropping any item with a suspicious name: an attacker could hide sensitive locations by naming them badly").
- **Console -> agent.** `SensitiveObject.object` in `audit.configure` jobs is an `Identifier` (or a `KeyPattern` since #280). An agent with a narrowed generated type cannot decode a job from an older console that carries a name the new rule refuses, and loses the whole job.

So the hardening needs a plan in which no released party ever refuses what another released party sends.

## Options

### (A) Agent-only producer rule

The agent normalizer applies the `KeyPattern` rules that fit `Identifier` (below) to every name it builds; a name that violates one becomes `*`, as any non-conforming name does today. The stricter rule is stated in the contract as a producer rule, in an unreferenced schema `IdentifierProduced` (the `Identifier` schema plus the new `not` rules), which the agent's contract tests check every `NormalizedName` against. No schema the console validates changes: compatible.

### (B) Option (A), then a console-side mask instead of a refusal

As (A). In addition, the console checks every incoming `Identifier` against `IdentifierProduced` after schema validation. A name that fails is not refused: the console stores `*` in its place (the contract's "masked name"), keeps the item, and records a security event for the agent (at most one per agent, endpoint and hour, with a daily notification outside the system-alert budget; decision 3). Every party keeps accepting what it accepts today, so this is compatible; it moves the check from refusal to masking, as ADR-0009's "sanitize, don't drop" does on the agent.

### (C) Option (A), then a refusal negotiated per agent

The agent lists a token (`identifier.produced_v1`) meaning "this build emits only `IdentifierProduced` names", and the console refuses, for that agent only, a name that fails it. This gives `HeartbeatRequest.accepts` a second meaning (a promise about what the agent sends, not what it accepts), which would refine ADR-0022 decision 3, and a refusal still drops the item (ADR-0009).

### (D) Narrow `Identifier` in `/api/agent/v2` only

Folded into the next incompatible protocol version, whenever one is needed for other reasons, with both sides moving together (ADR-0013). Not worth a v2 on its own.

### (E) Narrow `Identifier` in v1 now

Incompatible (ADR-0022 decision 6): items of older agents refused and dropped, jobs of older consoles lost.

## Decision

Accepted by the maintainer on 2026-10-22. Option (B), in this order: the agent first (A), then the console mask in a later release; (D) recorded as the target for a future `/api/agent/v2`.

### 1. Rules (`IdentifierProduced`)

The `Identifier` schema, plus these `not` rules, applied to the name and to each `.`-separated segment, with any Unicode decimal digit (`\p{Nd}`) counted as a digit and any Unicode space separator (`\p{Zs}`) as a space:

1. no segment made only of 9 or more digits, spaces, `_`, `+` and `-` (today's rule extended to `_`, `\p{Nd}` and `\p{Zs}`);
2. no run of 9 or more characters made of digits, separators (`.`, `_`, `+`, `-`, spaces, any `\p{Pd}` dash, U+FF0E), that starts and ends with a digit (a phone or card number split across segments: `06.12.34.56.78`, `06_12_34_56_78`);
3. no IPv4 address as whole segments (`host.10.0.0.1`, `10.0.0.1`), no MAC address in the dashed form (`00-1a-2b-3c-4d-5e`), and no dotted MAC form (`001a.2b3c.4d5e`: three segments of 4 hexadecimal characters, at least one of which holds a digit, so that a dotted name of hexadecimal-looking words such as `face.cafe.beef` is not refused);
4. no percent-encoded byte (`%` and two hexadecimal digits) and no `%uXXXX` escape;
5. the agent's gate, stated so that the contract says what a conforming agent sends: no run of more than 6 numeric characters, and no more than 8 numeric characters in the whole name, a numeric character being any `\p{N}` character. The agent's `is_numeric_like` counts every `\p{N}` character and also the CJK numerals that are letters in Unicode (`零〇一二三四五六七八九`, `壹贰叁肆伍陆柒捌玖`), so the contract rule is looser than the agent on CJK numerals: the safe direction, since a conforming agent's names always pass it.

The LDAP container DN form of `Identifier` gets the same rules on each RDN value.

### 2. Agent (`agent-engineer`), first release

1. `names.rs` applies the rules of item 1 before its final conformance check, so a name that violates one becomes `*` (its segment, where the existing segment rules apply, else the whole name).
2. `IdentifierProduced` is added to the contract (compatible, `security-reviewer` review), and the agent's contract tests and fuzz oracles check that every `NormalizedName` that is not a `KeyPattern` matches it. No request or response uses it, and the contract lint (`recommended-strict`, `npm run lint`) refuses unused components (`no-unused-components`), so it is held either in a separate schema file under `shared/protocol/` used by the tests, or referenced from `Identifier` through an `x-databastion-produced` extension; if neither suits the generators, the lint exception is recorded in `redocly.yaml` with this ADR as its reason. The implementation PR picks one; a separate file is preferred, since it changes nothing the generators read.
3. The agent's decoding of `SensitiveObject.object` is unchanged (today's `Identifier`), so jobs from any console still decode.
4. **Measurement first.** Before the rule is merged, the agent tests run it over the dev ground truth, the engine-matrix fixtures and the Discovery findings of the `load` and end-to-end runs, and the ADR records how many names it masks that today's agent keeps. Given the current gate (Context), the expected additions are only the dotted MAC form and short separated runs inside one segment (`1_2_3_4_5`, `v1-2-3-4-5`); IPv4 addresses, the dashed MAC form and dated names are already masked; open question 2.

### 3. Console (`console-engineer`), a later release

1. After schema validation, every `Identifier` of an incoming finding or event is checked against `IdentifierProduced`. A name that fails is stored as `*`, and the item is kept. The console never refuses an item for it.
2. Each masking is recorded as a `security_events` row (agent, endpoint, number of masked names; never the name), at most one per agent, endpoint and hour. It does not raise a system alert through the per-agent share of the system-alert budget (`console/src/db/schema.ts`, `max(2, ceil(limit / 4))` per channel and hour): an older agent masked at every batch would spend that share and hide the agent's other alerts. Instead, one daily notification lists the agents with masked names in the last 24 h, outside that budget.
3. Every agent is treated alike: the console makes no decision on the agent's version (ADR-0022 rejected alternative: negotiating on `agent_version`). From an agent of the release of section 2 or later, such a security event points at a bug, since a conforming agent never sends such a name.
4. The console's `audit.configure` jobs keep sending names as stored; a masked name is `*` there too.
5. **What the masking does not cover.**
   - Names outside findings and events: `TargetNameCaseException.database` in heartbeats (ADR-0055) and the other `Identifier` fields of heartbeats are checked by the schema only.
   - Rows stored before the console change keep their names.
   - A sensitive object derived from a masked finding is `*`: an older agent matches it as the literal `*` only, so its events on the real object below `min_rows` are no longer kept by the `sensitive_objects` filter (an upgraded agent sends no such name, so the case is limited to agents older than section 2).

### 4. Version 2

When `/api/agent/v2` is introduced for any reason, `Identifier` in v2 is `IdentifierProduced`, and the console masking of section 3 stays for v1 agents.

## Consequences

- On an upgraded agent, the dotted MAC form and short separated digit runs inside one segment no longer reach the console; IPv4 addresses, the dashed MAC form, percent escapes and longer digit runs were already masked. The rules are now stated in the contract on every engine, as they are for Redis / Valkey key patterns.
- Few legitimate names change on an upgraded agent: version-like names written with `_` or `-` (`v1_2_3_4_5`) and dotted names of three 4-character hexadecimal words with a digit become `*`. The console shows less detail for them (ADR-0009 consequence); the measurement of section 2 item 4 says how many.
- The main gain is on the console side (section 3): the contract states, and the console enforces by masking, a rule that today only the agent's code holds.
- With the console part, an older or non-conforming agent's value-bearing names are not stored, but they still reach the console process: masking at the console is defense in depth, not I2. The security events and the daily notification make such an agent visible.
- No released party refuses anything it accepts today: agents and consoles can be upgraded in either order.

### Residual risks

- Until agents are upgraded, the console (with section 3) masks what it stores but has received the name. Without section 3, the contract's weaker rule stays the console's only check.
- The gaps of section 3 item 5.
- The rules are pattern rules: they do not recognize a value without these shapes (ADR-0009 known gap).
- Short separated values outside these shapes pass by design (security review of the agent lot, L2): an IPv4 address without dots (`10_0_0_1`, `10-0-0-1`, `10~0~0~1`, or with an ideographic full stop `。`), an IPv4 address as LDAP components (`dc=192,dc=168,dc=1,dc=1`), and an unseparated 12-character hexadecimal MAC address with at most 8 digits (`a1b2c3d4e5f6`); each stays below the digit bounds of rule 5 ([docs/05](../05-security.md#masking-and-fingerprints)).

## Rejected alternatives

- **(C) A refusal negotiated per agent**: it gives `HeartbeatRequest.accepts` a meaning ADR-0022 does not define, and a refusal drops the item, which ADR-0009 rejects; masking keeps the item.
- **(E) Narrowing in v1**: incompatible; older agents' items refused and dropped, older consoles' jobs lost.
- **(D) alone, with nothing until v2**: no date, and the agent can apply the stricter rule today without any compatibility cost.
- **Narrowing the agent's decoder of `SensitiveObject.object`**: an older console's job with such a name would be lost as a whole; the names come from the console's own findings, and matching them is looser only.
- **The URL-scheme, IPv6 and `:`-separated MAC rules of `KeyPattern`**: `Identifier` forbids `:`, so a name can hold none of these forms.
- **An agent-integrity alert in the per-agent system-alert share**: an older agent would spend it at every batch.

## Open questions (for the maintainer)

1. (B) in two releases, agent first (proposed), or (A) only, leaving the console's check to v2? Proposed answer: (B); the console part costs one check per name and turns an older agent's value-bearing names into `*` before storage.
2. Rule 2 counts `_` as a separator, as `KeyPattern` does (`06_12_34_56_78` is a phone number). Keep it (proposed), or leave `_` out of rule 2 for `Identifier`, where `_` is the usual word separator of table and column names? Proposed answer: keep it, unless the measurement of section 2 item 4 shows names masked that today's agent keeps and that are not values.
3. Should the console part also mask names in `Location.schema` for OpenLDAP containers (RDN values), or only plain names? Proposed answer: every `Identifier`, the container form included.

**Answered by the maintainer on 2026-10-22**, each with its proposed answer:

1. (B) in two releases, agent first, with the acceptance.
2. Rule 2 keeps `_` as a separator, unless the measurement of section 2 item 4 shows names masked that today's agent keeps and that are not values.
3. The console masks every `Identifier`, the OpenLDAP container form (RDN values in `Location.schema`) included.

## Implementation note (2026-10-23): agent lot

Section 2, implemented on branch `feat/p9-adr0057-agent` (`agent-engineer`), with its `security-reviewer` review of 2026-10-23 (no Critical or High; M1 and L1 to L4 fixed in the same PR). The console masking (section 3) is for a later release.

- **Measurement first (section 2 item 4).** The first commit of this lot's PR added the rules and the measurement before the normalizer applied them; the measurement is now `agent/crates/classifiers/tests/identifier_produced_measure.rs` (`measurement_over_the_dev_corpus`). It reads the rules from the contract file and uses only the normalizers' entry points, so it runs against the normalizer of `dev` at `03d3956` too (the steps are in the file's header: `names.rs` checked out from `03d3956`, then from this lot, each run writing a SHA-256 prefix of every emitted name, never the name). It covers the distinct raw names of: the dev ground truth (locations and target databases, Redis / Valkey key patterns left out), the dev seeds (`dev/seed/out`: SQL tables and columns, MongoDB collections and field paths with their real keys, LDIF entry DNs, attributes and object classes), the dev, end-to-end and load init scripts, the tables the connectors' integration tests create (which the engine matrix runs), the CAS service registry and audit fixtures, and the `load` seed's schema, table and column names (999 tables, `e2e/load/seed.py`). The end-to-end runs discover the dev seeds; no Discovery finding of a `load` or end-to-end run is committed, so the `load` seed's names stand for them. Result (counts only, I2):

  | Source | Names | Kept (not `*`) | Refused on input | Kept and refused on output |
  |--------|------:|---------------:|-----------------:|---------------------------:|
  | Ground truth | 160 | 148 | 1 | 0 |
  | Dev seeds | 794 | 786 | 241 | 0 |
  | Init scripts | 1 | 1 | 0 | 0 |
  | Connector integration tests | 70 | 69 | 0 | 0 |
  | CAS fixtures | 123 | 121 | 0 | 0 |
  | `load` seed | 3 015 | 3 015 | 0 | 0 |
  | **Total** | **4 163** | **4 140** | **242** | **0** |

  On input, 242 raw names violate a rule (rule 1: 240, rule 2: 242, rule 5: 242; none of rules 3 and 4): value-bearing names of the seeds, mostly MongoDB keys made of phone and member numbers, all of which today's agent already masks. Compared name by name with `dev` at `03d3956`, **no emitted name changes** (0 of 4 163). So open question 2's condition is not met: rule 2 keeps `_` as a separator. The test asserts that no kept name violates a rule.
- **Normalizer (item 1).** `classifiers::names` applies the rules at two points. First on the folded input, before array indices become `[]` and digit-only keys become `*` (review M1): the rule matches join the value spans, so every segment a match touches becomes `*` and consecutive ones collapse (`dev.ab3c.1234.4d5e` -> `dev.*`, `a.1_2.3_4.5` -> `a.*`, `host.10.0.0.1` -> `host.*`, where `host[][][][]` was sent before; with the real keys, `dev` / `ab3c` / `1234` / `4d5e` -> `dev.*`). Then on the output, after the existing gate, as a backstop: on a plain name every segment a match touches becomes `*`, repeated until no rule matches; on an LDAP container DN, an RDN value that violates a rule becomes `*` (`ou=10.0.0.1,dc=x` -> `ou=*,dc=x`); a name that still violates one (rule 5 bounds the whole name) is `*`. A name turned into `*` is never marked altered (ADR-0056). One agent-only rule beyond the contract: a code point unassigned in the agent's Unicode tables (`\p{Cn}`) makes its segment `*`, as `KeyPattern`'s gate refuses it, since the console's engine may know it as a digit or a space (Unicode version drift).
- **Contract (item 2).** `IdentifierProduced` is held in a separate file, `shared/protocol/identifier-produced.schema.json` (the preferred option): `allOf` one `$ref` to `Identifier` and a `not.anyOf` of the rules, each titled with its id (`1`, `2`, `3-ipv4`, `3-mac-dashed`, `3-mac-dotted`, `4`, `5-run`, `5-total`). Nothing in `openapi.yaml` refers to it, no generator reads it, and the Redocly lint is unchanged. Its patterns are the agent's (`names::IDENTIFIER_PRODUCED_RULES`), checked verbatim. The rules apply at `[.,=]` boundaries, so the container DN form gets them on each RDN value. Rule 3's dashed MAC form is `KeyPattern`'s (six 2-character hexadecimal groups, no digit required); its dotted form requires a digit in one of the three segments. The optional widening of rule 3's IPv4 form to `_` and `-` separators (review L2) was not made; those forms are residual risks above.
- **Oracles.** The agent's check agrees with the contract compiled with `regress` (ECMAScript `u` mode, as Ajv), rule by rule, in a property test, and on every code point in a release-mode sweep (`no_drift_on_any_code_point`, run by the CI job `agent-keys-sweep` since review L1); every name the four normalizers emit matches it in property tests (a targeted alphabet, any text, any bytes), in `names_props.rs`, in the new fuzz target `classifiers_names` (also in the nightly campaign) and in the SQL Server Audit and Extended Events fuzz oracles; and a property test checks that a dotted MAC, an IPv4 address or a split digit run anywhere in a path leaves no digit and no 4-character hexadecimal group in the output, the surrounding words kept (review M1). `npm test` in `shared/protocol` runs the schema's own self-test (`scripts/identifier-produced.test.mjs`).
- **Item 3.** The agent's decoding of `SensitiveObject.object` is unchanged.
