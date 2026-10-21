# ADR-0057: `Identifier` hardening, agent first: the `KeyPattern` digit-run, address and escape rules for every normalized name

- **Status**: Proposed (2026-10-21), for the maintainer's decision; needs a `security-reviewer` review before acceptance
- **Date**: 2026-10-21
- **Refines** (on acceptance): [ADR-0009](0009-name-normalization-and-item-sanitization.md) (which stays Accepted), its normalized names, with stricter producer rules; uses [ADR-0013](0013-frozen-error-codes.md) and [ADR-0022](0022-protocol-capability-negotiation.md) decision 6 (narrowing a pattern is incompatible) without changing them
- **Context references**: ROADMAP [phase 9 follow-ups](../ROADMAP.md#phase-9-follow-ups), "Contract: `Identifier` hardening"; [ADR-0052](0052-redis-valkey-connector.md) decision 7 (`KeyPattern`); `shared/protocol/openapi.yaml` (`Identifier`, `KeyPattern`, `ObjectName`, `SensitiveObject`); `agent/crates/classifiers/src/names.rs` (`NormalizedName`, `MAX_INDEX_DIGITS`, `MAX_TOTAL_DIGITS`, `has_percent_escape`), `agent/crates/core/src/sanitize.rs` (read at `c2ae105`, `dev`)

## Context

`KeyPattern` (Redis / Valkey key patterns, phase 9) was written after `Identifier` and has stricter `not` rules: no segment of 9 or more digits, spaces, `_`, `+` or `-`; no digit-to-digit run of 9 or more digits and separators across segments (`06.12.34.56.78`); no IPv4 address as whole segments; no percent-encoded byte; no IPv6 or MAC address; no first segment naming a URL scheme. Digits and spaces are any Unicode decimal digit and space separator. `Identifier`, the schema of every other name (database, schema, table, collection, column, field path, LDAP container), has only one such rule: no name or `.`-separated segment made only of 9 or more digits and separators. Its pattern already forbids `:`, `/` and `@`, so the IPv6, `:`-separated MAC and URL-scheme rules cannot apply to it; the others can.

The contract schema is the console's check, not the agent's only defense: the agent normalizer (`names.rs`) is already stricter on some points. It masks a segment with a percent-encoded byte or a `%uXXXX` escape, treats a segment with more than 6 digits (consecutive or in total) as a value (`cust_12345678`, `events_2026_10_21`), and replaces a name with more than 8 numeric characters in total, in any script, by `*`. So most names the `KeyPattern` digit rules refuse are already masked. What the agent does not mask by these rules: runs of short digit groups below both bounds (`1.2.3.4.5`, 5 digits in 9 characters), the dotted IPv4 form (`10.0.0.1`, 5 digits) and the dashed or dotted MAC forms (12 hexadecimal characters, of which possibly 8 or fewer digits); whether another rule (the classifiers, the first-name or hexadecimal-key rules) masks them is not established here.

Narrowing `Identifier` in the contract is incompatible (ADR-0022 decision 6), in both directions:

- **Agent -> console.** A console with a narrowed `Identifier` refuses an item from an older agent whose name passes today's rule but not the new one, with a per-item `400`. Under ADR-0009 the agent drops refused items and resends the rest: a finding or event is lost, which ADR-0009 rejected ("dropping any item with a suspicious name: an attacker could hide sensitive locations by naming them badly").
- **Console -> agent.** `SensitiveObject.object` in `audit.configure` jobs is an `Identifier` (or a `KeyPattern` since #280). An agent with a narrowed generated type cannot decode a job from an older console that carries a name the new rule refuses, and loses the whole job.

So the hardening needs a plan in which no released party ever refuses what another released party sends.

## Options

### (A) Agent-only producer rule

The agent normalizer applies the `KeyPattern` rules that fit `Identifier` (below) to every name it builds; a name that violates one becomes `*`, as any non-conforming name does today. The stricter rule is stated in the contract as a producer rule, in an unreferenced schema `IdentifierProduced` (the `Identifier` schema plus the new `not` rules), which the agent's contract tests check every `NormalizedName` against. No schema the console validates changes: compatible.

### (B) Option (A), then a console-side mask instead of a refusal

As (A). In addition, the console checks every incoming `Identifier` against `IdentifierProduced` after schema validation. A name that fails is not refused: the console stores `*` in its place (the contract's "masked name"), keeps the item, and records an agent-integrity event for the agent (per agent and hour, inside the existing agent-integrity budget). Every party keeps accepting what it accepts today, so this is compatible; it moves the check from refusal to masking, as ADR-0009's "sanitize, don't drop" does on the agent.

### (C) Option (A), then a refusal negotiated per agent

The agent lists a token (`identifier.produced_v1`) meaning "this build emits only `IdentifierProduced` names", and the console refuses, for that agent only, a name that fails it. This gives `HeartbeatRequest.accepts` a second meaning (a promise about what the agent sends, not what it accepts), which would refine ADR-0022 decision 3, and a refusal still drops the item (ADR-0009).

### (D) Narrow `Identifier` in `/api/agent/v2` only

Folded into the next incompatible protocol version, whenever one is needed for other reasons, with both sides moving together (ADR-0013). Not worth a v2 on its own.

### (E) Narrow `Identifier` in v1 now

Incompatible (ADR-0022 decision 6): items of older agents refused and dropped, jobs of older consoles lost.

## Decision (proposed)

Option (B), in this order: the agent first (A), then the console mask in a later release; (D) recorded as the target for a future `/api/agent/v2`.

### 1. Rules (`IdentifierProduced`)

The `Identifier` schema, plus these `not` rules, applied to the name and to each `.`-separated segment, with any Unicode decimal digit (`\p{Nd}`) counted as a digit and any Unicode space separator (`\p{Zs}`) as a space:

1. no segment made only of 9 or more digits, spaces, `_`, `+` and `-` (today's rule extended to `_`, `\p{Nd}` and `\p{Zs}`);
2. no run of 9 or more characters made of digits, separators (`.`, `_`, `+`, `-`, spaces, any `\p{Pd}` dash, U+FF0E), that starts and ends with a digit (a phone or card number split across segments: `06.12.34.56.78`, `06_12_34_56_78`);
3. no IPv4 address as whole segments (`host.10.0.0.1`, `10.0.0.1`), no MAC address in the dashed or dotted form (`00-1a-2b-3c-4d-5e`, `001a.2b3c.4d5e`);
4. no percent-encoded byte (`%` and two hexadecimal digits).

The LDAP container DN form of `Identifier` gets the same rules on each RDN value.

### 2. Agent (`agent-engineer`), first release

1. `names.rs` applies the rules of item 1 before its final conformance check, so a name that violates one becomes `*` (its segment, where the existing segment rules apply, else the whole name).
2. `IdentifierProduced` is added to `shared/protocol/openapi.yaml` as an unreferenced schema (no request or response uses it; compatible, `security-reviewer` review), and the agent's contract tests and fuzz oracles check that every `NormalizedName` that is not a `KeyPattern` matches it.
3. The agent's decoding of `SensitiveObject.object` is unchanged (today's `Identifier`), so jobs from any console still decode.
4. **Measurement first.** Before the rule is merged, the agent tests run it over the dev ground truth, the engine-matrix fixtures and the Discovery findings of the `load` and end-to-end runs, and the ADR records how many names it masks that today's agent keeps. The expected additions are version-like names with several short numeric segments (`1.2.3.4.5`), IPv4 addresses and MAC addresses; dated names (`events_2026_10_21`) are already masked by the 6-digit segment rule; open question 2.

### 3. Console (`console-engineer`), a later release

1. After schema validation, every `Identifier` of an incoming finding or event is checked against `IdentifierProduced`. A name that fails is stored as `*`, and the item is kept. The console never refuses an item for it.
2. An agent-integrity event, at most one per agent and hour, inside the per-agent budget shared with the other agent-integrity events, names the agent, the endpoint and the number of masked names, never the name.
3. Every agent is treated alike: the console makes no decision on the agent's version (ADR-0022 rejected alternative: negotiating on `agent_version`). From an agent of the release of section 2 or later, an integrity event points at a bug, since a conforming agent never sends such a name.
4. The console's `audit.configure` jobs keep sending names as stored; a masked name is `*` there too.

### 4. Version 2

When `/api/agent/v2` is introduced for any reason, `Identifier` in v2 is `IdentifierProduced`, and the console masking of section 3 stays for v1 agents.

## Consequences

- Names that look like phone or card numbers split by `_` or spread across segments, IPv4 and MAC addresses, and percent-encoded bytes no longer reach the console from an upgraded agent, on every engine, as they already do not on Redis / Valkey.
- Few legitimate names change on an upgraded agent, since its digit bounds already mask most of what the new rules refuse: version-like names with several short numeric segments, and names holding an IPv4 or MAC address, become `*`. The console shows less detail for them (ADR-0009 consequence); the measurement of section 2 item 4 says how many.
- The main gain is on the console side (section 3): the contract states, and the console enforces by masking, a rule that today only the agent's code holds.
- With the console part, an older or non-conforming agent's value-bearing names are not stored, but they still reach the console process: masking at the console is defense in depth, not I2. The agent-integrity event makes such an agent visible.
- No released party refuses anything it accepts today: agents and consoles can be upgraded in either order.

### Residual risks

- Until agents are upgraded, the console (with section 3) masks what it stores but has received the name. Without section 3, the contract's weaker rule stays the console's only check.
- The rules are pattern rules: they do not recognize a value without these shapes (ADR-0009 known gap).

## Rejected alternatives

- **(C) A refusal negotiated per agent**: it gives `HeartbeatRequest.accepts` a meaning ADR-0022 does not define, and a refusal drops the item, which ADR-0009 rejects; masking keeps the item.
- **(E) Narrowing in v1**: incompatible; older agents' items refused and dropped, older consoles' jobs lost.
- **(D) alone, with nothing until v2**: no date, and the agent can apply the stricter rule today without any compatibility cost.
- **Narrowing the agent's decoder of `SensitiveObject.object`**: an older console's job with such a name would be lost as a whole; the names come from the console's own findings, and matching them is looser only.
- **The URL-scheme, IPv6 and `:`-separated MAC rules of `KeyPattern`**: `Identifier` already forbids `:`, `/` and `@`, so they cannot match.

## Open questions (for the maintainer)

1. (B) in two releases, agent first (proposed), or (A) only, leaving the console's check to v2? Proposed answer: (B); the console part costs one check per name and turns an older agent's value-bearing names into `*` before storage.
2. Rule 2 counts `_` as a separator, as `KeyPattern` does (`06_12_34_56_78` is a phone number). Keep it (proposed), or leave `_` out of rule 2 for `Identifier`, where `_` is the usual word separator of table and column names? Proposed answer: keep it, unless the measurement of section 2 item 4 shows names masked that today's agent keeps and that are not values.
3. Should the console part also mask names in `Location.schema` for OpenLDAP containers (RDN values), or only plain names? Proposed answer: every `Identifier`, the container form included.
