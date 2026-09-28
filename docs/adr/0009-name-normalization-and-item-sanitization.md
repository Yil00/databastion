# ADR-0009: Name normalization and per-item sanitization before the uplink

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
[ADR-0003](0003-data-minimization-at-source.md) and [ADR-0007](0007-mask-access-events.md) keep sampled values and query literals in the agent. Object and field names are a separate channel: they are engine metadata, but they can embed values (MongoDB dynamic keys such as `contacts.jane@example.com.phone`, LDAP entry DNs such as `uid=jdoe,ou=people,…`, tables named after a customer or a date). A JSON Schema pattern can reject obvious forms (e-mail addresses, `key=value`, URLs, long digit runs) but cannot prove that a name is free of values.

Names, account names and application names are also attacker-influenced: anyone who can create a table or a key can plant a string that makes the console reject a batch. With whole-batch rejection, one hostile name would silently suppress every finding or event in the same batch.

## Decision
- **Normalized names** (`x-databastion-normalized-name` in the contract): before the uplink the agent turns array indices into `[]`, replaces dynamic keys and any name segment matched by a classifier with `*`, reduces LDAP entry DNs to their parent container, lowercases attribute types, and replaces any name that still does not match `Identifier` with `*`.
- **Sanitize, don't drop**: before spooling, the agent validates **each item** against the contract and sanitizes it: control and format characters stripped, strings truncated on a character boundary, non-conforming name segment → `*`, non-conforming account name → `db_user_fingerprint`, non-conforming optional field omitted.
- **Per-item rejection**: when the console answers `400` or `404` with pointers that all designate items, the agent drops those items and resends the rest under a new `batch_id`.
- **Batch byte cap**: the agent keeps every serialized findings or events batch under 1 MiB (`x-databastion-max-bytes`); the console limit is 4 MiB. On `413` the agent splits the batch in halves.
- **Console alert on rejected batches**: since a conforming agent never sends a non-conforming item, a `400` on a findings or events batch (like a `batch_conflict`) is recorded in the console audit log and raises an agent-integrity alert.

## Consequences
- The name normalizer and item sanitizer are security components in the agent (P1-B, P2-A): property tests and a `security-reviewer` review, like masking.
- Some legitimate names become `*` (e.g. a column that matches a classifier). The console shows less detail for them; the administrator inspects the database directly.
- The dev ground truth must include value-bearing names (P0-C), and the invariant I2 test must cover names (P2-E).
- The console needs cross-field checks and alerting on rejected batches (P1-A, P2-D).

## Rejected alternatives
- **Relying on the schema pattern alone**: it cannot recognize a person name or an opaque identifier used as a key.
- **Dropping any item with a suspicious name**: an attacker could hide sensitive locations by naming them badly.
- **Hashing every name**: makes findings unreadable for the administrator, and names are needed to act on a finding.
