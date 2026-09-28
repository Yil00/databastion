# ADR-0007: Masking of Audit access events

- **Status**: Accepted
- **Date**: 2026-09-28

## Context
[ADR-0003](0003-data-minimization-at-source.md) states that no raw sensitive value leaves the agent, and details what a Discovery finding may carry. Audit access events ([09-agent-protocol.md](../09-agent-protocol.md#access-event-agent--console)) come from other sources: database audit logs (pgaudit, `server_audit`, MongoDB `auditLog`), `pg_stat_statements`, the OpenLDAP `cn=accesslog`. These sources contain query text with literals (`WHERE email = 'jane.doe@example.com'`), MongoDB filter documents, LDAP search filters and entry DNs (`uid=jdoe,ou=people,dc=example,dc=com`). Forwarding them as-is would move sensitive values to the console, which ADR-0003 forbids but does not spell out for events.

## Decision
Audit access events follow the same rule as findings: they are built from masked data only, in the agent, before the uplink.

- **Query text** is normalized before leaving the agent: every literal (strings, numbers, dates, lists) is replaced by a placeholder (`$1`, `?`), in the manner of `pg_stat_statements`. If a statement cannot be parsed reliably, the text is dropped and only its fingerprint and the extracted action / objects are kept.
- **Filter values** (SQL predicates, MongoDB filter documents, LDAP search filters) never leave in clear: they are removed, or replaced by a masked sample or an HMAC-SHA256 fingerprint with the agent-local key, as for findings.
- **Metadata that may leave in clear**, after normalization:
  - database user / LDAP bind identity, client IP address, client application name;
  - container names: database, schema, table / collection, column / field, LDAP attribute names;
  - action, row or entry counts, durations, timestamps, signals, source, aggregation count.
- **LDAP entry DNs** are reduced to their parent container (`uid=jdoe,ou=people,dc=example,dc=com` → `ou=people,dc=example,dc=com`). A bind DN used as the principal is kept, since it identifies who reads, not what is read.
- **Names are normalized** before the uplink: bounded length, control characters removed, identifiers that match a classifier (e.g. a column or collection named after a person or containing an email) are masked like a value.
- **Enforcement in the agent**: the uplink and the connector sinks only accept `MaskedEvent`, which can only be constructed in `classifiers::masking` (private fields, no constructor from a string, no `Deserialize`). Connectors hand raw event data to `classifiers::masking`; they never build the protocol type themselves.

## Consequences
- The console cannot show the exact query or the exact entries read, only their shape, their targets and their volume. An investigator goes to the database's own audit log, with their own permissions.
- Signals must be computed in the agent from the raw data (e.g. `signature.pg_dump`, `shape.full_table_copy`), because the console only sees the normalized form.
- The query normalizer is a security component: it needs property tests (no literal from the input survives in the output) and a `security-reviewer` review, like the masking of findings.
- The invariant I2 test (P2-E) is extended to access events once Audit lands (phase 4).

## Rejected alternatives
- **Sending raw query text, encrypted with a console key**: same objection as in ADR-0003, the console becomes the target.
- **Dropping query text entirely**: loses the shape needed to explain an incident (which columns, which kind of statement) for no gain once literals are removed.
- **Masking on the console side**: the raw values would already have left the agent.
