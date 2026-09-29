# ADR-0020: MySQL / MariaDB connector as merged: row estimates after the engine check, and status of the ADR-0018 follow-ups

- **Status**: Accepted
- **Date**: 2026-09-28
- **Refines**: [ADR-0018](0018-mysql-mariadb-grants-and-connector.md) (which stays Accepted), decisions 1, 2 and 3 and the "Dev environment" consequence
- **Context references**: P2-C merged in #52 (`agent/crates/connector-mysql`), end-of-phase-2 security review at 94607ab (finding M2: doc / code contradictions)

## Context
[ADR-0018](0018-mysql-mariadb-grants-and-connector.md) was accepted while the connector was in review. It records three items as not done yet: the `extended_grants` opt-in, fuzz or property tests of the protocol parsers, and moving the dev accounts to the minimal variant. All three landed with the connector in #52. The review also changed how row estimates are read, which decision 2 describes in words that no longer match the code. The end-of-phase-2 security review (M2) lists these contradictions. An accepted ADR is not edited, so this ADR records the merged state.

## Decision
1. **Row estimates (refines ADR-0018 decision 2).** Introspection still reads no statistics column. For each sampled table, inside its read-only sampling transaction, the connector first reads the table's type and engine alone (`information_schema.TABLES`, no statistics column). It asks for `TABLE_ROWS` only when that read shows a base table (`BASE TABLE` or MariaDB `SYSTEM VERSIONED`) on an allow-listed local engine. Otherwise the table is not sampled. Reason: computing `TABLE_ROWS` opens the table's handler, and MariaDB does so before it applies an `ENGINE` filter in the same query, so a query that filters on the engine does not keep a `FEDERATED` handler from connecting out (I5).
2. **Extended variant (refines ADR-0018 decision 1).** The `extended_grants` opt-in exists. It is a per-target boolean in the `mysql` block of `agent.yaml`, default `false` (`agent/crates/core/src/config.rs`, `agent/agent.example.yaml`). With `extended_grants: true`, `check()` reports a global `SELECT` as an expected warning ("extended variant") instead of over-privilege. Nothing else changes: other global privileges, privileges beyond `SELECT`, `WITH GRANT OPTION`, `SELECT` on `mysql` / `sys` and granted roles are still over-privilege, and the system schemas are still never sampled (`agent/crates/connector-mysql/src/check.rs`).
3. **Parser tests (refines ADR-0018 decision 3).** Property tests cover the protocol layer (`agent/crates/connector-mysql/src/proptests.rs`). Every packet parser and the two server-driven exchanges (authentication, result sets) run on arbitrary input, and the tests check three things: no panic, bounded reads, and the password is never written to a channel that may not carry it. There is no coverage-guided fuzzing.

## Consequences
- **Dev environment (replaces the ADR-0018 "Dev environment" consequence).** The dev MySQL and MariaDB agent accounts use the minimal variant (`dev/mysql/initdb/20-databastion.sh`, `dev/mariadb/initdb/20-databastion.sh`): `SELECT` on the seeded application database only (`hr` on MySQL, `support` on MariaDB), `REQUIRE SSL`, `MAX_USER_CONNECTIONS 4`, and on MariaDB `MAX_STATEMENT_TIME 30`. There is no `performance_schema` grant until Audit (P4-B). The host is `'%'` because the agent reaches the containers through a published port; this is a dev-only deviation from the ADR-0018 restricted-host recommendation.
- Sampling a table costs one extra statement (the engine read) before the row estimate.
- The ADR-0018 residual risk "engine change race" still applies: the window is between the in-transaction engine read and the sampling `SELECT`.
- ADR-0018's open questions stay open.

## Rejected alternatives
- **Edit ADR-0018 in place**: the ADR convention does not allow editing an accepted ADR.
- **Read `TABLE_ROWS` in the same statement as the engine, filtered on the engine**: MariaDB computes `TABLE_ROWS`, and so opens the handler, before the filter applies.
