# ADR-0015: PostgreSQL connector decisions (TLS, authentication, RLS policies, bounds)

- **Status**: Accepted
- **Date**: 2026-09-28
- **Refines**: [ADR-0012](0012-postgresql-agent-grants.md) (which stays Accepted), obligations 2, 4 and 6
- **Context references**: P2-B, #47 (`agent/crates/connector-postgres`, `agent/crates/core/src/config.rs`, `agent/crates/core/src/connector.rs`)

## Context
[ADR-0012](0012-postgresql-agent-grants.md) fixed the grants of the agent's PostgreSQL role and the obligations of the connector. Implementing the connector (P2-B) required decisions that ADR-0012 does not cover, or covers only partly:

- how the connector reaches the server: TLS or not, and which authentication methods it accepts, knowing that tokio-postgres has no `require_auth` and that the target password must never leave the agent host (I3);
- ADR-0012 obligation 2 decides whether a row-level security (RLS) table can be sampled from its `pg_depend` rows. The security review of #47 (H1) showed that this is not enough: `pg_depend` records no dependency on pinned built-in objects, so a policy such as `USING (pg_catalog.query_to_xml('select evil()', true, false, '') IS NOT NULL)` has no dependency row and would run arbitrary SQL in the agent's session;
- the audit level `check()` may report before the Audit connector (P4-A) exists;
- how partitioned tables are reported, and how much memory one relation's sample may take;
- how `check()` knows which target it checks when one connector serves several targets.

## Decision
1. **TLS policy** (`targets[].postgres.tls` in `agent.yaml`, rustls only):
   - `verify_full` (default): TLS 1.2 or 1.3, server certificate verified against a pinned CA file (`postgres.ca_file`, then the only trusted root) or the system store, host name checked. There is no "encrypt without verifying" mode.
   - `disable`: no TLS, accepted by the configuration only for a Unix socket or a loopback IP literal (`127.0.0.1`, `::1`; not the name `localhost`). A Unix socket requires `disable`.
   - `disable_insecure`: no TLS on a network connection, an explicit opt-in (for example an isolated container network, as in the E2E harness). The connector logs a warning at every connection stating that samples and statements travel in clear and that **read-only is not guaranteed**: an attacker on the path can relay the SCRAM exchange, which has no channel binding, and then send its own statements.
2. **Authentication without TLS.** The connector opens the socket itself and reads the server's authentication requests before the driver answers them. On a connection without TLS it refuses cleartext and MD5 password requests, and SCRAM with fewer than 4096 iterations (an attacker on the path could otherwise ask for 1 iteration to make the relayed proof cheap to attack offline). Only SCRAM, or password-less peer / trust authentication on a local socket, is accepted. A refusal is reported as `authentication_failed`.
3. **RLS policy expressions are checked by an allow-list** (extends ADR-0012 obligation 2: its `pg_depend` check stays, and is no longer sufficient on its own). For each RLS table not already skipped by `pg_depend`, the stored `SELECT` policy expressions (`pg_policy.polqual` and `polwithcheck` for `polcmd` `r` or `*`, as `pg_node_tree` text) are read and walked **locally** in the agent:
   - a node type outside a fixed allow-list, a malformed tree, or a tree larger than 1 MiB makes the table unsupported (fail closed);
   - a subquery on any relation other than the policy's own table (catalogs included) makes the table unsupported;
   - every function, operator and I/O coercion the expression uses is collected (oids only) and checked on the server: allowed are immutable `pg_catalog` functions outside a denylist (the functions that run SQL text or resolve names at run time, such as `query_to_xml`, `cursor_to_xml`, `ts_stat`, `to_reg*`, `reg*in`, and those with side effects or file access), plus `current_setting`, `now`, `current_database` and `current_schema`; operators and types are allowed when their function is.

   A table that fails any check is not sampled and is reported by `check()` as not covered. The expression text is never logged, stored or sent (it may hold literals).
4. **Full audit level withheld until P4-A.** `check()` reports only what it can prove without `pg_read_all_settings`: **Limited** when `pg_stat_statements` is installed and loaded in a monitored database and the role sees other users' statements (member of `pg_read_all_stats`, or superuser); **None** otherwise. **Full** is never reported yet, because it needs a readable pgaudit log file and the log path is not configured before P4-A; a loaded pgaudit is only mentioned in the local detail.
5. **Partitioned tables are reported under their root.** A partitioned root is never read (ADR-0012 obligation 1); its readable leaves are sampled one by one (`FROM ONLY`), classified together and reported under the root's name, within the job's `sample_rows` budget. At most **64 leaves** per root are sampled (the largest by `reltuples`); the others are counted as not covered.
6. **Per-relation byte budget.** At most 32 MiB of sampled values are read per relation, checked per row before decoding. When the budget is reached, the statement is **cancelled on the server** (cancel request) instead of drained, the session is marked unusable, and the next object uses a new session. Values are truncated to 4096 bytes before classification.
7. **`Connector::check(target)`.** The core trait takes the target: `async fn check(&self, target: &TargetConfig) -> TargetHealth`. One connector instance serves every declared target of its engine; `check()` had no way to know which one to check.

## Consequences
- The default configuration requires a verifiable certificate. Deployments without TLS on a network have to write `disable_insecure`, and they get a warning at every connection.
- RLS tables whose policies use user functions, views, other tables or denylisted built-ins are not sampled. This is visible as "not covered" in the agent's `check()` log (see the residual risks for its visibility in the console).
- The console shows at most Limited for PostgreSQL targets until P4-A, even when pgaudit is set up.
- A root with more than 64 leaves is partly sampled; the skipped leaves are counted as not covered.
- Adding the target parameter to `check()` changed the core trait; the stub connectors (MySQL, MongoDB, OpenLDAP) were updated with it.

### Residual risks
- **Single-row peak.** The byte budget is checked per row, after the driver has received the whole row. One row is the residual peak: a PostgreSQL field can hold up to about 1 GiB, so one hostile or unusual row can take that much memory before the budget check stops the statement.
- **Driver buffers are not zeroized.** The target password is read into zeroized memory, but tokio-postgres keeps a copy in its `Config` (dropped right after the connection, not zeroized), and the row buffers of the driver are not zeroized either. Sampled values are zeroized from the point they are wrapped in `RawValue`.
- **No SCRAM channel binding.** SCRAM runs without `-PLUS`; server authentication relies on the certificate check (`verify_full`). Without TLS, nothing binds the SCRAM exchange to the connection (hence the `disable_insecure` warning).
- **No TCP keepalive** is set on target connections. A connection silently dropped by the network is detected only by the statement or setup timeouts.
- **Policy expressions are read by the agent.** `polqual` can contain literals written by the table owner; it is read into agent memory for the walk, never logged or sent.
- **`disable_insecure` semantics.** It only removes transport protection; the authentication refusals of decision 2 still apply. An active attacker on that network can still read the samples and the statements, and can act as the agent's role on the server after relaying a SCRAM exchange.
- **Over-privilege and coverage are only in the agent logs.** `check()` computes them (ADR-0012 obligation 6) but `TargetStatus` has no field to carry them to the console. Surfacing them needs a compatible protocol change (ROADMAP follow-up).

## Rejected alternatives
- **`require`-style TLS without certificate verification**: protects against passive listeners only, and gives a false impression of security; `disable_insecure` makes the absence of protection explicit instead.
- **Accept `disable` for any host**: a single word would silently put the target password exchange and the samples in clear on a network.
- **`pg_depend` alone for RLS policies** (ADR-0012 obligation 2 as written): misses pinned built-ins such as `query_to_xml`, which run arbitrary SQL.
- **Denylist of dangerous node types or functions in policies**: any node type or built-in not on the list (or added by a later PostgreSQL release) would pass. An allow-list fails closed.
- **Report Full when pgaudit is loaded**: the agent cannot read the log yet, so the level would overstate what the console will see (docs/08: a Limited audit must never pass for a full one).
- **Drain a sample past its byte budget**: keeps reading data the agent will not use, from a relation that may be huge or hostile.
- **One connector instance per target**: more state for the core to manage, while the connection settings are already per target in `TargetConfig`.
