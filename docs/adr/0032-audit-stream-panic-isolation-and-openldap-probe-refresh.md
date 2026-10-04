# ADR-0032: Audit stream panic isolation, poison-record skip and OpenLDAP probe refresh

- **Status**: Accepted
- **Date**: 2026-09-30
- **Refines**: [ADR-0031](0031-openldap-principals-dedup-and-stream-alerts.md) decision 6 (skip a record that always panics), [ADR-0029](0029-openldap-connector.md) decisions 1 (panic guard bullet), 4 (recommended `olcAccess`), 7 (persisted cursor) and 10 (failed-operation proof), [ADR-0027](0027-mongodb-audit.md) decisions 3 and 4 (profiler entries whose command is truncated or not an object). All stay Accepted.
- **Refined by**: [ADR-0043](0043-audit-logs-opened-without-following-a-final-symlink.md) (decision 8: audit log files opened with `O_NOFOLLOW`, a final symlink refused, per-source open check)
- **Context references**: PR #83 (`fix/p7-agent-followups`, commit f546844) and its re-reviews; PR #82 (`dev/openldap/config.ldif`); `agent/crates/core/src/panics.rs` (`isolate`, `resume_panic`), `agent/crates/core/src/runtime.rs` (`PanicTracker`, `audit_restart_delay`), `agent/crates/core/src/audit.rs` (`CursorStore::isolate`, `CursorStore::skip_records`, `PositionRegistry`), `agent/crates/core/src/audit/tail.rs` (`writable_by_agent`), `agent/crates/connector-openldap/src/audit/mod.rs` (`Position`), `agent/crates/connector-openldap/src/check.rs` (`prove`, `search_record`, `probe_record`), `agent/crates/connector-mongodb/src/audit/profiler.rs`; `agent/README.md` ("Audit streams that panic", "Audit log files")

## Context
[ADR-0029](0029-openldap-connector.md) decision 1 put every connector call behind a panic guard in the core; an Audit stream that panicked 3 times in a row was stopped (`audit.stream_stopped`, level None). [ADR-0031](0031-openldap-principals-dedup-and-stream-alerts.md) decision 6 decided that a record that always panics must be skipped after repeated panics at the same persisted position, and left the threshold and the counter to the implementation. PR #83 implemented it, together with other phase-7 agent follow-ups whose design choices were not recorded in an ADR:

- Skipping "the record at the saved position" is only safe when the stream can tell which record that is. A file tailer saves a byte offset after a batch of records; the OpenLDAP stream saves a CSN after a search round of up to 1000 entries. A skip bound to such a position could drop records that never panicked.
- The phase-6 security review (round 3) found two weaknesses in the OpenLDAP failed-operation proof of ADR-0029 decision 10: proofs were kept 24 h (a later `olcAccessLogSuccess: TRUE` went unseen as long), and a record under a nested naming context proved its parent context too.
- The end-of-phase-6 review (L3) found that an OpenLDAP record committed out of CSN order just before a restart was lost: the restarted stream kept only the cursor, not which overlap entries it had read.
- The end-of-phase-5 review (I1) found that the MongoDB profiler projection failed, or produced a misleading shape, on a `command` that the server truncated (`{$truncated: …}`) or that is not a document.
- The end-of-phase-4 review (L4) asked that an audit log file the agent's own account could have written is not trusted as evidence.
- The recommended OpenLDAP ACL of ADR-0029 decision 4 names `authPassword`. A stock `slapd` (Debian / Ubuntu 2.6, the dev and end-to-end image) defines no `authPassword` attribute unless built with `SLAPD_AUTHPASSWD`, and refuses an `olcAccess` clause that names an unknown attribute: the recommended configuration does not load there (found while building the end-to-end OpenLDAP target, #82).

## Decision
1. **Per-record isolation on the log-file sources, the MongoDB profiler and the OpenLDAP accesslog.** These sources handle every audit record inside `databastion_core::isolate` (a `catch_unwind` of the synchronous handling of one record):
   - the log-file sources (PostgreSQL pgaudit log, MariaDB `server_audit`, the MySQL / Percona JSON logs including their connection lines, the MongoDB `auditLog` and server log) parse each record in isolation and convert records to events in isolation: one record, or one statement's group of records (PostgreSQL, and the MySQL / MariaDB log files);
   - the MongoDB profiler and the OpenLDAP accesslog parse and convert each entry in isolation.

   **Not isolated**: the PostgreSQL `pg_stat_statements` source (`analyze_pss`) and the MySQL / MariaDB `performance_schema` source (statement analysis in the event builder). A panic there ends the stream, and 3 panics in a row stop it (decision 2). The stop is loud (`audit.stream_stopped`, the `agent.audit_stream_stopped` alert), but Audit of the target stays blind until Audit is reconfigured or the agent restarts, and a client who finds a statement that makes the analysis panic can repeat it. Isolating that analysis per record is a ROADMAP follow-up.

   On the isolated sources, a unit whose handling panics is dropped alone and the stream goes on:
   - its records are counted as dropped (`audit.records_dropped`, per record, reported by `check()` for 24 h);
   - the heartbeat metric **`audit_record_panics_total`** counts one per failed isolated unit (a record or a statement group), which tells a crafted-record campaign apart from malformed input;
   - the panic hook logs the code location and a panic id, never the message.
   A panic in a blocking parse task is resumed on the stream (`databastion_core::resume_panic`), so it reaches the core's guard and is never turned into an ordinary error that restarts the stream in a loop.
2. **Panics that still end the stream.** The core tracks the panics of each stream (`PanicTracker`):
   - **A stream with a saved position** (the cursor files it registered: the file sources and the OpenLDAP accesslog) is restarted with a backoff. The position is identified by a hash of its cursor files at the panic. After **3 panics at one exact position**, the core asks the stream to skip **one** record there. The request is applied only if the saved position is still byte-for-byte the one the panics happened at.
   - **The stream is stopped** (level None, `audit.stream_stopped`, the alert of ADR-0031 decision 3) after **7 panics at one position with no progress between them**, or more than **8 skips**, or more than **64 panics** within one hour.
   - **A stream whose position is in memory** (PostgreSQL `pg_stat_statements`, MySQL / MariaDB `performance_schema`, the MongoDB profiler: restarted afresh anyway) is stopped after **3 panics in a row**; a session that ran 10 minutes resets the count.
   - A stopped stream gets another chance when Audit is reconfigured or the agent restarts.
   - The restart delay is the backoff, at least the stream's poll interval, and at most 300 s or the poll interval when that is longer. The computation cannot overflow or panic for any accepted poll interval (up to 3600 s).
3. **Exact skip on OpenLDAP only; isolation mode.** Only the OpenLDAP accesslog stream implements the skip request (`CursorStore::skip_records`). After a panic that reaches the core, it restarts in **isolation mode** (`CursorStore::isolate`): for its first read round (up to 1000 entries) it hands over and saves its position after **every** entry, and saves the CSN of the entry being handed over before converting it (the `handing` line of decision 5). A panic that comes again is therefore at that exact entry, and the skip drops that entry and no other. The skipped entry is counted as dropped and in `audit_records_skipped_total`. An isolation request ends when a session ends without a panic.
   The file sources do not implement the skip: their parsing and conversion are already isolated per record (decision 1), so a panic that still ends the stream happened outside record handling, where skipping a record would not help. Such a stream is stopped by the thresholds of decision 2. This replaces the "every engine" skip of ADR-0031 decision 6.
4. **Detection gaps are counted, not hidden.** A dropped or skipped record loses its events. On PostgreSQL and the MySQL / MariaDB log files, a conversion panic drops the whole statement group, so a statement's reads can be lost because of one bad record in its group. Both are counted (decision 1). The console does not alert on these counters yet (see Consequences).
5. **OpenLDAP cursor format** (refines ADR-0029 decision 7). The persisted position is a text file:
   - first line `v2`;
   - `cursor <csn>`: the newest CSN read;
   - optional `floor <csn>`: nothing at or below it is reported again;
   - optional `handing <csn>`: the entry being handed over in isolation mode;
   - `seen <csn>` lines: the CSNs read within the 10 s overlap below the cursor, at most the 1000 newest. When more were read, the newest one left out becomes the floor.

   After a restart the stream reads the overlap again and reports only the entries whose CSN is not listed, so an entry committed out of CSN order just before the restart is still reported (end-of-phase-6 review L3). The entry named by `handing` is never listed as `seen`: after a crash it is read again, or skipped on the core's request. A `handing` line found without an isolation or skip request is treated as an ordinary entry and cleared.
   **Backward compatible**: a phase-6 cursor file (a bare CSN) is read as both the cursor and the floor, so nothing up to it is reported again; the next save writes `v2`.
6. **OpenLDAP failed-operation proof refreshed at every report** (refines ADR-0029 decision 10; phase-6 round-3 review L1 and L2).
   - **Probe DN.** Each probe reads an entry that does not exist, `cn=databastion-absent-probe-<suffix>,<context>`. The suffix is unique to the probe (time and a process counter).
   - **What counts.** Only that probe's own record counts: an `auditSearch` with that exact `reqDN`, a non-zero `reqResult`, from the last 24 h. Records of earlier probes or of other clients do not.
   - **When.** The probe runs at every privilege report (at most every 10 minutes per target), on at most 8 naming contexts per report, those with the oldest answer first.
   - **Latest answer.** The latest answer, logged or not, **replaces** the previous one. Turning `olcAccessLogSuccess` to `TRUE` therefore caps the level at Partial from the next report that probes that context, not up to 24 h later. A failed search that returned entries, seen by the stream, still counts as a positive answer until the next probe of that context.
   - **Nested contexts.** The search-record proof of a context excludes records under a deeper naming context (`(!(reqDN:dnSubtreeMatch:=<deeper>))` for each). A context never borrows another's proof. The probe's DN is below the context itself, so nested contexts cannot lend that proof either.
   - Proofs that reads are logged are still kept 24 h and renewed by the stream's own search records (unchanged).
7. **MongoDB profiler: truncated or odd commands** (refines ADR-0027 decisions 3 and 4; end-of-phase-5 review I1).
   - **Flag.** The server replaces a command document over its size limit with `{$truncated: "<text>", …}`. The fixed projection flags (`tr`) an entry whose `command` or `originatingCommand` is truncated or is not a document. `$truncated` is matched as a literal and never fetched as text.
   - **Unknown shape.** Such an entry has an **unknown shape**: no filter-key count, so no whole-read signal from a filter that was cut off.
   - **Lost command name.** When the command name itself was lost, the entry is still reported by what it did: a write when it wrote documents, else a read when it returned documents. Otherwise it yields no event.
   - **Odd values.** A `command` that is not a document never makes the projection fail.
   - **Unparsable entries.** An entry that is not a document or does not parse (or whose parsing panics) is skipped and counted as dropped (`audit.records_dropped`); it never fails the whole poll.
8. **Audit log files the agent could have written are refused** (end-of-phase-4 review L4, every file source).
   - **What is refused.** The core tailer refuses a log file that the agent's own account could have written:
     - owned by the agent's effective uid;
     - world-writable;
     - group-writable when its group is one of the agent's (effective or supplementary).
   - **How.** The check runs on the opened handle, after symlinks are followed, with the regular-file check. A refused file is treated as unreadable: `check()` reports `audit.log_not_readable`, the stream re-evaluates its source, and the agent logs `audit log refused`.
   - **Deployment consequence.** An agent running as root while the log belongs to root, or running as the database server's own user, gets `audit.log_not_readable`. The agent must run as its own user, with read access through a group without write permission or an ACL on a file the server owns (for instance `0640`, owner `mysql`, group `databastion`).
   - **Tests.** They enable their own files through a hook compiled only for tests and the core's `test-support` feature; an architecture test checks that only test code calls it.
9. **Recommended OpenLDAP ACL** (refines ADR-0029 decision 4). The recommended credential rule names the credential attributes the **loaded schemas** define. On a stock `slapd` with the `core`, `cosine` and `inetorgperson` schemas:

   ```
   olcAccess: {0}to attrs=userPassword,userPKCS12 by self =xw by anonymous auth by * none
   ```

   Add `authPassword` only where the server defines it (built with `SLAPD_AUTHPASSWD`), the Samba (`sambaNTPassword`, `sambaLMPassword`, `sambaPasswordHistory`, `sambaClearTextPassword`) and Kerberos (`krbPrincipalKey`, `krbExtraData`) attributes where their schemas are loaded, and `pwdHistory` where the ppolicy overlay module is loaded. `slapd` refuses a clause that names an attribute it does not know. The agent's own rule is unchanged: it never requests `userPassword`, `authPassword`, their subtypes or the closed list of credential attributes, whatever the ACL. The dev and end-to-end environments use the rule above (#82).

## Consequences
- On the isolated sources, a record that crashes a parser costs that record (or, on conversion of PostgreSQL and MySQL / MariaDB log files, that statement group), not the target's Audit. On `pg_stat_statements` and `performance_schema`, a repeated panic stops the stream (decision 1). Streams stop only on repeated panics outside record handling. When they do, operators are alerted (ADR-0031 decision 3).
- **Detection gap, counted.** A client that can get a record written that makes the parser panic hides that record's events. The loss shows only in `audit.records_dropped` (target note), `audit_record_panics_total` and `audit_records_skipped_total` (heartbeat metrics). The console raises no alert on them. The ADR-0031 decision 3 optional panic-count alert is not implemented. A masked "conversion failed" access event, so dropped statements reach policies, is a ROADMAP follow-up.
- Per-record isolation assumes the handling of one record leaves no shared state half-updated beyond that record. Connectors keep per-record work local; a bounded map may keep a partial entry.
- OpenLDAP restarts are exact within the overlap. After a panic, the events of at most one search round may be sent again (at-least-once, ADR-0029), and in isolation mode at most the one entry that was being handed over. Entries committed out of CSN order more than 10 s below the cursor, or beyond the 1000 persisted overlap CSNs, are still lost (the floor).
- The failed-operation probe writes one `cn=accesslog` record per context and report: at most 8 per target every 10 minutes. With more than 8 naming contexts, each context is re-probed less often than every report.
- Deployments where the agent runs as root or as the database user lose their file Audit source (`audit.log_not_readable`) until the file permissions are fixed. [05-security.md](../05-security.md#recommended-database-accounts-read-only) and `agent/README.md` say how.
- `docs-keeper` updates [05-security.md](../05-security.md) and [08-engine-capabilities.md](../08-engine-capabilities.md); no protocol change. The metric names travel in the heartbeat `metrics` map, which is open by contract.

### Residual risks
- The writability refusal (decision 8) checks mode bits and the owner uid / gid only. A POSIX ACL entry that grants the agent write access is not detected, nor an agent running as root or with `CAP_DAC_OVERRIDE`, which can write a `0640` file owned by the database server. Run the agent as a dedicated non-root user without that capability.
- `pg_stat_statements` and `performance_schema` analysis is not isolated per record (decision 1): a statement that makes it panic, repeated, stops the target's Audit until an operator acts.
- A panic outside record handling on a file source is not skippable: the stream stops after 7 panics at one position and stays stopped until Audit is reconfigured or the agent restarts. It resumes from the same cursor, so the same panic can stop it again.
- `privilege.password_attributes_readable` probes `userPassword` and `authPassword` only: an account that can read `userPKCS12` or the other listed credential attributes is not flagged. The agent still never requests them.
- The failed-operation proof is as fresh as the last report that probed the context (10 minutes with at most 8 contexts). A server that logs failed operations for the probe's DN only, through an `olcAccessLogBase` covering part of a context, still passes (ADR-0029 residual, unchanged).

## Rejected alternatives
- **Skip on file sources by byte offset**: the offset is saved after a batch, so a skip from it could drop records that never panicked; per-record isolation already covers the parser and the conversion.
- **Skip without isolation mode on OpenLDAP**: the position is saved after a search round of up to 1000 entries, so the entry at fault is not known.
- **Skip the whole statement group instead of isolating conversion per group** (PostgreSQL, MySQL / MariaDB log files): same loss when it panics, and no isolation when it does not.
- **Keep the failed-operation proof for 24 h and let any failed search record count**: a change of `olcAccessLogSuccess` stayed unseen for up to 24 h, and other clients' records (or a nested context's) could prove a context.
- **A fixed probe DN**: its earlier records answered for later probes, so a turned-off setting kept its proof.
- **Keep only the cursor for OpenLDAP**: loses records committed out of CSN order across a restart (L3).
- **Refuse only files owned by the agent's uid** (the first form of the L4 fix): a group-writable or world-writable file is just as forgeable by the agent's account.
- **Name `authPassword` unconditionally in the recommended ACL**: `slapd` refuses the configuration on servers that do not define it.
- **Edit ADR-0029, ADR-0027 or ADR-0031 in place**: the ADR convention does not allow editing an accepted ADR.
