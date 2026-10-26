# Phase 10 Firebird facts (P10-B measurements)

Facts that [ADR-0060](../adr/0060-firebird-connector.md) (Firebird connector) marked "to verify", measured on 2026-10-25 against throwaway containers of the two pinned official images, run locally on loopback only. These results decide implementation details of P10-B; they do not edit the ADR. Where a result contradicts a decision, the "ADR impact" column states the refinement needed, for the maintainer and the docs-keeper to carry into the ADR.

Images: `firebirdsql/firebird` `5.0.4` (`sha256:1529560400fc7847f015c57fc9d70729c44d9a9d8f9000df19c5ce1950b4c202`, `LI-V5.0.4.1812`) and `4.0.7` (`sha256:456aeb748f6f70a4adbc910a2adc56f4d43270bcdf12808c47ca6e9603c6b17e`, `LI-V4.0.7.3271`), amd64, extracted from the Docker Hub layers and run under `chroot` as uid 84 (`firebird`) on loopback (`RemoteBindAddress = 127.0.0.1`), `WireCrypt = Required`, `ServerMode = Super` unless noted. Probe accounts were throwaway users with fake passwords; no value from any ground truth was used as a marker. Base `firebird.conf` keys were set from the measurements; the audit trace configuration logged statements, procedures, functions, triggers, BLR, connections and transactions with `time_threshold = 0` and `print_perf = true`.

Accounts (as ADR-0060 decision 4 names them): `min` (minimal variant: a reader role with `SELECT` on one table, granted `DEFAULT`), `ext` (extended variant: a role `SET SYSTEM PRIVILEGES TO SELECT_ANY_OBJECT_IN_DATABASE`, granted `DEFAULT`), `none` (a user with no grant), and `SYSDBA`.

## Obligation 1 — wire encryption (ChaCha64 / ChaCha / Arc4 on 4.0 and 5.0)

**Done; the result is with the maintainer** (ADR-0060 security review N1). A ChaCha64, a ChaCha and an Arc4 loopback session were captured on both 4.0.7 and 5.0.4 with `WireCrypt = Required`. The result is held outside the repository pending the maintainer's disclosure decision. The ADR's decisions do not depend on it (they rest on the already-documented missing MAC and missing server authentication). | **Confirms** the ADR's transport reasoning (loopback only). |

## Obligation 2 — protocol offer and `op_cancel`

**Open (needs the connector's own client).** A client offering protocol 16 only, and `op_cancel` during a pending fetch in `ptype_batch_send`, cannot be exercised with `isql` (it negotiates the highest protocol the server supports: 19 on 5.0, 18 on 4.0). To test on the engine matrix once the P10-B lot 1 client exists. The servers' context variable `RDB$GET_CONTEXT('SYSTEM','ENGINE_VERSION')` returns `5.0.4` / `4.0.7` as decision 2 expects.

## Obligation 3 / 15 — the I4 account matrix (catalog visibility and grants)

| Fact | Method | Result | ADR impact |
|---|---|---|---|
| Default DDL rights of a plain user | `CREATE TABLE`, `CREATE TABLE … EXTERNAL FILE`, `CREATE PROCEDURE`, `CREATE GLOBAL TEMPORARY TABLE`, `CREATE SEQUENCE` as `min` and `none` | **All denied** ("No permission for CREATE TABLE / CREATE PROCEDURE / CREATE GENERATOR operation", SQLSTATE 42000). A plain Firebird user holds no DDL right by default | **Confirms** decision 4: no default-DDL residual to warn about (unlike MySQL temporary tables); `privilege.beyond_select` only when a grant adds it |
| `EXECUTE STATEMENT … ON EXTERNAL` | `EXECUTE BLOCK` with `EXECUTE STATEMENT '…' ON EXTERNAL 'inet://127.0.0.1//data/app.fdb' AS USER … PASSWORD … INTO …` as `min` | **Allowed** (outbound loopback connection succeeded, returned the value). No permission gate; `ExternalFileAccess`/`UdfAccess` do not block it | **Confirms** the outbound-primitive note in decision 4: any account, `min` included, can open an outbound connection from the server. The agent never sends it; a stolen credential could |
| `RDB$CONFIG` visibility | `COUNT(*) FROM RDB$CONFIG` per account | `min` 0, `none` 0, **`ext` 77 (5.0) / 73 (4.0)**, `SYSDBA` 77/73 | **Refines** the extended-variant risk (decision 4, obligation 3): `SELECT_ANY_OBJECT_IN_DATABASE` **exposes the whole server configuration** (`ExternalFileAccess`, `AuthServer`, `WireCrypt`, `RemoteBindAddress`, `ServerMode`, …), which the minimal account cannot see. The extended variant widens visibility beyond user tables; keep it opt-in only (open question 5) |
| `ExternalFileAccess` / `UdfAccess` / mode | `RDB$CONFIG` as `SYSDBA` | `ExternalFileAccess = None`, `UdfAccess = None`, `WireCrypt = Required`, `AuthServer = Srp256, Srp`, `RemoteBindAddress = 127.0.0.1`, `ServerMode = Super`; all readable via `RDB$CONFIG` (to `ext`/`SYSDBA`, not `min`) | Confirms decision 4's "read through `RDB$CONFIG` where visible": visible only with the extended or higher privilege |
| `MON$ATTACHMENTS` of other attachments | `COUNT(*) … WHERE MON$ATTACHMENT_ID <> CURRENT_CONNECTION` per account | `min`, `ext`, `none`: **0** (own attachment only); `SYSDBA`: 2 | **Confirms** decision 4: a non-privileged account sees only its own `MON$` rows; `SELECT_ANY_OBJECT_IN_DATABASE` does **not** grant visibility of other attachments (needs `MONITOR_ANY_ATTACHMENT`) |
| `SEC$USERS` rows | `COUNT(*)` per account | `min`/`ext`/`none`: **1** (own row only); `SYSDBA`: 5 (all) | **Confirms** decision 4: a non-administrator sees its own `SEC$USERS` row only |
| `RDB$USER_PRIVILEGES`, `RDB$ROLES`, `RDB$AUTH_MAPPING`, `RDB$DB_CREATORS`, `MON$DATABASE` | `COUNT(*)` per account | Readable by **every** account including `none` (`RDB$USER_PRIVILEGES` 1187, `RDB$ROLES` 3, `RDB$AUTH_MAPPING` 0, `RDB$DB_CREATORS` 0, `MON$DATABASE` 1); no permission error | **Confirms** decision 4 can read `RDB$USER_PRIVILEGES` and `RDB$ROLES` with the minimal account; `RDB$AUTH_MAPPING` is readable too (empty here) |
| Default role active without `SET ROLE` | `RDB$ROLE_IN_USE('DATABASTION_READER')`, `CURRENT_ROLE`, `SELECT` on the granted table, as `min` | `RDB$ROLE_IN_USE` = TRUE and the granted `SELECT` works, but `CURRENT_ROLE` = `NONE` | **Confirms** decision 4's approach, with a nuance: a `DEFAULT`-granted role is **in use** but `CURRENT_ROLE` stays `NONE`; `check()` must use `RDB$ROLE_IN_USE` / `RDB$SYSTEM_PRIVILEGE`, never `CURRENT_ROLE` (the ADR already does) |
| System-privilege test function | `RDB$SYSTEM_PRIVILEGE(<name>)` | The argument is an **unquoted keyword**, not a string: `RDB$SYSTEM_PRIVILEGE(SELECT_ANY_OBJECT_IN_DATABASE)` works, `'…'` is a syntax error | For the `check()` statements (decision 4) |
| `SELECT_ANY_OBJECT_IN_DATABASE` bit | `RDB$ROLES.RDB$SYSTEM_PRIVILEGES` of the extended role | bit mask `0000010000000000` on 4.0 and 5.0 | One datum for the per-version bit-position table (decision 4); the full table is a P10-B drift test |
| `RDB$PROCEDURE_SOURCE` readable | `COUNT(* …) FROM RDB$PROCEDURES WHERE RDB$PROCEDURE_SOURCE IS NOT NULL` per account | Readable by **every** account (`none` included) | **Confirms** the residual (open question 7): source texts of user code are readable by every user |
| `RDB$PROFILER` system package | `SELECT RDB$PROFILER.START_SESSION('x') FROM RDB$DATABASE` as `min` and `none` | **Succeeds** for both | `RDB$PROFILER` is granted to `PUBLIC`; documented for decision 4's "PUBLIC system packages" (own-session profiling only; other attachments need `PROFILE_ANY_ATTACHMENT`) |
| Remote attach to the security database | `isql` to `inet://…/opt/firebird/security5.fdb` as `SYSDBA` and `min` | **Refused**: "no permission for remote access to database …security5.fdb" | The shared security database cannot be opened remotely; `PLG$SRP`/`PLG$USERS` are unreachable there (relevant only to a database that is its own security database — see obligation note below) |

## Obligation 4 — transactions

`SET TRANSACTION READ ONLY READ COMMITTED READ CONSISTENCY` → `RDB$GET_CONTEXT('SYSTEM','READ_ONLY')` = `TRUE`, `RDB$GET_CONTEXT('SYSTEM','ISOLATION_LEVEL')` = `READ COMMITTED`. **Confirms** decision 4: the TPB is honoured and the context variable names (`READ_ONLY`, `ISOLATION_LEVEL`) are correct. (The "a read-only read-committed transaction does not hold the oldest active transaction back" part is a load-time check, not run here.)

## Obligation 5 — conversions and `FIRST n`

- `SELECT FIRST 1 CAST(SUBSTRING(col FROM 1 FOR 4000) AS VARCHAR(4000) CHARACTER SET UTF8)` works on `VARCHAR`, on a `WIN1252` column (transliterated to UTF8), and the `CHARACTER SET OCTETS` form works on `BLOB SUB_TYPE TEXT`. **Confirms** decision 5's conversion forms on 5.0.
- `FIRST n` stops the natural scan early: `SELECT FIRST 1 ID FROM CUSTOMERS` on a 2-row table recorded `Natural = 1` in the per-table block (not 2). **Confirms** decision 5's storage-order early-stop assumption.

## Obligation 6 — audit log file modes

The server creates the audit log `-rw------- (0600)` owned by `firebird:firebird` (uid/gid 84). **Impact**: an agent that is only in the `firebird` **group** cannot read it (no group read under the default umask). The operator must grant the agent read access explicitly (a supplementary ACL, or group ownership plus `chmod g+r` / `UMASK`); docs/08 and the user guide must state it.

## Obligation 7 — per-table counters (nested reads)

**Confirms** the key assumption (and answers open question 13 affirmatively). With `print_perf = true` each finish record carries the `Table / Natural / Index / Update / Insert / Delete / Backout / Purge / Expunge` block. A `SELECT N FROM CALLER` where `CALLER` calls `READTWO` which reads `CUSTOMERS` and `NONEC` produced, on the **top-level** `EXECUTE_STATEMENT_FINISH`, a per-table block naming **both** `CUSTOMERS (2)` and `NONEC (1)` — i.e. the counters include relations read two call levels deep. Separate `EXECUTE_PROCEDURE_FINISH` records (with `log_procedure_finish`) carry the same aggregated block, so the agent must avoid double-counting the same read across the statement and procedure records. | **Confirms** decision 6 / open question 13: name the procedure plus the counters' relations (no forced `*`), **because** the counters include reads inside called code. |

## Obligation 8 — header tokens `(pid:address)`

**Contradicts the ADR's token model; an ADR refinement is needed before Audit ships (as decision 6 anticipated).**

- The token is `(server_pid : plugin-instance heap address)`. In **SuperServer** the server pid is constant within a run (e.g. `21608`) but the **address is per attachment** — the one log held 21 distinct tokens with a single pid, one per attachment/thread. There is therefore **no single "current token per database path"**: many coexist concurrently for the same database.
- The pid changes only at server restart (distinct pids in the log correspond to restarts).
- `TRACE_INIT` / `TRACE_FINI` (`SESSION_1 Firebird Audit`) bracket the **whole server run** in SuperServer, but in **SuperClassic** each attachment emits its **own** `TRACE_INIT` / `TRACE_FINI`.

**ADR impact**: decision 6 fix 4/7 ("keeps a token per database path … changed only at a `TRACE_INIT`/`TRACE_FINI` boundary; a record whose token is not the current one for its database marks records ambiguous") cannot stand as written — it would mark almost every record ambiguous. The refinement should treat the **pid** as the stable per-run discriminator (constant across attachments, changes at restart) and the **address** as per-attachment, not per-database, and must accept per-attachment `TRACE_INIT`/`TRACE_FINI` in SuperClassic/Classic. The forged-header defence must be re-derived on that basis.

## Obligation 9 — trace text facts and failed logins

- **`CREATE USER … PASSWORD` is written verbatim** in the statement text: `CREATE USER MARKERUSER PASSWORD 'MARKERSECRET12345' USING PLUGIN Srp` appeared in clear in the trace (the server does **not** mask it, unlike SQL Server). The internal `plg$srp_view` update that follows carries the verifier and salt as `param0`/`param1` (binary), and the user name as a parameter. **Confirms** decision 6 and the password-bearing-statements rule: the agent must keep the kind only and the #82 marker test must cover `CREATE USER`.
- **Attachment line format** (4.0 and 5.0, identical): `<path> (ATT_<n>, <USER>:<ROLE>, <charset>, <protocol>:<address>/<port>)`, e.g. `/data/app.fdb (ATT_78, AGENT_MIN:NONE, NONE, TCPv4:127.0.0.1/41370)`; then the client line `<process path>:<pid>` and the transaction line `(TRA_<n>, READ_COMMITTED | READ_CONSISTENCY | WAIT | READ_WRITE)`. **Confirms** decision 6's format.
- **Failed login**: a wrong password gives SQLSTATE `28000` "Your user name and password are not defined…" (GDS `isc_login`), and a `FAILED ATTACH_DATABASE` record is written (with `log_connections`), the attempted user in the attachment line. **Confirms** the mapping `isc_login → authentication_failed` (decision 1).
- **Delay after repeated failures**: five rapid wrong-password attempts from the same loopback source were fast (~30 ms) for the first three, then the **fourth was delayed ~8 s**; later attempts fast again; a correct login immediately afterwards **succeeded** (no permanent lockout). **Impact**: Firebird throttles repeated failed logins per source with a delay, not a lockout; the connector's "stop retrying until the next heartbeat" (decision 1) already avoids tripping it.

## Obligation 10 — attachment ids

`CURRENT_CONNECTION` was 133 on the live database; on a `gbak` backup+restore to a new file it was **7**. **Confirms** the ADR: the attachment-id counter is **reset by a restore**, so an id seen after a restore is not the agent's earlier one (the own-attachment set must account for restores).

## Obligation 11 — when the audit configuration is read

Changing `log_statement_finish` to `false` in the live trace configuration **without a restart** had no effect: a fresh attachment's statement was still logged (both `START` and `FINISH`). **Confirms** decision 6 / M3: the system-audit configuration is read at **trace-session (server process) start**, not at each attach. The "files changed after the server process started = not proven" rule (proof 2) is the correct one.

## Obligation 12 — database paths in the trace

- **symlink, `..`, `//`**: all three attach forms are **canonicalised to the real path** `/data/app.fdb` in both `MON$DATABASE.MON$DATABASE_NAME` and the trace `ATTACH_DATABASE` line. **Confirms** exact-path matching is safe for these.
- **alias** (a `databases.conf` name): the trace prints the **alias string verbatim** (`appalias`), while `MON$DATABASE_NAME` returns the resolved path `/data/app.fdb`. **They differ.**
- **hard link**: `MON$DATABASE_NAME` and the trace both print the **hard-link path** used to attach (`/data/app_hard.fdb`, same inode as `/data/app.fdb`); hard links are not resolved to a canonical name.

**ADR impact (refinement candidate for decision 6 / M4)**: the trace path is the **attach string as the client gave it** (a `databases.conf` alias stays an alias; a path is canonicalised), so a path learned from `MON$DATABASE_NAME` will **not** match records of a client that attached through an alias (or through a different hard link). The agent must match against the declared `attach` **alias string too**, not only the resolved path, and the inode-based ambiguity rule (M4) is justified by the hard-link case.

## Obligation 13 — section matching in the trace configuration

With a disabled default section and two named sections, `database = /data/app.fdb` (exact full path) and `database = %[\\/]app.fdb` (a `SIMILAR TO` pattern), a query on `/data/app.fdb` was logged **only to the first section's log** (`exactpath.log`), not the second. **Confirms**: section patterns are matched against the **full database path**, and **only the first matching section applies** (the default section is processed first, then search stops at the first matching named section — sections do not accumulate). This supports decision 6 proof 3 (evaluate only the default section and plain full-path/file-name sections without `SIMILAR TO` metacharacters; cap at Limited otherwise, open question 12).

## Obligation 14 — `MON$ATTACHMENTS` remote fields on loopback

For a loopback attachment: `MON$REMOTE_PROTOCOL` = `TCPv4`, `MON$REMOTE_ADDRESS` = `127.0.0.1/<client port>` (address and port combined in one field), `MON$REMOTE_PROCESS` / `MON$REMOTE_PID` set, `MON$WIRE_CRYPT_PLUGIN` = the negotiated plugin (`ChaCha64`), `MON$AUTH_METHOD` = `Srp256`. **Confirms** decision 3's forwarder check reads (`MON$REMOTE_ADDRESS` carries the client address and port; compare with the socket). The tunnel/forwarder variants are to confirm with a `socat` forwarder in the P10-D integration test.

## Obligation 15 — I4 measurement plan

Executed above (obligations 3/4; accounts `min`, `ext`, `none`, `SYSDBA`). A `sysdba_mapped` account via `RDB$AUTH_MAPPING` was not exercised (no mapping defined on these images; `RDB$AUTH_MAPPING` was empty and readable); to add on the engine matrix with an explicit mapping. **Confirms** the plan is runnable and the probes behave as decision 4 expects.

## Other facts

| Fact | Result | ADR impact |
|---|---|---|
| Upper-casing of non-ASCII unquoted identifiers (security review L9) | `CREATE TABLE café` is a **syntax error** ("Token unknown" at the `é`) even with a UTF8 client, as `SYSDBA`, on 4.0 and 5.0. A quoted `"café"` is accepted and stored **as written** (lower-case kept) | **Confirms** open question 11: unquoted identifiers are **ASCII-only**, so ASCII `a–z` upper-casing is sufficient and non-ASCII names must be quoted and kept verbatim; no `name_case` value is needed |
| `PLG$SRP` / `PLG$USERS` system flag in a self-security database | **Partially open**: the shared security database refuses remote attach, and a database configured as its own security database could not be bootstrapped over the wire here (a chicken-and-egg authentication failure at `CREATE DATABASE`). To measure on the matrix with a pre-built self-security database | The M5 closed list (never sampled whatever the system flag) handles it conservatively regardless |
| Classic vs SuperServer peer uid (`/proc/net/tcp`) | The Firebird listening socket (ports 3049/3050) is owned by **uid 84 (`firebird`)** in SuperServer and SuperClassic; the per-attachment server process runs as `firebird` | **Confirms** decision 3's peer-uid check (declared `peer_uid = firebird`). **SuperClassic** confirmed for Audit; true **Classic** (one forked process per connection) was not run here — left open (open question 9), reason: the forking inet listener is awkward to run in this chroot |

## Summary of contradictions to carry into ADR-0060

1. **Obligation 8 (header tokens)** — the token's address is **per attachment**, not per database (many coexist for one database); the pid is the per-run constant; SuperClassic emits per-attachment `TRACE_INIT`/`TRACE_FINI`. Decision 6's "one current token per database path" rule must be refined before Audit ships.
2. **Obligation 12 (alias paths)** — the trace prints a `databases.conf` **alias verbatim** while `MON$DATABASE_NAME` gives the resolved path; the agent must match the declared `attach` alias string as well as the resolved path.
3. **Obligation 3 (extended variant)** — `SELECT_ANY_OBJECT_IN_DATABASE` exposes `RDB$CONFIG` (the whole server configuration) beyond user tables; keep the extended variant opt-in and documented.

All other obligations measured here **confirm** the ADR's assumptions.

## Lot 3 prerequisites (2026-10-26)

The measurements that the [ADR-0060 refinement of 2026-10-25](../adr/0060-firebird-connector.md#obligations-still-open) lists as "new with this refinement" (3b, 7b, 8a to 8f, 12b, 12c, 13b), with three items still open after the earlier round: true Classic mode (open question 9 and R1 rule 10), `PLG$SRP` / `PLG$USERS` in a database that is its own security database, and the lot 1 re-review residual A (`SEC$GLOBAL_AUTH_MAPPING` visibility). These results do not edit the ADR. Where a result contradicts the accepted refinement, the "ADR impact" says so, and the [summary](#lot-3-summary-of-contradictions) lists the refinement needed before the Audit lot.

**Method.** The pinned images of the [first round](#phase-10-firebird-facts-p10-b-measurements) (`5.0.4` `LI-V5.0.4.1812` and `4.0.7` `LI-V4.0.7.3271`, by digest), one throwaway container per run, started with `--network none` (loopback only) and `--cap-drop NET_RAW --cap-drop NET_ADMIN`, data and logs on `tmpfs`. Inside it, the accounts and databases were created with the image's `isql` over embedded connections before the server started; the server then ran as uid 84 (`firebird`) with `RemoteBindAddress = 127.0.0.1`, `WireCrypt = Required`, `AuthServer = Srp256`, `ServerMode` = `Super`, `SuperClassic` or `Classic`, and `AuditTraceConfigFile` naming a trace configuration with `log_connections`, `log_transactions`, `log_statement_finish`, `log_procedure_finish`, `log_function_finish`, `log_trigger_finish`, `log_blr_requests`, `log_errors`, `log_initfini`, `log_sweep`, `time_threshold = 0`, `print_perf = true` and `max_sql_length = 4096`, plus a services section with `log_services`. Every client (`isql`, `gbak`, `gfix`, `fbsvcmgr`) ran as uid 65534 (`nobody`) over `127.0.0.1:3050`, so that no client's embedded engine could write the log (see 8e). Passwords were random, in `0600` files, given to the tools through `ISC_PASSWORD`, never on a command line. Accounts as in the first round: `min` (`DATABASTION_AGENT`, reader role granted `DEFAULT`), `ext` (`AGENT_EXT`, `SELECT_ANY_OBJECT_IN_DATABASE` role granted `DEFAULT`), `none` (`AGENT_NONE`), `OTHER_U` (another plain user) and `SYSDBA`. Logs were parsed by a throwaway script (header grammar, attachment line, per-table block); harness and logs were deleted afterwards. Nothing was captured on the wire.

### 8a, 8b — the address is constant per attachment, carried by `DETACH_DATABASE`, and reused

| Fact | Method | Result | ADR impact |
|---|---|---|---|
| Token per attachment under concurrency (8a) | 8 concurrent `isql` sessions (two accounts), 40 statements each, one in five a cross join of `RDB$FIELDS`; then bursts of 16, 32 and 64 concurrent attaches; 4.0 and 5.0, SuperServer and SuperClassic | Over 70 to 119 attachments per run, **no attachment's records carried two tokens**; up to 11 attachments were live at once (in record order) | **Confirms** R1 rule 3 (a binding per attachment) |
| `DETACH_DATABASE` (8b) | same logs | Every `DETACH_DATABASE` carries its attachment's `ATTACH_DATABASE` token | **Confirms** R1 rule 3 |
| Address reuse (8b) | same logs | Addresses are reused after a detach, never while the earlier holder is live: 10 to 19 distinct addresses served 119 attachments in one run. In Classic, the same **two** addresses appear in every per-connection process (below) | **Confirms** R1 rule 4 and H1 fix 7 (the address is guessable: very few values occur) |

### 8c — `TRACE_INIT` / `TRACE_FINI` are per attachment in SuperServer too

| Fact | Method | Result | ADR impact |
|---|---|---|---|
| `TRACE_INIT` / `TRACE_FINI` in SuperServer | every SuperServer log of 8a, 8b and 8e, 4.0 and 5.0 | Each attachment (the server's own `<internal>` attachments to the security database included), each service session and each failed or unauthorized attach is preceded by a `TRACE_INIT` and followed by a `TRACE_FINI`, both with **that attachment's token**: in one 5.0.4 run, 77 `TRACE_INIT` for 70 `ATTACH_DATABASE`, 3 `ATTACH_SERVICE`, 1 `UNAUTHORIZED ATTACH_DATABASE`, 1 `CREATE_DATABASE` and 2 Garbage Collector attachments. **No** `TRACE_INIT` brackets the server run. The same holds in SuperClassic and Classic | **Contradicts** R1 rule 2 and the first round's obligation 8 note ("in SuperServer, `TRACE_INIT` / `TRACE_FINI` bracket the server run"). R1 rule 2 makes "a `TRACE_INIT` that carries the current pid" in SuperServer trigger a stop and a confirmation, and a second `TRACE_INIT` in the current run ambiguous: applied to these logs, every attachment would stop the stream (or, in the cooldown, be ambiguous). The SuperClassic branch of rule 2 ("belong to attachments, never trigger a stop") matches what SuperServer does; a restart with the same pid then has to be found from the start time read by `check()` |
| Tokens of `FAILED` / `UNAUTHORIZED ATTACH_DATABASE` | 8f failed attaches (missing file) and remote attaches to the security database, all configurations | A fresh token, introduced by its own `TRACE_INIT` and ended by `TRACE_FINI`; never a token held by a live binding | **Confirms** R1 rule 4 for these records |
| Tokens of service records | `fbsvcmgr info_server_version`, `gbak -b` and `gbak -rep` through `service_mgr` | `ATTACH_SERVICE`, `START_SERVICE` and `DETACH_SERVICE` share one token, introduced by a `TRACE_INIT`; never a token held by a live database binding. A failed service login (wrong password) writes nothing | **Confirms** R1 rule 6 |
| Restore through the services API | `gbak -rep -se … service_mgr` onto the live database file | The service's database attachment writes `DROP_DATABASE` (ending its binding), then `CREATE_DATABASE` **on the same token** for the new database's first attachment (`ATT_3` on SuperServer, `ATT_1` on SuperClassic), with no `ATTACH_DATABASE` record | R1 rules 3 and 5 should treat `CREATE_DATABASE` as anchoring a binding and `DROP_DATABASE` as ending one |
| `SWEEP_START` / `SWEEP_FINISH` | `gfix -sweep` over TCP | Carry the `gfix` attachment's id and token | Bound like any record of that attachment |

### 8d — `MON$SERVER_PID`, the process start time, and restores

| Fact | Method | Result | ADR impact |
|---|---|---|---|
| `MON$SERVER_PID` on the minimal account's own row | `SELECT CURRENT_CONNECTION, MON$SERVER_PID FROM MON$ATTACHMENTS WHERE MON$ATTACHMENT_ID = CURRENT_CONNECTION` as `min` | Readable; equals the header pid and `pgrep -x firebird` (SuperServer, SuperClassic), before and after a restart (a new pid); `min` sees 1 row of `MON$ATTACHMENTS` | **Confirms** R1 rule 1 |
| Start time from `/proc` | `/proc/<server pid>/stat` field 22 read as uid 65534 | Readable by another uid; `/proc/<pid>/fd` is not (permission denied) | **Confirms** R1 rule 1 (the start time is available to the agent's uid in the same pid namespace) |
| `DB_GUID` and `MON$CREATION_DATE` at a restore | Read as `min` before and after `gbak -rep` | **Both change** (a new GUID, the restore's time as the creation date); `CURRENT_CONNECTION` restarts low (7 on SuperServer, 3 on SuperClassic, against about 110 before) | **Confirms** R1 rule 5's restore detection |
| The agent's `MON$SERVER_PID` read in the log | the text above as `ext` | Its finish record has **no per-table block** (3b) | See 3b: R1 rule 1's own read is a record without a block |

### 8e — attachment ids, system attachments, failed attaches, attach order

| Fact | Method | Result | ADR impact |
|---|---|---|---|
| System attachments (SuperServer) | `MON$ATTACHMENTS` as `SYSDBA`; id gaps of `ATTACH_DATABASE` records | Each time SuperServer **opens** a database (the first attachment after it was closed), a `Cache Writer` and a `Garbage Collector` system attachment (`MON$SYSTEM_FLAG = 1`) take the two ids before it: 12 sequential attaches used 3 ids each. The Cache Writer writes nothing. The **Garbage Collector writes a `TRACE_INIT`, then `START_TRANSACTION` and `COMMIT_TRANSACTION` records**, attachment line `(ATT_<n>, Garbage Collector, NONE, <internal>)` (no `:role`), with **no `ATTACH_DATABASE` record**, on a token no live binding holds. SuperClassic and Classic have neither system attachment (no id gaps) | **Contradicts** R1 rule 5 as written: the Garbage Collector's records name an id above the watermark with no `ATTACH_DATABASE` record read for it, so they are ambiguous at every database open. Rule 5 needs a decision for this record shape (it is forgeable like any line) |
| Failed logins and ids | `CURRENT_CONNECTION` before and after three wrong-password logins | No id consumed (the two-id gap is the Cache Writer and Garbage Collector of the next open) | **Confirms** R1 rule 5 |
| Failed attaches | an authenticated attach to a missing file | `FAILED ATTACH_DATABASE` with `ATT_0`, then `ERROR AT JProvider::attachDatabase` with its GDS codes | No id consumed |
| Sweep and profiler | `gfix -sweep`; `RDB$PROFILER.START_SESSION` / `FINISH_SESSION(TRUE)` as `min` (5.0) | The sweep runs in the `gfix` attachment; the profiler writes no record of another attachment | No other id-consuming writer found |
| A client's own embedded engine | the first run, before clients ran as `nobody`: `isql` as root, a remote attach refused | The **client process** wrote `TRACE_INIT`, `FAILED ATTACH_DATABASE` (database `127.0.0.1/3050:/opt/firebird/security5.fdb`, `<internal>`) and `TRACE_FINI` into the audit log **under its own pid**: after the remote provider failed, the client's embedded provider tried the connection string as a file, reading the same `firebird.conf` and able to write the log | Any local process that runs Firebird's embedded engine with write access to the log (root, the server's account) writes records with another pid: R1 rule 2 then stops the stream once per such pid |
| Attach order, database already open | bursts of 16, 32 and 64 concurrent attaches with another attachment held open | `ATTACH_DATABASE` records out of id order: max inversion 3, 7 and 5 (5.0 SuperServer), 3, 6 and 11 (4.0 SuperServer), at most 6 in SuperClassic | Within the proposed tolerance of 16 |
| Attach order, burst that opens the database | 30 concurrent attaches as the first attaches after the database closed; three repeated runs per configuration plus the first | **4.0.7 SuperServer: max inversion 29, 30, 30 and 30**, the late `ATTACH_DATABASE` records written about 1 s after those of higher ids; 5.0.4 SuperServer: 4, 7, 7 and 12; SuperClassic (both): 2 to 6 | **Contradicts** R1 rule 5's tolerance of 16 on 4.0.7 SuperServer: the inversion reached the size of the burst. A constant tolerance does not bound it |

### 8f — line breaks per field, and the remote 4-tuple

Each field was given a value holding a line break followed by a complete header line (`2026-01-01T00:00:00.0000 (1:0x1) ATTACH_DATABASE`), then the log was searched; 4.0 and 5.0, SuperServer and SuperClassic, identical results.

| Field | Method | Result | ADR impact |
|---|---|---|---|
| Statement text | a `/* … */` comment and a string literal | **Verbatim**: the header text starts a line of the record | The H1 injection point stands |
| `isc_dpb_process_name` | a hard link of `isql` whose file name holds the line break (the client sends its executable path) | **Verbatim** on the client line of every record of the attachment | Stands |
| User name of a failed login | `ISC_USER` holding the line break, wrong password | No `FAILED ATTACH_DATABASE` record (below); the name appears **verbatim** as `param0` of the server's verifier lookup in the security database's records | Stands, in the security database's records |
| User name of an attachment | a user created by `SYSDBA` with a quoted name holding the line break, then used | **Verbatim** in the attachment line of every record | Stands (needs an administrator to create the name) |
| Role (`isc_dpb_sql_role_name`) | `isql -r` with the line break | Successful attach: the role is not granted, the line shows `NONE`. Failed attach (missing file): **verbatim** in the `FAILED ATTACH_DATABASE` attachment line | Stands for failed attaches |
| Error texts | `CAST('…' AS DATE)` conversion error; a user exception raised with a message holding the line break | The conversion error quotes the value with the line break **escaped as `#x0a`**; the user exception's message is written **verbatim** | Stands for user exception messages |
| Remote 4-tuple (rule 9) | a live attachment held open; the `ATTACH_DATABASE` record read from the log, then `/proc/net/tcp` | The record was in the log about 40 ms after the client sent its statement; `/proc/net/tcp` had exactly one server-side row, local `127.0.0.1:3050`, remote `127.0.0.1:<printed port>`, state `ESTABLISHED`, uid 84, while the attachment lived, and none after the detach. A bare TCP connection held open without attaching has the same kind of row (uid 84, `ESTABLISHED`) and **writes nothing** to the log | **Confirms** rule 9 is applicable (the printed port can be corroborated at read time), with the limit the refinement states: a local forger can hold a connection without attaching and print its port |

**8f result**: the server escapes line breaks only inside the quoted value of a conversion error. Statement texts, process names, user and role names and user exception messages are written verbatim, so the **misattribution residual stands** (open question 6 of the refinement, accepted by the maintainer), and **rule 9 applies**.

**Failed logins** (from 8c, 8e and 8f, and a dedicated run with `AuthServer` = `Srp256`, `Srp256, Srp` and `Srp256, Srp, Legacy_Auth`, `WireCrypt = Enabled` in that run): a wrong password, for an existing user or an unknown one, writes **no `FAILED ATTACH_DATABASE` record** for the target database, on 4.0.7 and 5.0.4, SuperServer and SuperClassic, with `log_connections = true`. The only trace is the server's own attachment to its security database (`SELECT PLG$VERIFIER, PLG$SALT FROM PLG$SRP WHERE PLG$USER_NAME = ? AND PLG$ACTIVE`, the attempted name as `param0`), written only where a section applies to the security database's path. `FAILED ATTACH_DATABASE` is written only when an authenticated attach fails (a missing file), and `UNAUTHORIZED ATTACH_DATABASE` when remote access is refused. **This contradicts** the first round's obligation 9 note ("a `FAILED ATTACH_DATABASE` record is written … the attempted user in the attachment line") and decision 6, "Principals", which counts the user names of failed attaches toward the failed-login flood cap: wrong passwords are not seen in the declared database's records, and under proof 11 (default section disabled) not at all.

### 7b — nested finish records come first

| Fact | Method | Result | ADR impact |
|---|---|---|---|
| Order of nested finish records | as `min`: `SELECT … FROM CALLER` (a selectable procedure calling `READTWO`), `SELECT F_COUNT() FROM RDB$DATABASE` (a PSQL function), `EXECUTE PROCEDURE EXEC_ONE`; as `SYSDBA`: an `INSERT` firing an `AFTER INSERT` trigger that reads `CUSTOMERS`; 4.0 and 5.0 | Every `EXECUTE_PROCEDURE_FINISH`, `EXECUTE_FUNCTION_FINISH` and `EXECUTE_TRIGGER_FINISH` is written **before** the `EXECUTE_STATEMENT_FINISH` of its statement, on the same attachment and token, innermost first (`READTWO`, then `CALLER`, then the statement). The statement's block is the union (`F_COUNT`: `RDB$DATABASE` and `NONEC`; the `INSERT`: `T_TRIG` and `CUSTOMERS`) | **Confirms** R4 ("nested finish records are written before the finish record of their statement") |

### 3b — the extended variant on a populated state, and the counters of virtual relations

**Populated state**: an `OTHER_U` attachment held open with a context variable set (`RDB$SET_CONTEXT('USER_SESSION', …)`) and, on 5.0, a profiler session started; five users in the security database; global and local mappings; and a database that is its own security database (below). Every relation of `RDB$RELATIONS` (70 on 5.0, 58 on 4.0; 59 and 57 in the self-security database), system relations included, was counted with `SELECT COUNT(*)`, one `isql` attachment per relation, as `min`, `ext`, `none` and `SYSDBA`.

| Fact | Result | ADR impact |
|---|---|---|
| Relations whose visible rows differ between `min` and `ext` | Only the user tables without a `min` grant, **`RDB$CONFIG`** (`min` 0, `ext` 77 on 5.0 / 73 on 4.0) and, in the self-security database, **`PLG$SRP`** (`min` denied, `ext` 4 rows: every user's SRP verifier and salt) | **Contradicts** R3's assessment for self-security databases (below) |
| `MON$` relations of other attachments | `MON$ATTACHMENTS` 1, `MON$STATEMENTS` 1, `MON$TRANSACTIONS` own only, `MON$CONTEXT_VARIABLES` 0 (the other attachment's variable is not seen) for both `min` and `ext` (`SYSDBA`: 4, 2, 5, 1); `MON$TABLE_STATS` rows whose `MON$STAT_ID` belongs to no visible attachment, transaction, statement, call or database row: 0 for both; the same query on `MON$RECORD_STATS` (whose rows also back the table statistics) gives the same count for `min` and `ext` (26 on SuperServer, 14 on SuperClassic) against 50 and 34 for `SYSDBA`. Their row counts differ between accounts only with the own attachment's activity (`none` differs from `min` as much as `ext` does) | **Confirms** R3: no other attachment is visible to `ext` |
| `SEC$` relations | `SEC$USERS` own row only (1 of 6), `SEC$USER_ATTRIBUTES`, `SEC$DB_CREATORS`: the same for `min` and `ext` | **Confirms** R3 |
| `RDB$CONFIG` keys | 77 on 5.0.4, 73 on 4.0.7. Only on 5.0: `AllowUpdateOverwrite`, `DefaultProfilerPlugin`, `MaxParallelWorkers`, `MaxStatementCacheSize`, `OptimizeForFirstRows`, `OuterJoinConversion`, `ParallelWorkers`, `SubQueryConversion`. Only on 4.0: `ClearGTTAtRetaining`, `RemotePipeName`, `TcpLoopbackFastPath`, `UseLegacyKernelObjectsNames`. No key holds a credential; values include paths (`AuditTraceConfigFile`, `SecurityDatabase`, `TempDirectories`, `TempTableDirectory`) | **Confirms** R3's condition on keys (none carries a credential); the drift test's reviewed list starts from these |
| Counters of virtual relations | as `ext`: the probe `SELECT CASE WHEN EXISTS (SELECT 1 FROM RDB$CONFIG) THEN 1 ELSE 0 END FROM RDB$DATABASE` has a block naming **`RDB$DATABASE` only**; `SELECT RDB$CONFIG_NAME, RDB$CONFIG_VALUE FROM RDB$CONFIG WHERE …` (6 records fetched), `COUNT(*) FROM RDB$CONFIG`, `COUNT(*) FROM MON$ATTACHMENTS`, the `MON$SERVER_PID` own-row read and an `EXECUTE BLOCK` that reads no table have **no per-table block at all**: `records fetched` and a performance line (`0 ms`, no fetch count) only. The first `MON$` read of an attachment named `RDB$DATABASE` and `RDB$RELATIONS` (metadata loading), later ones nothing | **Contradicts** R3's own-read condition (L-1): the agent's `RDB$CONFIG` read cannot have a block naming `RDB$CONFIG`. It also **contradicts** H1 fix 2 as applied to these records: a statement finish with no per-table block while `print_perf` is on is ambiguous and opens a split window (R1 rule 7), so every read of only virtual relations, the agent's own `CURRENT_CONNECTION` / `MON$SERVER_PID` read at every `check()` included, would open a window |

### `PLG$SRP` / `PLG$USERS` in a self-security database (open item)

**Method**: `/data/self.fdb` created embedded, `databases.conf` alias `selfsec = /data/self.fdb { SecurityDatabase = selfsec }`, the users created through it over an embedded connection (the `Srp` user manager then creates its tables in the database), then remote attaches through the alias; 4.0 and 5.0, SuperServer.

| Fact | Result | ADR impact |
|---|---|---|
| System flag and type | `PLG$SRP`: `RDB$SYSTEM_FLAG = 0`, relation type 0 (a **persistent user table**), owner `SYSDBA`; `PLG$SRP_VIEW`: flag 0, type 1 (a view); the `SEC$` relations: flag 1, type 3 (virtual) | **Confirms** M5: the closed list, not the flag, must keep `PLG$SRP` out of Discovery |
| Grants on `PLG$SRP_VIEW` | `PUBLIC` holds `SELECT` and column `UPDATE` on `PLG$SRP_VIEW` | — |
| Readability | `PLG$SRP`: denied to `min` and `none`, **readable by `ext`** (4 rows). `PLG$SRP_VIEW`: **1 row for `min`, `ext` and `none`** (each account's own verifier and salt), 4 for `SYSDBA` | **Contradicts** decision 4's one-bit probe: "a readable verifier or hash relation (`PLG$SRP`, `PLG$USERS`, their views) is a refusal" refuses **every** account, the minimal one included, on a self-security database, because `PLG$SRP_VIEW` shows each user its own row. The probe cannot tell its own row from every row. With `ext`, the refusal is right (`PLG$SRP` is readable) |
| `PLG$USERS` | Not measured: `CREATE USER … USING PLUGIN Legacy_UserManager` failed ("table `PLG$VIEW_USERS` is not defined"); the legacy user manager needs a security database built with its own schema | Still open |

### Residual A — `SEC$GLOBAL_AUTH_MAPPING` is not filtered

Two global mappings created by `SYSDBA` (`FROM USER OTHER_U TO ROLE …` and `FROM USER AGENT_NONE TO USER OTHER_U`) and one local mapping: `min`, `ext`, `none` and `OTHER_U` each see **both global mappings** (`SEC$MAP_NAME`, `SEC$MAP_FROM`), and the local one in `RDB$AUTH_MAPPING`, on 4.0 and 5.0. **Result**: a plain account sees every user's global mappings. Per the lot 1 residual A, if `SEC$GLOBAL_AUTH_MAPPING` stays on the `credential_relation_readable` probe list, any global mapping makes every account report that label; the table should leave the probe list (its readability is universal), while the lot 1 mapping refusal, which reads it, keeps working.

### 12b, 12c, 13b — sections, aliases and `databases.conf`

**Method**: `databases.conf` with `appalias = /data/app.fdb`; one server start per trace configuration (obligation 11: the configuration is read at start); each probe a statement with a unique marker; 4.0 and 5.0, SuperServer and SuperClassic (identical per version).

| Case | Configuration | Result | ADR impact |
|---|---|---|---|
| 12b, alias section | default section disabled; `database = appalias` | **4.0.7**: logs the attaches through `appalias` only. **5.0.4**: logs the attaches through `appalias` **and** through `/data/app.fdb` (the path is printed as given) | Version-dependent; R2 rule 4's fail-closed evaluation (resolved path and every alias) covers both |
| 12b, path section | default disabled; `database = /data/app.fdb` | Both versions: logs the attaches through the path only; an attach through `appalias` (or an alias added later) is **written nowhere** | Under a path-only configuration a client attaching through an alias leaves no record, so there is nothing to mark ambiguous: R2 rule 4's requirement that every alias mapping to a declared database be evaluated is what catches it |
| 13b, inheritance | default section enabled with every key; `database = /data/app.fdb` with only `enabled` and `log_filename` | The path's statement was written to the named section's log with a per-table block (it took 0 ms, so `time_threshold`, `log_statement_finish` and `print_perf` came from the default section); the alias and the other database were written to the default log only | **Confirms** R2 rule 4: effective settings are the default's overridden by the first matching section's; sections do not accumulate |
| 13b, matching section disabled | default enabled; `database = /data/app.fdb` with `enabled = false` | The path's attaches are **written nowhere** (the default section does not apply once a named section matched) | Confirms first match |
| 13b, plain file name | default disabled; `database = app.fdb` | **No match** (nothing written) | **Confirms** R2 rule 4 (a plain file name is not a match) |
| 13b, case | default disabled; `database = /DATA/APP.FDB` | **No match**: path matching is case-sensitive (Linux) | Confirms exact matching |
| 12c, alias case | attach through `APPALIAS` | Not resolved: the server opens `APPALIAS` as a file name (I/O error) | Alias lookup is **case-sensitive**: confirms R2 rule 1 (a case variant is not the alias) |
| 12c, change while running | server running; `newalias = /data/app.fdb` added, then `appalias` pointed at `/data/other.fdb` | Both took effect **at the next attach, without a restart**: `newalias` attached, `appalias` then opened `/data/other.fdb` (`MON$DATABASE_NAME`) | R2 rule 5's fail-closed rule is the right direction (the change is live at once), and an alias added while the server runs with no section of its own is not logged at all until the agent's `stat` sees the change |
| 12c, per-database keys | `AuditTraceConfigFile` set inside a `databases.conf` block for an alias | **Ignored**: that alias's records went to the `firebird.conf` audit configuration's log, the second configuration's log was never created. `AuditTraceConfigFile` is not among the per-database keys the image's `firebird.conf` lists | No per-database key changes the trace configuration; `RemoteAccess = false` only turns remote attaches into `UNAUTHORIZED ATTACH_DATABASE` records |

### True Classic mode (open question 9, R1 rule 10)

**Method**: `ServerMode = Classic`, the `firebird` binary started as uid 84 (no socket activation); a held session, 5 sequential and 8 concurrent attaches; 4.0 and 5.0.

| Fact | Result | ADR impact |
|---|---|---|
| Processes | The listener (uid 84) forks **one process per connection** (uid 84, parent the listener); `MON$SERVER_PID` is the child's pid, a new one for each connection | **Confirms** R1 rule 10 (the pid is not a run constant) |
| Peer uid | The listening socket and each connection's server-side socket are uid 84 in `/proc/net/tcp`; the connection's socket is held by the child whose pid is `MON$SERVER_PID` (found through `/proc/<pid>/fd` read as uid 84) | **Confirms** the peer-uid rule of decision 3 under Classic (socket activation by a service manager not tested) |
| Header tokens | Each child writes its records (its own security-database attachments included) under its own pid; the listener writes none; `TRACE_INIT` / `TRACE_FINI` per attachment. Every child uses the **same two addresses** (5.0.4: `…6040` and `…7cc0` of one base; 4.0.7: likewise two), so the address carries almost no information | **Confirms** R1 rule 10: Classic stays Limited |

### Lot 3: summary of contradictions

To carry into an ADR-0060 refinement before the Audit lot:

1. **8c, `TRACE_INIT` / `TRACE_FINI` in SuperServer** — per attachment, as in SuperClassic, on 4.0.7 and 5.0.4; nothing brackets the server run. R1 rule 2's SuperServer handling (a `TRACE_INIT` with the current pid triggers a stop; a second one is ambiguous) would stop or mark every attachment.
2. **8e, the Garbage Collector** — in SuperServer, each database open creates a Garbage Collector attachment that writes transaction records with no `ATTACH_DATABASE`, above the watermark: ambiguous under R1 rule 5 at every open.
3. **8e, attach-order tolerance** — 4.0.7 SuperServer wrote `ATTACH_DATABASE` records up to 30 ids (a whole burst) out of order, about 1 s late, when a burst opened the database; the proposed constant tolerance of 16 does not hold.
4. **3b, records without a per-table block** — reads of virtual relations only (`RDB$CONFIG`, `MON$*`, the agent's `MON$SERVER_PID` read) have no block: R3's own-read condition cannot hold as written, and H1 fix 2 / R1 rule 7 would open a split window at every such statement.
5. **3b and the self-security database** — `ext` reads every verifier in `PLG$SRP`, so R3's "server configuration, not user data" does not hold there (decision 4 refuses `ext` there, as it should); and `PUBLIC`'s own-row `PLG$SRP_VIEW` makes decision 4's one-bit probe refuse **every** account on a self-security database.
6. **Failed logins** — a wrong password writes no `FAILED ATTACH_DATABASE` (any `AuthServer`); the first round's obligation 9 note and decision 6's failed-login counting from those records do not hold. Wrong passwords are visible only in the security database's records, if at all.

Confirmed: 7b; 8a; 8b; 8d; 8f (no field escapes line breaks except conversion-error values, so the misattribution residual stands and rule 9 applies); 12b (version-dependent, covered fail closed), 12c and 13b; Classic (Limited, peer uid holds); residual A (not filtered). Still open: `PLG$USERS` in a self-security database (needs a legacy-schema security database), Classic under socket activation, and the `sysdba_mapped` and `op_cancel` items listed by the refinement.
