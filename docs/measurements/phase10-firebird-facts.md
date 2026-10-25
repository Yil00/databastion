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
