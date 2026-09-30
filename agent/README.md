# DataBastion agent

Rust Cargo workspace for `databastion-agent`, the single agent binary with
per-engine connectors ([ADR-0002](../docs/adr/0002-single-agent-connectors.md)).

> **Status: P1-B part 1.** `agent.yaml` configuration, enrollment, `0600`
> identity storage, HTTPS uplink, heartbeat and jobs loops, secret rotation
> (ADR-0008). No spool, local engine detection, Discovery or Audit yet:
> `discovery.scan` / `audit.configure` jobs are reported `failed`
> (`unsupported`).

## Layout

| Crate | Path | Role |
|-------|------|------|
| `databastion-agent` | `crates/agent` | Binary: CLI (`--config`), JSON logs, connector selection by Cargo feature |
| `databastion-core` | `crates/core` | `Connector` trait, `Engine`, `AuditLevel`, `TargetHealth`, sinks, `agent.yaml`, enrollment, runtime (heartbeat / jobs), crate-private HTTPS uplink and session |
| `databastion-classifiers` | `crates/classifiers` | Classifiers and `masking` (the only producer of uplink-bound data) |
| `databastion-connector-postgres` | `crates/connector-postgres` | PostgreSQL connector: Discovery and `check()` (P2-B), Audit (P4-A, [README](crates/connector-postgres/README.md)) |
| `databastion-connector-mysql` | `crates/connector-mysql` | MySQL / MariaDB connector: Discovery and `check()` (P2-C), Audit (P4-B, [README](crates/connector-mysql/README.md)) |
| `databastion-connector-mongodb` | `crates/connector-mongodb` | MongoDB connector: Discovery and `check()` (P5-A, [ADR-0026](../docs/adr/0026-mongodb-connector.md), [README](crates/connector-mongodb/README.md)); Audit from the `auditLog`, the server log or the profiler (P5-B, P5-C, [ADR-0027](../docs/adr/0027-mongodb-audit.md)) |
| `databastion-connector-openldap` | `crates/connector-openldap` | OpenLDAP connector: Discovery, `check()` and Audit through `cn=accesslog` (phase 6, [ADR-0029](../docs/adr/0029-openldap-connector.md), [README](crates/connector-openldap/README.md)) |
| `databastion-protocol` | `crates/protocol` | Protocol types generated from `shared/protocol/openapi.yaml` (used by the uplink only) |
| `databastion-protocol-codegen` | `crates/protocol-codegen` | Developer tool: regenerates `crates/protocol/src/generated.rs` (not linked into the binary) |

Dependency direction: `classifiers` ← `core` ← `connector-*` ← `agent`;
`protocol` ← `core` (uplink only, not re-exported).

### Cargo features (binary)
`postgres`, `mysql`, `mongodb`, `openldap`: all enabled by default. A minimal
binary: `cargo build --no-default-features --features postgres`.

## Security boundaries

### Masking boundary (invariant I2)
- Connectors never get the uplink; they push results into `FindingSink` /
  `EventSink` from `core`. The uplink module is crate-private in `core`:
  connectors can neither name nor construct it. The core runtime (to come)
  will own it; the binary only gets that runtime.
- Sinks and the uplink only accept `MaskedFinding` / `MaskedEvent` from
  `classifiers::masking`. These types hold no caller-provided `String`: a
  `MaskedSample` only comes from `masking::mask`, the classifier is a closed
  `ClassifierId` created inside `classifiers`, and a `MaskedFinding` is built
  only from those. `compile_fail` doctests in `masking.rs` prove a connector
  cannot build them from a string.
- Raw values are wrapped in `RawSample`: redacted `Debug`, no `Display`, no
  serialization, and `expose()` is crate-private to `classifiers`.

### Results path: normalization, sanitization, spool (ADR-0009)
- Names: `classifiers::names` is the only producer of `NormalizedName`
  (array indices of up to 6 digits → `[]`; value-like segments such as any
  segment with more than 6 digits (dates, phone or customer numbers), UUIDs,
  e-mail addresses → `*`, LDAP entry DN → parent container, attribute types
  lowercased, anything non-conforming → `*`). A `FindingLocation` is built
  only from `NormalizedName`s. Property tests
  (`crates/classifiers/tests/names_props.rs`, deterministic generator, no
  extra dependency) check every output against the generated `Identifier`
  type and its `not` rule. Classifier matches are located in the whole name,
  so a value split across separators is masked (`a.0612.345678` -> `a.*`);
  connectors that know the real keys use `normalize_field_path`
  (`contacts.*.phone`). Gate property tests: generated names embedding split
  cards, phones, IBANs and e-mail addresses never survive (see
  `crates/classifiers/README.md`).
- Conversion: `uplink::to_batches` is the single conversion from
  `MaskedFinding` / `MaskedEvent` to `FindingsBatch` / `EventsBatch`. Each
  item goes through `sanitize` (the `NOT_ENFORCED_BY_SERDE` keywords for sent
  types: `not` → `*`, `confidence` / `sampled` / `matched` ranges and
  `matched <= sampled`, `maxItems` / `uniqueItems` of samples, fingerprints,
  objects and signals, the `read` / `write` object requirement, `Count`
  ranges); an item still invalid is dropped and counted. Batches hold at most
  200 findings / 500 events and 1 MiB serialized, each with a fresh UUIDv7.
- Account names: control / format characters stripped, truncated on a
  character boundary; a non-conforming name goes to `db_user_fingerprint`,
  computed with the agent HMAC key in the `db_user` domain. `MaskedEvent` has
  no content yet (P4): no event reaches the spool today.
- HMAC key: `<state_dir>/hmac.key` is loaded once at startup into a
  `classifiers::masking::HmacKey` (keyed state, zeroized on drop, redacted
  `Debug`) held by the runtime and shared with scan jobs. Findings carry the
  masked samples and fingerprints of `MaskedFinding`; heartbeats and findings
  batches report `classifiers_version` (`CLASSIFIERS_VERSION`).
- Job parameters (`core::job`): `discovery.scan` / `audit.configure`
  parameters reach a connector only through `ScanParams::try_from` /
  `AuditParams::try_from` (contract ranges, empty filter lists and unknown
  or duplicate classifier ids refused → `invalid_params`), then
  `ScanJob::new` / `AuditConfig::new`, which clamp to `limits` in
  `agent.yaml`. A statement timeout is never `0`: a requested `0` becomes
  `limits.statement_timeout_ms`. Scans run in a scan worker next to the jobs
  loop (at most 16 queued, one at a time), so `rotate` / `reload` jobs never
  wait behind a scan. A scan is stopped at its clamped duration (`timeout`)
  and when the agent is suspended or revoked (`cancelled`); findings are
  spooled per chunk of 500, the partial chunk is flushed on every exit, and
  findings that cannot be spooled are counted (`findings_lost_total`). The
  terminal status of a scan waits until the console has answered every
  findings batch of the job (P2-G), for at most 2 minutes; it does not wait
  for a cancelled scan, while `/findings` is parked after a `501`, while the
  spool worker is backing off (console unreachable, `5xx`, `429`), once the
  agent is suspended, or on shutdown. A status sent with batches still
  spooled is counted (`scan_status_before_flush_total`); the batches are
  sent later (the console accepts them for 24 h after the status).
- Spool: `<state_dir>/spool/`, one `0600` file per batch written with
  tmp + `fsync` + `rename` + directory `fsync`; stale temporary files are
  removed at startup, unreadable files are moved to `spool/quarantine/` (32
  kept) and counted (`quarantined`), never crash the agent and are never
  logged. Bounded by `spool.max_bytes` (default 256 MiB) and
  `spool.max_batches` (default 10000). When full, a batch is dropped by
  priority (phase 7): findings and events each keep up to 3/4 of the bounds
  against the other, so an events flood cannot evict the findings; within
  the events, batches holding a `signature.*` signal (packed apart from the
  others) are dropped last, and a new batch without one is dropped rather
  than evict them; within a class, the oldest goes first. FIFO send:
  `2xx` (including `duplicate: true`) removes the batch; `400` / `404` whose
  pointers all designate items → those items dropped, the rest resent under
  a new `batch_id` at the same queue position; `413` → two halves with new
  ids (a single item is dropped); `409 batch_conflict` → dropped, counted
  (`batch_conflicts_total`), warned, never resent; other `4xx` with a
  parseable contract `Error` body → dropped. Anything that is not a contract
  answer (a proxy's HTML `200`, a bare `404` / `409`, an unparseable or
  mismatched `BatchAck`) is kept, counted
  (`batches_unexpected_response_total`) and retried, so a middlebox cannot
  empty the spool. Network / `5xx` / `429` → kept and retried; retries back
  off exponentially (1 s doubling to 5 min, full jitter) over consecutive
  failures. `401` / `426` → kept (spooling continues within bounds). Stored
  bytes are sent verbatim (parsed only for `batch_id`, item count and
  splitting). Quarantine is only for unparseable files or files refused by
  the state-file checks (symlink, owner, mode, not regular; opened with
  `O_NONBLOCK` so a planted FIFO cannot block); transient errors (`EMFILE`,
  `ENOMEM`) are retried. `spool_quarantined_total` is exported in the
  heartbeat metrics. Real stats go into the heartbeat `spool` section.

### Local engine detection (ADR-0006, I5)
`detect` looks at the agent host only, read-only, with no network I/O: a
fixed list of Unix socket paths under `/run`, `/var/run`, `/tmp`,
`/var/lib/mysql` (`lstat`, never connect); `LISTEN` entries of
`/proc/net/tcp{,6}` for ports 5432 / 3306 / 27017 / 389 / 636 (the address is
never reported); `/proc/<pid>/comm` for `postgres`, `mysqld`, `mariadbd`,
`mongod`, `slapd` (never the command line). Declared targets are excluded
(same socket; loopback host with the same port; a local target of the same
engine family hides the process entry). At most 16 entries, reported as
`detected_targets` in the heartbeat. Detection runs in `spawn_blocking` and
is cached for 5 minutes (reset on `agent.config.reload`). The host root is
injectable; tests use fixture trees.

`/proc/net/tcp{,6}` only lists sockets of the agent's **network
namespace**: an agent running in a container (without host networking)
detects no listening port of the host, and its `/proc` shows only its own
processes. Sockets are only seen if their directory is mounted in.

### Guards
`crates/agent/tests/architecture.rs` checks that connectors do not depend on
an HTTP client or `socket2` (including `[dependencies.x]` tables and
`package = "…"` renames) nor reference the uplink, that no listening or raw
socket API appears in any crate's `src/`, `tests/`, `examples/`, `benches/`
or `build.rs` (I1), and that `Cargo.lock` contains no OpenSSL / native-tls.
These are text-level guards against honest mistakes; the types and code
review remain the primary controls.

### Uplink, TLS and state files
- reqwest `default-features = false`, features `rustls-tls-native-roots` +
  `json`: rustls only, **`ring`** crypto provider (reqwest's
  `__rustls-ring`; no `aws-lc-rs`, so no C/CMake build and no extra
  license), trust roots from the system store (`rustls-native-certs`, which
  pulls the pure-Rust `openssl-probe` path finder, not OpenSSL). `webpki-roots`
  (`rustls-tls`) was not used: it bundles a fixed root set under
  CDLA-Permissive-2.0 and ignores the enterprise CAs of the host store.
  `console.ca_file` pins a single CA (built-in roots disabled).
- TLS 1.3 minimum, no redirects, no http2 / cookies / compression,
  30 s request timeout (`wait + 15` s for the long-poll), 1 MiB response cap.
  `http://` only with `insecure_dev_http: true` **and** an IP-literal
  loopback URL (`127.0.0.1` / `[::1]`, not `localhost`); such a client never
  uses a proxy. Otherwise `HTTPS_PROXY` / `NO_PROXY` are honoured.
  `console.ca_file` may hold a PEM bundle (all certificates trusted, built-in
  roots disabled).
- `<state_dir>/identity.json` (agent id, secret, pending rotation secret)
  and `<state_dir>/hmac.key` (32 random bytes, never transmitted) are
  `0600`, written atomically (temp file, fsync, rename, directory fsync).
  `state_dir` must be a real directory owned by the agent user and not
  group / world writable (a mode other than `0700` warns). State files are
  opened with `O_NOFOLLOW` (`rustix`) and checked on the handle: regular
  file, owned by the agent user, no group / other access.
- Enrollment refuses a token file readable by others. `enroll --force`
  replaces the identity (revoke the old agent in the console first) and keeps
  the HMAC key unless `--new-hmac-key`.
- Rotation (ADR-0008): a `/rotate` attempt with an unknown outcome keeps S1
  first; S0 is preferred only after S1 got a `401` following the latest
  attempt. Up to 8 rotate job ids satisfied by the pending / promoted secret
  are persisted (redelivery acknowledged without a new secret); a new
  rotation within 60 s of a promotion is deferred.
- `long_poll_wait_s` is `5..=25` (below 5 only with `insecure_dev_http`),
  and a poll returning in under 1 s without jobs is followed by at least
  1 s plus jittered backoff. A config reload that changes `console.*` or
  `state_dir` is refused (`invalid_params`).
- Console-provided `heartbeat_interval_s` is clamped to [10, 300], values
  `<= 0` are ignored. The heartbeat runs the targets' `check()`
  concurrently under one 10 s deadline, so it waits at most 10 s for all of
  them (P2-G); targets reaching the same account (engine family, host or
  socket, port, account) are checked one at a time, so an account holds at
  most one check next to one scan; Audit streams hold their own connections
  outside these turns (sizing in ADR-0025 decision 11). The account key
  recognizes aliases (phase 7, `crates/core/src/checks.rs`): an omitted port
  and the engine's default one, host names in any case or with a trailing
  dot, IP literal forms (`[::1]`, `::ffff:127.0.0.1`), `localhost` and the
  loopback addresses, a socket path through symlinks, and host names that
  resolve to a shared address. Names are resolved only when two targets of
  one engine family, account and port name different hosts: through the
  system resolver (the declared targets only, as the connectors resolve
  them anyway; no scan, I5), at most 1 s and within the deadline, cached
  5 minutes; a name not resolved in time keeps its literal key. A check
  still running at the deadline is reported unreachable with `timeout` and
  the `check.timed_out` note, and takes the last turn of its account at the
  next heartbeats (the other targets of the account rotate), so a hung
  check no longer uses up the deadline of the others every time. A target
  whose turn did not come before the deadline (account busy) is reported
  the same way (the contract has no other status) but logged apart and
  counted in `checks_account_busy_total`, next to `checks_timed_out_total`
  (heartbeat metrics). At most 16 jobs are handled per poll, each parsed on
  its own; an unparseable job is reported `failed` (`unsupported` /
  `invalid_params`) when its `job_id` is readable.
- Access event timestamps (`ts`, `ts_last`) come from the target's audit
  records and are clamped to the agent clock when the events are spooled, so
  a target clock running ahead cannot make the console reject a batch as
  future-dated (`formatMaximum`). The agent clock itself must stay within
  5 min of the console's: run NTP on the agent host. Batches spooled by an
  older agent are resent unchanged; after an upgrade, their future-dated
  items can still be rejected once (only those items are dropped).
- HTTP tests use `wiremock` (dev-dependency, 127.0.0.1, test code only).
  `deny.toml` sets `[graph] exclude-dev = true`: the hyper `server` feature
  it needs is never linked into the binary, and the bans stay strict for
  the shipped graph. `deny-dev.toml` checks licenses and sources of the full
  graph, dev-dependencies included.

### Audit streams that panic
A connector call that panics fails that call only (`crate::panics`).
Connectors parse every audit record in isolation (`databastion_core::isolate`),
and the file sources also convert each record (PostgreSQL: each statement's
group of records) to events in isolation, as do the polled sources for each
statement (`performance_schema`: its conversion; `pg_stat_statements`: its
text's analysis and its conversion; the MongoDB profiler: each entry): a
record that makes that code panic is dropped alone and counted (`audit.records_dropped`, per record; and the
heartbeat metric `audit_record_panics_total`, one per isolated unit that
failed, a record or a statement's group, which tells crafted-record campaigns
apart from malformed input). A panic in a blocking parse task is resumed on the stream,
never turned into an ordinary error that restarts it in a loop
(`databastion_core::resume_panic`).

A panic that still ends the stream is handled by the core: a stream with a
saved position (the cursor files it uses) is restarted in **isolation mode**
(`CursorStore::isolate`: for its first read round it hands over and saves its
position after every record, the OpenLDAP stream also saving the entry being
handed over), so a panic that comes again is at the exact record at fault;
after 3 panics at that exact position, the stream is asked to skip **that one
record** (`CursorStore::skip_records`, applied only when the saved position is
still the one the panics happened at; counted as dropped, and in
`audit_records_skipped_total`). Only the OpenLDAP accesslog stream can skip;
the file sources rely on per-record isolation. A stream is stopped until Audit
is reconfigured or the agent restarts (`audit.stream_stopped`) after 7 panics
at one position with no progress between them, more than 8 skips or 64
panics within an hour, or 3 panics in a row on a source whose position is in
memory (restarted afresh anyway). A stream that fails is restarted after its
backoff, at least its poll interval (up to 3600 s) and at most 300 s or the
poll interval when longer.

### Failed-login flood
A client that can reach the database port can try many made-up account
names, each its own `auth_failure` group (ADR-0025, docs/08). Per target
and aggregation window, the core keeps at most 100 `auth_failure` groups;
beyond, a failed login joins an **overflow** event: an `auth_failure` of an
unidentified account (a `db_user` fingerprint, as for any failed login),
per client address for at most 16 addresses, then one without address,
whose `aggregated_count` is the number of attempts and whose `ts` /
`ts_last` span them. No attempt goes uncounted, and a flood gives at most
117 `auth_failure` events per window instead of one per name. Folded
attempts are counted in `auth_failures_overflowed_total` (heartbeat
metrics). With the spool priorities above, a later dump's
`signature.*` batches are kept, though they still queue behind earlier
batches for sending.

### Audit state kept across restarts
Under `<state_dir>/audit/` (`0700`), every file `0600`, owned by the agent
user, written atomically (temporary file, `fsync`, `rename`, directory
`fsync`), read with `O_NOFOLLOW` and a size bound, and never holding a value,
a statement or a query text:
- read positions (`<target>.<name>.cursor`, at most 64 KiB): the file sources'
  offsets, the OpenLDAP accesslog CSNs, and (phase 7) the MySQL / MariaDB
  `performance_schema` cursor (end timers, statement ids, the server's start
  time) and the MongoDB profiler positions (per database, a time and SHA-256
  hashes of the entries read at it). They are saved once the events read
  before them are handed to the core (at-most-once delivery);
- (phase 7) the agent's own-account row counters
  (`<target>.own_usage.counters`, at most 2 MiB: normalized object names and
  rows per hour over the last 24 h), saved at most every 30 s while charging
  and when a stream ends, so an agent restart does not give a fresh
  Discovery budget per object. A file that is not understood is ignored
  (counted from zero), as before persistence; hours ahead of the agent's
  clock count as the current hour; when the file would exceed its bound, the
  objects read longest ago are left out (logged).

### Logs
`DATABASTION_LOG` sets the filter, but targets outside `databastion_*` are
capped at `warn`: drivers and HTTP clients may log parameters or payloads at
debug/trace level.

### Audit log files
Every file source (the PostgreSQL server log, the MariaDB `server_audit` log,
the MySQL `audit_log` / `audit_log_filter` JSON file, the MongoDB `auditLog` and
server log) is read by the core tailer (`crates/core/src/audit/tail.rs`):
opened without blocking, it must be a regular file, and it must **not be
writable by the agent's own account**: not owned by the agent's effective uid,
not world-writable, and not group-writable when its group is one of the
agent's (effective or supplementary groups). This is checked on the opened
handle, so after following symlinks (end-of-phase-4 review L4). An audit log is
the database server's evidence: a file the agent's account could write could
have been forged or rewritten by it. Such a file is refused like an unreadable
one: `check()` reports `audit.log_not_readable`, the Audit stream re-evaluates
its source, and the agent logs `audit log refused`. **Consequently, an agent
running as root while the log belongs to root, or running as the database's
own user, gets `audit.log_not_readable`**: run the agent as its own user and
give it read access through a group without write permission or an ACL on a
file the server owns (for instance `0640`, owner `mysql`, group
`databastion`). Tests enable their own files through
`allow_agent_owned_logs_for_tests()`, compiled only for tests and the core's
`test-support` feature (enabled from the connectors' `[dev-dependencies]`),
and only test code calls it (guarded by `crates/agent/tests/architecture.rs`).

### PostgreSQL connector
tokio-postgres with the connector's own rustls adapter
(`crates/connector-postgres/src/tls.rs`: `verify_full` against a pinned CA or the system
store; `disable` for a Unix socket or loopback literal; `disable_insecure`, an explicit and
warned opt-in, on a network). The connector opens the connection itself (`src/net.rs`) and,
without TLS, refuses cleartext and MD5 password requests before the driver answers (SCRAM
only). Chosen over sqlx for its cancel requests (server-side
cancellation of a dropped statement) and its explicit extended-protocol API. It follows the
[ADR-0012](../docs/adr/0012-postgresql-agent-grants.md) obligations:

- scope: tables and materialized views read `FROM ONLY`; partitioned tables through their
  leaves (reported under the root); never foreign tables, system schemas, extension objects
  or the credential-bearing catalogs; RLS tables are sampled only when their `SELECT` policies
  (the stored expression, scanned locally, plus `pg_depend`) use allow-listed node types and
  immutable `pg_catalog` functions / operators / I/O coercions outside a denylist (`query_to_xml`
  and the other SQL-text or run-time name functions), or a few stable built-ins
  (`current_setting`, `now`…); others, and leaves / children of an RLS ancestor, are skipped
  and reported as not covered;
- every unit of work in `BEGIN TRANSACTION READ ONLY` with `SET LOCAL` `statement_timeout`
  (clamped job parameter, never `0`), `lock_timeout` and `idle_in_transaction_session_timeout`;
  `search_path = ''`, `pg_catalog`-qualified built-ins only, catalog identifiers quoted by one
  function, no expression on sampled columns (binary values decoded in Rust);
- transactions are committed before `FindingSink::submit().await`; a statement whose future is
  dropped gets a cancel request; a sample stopped at its byte budget (32 MiB per relation,
  checked per row) is cancelled, not drained, and the next object uses a new session;
- server messages are reduced to a SQLSTATE and a stage; notices are discarded;
- `check()`: reachability, audit level (Limited with `pg_stat_statements` and
  `pg_read_all_stats`; Full is not reported before the audit log path exists, P4-A),
  over-privilege and coverage (logged, summarized in the target detail).

Target settings: the `postgres` block of a target in `agent.example.yaml`. Integration tests
(`src/it.rs`) run against the dev environment or `dev/postgres/local-cluster.sh` when
`DATABASTION_TEST_PG_URL` (and, for the ADR-0012 fixture probes,
`DATABASTION_TEST_PG_ADMIN_URL`) is set, and are skipped otherwise:

```sh
eval "$(../dev/postgres/local-cluster.sh start)"   # or the dev/.env values with `make dev`
cargo test -p databastion-connector-postgres -- --nocapture
../dev/postgres/local-cluster.sh stop
```

### MySQL / MariaDB connector
No driver crate: the connector speaks the text client protocol itself
(`crates/connector-mysql/src/proto.rs`, `auth.rs`, `conn.rs`) over tokio and the same
rustls crates (`ring` provider). The available pure-Rust drivers (mysql_async) cannot refuse
the RSA public-key retrieval of `caching_sha2_password` nor choose the capability flags, and pull
the `rsa` crate (RUSTSEC-2023-0071, no fix). Owning the protocol lets the connector:

- never set `CLIENT_LOCAL_FILES` (and refuse a `LOCAL INFILE` request anyway),
  `CLIENT_MULTI_STATEMENTS` or compression; keep only the error number and SQLSTATE of an
  error packet (the message is never stored); read rows one packet at a time (zeroized buffers);
- authenticate by transport: `caching_sha2_password` (scramble) everywhere, its full
  authentication (the password itself) only over TLS or a Unix socket, never through RSA key
  retrieval; `mysql_native_password` over TLS, a Unix socket or a loopback literal, never on a
  network without TLS; every other plugin (`mysql_clear_password`, PAM `dialog`,
  `sha256_password`, `client_ed25519`, GSSAPI) refused before any password-derived byte;
- TLS: `verify_full` (default) against a pinned CA or the system store, host name or IP SAN
  checked; the server must offer TLS; `disable` only on a Unix socket or loopback literal;
  `disable_insecure`, an explicit and warned opt-in, on a network.

Behavior:

- sessions verified after setup: `sql_mode` pinned (`NO_BACKSLASH_ESCAPES`, never
  `ANSI_QUOTES`), utf8mb4, `SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY`,
  `wait_timeout` 60 s (idle sessions are replaced after 45 s), `net_read_timeout` /
  `net_write_timeout` 30 s, `lock_wait_timeout` / `innodb_lock_wait_timeout` 2 s, MariaDB
  `idle_(readonly_)transaction_timeout` 10 s, and the statement timeout (`max_execution_time`
  on MySQL, `max_statement_time` on MariaDB; clamped job parameter, never `0`), also set per
  sampling statement (optimizer hint / `SET STATEMENT … FOR`); a server connection id that
  differs from the handshake (a proxy) is refused, since `KILL QUERY` could not reach it;
- every unit of work in `START TRANSACTION READ ONLY` (the OK status must show a read-only
  transaction), committed before `FindingSink::submit().await`; a statement whose future is
  dropped is killed from a separate connection (`KILL QUERY <id>`); a sample stopped at its
  byte budget (32 MiB per table, checked per row) is killed, not drained, and the next table
  uses a new session;
- scope: base tables of local engines (InnoDB, MyISAM, Aria, MEMORY, ARCHIVE, RocksDB,
  TokuDB) outside `mysql`, `sys`, `information_schema`, `performance_schema`; never views
  (definer code), `FEDERATED` / `CONNECT` / `SPIDER` / `S3` / `SPHINX` / NDB tables (I5),
  merge tables or other engines; never virtual generated columns; a partitioned table is one
  table. The introspection reads no statistics column (`TABLE_ROWS` opens the handler, and a
  `FEDERATED` handler connects to its remote server; MariaDB opens the table before applying an
  `ENGINE` filter): in the sampling transaction the engine is read alone and checked again, and
  `TABLE_ROWS` is only asked for a local table;
- sampling: `LIMIT sample_rows` (no `ORDER BY RAND()`: a full scan and sort), also enforced on
  the client (a server sending more rows is stopped); text columns as `LEFT(col, 4096)`, values
  cut to 4096 bytes in Rust; every value charged its length plus 16 bytes to the budget (NULL and
  empty values included); at most 1024 columns per statement, so that a row stays far below the
  largest accepted packet (40 MiB); a table whose row is still too large is skipped and reported
  as not covered, the scan goes on; character, JSON, `int` / `bigint` / `decimal` and `date`
  columns only;
- `check()`: reachability; audit level and source with the Audit stream's rule (Partial from
  a readable `server_audit` / `audit_log` JSON file once a record was read, or from the
  `events_statements_history_long` consumer and those it depends on; Limited with the
  per-thread consumers only; never Full: no source gives both every statement and its rows;
  see [crates/connector-mysql/README.md](crates/connector-mysql/README.md));
  over-privilege (any global privilege including `SELECT ON *.*`, privileges beyond `SELECT`,
  `WITH GRANT OPTION`, `SELECT` on `mysql` / `sys`, `SELECT` on `performance_schema` while no
  Audit stream runs; a database grant is a `LIKE` pattern, so `%`, `m%` or
  `performance\_schema` count as the system database they match), `init_connect`, and
  coverage (views, engines). A privilege list that is cut at its `LIMIT` or has an unreadable
  row leaves the privileges not evaluated. The same rules apply to
  the privileges held through roles (P4-D): every role in `information_schema.APPLICABLE_ROLES`
  (granted directly or through a role, MySQL mandatory roles, the MariaDB default role; enabled
  or not). MySQL: `SHOW GRANTS FOR CURRENT_USER() USING …` with the direct and mandatory roles
  (at most 16; names written into the statement only when they match an allow-listed charset),
  which covers every role. MariaDB shows a role's grants to a least-privilege account only for
  the session's current role: `SHOW GRANTS FOR CURRENT_ROLE` evaluates the default role, and
  every other applicable role is reported as not evaluated. `WITH ADMIN OPTION` counts as a
  grant option. A role whose grants cannot be read or parsed is reported as
  `privilege.roles_not_evaluated`. On MariaDB 10.11 and later, the privileges granted to
  `PUBLIC` (held by every account, not listed in `APPLICABLE_ROLES`) are read with
  `SHOW GRANTS FOR PUBLIC` (no privilege needed; "no such grant" means none) and evaluated the
  same way (phase 7); when they cannot be read or parsed, or `PUBLIC` is granted a role, `PUBLIC`
  counts as a role not evaluated. When `APPLICABLE_ROLES` cannot be read (MySQL before
  8.0.19, or any error), the roles are counted from the role lines of the account's own
  `SHOW GRANTS FOR CURRENT_USER()` (and MySQL's `mandatory_roles`), all as not evaluated; when
  that cannot be read or has a line the parser does not understand, the privileges are reported
  as `privilege.not_evaluated` (fail closed);
- Audit (P4-B): access events from the `server_audit` log or the `audit_log` /
  `audit_log_filter` JSON file (`mysql.audit_log`, tailed by the core with a persisted cursor),
  or from `performance_schema` (`DIGEST_TEXT` first); statement text analyzed by the MySQL
  dialect of the query normalizer only, never sent or logged; signals `signature.mysqldump`,
  `signature.into_outfile`, `shape.full_table_read`, `volume.large_result`. With `extended_grants: true` on the target (ADR-0018 extended variant), a global
  `SELECT` is an expected warning instead of over-privilege; the system schemas are never read
  either way.

`disable_insecure` accepts the `caching_sha2_password` fast path only, and its scramble
(SHA-256, no key stretching) can be brute-forced offline by anyone who sees it; an attacker on the
path can force that exchange with an auth switch. Use it only on an isolated network, with a long
random password.

Target settings: the `mysql` block of a target in `agent.example.yaml`. Integration tests
(`src/it.rs`) run against the dev environment (`make dev`, see
[dev/README.md](../dev/README.md#connector-integration-tests)) when `DATABASTION_TEST_MYSQL_URL` /
`DATABASTION_TEST_MARIADB_URL` (and the `_ADMIN_URL` / `_CA_FILE` variables for the probes) are
set, and are skipped otherwise; protocol refusals are also tested against a scripted server over
an in-memory stream (`src/fake.rs`).

### MongoDB connector
No driver crate ([ADR-0026](../docs/adr/0026-mongodb-connector.md) decision 1): the official
`mongodb` crate pulls `webpki-roots` (CDLA-Permissive-2.0, outside `deny.toml`) as its only trust
store without a CA file, needs Rust 1.88, compiles process spawning in, and follows the replica-set
topology to hosts the server names (I5). The connector speaks a closed subset of the wire protocol
itself (`crates/connector-mongodb/src/wire.rs`, `bson.rs`, `scram.rs`, `conn.rs`) over tokio and
the same rustls crates:

- `OP_MSG` only, one body section, no compression, no exhaust; the reply length is checked on the
  header before the body is read (16 MiB + 64 KiB), and reply buffers are zeroized; BSON parsed by
  a bounded reader that fails closed; error replies reduced to their numeric code (never `errmsg`);
- one declared host or socket, direct connection: `hello`'s `hosts` are never followed, no
  `mongodb+srv`; one connection per scan and per `check()`, no pool, no monitoring connection;
- SCRAM-SHA-256 only (SASLprep, iteration count 4096 to 100 000, derived off the async runtime, the server nonce must extend
  the client's, the server signature verified before any other command); SCRAM-SHA-1, `PLAIN`,
  X.509, Kerberos, AWS and OIDC are not supported; `authSource` from `mongodb.auth_source`
  (default `admin`);
- TLS from the first byte: `verify_full` (default) against a pinned CA (`mongodb.ca_file`) or the
  system store, host name or IP SAN checked; `disable` only on a Unix socket or a loopback
  literal; `disable_insecure`, an explicit and warned opt-in, on a network.

Behavior:

- a closed set of commands built in code (`hello`, `saslStart`, `saslContinue`, `buildInfo`,
  `connectionStatus`, `listDatabases`, `listCollections`, `count`, `find`, `aggregate` with
  `[{$sample}]` only and `allowDiskUse: false`, `killCursors`; for Audit, `whatsmyuri` and the
  profiler `find` of ADR-0027 decision 8); `maxTimeMS` (clamped job
  parameter, never `0`) and `$readPreference: secondaryPreferred` on every read; a client-side
  deadline on every exchange; no `getMore`: `find` uses `singleBatch`, `aggregate` a batch of
  `n + 1`, and a reply with an open cursor is followed by `killCursors`; no session id, so no
  server session or transaction; each collection is read by one command parsed whole before
  `FindingSink::submit().await`;
- scope: the databases and collections the account holds privileges on (`authorizedDatabases`,
  `authorizedCollections`, `nameOnly`), never `admin`, `local`, `config`, `system.*` or
  `enxcol_.*`; views are never read (their pipeline could read other collections or run
  JavaScript); time-series collections are read through their view with `find`, `limit` and a batch of
  `n + 1` (no `count`, and no `singleBatch`: the server's view conversion refuses it); one the
  server refuses is counted as not readable and reported by `check()` as
  `coverage.timeseries_not_readable` (observed in the last scan);
- sampling: `count` (metadata) as the estimate; `$sample` of `sample_rows` documents above 20 times
  that, natural order with `limit` otherwise; per document at most 20 levels, 16 elements per
  array, 512 values; per collection 1024 normalized paths; values cut to 4096 bytes;
- field paths: arrays as `[]`, keys through `names::normalize_field_path` (digit-only keys, keys
  with a dot or that look like values become `*`), object levels that are maps keyed by data
  (more than 16 distinct keys in the sample, or keys each in one document) collapsed to `*`,
  values of every raw path with the same normalized path pooled; collection names through `names::normalize_path` (`fs.files`);
- values: strings and symbols; `int32` / `int64` digits; integral doubles below 2^53; finite
  `Decimal128`; dates as `YYYY-MM-DD`; generic and user binaries only when they are UTF-8 text;
  UUID, encrypted, compressed, sensitive and vector binaries, ObjectIds, booleans, code and
  timestamps are never read;
- `check()`: reachability; the audit level and source of ADR-0027 (below); version and edition
  from `buildInfo` (the edition decides whether an `auditLog` can be used);
  over-privilege from `connectionStatus` (resolved privileges of every role): write or
  administration actions, read actions beyond `find` / `listCollections`, cluster-wide actions,
  privileges on every database, system collections or the `admin` / `local` / `config`
  databases; views not sampled. Recomputed at most every 10 minutes per target.

Audit ([ADR-0027](../docs/adr/0027-mongodb-audit.md); `src/audit/`):

- sources, one per target, chosen by the same rule as `check()` and re-evaluated every 5 minutes:
  the Enterprise / Percona `auditLog` JSON file (`mongodb.audit_log` with `format: audit_log`;
  **Partial** once a successful `authCheck` record was read in the last 24 h, which needs
  `auditAuthorizationSuccess`, Limited once any `auditLog` record was read in the last 24 h, None
  before ([ADR-0030](../docs/adr/0030-mongodb-auditlog-freshness.md); the agent's own
  authentication at each check writes one); no document counts), the structured JSON server
  log (`format: server_log`; **Limited**), or, without a usable file, the profiler of the
  databases whose `system.profile` the account can `find` (**Limited**; not on a `mongos`); the
  three sources report None (`audit.limited_pending_first_record`) until the stream read a record
  of them in the last 24 h.
  **Full is never reported**;
- files are read by the core tailer (cursor persisted, rotation followed); the profiler by one
  bounded `find` per database and poll (`ts` filter, `limit` 1000, `singleBatch`, `maxTimeMS`),
  position persisted after each poll (phase 7: per database, the last `ts` and SHA-256 hashes of
  the entries read at it; an agent restart resumes there, within what the capped collection
  still holds), a database without a saved position starting at its newest entry; the saved
  position is removed while a log file is the source;
- closed-shape facts only: command name (closed list), namespace (normalized), `name@authdb`,
  client IP, application name, document counts, a failure flag, and whether the filter has keys,
  a numeric limit and pass-through pipeline stages. Command documents are skipped by a `serde`
  visitor (`IgnoredAny`) in the files, and reduced by a fixed server-side projection on the
  profiler, so their literals are never kept, logged or sent;
- the server log has no user on slow-query lines: connections are followed by `ctx` (accept,
  client metadata and authentication lines, at most 4096); an operation on a connection that
  authenticated before the agent started reading is reported as an unidentified account;
- signals: `signature.mongodump` / `signature.mongoexport` (the client's `appName`),
  `shape.full_table_read` (a `find` without filter keys and without a limit or above 10 000, a
  pass-through `aggregate`, a `getMore` of such a cursor), `volume.large_result` (more than
  10 000 documents; log and profiler only);
- the agent's own reads are left out only for `account@auth_source`, `appName`
  `databastion-agent`, the address `whatsmyuri` returns, no signal, and the Discovery budget per
  collection and day, and only for reads (writes, DDL and DCL are always reported, for every
  engine); on the `auditLog`, only a `find` with a limit within the budget; its `count` without
  filter and, on the profiler source, its exact profiler polls (no more than it sent per database) are not charged;
- `check()` counts `find` on `<db>.system.profile` as the Audit grant only while a stream reads
  the profiler (otherwise `privilege.system_collections`); notes `audit.auditlog_on_community`,
  `audit.authcheck_success_pending`, `audit.slow_operations_only`, `audit.source_not_configured`,
  `audit.log_not_readable`, `audit.log_without_row_counts`, `audit.records_dropped`.

Target settings: the `mongodb` block of a target in `agent.example.yaml`. Integration tests
(`src/it.rs`, `src/it_audit.rs`) run against the dev `mongo` service when
`DATABASTION_TEST_MONGO_URL` (and `DATABASTION_TEST_MONGO_ADMIN_URL` for the probes and the Audit
tests, `DATABASTION_TEST_MONGO_LOG` for the server-log source, `DATABASTION_TEST_MONGO_DUMP_CMD` /
`_EXPORT_CMD` for real tool runs) are set, and are skipped otherwise; the handshake,
hostile SCRAM answers, cursor handling and a whole scan of the dev seed (checked against
`dev/ground-truth.json`) also run against a scripted server over an in-memory stream
(`src/fake.rs`).

### OpenLDAP connector
No LDAP library ([ADR-0029](../docs/adr/0029-openldap-connector.md) decision 1): `ldap3` 0.12
builds without OpenSSL, but its codec buffers whatever length a server announces, its decoder
panics on an empty `LDAPMessage`, its errors carry the server's `diagnosticMessage` and
`matchedDN`, and the write operations are compiled in. The connector speaks a closed subset of
LDAPv3 itself (`crates/connector-openldap/src/ber.rs`, `proto.rs`, `conn.rs`) over tokio and the
same rustls crates:

- encoders for `BindRequest` (simple, SASL `EXTERNAL`), `SearchRequest`, the StartTLS and Who am
  I? extended requests and `UnbindRequest` only: no write operation, compare or other extended
  operation can be sent (I4); filters built in code;
- BER read by a bounded reader: definite lengths of at most 4 octets, low tag numbers, the
  message length checked before the body (16 MiB), zeroized buffers, fail closed; results reduced
  to their numeric code (never `diagnosticMessage`, `matchedDN` or referral URIs); a response to
  another message id or an unsolicited notification ends the connection;
- referrals and continuation references are never followed (I5), aliases never dereferenced;
- TLS: `verify_full` (default, LDAPS on 636) or `start_tls` (StartTLS on 389, no fallback, and no
  byte accepted between the StartTLS response and the handshake), against a pinned CA
  (`openldap.ca_file`) or the system store, host name or IP SAN checked; `disable` only on an
  `ldapi://` socket or a loopback literal; **no `disable_insecure`** (a simple bind sends the
  password itself);
- authentication: simple bind with the service DN (`account`) and its password (an empty
  password is never sent: it would be an unauthenticated bind), or SASL `EXTERNAL` over `ldapi://`
  (`openldap.bind: sasl_external`, no `secret`); then Who am I? must return a DN (never
  anonymous), equal to `account` for `EXTERNAL`.

Behavior:

- every search has a size limit, a time limit (the job's statement timeout, at least 1 s) and a
  client-side deadline, `derefAliases: never`, and an attribute list built in code; a search is
  read to its end before any finding is submitted;
- Discovery: the root DSE's naming contexts (at most 64; the `openldap.accesslog_base` database
  never), the schema from the subschema subentry, then per naming context a subtree listing of
  the containers (`organizationalUnit`, `organization`, `dcObject`, `domain`, `country`,
  `locality`; DNs only, at most 1024) and one one-level search per container (`sizeLimit` =
  `sample_rows`). Requested attributes: `userApplications` attributes of a text syntax (Directory,
  IA5, Printable, Numeric and Country String, Telephone Number, Postal Address, Generalized Time,
  Integer), custom ones included; **never** `userPassword`, `authPassword`, their subtypes or the
  closed list of password-equivalent hashes, nor DN-valued, binary or unknown syntaxes;
- locations: naming context (`database`), container (`schema`, the entry's parent reduced by
  `names::normalize_ldap_dn`: `ou=<a person>` becomes `ou=*`), structural object class
  (`object`), attribute (`field`, canonical name lowercased, options dropped); containers with
  the same normalized name are pooled; entry DNs never leave the agent nor reach the logs;
- `check()`: reachability; `cn=config` readable, password attributes disclosed to an
  attributes-only search of the first 64 entries of each naming context (values never
  transferred), `cn=accesslog` readable without a running Audit stream; write access is never
  tested and always noted as not evaluated; recomputed at most every 10 minutes per target.

Audit (ADR-0029 decisions 7 to 10; `src/audit/`):

- source `cn=accesslog` (`slapo-accesslog`), read over LDAP with the same session settings:
  **Full** when every naming context has a search record from the last 24 h (checked by
  `check()`, after one base search of the context when none is found), Partial when some do,
  Limited when none do (`audit.reads_not_logged`), None when the log is not readable
  (`audit.accesslog_not_readable`);
- incremental by `entryCSN` (commit order; `reqStart` would skip long exports), with a 10 s
  overlap and the CSNs already read; `sizeLimit` 1000 per search, repeated while cut; cursor
  and the CSNs read within the overlap (at most 1000) persisted by the core, so an entry
  committed out of CSN order just before a restart is still read after it; first start one
  minute back;
- read: `reqType`, `reqStart`, `reqSession`, `reqAuthzID`, `reqDN`, `reqResult`, `reqScope`,
  `reqFilter`, `reqAttr`, `reqAttrsOnly`, `reqEntries`, `reqSizeLimit`, `reqMethod`,
  `entryCSN`; never `reqMod`, `reqOld`, `reqAssertion`, `reqMessage` or the controls. The filter
  and the DN are reduced in memory to closed facts (unselective or not, the agent's own filter or
  not; naming context, normalized container, a keyed hash for paged totals);
- events: principal = authorization DN (bind DN for binds), sent by name only for `anonymous`, the
  agent's own DN and `openldap.clear_principals`, a keyed fingerprint otherwise (entry DNs name
  people); no client address (the log has none); objects = the naming context and the console's `sensitive_objects`
  reachable from the base and scope, else `*` with the container; rows = `reqEntries`;
- signals: `shape.bulk_search` (scope one-level, subtree or children with a filter of presence
  tests and `objectClass` assertions only), `volume.large_result` (more than 10 000 entries by one
  search or by the pages of one paged search: same connection, base and scope);
- the agent's own reads and binds are left out for its Who am I? DN, without signal, within the
  Discovery budget per object and day (`ClientSeen::NotRecorded`: no address rule); its exact
  container listing and check probes are not charged; writes are always reported.

Target settings: the `openldap` block of a target in `agent.example.yaml`. Integration tests
(`src/it.rs`) run against the dev `openldap` service when `DATABASTION_TEST_LDAP_URL` and
`DATABASTION_TEST_LDAP_PASSWORD` are set (`DATABASTION_TEST_LDAP_ADMIN_PASSWORD` for the
over-privilege and Audit tests, `DATABASTION_TEST_LDAP_EXPORT_CMD` for a real paged `ldapsearch`,
`DATABASTION_TEST_LDAPS_URL` / `DATABASTION_TEST_LDAP_CA_FILE` for TLS), and are skipped otherwise;
the handshake, StartTLS injection, hostile responses and a scan also run against a scripted
server over an in-memory stream (`src/fake.rs`); property tests in `src/proptests.rs`.

### Future database drivers
Add them with `default-features = false` and rustls-only TLS features, and
re-check `Cargo.lock` for OpenSSL. Every query gets a timeout and bounded
sampling (I4). Driver errors can echo query text or values: map them to
`ConnectorError` variants without the driver message before logging.

### Generated protocol types
Generated types (P0-B) must not become a bypass: connectors never build them
directly. `MaskedFinding` / `MaskedEvent` wrap them, and only
`classifiers::masking` converts to them. No `Deserialize` into masked types,
and `additionalProperties: false` in the schema.

### Protocol types
Protocol types are generated from `shared/protocol/openapi.yaml` and never
written by hand (I6): `crates/protocol/src/generated.rs` is produced by
`databastion-protocol-codegen` (typify) and committed. Its header lists the
schema rewrites applied before generation and the keywords that serde does
not enforce (`if` / `then` / `else`, `not`, numeric bounds, `minItems` /
`maxItems`…). The console's Ajv validation enforces them on what the agent
sends. On what the agent receives, the heartbeat interval is clamped (P1-B)
and the scan / audit job parameters go through the `core::job` `TryFrom`
gates (`crates/core/tests/job_fixtures.rs`); `crates/protocol/tests/fixtures.rs`
lists the invalid fixtures serde accepts.
`AgentSecret` / `EnrollmentToken` are hand-written wrappers (redacted
`Debug`, zeroized on drop), as are `Uuid` / `UuidV7` (canonical, version
checked).

The generator (developer tool only, never linked into the binary) parses
YAML with `serde_yaml_ng`, a maintained fork of the deprecated `serde_yaml`.
Only the crate-private uplink uses these types; connectors may not depend on
`databastion-protocol` (architecture test). `ScanJob` and `AuditConfig`
(`core::job`) are mapped from the generated job parameters by `TryFrom`,
then clamped; connectors never see the generated types.

## Commands
Run from `agent/` (same as CI):

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo build --no-default-features --locked   # minimal binary, no connector
cargo deny --locked check bans licenses sources
cargo deny --config deny-dev.toml --locked check licenses sources   # dev-deps too
cargo run -p databastion-protocol-codegen      # after changing shared/protocol/openapi.yaml
cargo run -- enroll --config agent.example.yaml --token-file /path/to/token
cargo run -- run --config /etc/databastion/agent.yaml
```

`agent.example.yaml` documents every configuration key. Logs are JSON on stdout; the filter is read from `DATABASTION_LOG`
(e.g. `DATABASTION_LOG=debug`), default `info`.

## Docker image
[`Dockerfile`](Dockerfile) (build context `agent/`): `rust:1.94.1-bookworm` builder
(`cargo build --release --locked`, default features: every connector) and a
`gcr.io/distroless/cc-debian12` runtime (glibc + libgcc only, no shell, no package manager;
`static` would need a musl build). Base images are pinned by tag and digest. Runs as uid/gid
10001; the binary is root-owned. Mounts: `/etc/databastion/agent.yaml` (read-only),
`/var/lib/databastion` (state volume, `0700`, owned by 10001: an empty named volume inherits
it), and the secret files referenced by `agent.yaml` (read-only, `0600`, owned by 10001).
Nothing secret is baked in. No `HEALTHCHECK`: the agent has no listener (I1); its health is
the console's `databastion_agent_up`. Compatible with `read_only: true` and `cap_drop: ALL`.
The end-to-end harness in [`e2e/`](../e2e/README.md) builds and runs it.

## Rules
See [AGENTS.md](../AGENTS.md): `#![forbid(unsafe_code)]` in every crate,
rustls only, no `println!` (enforced by clippy `print_stdout` /
`print_stderr`), no `unwrap` / `panic!` / `todo!` outside tests, never a
sampled value in logs. The workspace version is managed by
`scripts/bump-version.mjs` (`[workspace.package] version`).
