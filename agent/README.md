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
| `databastion-connector-mongodb` | `crates/connector-mongodb` | MongoDB connector (stub) |
| `databastion-connector-openldap` | `crates/connector-openldap` | OpenLDAP connector (stub) |
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
  for a cancelled scan, while `/findings` is parked after a `501`, once the
  agent is suspended, or on shutdown. A status sent with batches still
  spooled is counted (`scan_status_before_flush_total`); the batches are
  sent later (the console accepts them for 24 h after the status).
- Spool: `<state_dir>/spool/`, one `0600` file per batch written with
  tmp + `fsync` + `rename` + directory `fsync`; stale temporary files are
  removed at startup, unreadable files are moved to `spool/quarantine/` (32
  kept) and counted (`quarantined`), never crash the agent and are never
  logged. Bounded by `spool.max_bytes` (default 256 MiB) and
  `spool.max_batches` (default 10000): oldest dropped first. FIFO send:
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
  concurrently, each bounded at 10 s, so it waits at most 10 s for all of
  them (P2-G); a check still running then is reported unreachable with
  `timeout` and the `check.timed_out` note. At most 16 jobs are handled per poll, each parsed on
  its own; an unparseable job is reported `failed` (`unsupported` /
  `invalid_params`) when its `job_id` is readable.
- HTTP tests use `wiremock` (dev-dependency, 127.0.0.1, test code only).
  `deny.toml` sets `[graph] exclude-dev = true`: the hyper `server` feature
  it needs is never linked into the binary, and the bans stay strict for
  the shipped graph. `deny-dev.toml` checks licenses and sources of the full
  graph, dev-dependencies included.

### Logs
`DATABASTION_LOG` sets the filter, but targets outside `databastion_*` are
capped at `warn`: drivers and HTTP clients may log parameters or payloads at
debug/trace level.

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
  Audit stream runs), `init_connect`, and coverage (views, engines). The same rules apply to
  the privileges held through roles (P4-D): every role in `information_schema.APPLICABLE_ROLES`
  (granted directly or through a role, MySQL mandatory roles, the MariaDB default role; enabled
  or not), read with `SHOW GRANTS FOR CURRENT_USER() USING …` (MySQL) or `SHOW GRANTS FOR
  <role>` (MariaDB), at most 16 roles, names written into the statement only when they match
  an allow-listed charset; `WITH ADMIN OPTION` counts as a grant option. A role whose grants
  cannot be read or parsed is reported as `privilege.roles_not_evaluated`;
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

### Future database drivers (mongodb, ldap3)
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
