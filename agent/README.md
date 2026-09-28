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
| `databastion-connector-postgres` | `crates/connector-postgres` | PostgreSQL connector (stub) |
| `databastion-connector-mysql` | `crates/connector-mysql` | MySQL / MariaDB connector (stub) |
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
  (array indices → `[]`, value-like segments such as long digit runs, UUIDs,
  e-mail addresses → `*`, LDAP entry DN → parent container, attribute types
  lowercased, anything non-conforming → `*`). A `FindingLocation` is built
  only from `NormalizedName`s. Property tests
  (`crates/classifiers/tests/names_props.rs`, deterministic generator, no
  extra dependency) check every output against the generated `Identifier`
  type and its `not` rule. Skeleton: classifier matches on segments are
  added by P2-A.
- Conversion: `uplink::to_batches` is the single conversion from
  `MaskedFinding` / `MaskedEvent` to `FindingsBatch` / `EventsBatch`. Each
  item goes through `sanitize` (the `NOT_ENFORCED_BY_SERDE` keywords for sent
  types: `not` → `*`, `confidence` / `sampled` / `matched` ranges and
  `matched <= sampled`, `maxItems` / `uniqueItems` of samples, fingerprints,
  objects and signals, the `read` / `write` object requirement, `Count`
  ranges); an item still invalid is dropped and counted. Batches hold at most
  200 findings / 500 events and 1 MiB serialized, each with a fresh UUIDv7.
- Account names: control / format characters stripped, truncated on a
  character boundary; a non-conforming name goes to `db_user_fingerprint`.
  **Stub**: HMAC fingerprints are not wired yet (P2-A), so such an event is
  dropped and counted instead. `MaskedEvent` has no content yet (P4): no
  event reaches the spool today.
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
  (`batch_conflicts_total`), warned, never resent; other `4xx` → dropped;
  network / `5xx` / `429` → kept and retried with backoff; `401` / `426` →
  kept (spooling continues within bounds). Real stats go into the heartbeat
  `spool` section.

### Local engine detection (ADR-0006, I5)
`detect` looks at the agent host only, read-only, with no network I/O: a
fixed list of Unix socket paths under `/run`, `/var/run`, `/tmp`,
`/var/lib/mysql` (`lstat`, never connect); `LISTEN` entries of
`/proc/net/tcp{,6}` for ports 5432 / 3306 / 27017 / 389 / 636 (the address is
never reported); `/proc/<pid>/comm` for `postgres`, `mysqld`, `mariadbd`,
`mongod`, `slapd` (never the command line). Declared targets are excluded
(same socket; loopback host with the same port; a local target of the same
engine family hides the process entry). At most 16 entries, reported as
`detected_targets` in each heartbeat. The host root is injectable; tests use
fixture trees.

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
  `<= 0` are ignored. At most 16 jobs are handled per poll, each parsed on
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

### Future database drivers (sqlx, mongodb, ldap3)
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
`maxItems`…). The console's Ajv validation enforces them; checking received
values on the agent side is a required future step (P1-B heartbeat
scheduler, P2 scan / audit parameter mapping), not an existing guarantee
(`crates/protocol/tests/fixtures.rs` lists the affected invalid fixtures).
`AgentSecret` / `EnrollmentToken` are hand-written wrappers (redacted
`Debug`, zeroized on drop), as are `Uuid` / `UuidV7` (canonical, version
checked).

The generator (developer tool only, never linked into the binary) parses
YAML with `serde_yaml_ng`, a maintained fork of the deprecated `serde_yaml`.
Only the crate-private uplink uses these types; connectors may not depend on
`databastion-protocol` (architecture test). `ScanJob` and `AuditConfig`
remain opaque placeholders that the core will map from the generated job
parameters.

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

## Rules
See [AGENTS.md](../AGENTS.md): `#![forbid(unsafe_code)]` in every crate,
rustls only, no `println!` (enforced by clippy `print_stdout` /
`print_stderr`), no `unwrap` / `panic!` / `todo!` outside tests, never a
sampled value in logs. The workspace version is managed by
`scripts/bump-version.mjs` (`[workspace.package] version`).
