# DataBastion agent

Rust Cargo workspace for `databastion-agent`, the single agent binary with
per-engine connectors ([ADR-0002](../docs/adr/0002-single-agent-connectors.md)).

> **Status: skeleton (P0-D).** The workspace compiles and the binary starts,
> logs and exits. No enrollment, uplink, Discovery or Audit logic yet.

## Layout

| Crate | Path | Role |
|-------|------|------|
| `databastion-agent` | `crates/agent` | Binary: CLI (`--config`), JSON logs, connector selection by Cargo feature |
| `databastion-core` | `crates/core` | `Connector` trait, `Engine`, `AuditLevel`, `TargetHealth`, sinks, HTTPS uplink (stub) |
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

### Guards
`crates/agent/tests/architecture.rs` checks that connectors do not depend on
an HTTP client or `socket2` (including `[dependencies.x]` tables and
`package = "…"` renames) nor reference the uplink, that no listening or raw
socket API appears in any crate's `src/`, `tests/`, `examples/`, `benches/`
or `build.rs` (I1), and that `Cargo.lock` contains no OpenSSL / native-tls.
These are text-level guards against honest mistakes; the types and code
review remain the primary controls.

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
`maxItems`…); for those, the console's Ajv validation and the agent's
sanitizer before spooling are the enforcement points
(`crates/protocol/tests/fixtures.rs` lists the affected invalid fixtures).
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
cargo run -p databastion-protocol-codegen      # after changing shared/protocol/openapi.yaml
cargo run -- --config /etc/databastion/agent.yaml
```

Logs are JSON on stdout; the filter is read from `DATABASTION_LOG`
(e.g. `DATABASTION_LOG=debug`), default `info`.

## Rules
See [AGENTS.md](../AGENTS.md): `#![forbid(unsafe_code)]` in every crate,
rustls only, no `println!` (enforced by clippy `print_stdout` /
`print_stderr`), no `unwrap` / `panic!` / `todo!` outside tests, never a
sampled value in logs. The workspace version is managed by
`scripts/bump-version.mjs` (`[workspace.package] version`).
