# DataBastion agent

Rust Cargo workspace for `databastion-agent`, the single agent binary with
per-engine connectors ([ADR-0002](../docs/adr/0002-single-agent-connectors.md)).

> **Status: skeleton (P0-D).** The workspace compiles and the binary starts,
> logs and exits. No enrollment, uplink, Discovery or Audit logic yet.

## Layout

| Crate | Path | Role |
|-------|------|------|
| `databastion-agent` | `crates/agent` | Binary: CLI (`--config`), JSON logs, connector selection by Cargo feature |
| `databastion-core` | `crates/core` | `Connector` trait, `Engine`, `AuditLevel`, `TargetHealth`, sinks, HTTPS uplink (stub), protocol placeholder |
| `databastion-classifiers` | `crates/classifiers` | Classifiers and `masking` (the only producer of uplink-bound data) |
| `databastion-connector-postgres` | `crates/connector-postgres` | PostgreSQL connector (stub) |
| `databastion-connector-mysql` | `crates/connector-mysql` | MySQL / MariaDB connector (stub) |
| `databastion-connector-mongodb` | `crates/connector-mongodb` | MongoDB connector (stub) |
| `databastion-connector-openldap` | `crates/connector-openldap` | OpenLDAP connector (stub) |

Dependency direction: `classifiers` ← `core` ← `connector-*` ← `agent`.

### Cargo features (binary)
`postgres`, `mysql`, `mongodb`, `openldap`: all enabled by default. A minimal
binary: `cargo build --no-default-features --features postgres`.

### Masking boundary (invariant I2)
- Connectors never get the uplink; they push results into `FindingSink` /
  `EventSink` from `core`.
- Sinks and the uplink only accept `MaskedFinding` / `MaskedEvent` from
  `classifiers::masking`. These types have private fields; a `MaskedSample`
  can only be produced by `masking::mask`, and a `MaskedFinding` only from
  `MaskedSample`s. Passing an unmasked value to the uplink does not compile.
- Raw values are wrapped in `RawSample`, whose `Debug` is redacted and which
  has no `Display` nor serialization.
- `crates/agent/tests/architecture.rs` also checks that connectors do not
  depend on an HTTP client or reference the uplink, that no listening socket
  appears in agent code (I1), and that `Cargo.lock` contains no OpenSSL /
  native-tls (rustls only).

### Protocol types
Protocol types are generated from `shared/protocol/openapi.yaml` and never
written by hand (I6). `databastion_core::protocol` is an empty placeholder
until the contract (P0-B) lands; `ScanJob` and `AuditConfig` are opaque
placeholders.

## Commands
Run from `agent/` (same as CI):

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo build --no-default-features --locked   # minimal binary, no connector
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
