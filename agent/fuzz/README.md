# Fuzz targets (agent)

Coverage-guided fuzz targets ([cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), libFuzzer) for
the parsers of the agent that a hostile server or log writer feeds. They complement the property
tests of each connector (`src/proptests.rs`).

| Target | Entry point | Input |
|--------|-------------|-------|
| `mongodb_bson` | `databastion_connector_mongodb::fuzz::bson` | A BSON document, every element walked |
| `mongodb_op_msg` | `…::fuzz::op_msg` | An `OP_MSG` reply: header, flags, body section |
| `mongodb_audit_log` | `…::fuzz::audit_log` | One `auditLog` JSON line |
| `mongodb_server_log` | `…::fuzz::server_log` | One structured JSON server log line |
| `mongodb_profiler` | `…::fuzz::profiler` | One profiler entry (BSON); the persisted profiler positions |
| `openldap_ber` | `databastion_connector_openldap::fuzz::ber` | BER TLVs, nested encodings walked |
| `openldap_message` | `…::fuzz::message` | One `LDAPMessage`; an entry is also reduced as an accesslog entry |
| `openldap_filter` | `…::fuzz::search_filter` | One logged search filter (`reqFilter`) |
| `openldap_accesslog` | `…::fuzz::accesslog` | One `cn=accesslog` entry, NUL-separated attribute values |
| `cas_registry` | `databastion_connector_cas::fuzz::registry` | One CAS service definition file (JSON); paths named, service indexed |
| `cas_registry_yaml` | `…::fuzz::registry_yaml` | One CAS YAML service definition file: the pre-scan (anchors, aliases, tags, merge keys refused), then the same visitor |
| `cas_audit_log` | `…::fuzz::audit_log` | A short CAS JSON audit log excerpt (at most 64 lines, in order): each line parsed, `what` reducer, time parser, event builder with the token request / response correlation state ([ADR-0044](../../docs/adr/0044-cas-token-only-grants-client-naming.md)) |

The connectors expose these entry points only with their `fuzzing` feature, which the agent binary
never enables. This directory is its own Cargo workspace: `cargo test` and `cargo clippy` in
`agent/` never build it, and nothing here needs a nightly toolchain to compile.

## Running

Stable smoke run (CI job `agent-fuzz-smoke`: 10 s per target), with the coverage instrumentation
cargo-fuzz uses but without a sanitizer:

```sh
agent/fuzz/smoke.sh 60     # seconds per target
```

`smoke.sh` seeds `cas_registry` and `cas_registry_yaml` with the committed fake definitions of
`crates/connector-cas/fixtures/registry/` (JSON and YAML respectively): from an empty corpus a
YAML input rarely gets past the `--- !<class>` header the pre-scanner requires. It seeds
`cas_audit_log` with the token request and response records of the redacted CAS 8.0.2 excerpt
`crates/connector-cas/fixtures/cas-8.0.2-oauth-oidc-audit.jsonl` (fake user, every token and ticket
replaced): all of them as one input, and each request with its response, so the correlation state
sees request and response pairs from the start. The other targets start empty. For a cargo-fuzz campaign, copy the same files into `corpus/<target>/`.

Longer campaigns with AddressSanitizer need a nightly toolchain and cargo-fuzz:

```sh
cd agent/fuzz
cargo +nightly fuzz run openldap_accesslog -- -max_total_time=600
```

`target/`, `corpus/` and `artifacts/` are git-ignored. Seed a corpus only with synthetic input (the
unit tests of each `fuzz.rs` show the shapes); never with real log lines or server replies, which
hold other users' values (I2).

The targets are a test harness, not shipped code: `libfuzzer-sys`' `fuzz_target!` exports a
`#[no_mangle]` entry point, so these binaries cannot carry `#![forbid(unsafe_code)]`; the connector
code they call does.
