# Fuzz targets (agent)

Coverage-guided fuzz targets ([cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), libFuzzer) for
the parsers of the agent that a hostile server or log writer feeds. They complement the property
tests of each connector (`src/proptests.rs`).

| Target | Entry point | Input |
|--------|-------------|-------|
| `classifiers_names` | `databastion_classifiers::names::fuzz_normalize` | A name (lossy UTF-8; `/` separates field-path keys, a `*` part is an array level): `normalize_path`, `normalize_field_path`, `normalize_ldap_dn` and `normalize_ldap_attribute`; every emitted name must be `*` or match the contract `IdentifierProduced` ([ADR-0057](../../docs/adr/0057-identifier-hardening-agent-first.md) decision 1), else it panics |
| `core_csv_splitter` | `databastion_core::audit::tail::fuzz::splitter` | Selector bytes (chunk size, start offset, damage position, record bound), then statement texts: csvlog records quoted as PostgreSQL writes them (pgaudit and `log_statement`) fed to the CSV splitter; oracles: aligned input gives exactly the records with no realignment, a first start anywhere in the first record exactly the records after it, a record cut inside a quoted field only that record lost (one damaged count), a record bound never a forged record (#267 review L3) |
| `mongodb_bson` | `databastion_connector_mongodb::fuzz::bson` | A BSON document, every element walked |
| `mongodb_op_msg` | `…::fuzz::op_msg` | An `OP_MSG` reply: header, flags, body section |
| `mongodb_audit_log` | `…::fuzz::audit_log` | One `auditLog` JSON line |
| `mongodb_server_log` | `…::fuzz::server_log` | One structured JSON server log line |
| `mongodb_profiler` | `…::fuzz::profiler` | One profiler entry (BSON); the persisted profiler positions |
| `openldap_ber` | `databastion_connector_openldap::fuzz::ber` | BER TLVs, nested encodings walked |
| `openldap_message` | `…::fuzz::message` | One `LDAPMessage`; an entry is also reduced as an accesslog entry |
| `openldap_filter` | `…::fuzz::search_filter` | One logged search filter (`reqFilter`) |
| `openldap_accesslog` | `…::fuzz::accesslog` | One `cn=accesslog` entry, NUL-separated attribute values |
| `redis_resp_decoder` | `databastion_connector_redis::fuzz::resp_decoder` | Server bytes after a selector byte (a request's reply limits and a chunk size): the streaming RESP3 decoder fed chunk by chunk, several replies, each decoded reply read as a `HELLO` map and an `ACL DRYRUN` verdict ([ADR-0052](../../docs/adr/0052-redis-valkey-connector.md) decision 1) |
| `redis_info` | `…::fuzz::info` | An `INFO` reply text: engine, version, mode, role and keyspace parsers |
| `redis_key_pattern` | `…::fuzz::key_pattern` | A key name: the key-pattern normalizer (`classifiers::keys`; its output must pass the contract `KeyPattern` gate, else it panics), the Redis glob matcher and example key, the CAS guard |
| `redis_slowlog_entry` | `…::fuzz::slowlog_entry` | A `SLOWLOG GET` / `COMMANDLOG GET` reply: decoded under its limits, each entry reduced at parse time (closed command table, key positions, learned patterns, CAS guard); every object must be `*` or a contract `KeyPattern` ([ADR-0052](../../docs/adr/0052-redis-valkey-connector.md) decision 8) |
| `redis_acl_log_entry` | `…::fuzz::acl_log_entry` | An `ACL LOG` reply (entries and their `client-info`) and the same bytes as a `CLIENT LIST` line |
| `redis_learned_patterns` | `…::fuzz::learned_patterns` | Learned patterns (first half, one per line) and a key name (second half): the Audit object must pass the contract `KeyPattern` gate |
| `sqlserver_token_stream` | `databastion_connector_sqlserver::fuzz::token_stream` | Server bytes after a selector byte (slice size, PLP cap, discard mode): the TDS token stream decoder fed slice by slice; every step must make progress ([ADR-0051](../../docs/adr/0051-sqlserver-connector.md) decision 1) |
| `sqlserver_packets` | `…::fuzz::packets` | TDS packet reassembly (headers checked before bodies) and the `PRELOGIN` response parser |
| `sqlserver_prelogin_tls` | `…::fuzz::prelogin_tls_framing` | The packet header check of the TLS handshake wrapped in `PRELOGIN` packets |
| `sqlserver_plp` | `…::fuzz::plp` | The body of an `nvarchar(max)` row: PLP chunks reassembled under their cap (obligation L1) |
| `sqlserver_tsql` | `…::fuzz::tsql` | The T-SQL analysis of SQL Server Audit statement texts (password-bearing statements keep their class only) and the own-text matcher |
| `sqlserver_audit_records` | `…::fuzz::audit_records` | SQL Server Audit records: statement parts reassembled, records grouped per statement, events converted |
| `sqlserver_xe_xml` | `…::fuzz::xe_event_xml` | SQL Server Extended Events event XML: the bounded reader (no DTD, no entity beyond the predefined ones, closed fields, bounds) |
| `sqlserver_xe_records` | `…::fuzz::xe_records` | SQL Server Extended Events records: the context pass (RPC procedures, duplicate failed logins, statistics builds) and the conversion |
| `cas_registry` | `databastion_connector_cas::fuzz::registry` | One CAS service definition file (JSON); paths named, service indexed |
| `cas_registry_yaml` | `…::fuzz::registry_yaml` | One CAS YAML service definition file: the pre-scan (anchors, aliases, tags, merge keys refused), then the crate's own YAML parser and the same visitor |
| `cas_registry_yaml_diff` | `…::fuzz::registry_yaml_diff` | Differential ([ADR-0046](../../docs/adr/0046-cas-yaml-registry-parser-without-unsafe-libyaml.md)): on every file the pre-scan accepts, the crate's YAML parser and `serde_yaml_ng` (the oracle, a dependency of this harness only) must read the same values and the same definition, or both fail; a disagreement panics |
| `cas_audit_log` | `…::fuzz::audit_log` | A short CAS JSON audit log excerpt (at most 64 lines, in order): each line parsed, `what` reducer, time parser, event builder with the token request / response correlation state ([ADR-0044](../../docs/adr/0044-cas-token-only-grants-client-naming.md)) |
| `sqlite_file` | `databastion_connector_sqlite::fuzz::file` | A hostile SQLite file and its optional `-wal`, `-shm` and `-journal` files (3-byte length-prefixed parts), written to a private directory and run through the reader's real pipeline: the path and file checks, the header pre-check, the connection setup, the catalog, `table_xinfo`, rowid bounds and sampling statements with the production limits and a 50 ms statement deadline ([ADR-0059](../../docs/adr/0059-sqlite-connector.md) decision 5). The setup runs the decision 1 self-check, so a build without the production `LIBSQLITE3_FLAGS` (`agent/.cargo/config.toml`, read when cargo runs under `agent/`) fails the run. Nightly campaigns build the bundled C code with AddressSanitizer (feature `asan`, `CC=clang`, `CFLAGS=-fsanitize=fuzzer-no-link`). Seeded by `sqlite_seed.py`. The forked helper of decision 5 that holds the `-shm` DMS lock (the reliable `-shm` path) is not there yet: the heap-index path is fuzzed |
| `sqlite_header` | `…::fuzz::header` | The Rust SQLite header pre-check alone (no SQLite) |
| `sqlite_ipc` | `…::fuzz::ipc` | Both decoders of the reader IPC and its frame assembler (bounds, every split) |
| `firebird_messages` | `databastion_connector_firebird::fuzz::messages` | Server bytes after a phase byte and a slice-size byte: the Firebird protocol-16 messages of the closed set (`op_accept*`, `op_response` with its status vector reduced to GDS codes, `op_cont_auth`, `op_fetch_response`), fed slice by slice; every step must make progress ([ADR-0060](../../docs/adr/0060-firebird-connector.md) decision 1) |
| `firebird_describe_rows` | `…::fuzz::describe_and_rows` | The describe answer of `op_prepare_statement` (an info buffer, the first two bytes give its length) and rows of the described columns |
| `firebird_srp_data` | `…::fuzz::srp_data` | The server's SRP data (salt and `B` with their checks), and the client proof when accepted |
| `firebird_keys` | `…::fuzz::keys` | The wire-crypt key clumplets, the plugin choice (never Arc4) and the cipher it builds |
| `firebird_proc_net_tcp` | `…::fuzz::proc_net_tcp` | `/proc/net/tcp` tables for the peer-uid rule (decision 3, security review L1): the right row or none |

The core and the connectors expose these entry points only with their `fuzzing` feature, which the agent binary
never enables. This directory is its own Cargo workspace: `cargo test` and `cargo clippy` in
`agent/` never build it, and nothing here needs a nightly toolchain to compile.

## Running

Stable smoke run (CI job `agent-fuzz-smoke`: 10 s per target), with the coverage instrumentation
cargo-fuzz uses but without a sanitizer:

```sh
agent/fuzz/smoke.sh 60     # seconds per target
```

`smoke.sh` seeds `cas_registry` and `cas_registry_yaml` with the committed fake definitions of
`crates/connector-cas/fixtures/registry/` (JSON and YAML respectively; the YAML targets, `cas_registry_yaml_diff` included, also with the synthetic hostile files of `crates/connector-cas/fixtures/registry-hostile/`): from an empty corpus a
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
