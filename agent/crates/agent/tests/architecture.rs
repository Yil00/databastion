//! Architecture guards, run by `cargo test` in CI.
//!
//! - rustls only: no OpenSSL / native-tls in the dependency graph.
//! - Connectors never depend on an HTTP client nor on the generated protocol
//!   types, and never reference the uplink or `databastion_protocol`
//!   (AGENTS.md: no direct uplink access from a connector; I2).
//! - No listening socket in agent code (I1). The future opt-in
//!   `metrics.local_listen` (127.0.0.1 only) will be the single allowlisted
//!   exception.
//!
//! These are text-level guards: they catch honest mistakes, not a determined
//! author. The type boundary in `classifiers::masking` and code review remain
//! the primary controls; cargo-deny is planned in CI.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CONNECTORS: [&str; 9] = [
    "connector-postgres",
    "connector-mysql",
    "connector-mongodb",
    "connector-openldap",
    "connector-cas",
    "connector-redis",
    "connector-sqlserver",
    "connector-sqlite",
    "connector-firebird",
];

/// Crates a connector must never depend on (directly or through a rename).
const BANNED_CONNECTOR_DEPS: [&str; 11] = [
    "reqwest",
    "hyper",
    "hyper-util",
    "ureq",
    "isahc",
    "surf",
    "attohttpc",
    "socket2",
    "databastion-agent",
    // Generated protocol types: only the uplink builds payloads, from masked
    // types (I2, ADR-0003). The codegen is a developer tool.
    "databastion-protocol",
    "databastion-protocol-codegen",
];

/// Identifiers that indicate a listening (or raw) socket.
const BANNED_SOCKET_APIS: [&str; 7] = [
    "TcpListener",
    "TcpSocket",
    "UdpSocket",
    "UnixListener",
    "UnixDatagram",
    ".listen(",
    "socket2",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    if !dir.is_dir() {
        return;
    }
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every Rust file of every crate: `src/`, `tests/`, `examples/`, `benches/`
/// and `build.rs`, except this file (which lists the banned identifiers).
fn all_crate_sources() -> Vec<PathBuf> {
    let this_file = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/architecture.rs")
        .canonicalize()
        .unwrap();
    let mut sources = Vec::new();
    for entry in fs::read_dir(workspace_root().join("crates")).unwrap() {
        let krate = entry.unwrap().path();
        for dir in ["src", "tests", "examples", "benches"] {
            rust_sources(&krate.join(dir), &mut sources);
        }
        let build = krate.join("build.rs");
        if build.is_file() {
            sources.push(build);
        }
    }
    sources.retain(|p| p.canonicalize().unwrap() != this_file);
    assert!(sources.len() > 10, "source discovery looks broken");
    sources
}

/// Source lines, without `//`, `///` and `//!` comment lines.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim_start().starts_with("//"))
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches('"').trim_matches('\'')
}

/// Value of a `package = "…"` key in a manifest line, if any.
fn package_rename(line: &str) -> Option<&str> {
    let idx = line.find("package")?;
    let rest = line[idx + "package".len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start().strip_prefix('"')?;
    rest.split('"').next()
}

/// Dependencies declared in a manifest: for each entry, the key and, if
/// renamed, the real package name. Handles inline entries
/// (`foo = …`, `foo.workspace = true`), `[dependencies.foo]` tables and
/// `[target.'cfg(…)'.dependencies]` sections.
fn declared_dependencies(manifest: &str) -> Vec<(String, Option<String>)> {
    let mut deps: Vec<(String, Option<String>)> = Vec::new();
    // None: not in a dependency section; Some(None): in a dependency list;
    // Some(Some(i)): inside the `[dependencies.<name>]` table of deps[i].
    let mut section: Option<Option<usize>> = None;
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let header = header.trim();
            section = if header.ends_with("dependencies") {
                Some(None)
            } else if let Some(pos) = header.rfind("dependencies.") {
                let name = unquote(&header[pos + "dependencies.".len()..]);
                deps.push((name.to_owned(), None));
                Some(Some(deps.len() - 1))
            } else {
                None
            };
            continue;
        }
        match section {
            Some(None) => {
                let key = line.split('=').next().unwrap_or("");
                let key = unquote(key.split('.').next().unwrap_or(""));
                deps.push((key.to_owned(), package_rename(line).map(str::to_owned)));
            }
            Some(Some(i)) => {
                if let Some(pkg) = package_rename(line) {
                    deps[i].1 = Some(pkg.to_owned());
                }
            }
            None => {}
        }
    }
    deps
}

fn is_banned(key: &str, pkg: Option<&str>) -> bool {
    BANNED_CONNECTOR_DEPS.contains(&pkg.unwrap_or(key))
}

/// Keys of the root `[workspace.dependencies]` that alias a banned crate.
fn banned_workspace_aliases() -> Vec<String> {
    let root = fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
    declared_dependencies(&root)
        .into_iter()
        .filter(|(key, pkg)| is_banned(key, pkg.as_deref()))
        .map(|(key, _)| key)
        .collect()
}

/// The classifiers use case-insensitive groups (`(?i:…)`); without the
/// `unicode-case` feature `Regex::new` fails and the detector is silently
/// disabled in the shipped binary. Test builds of the whole workspace get
/// the feature through dev-dependencies (feature unification), so only the
/// manifest can be checked.
#[test]
fn regex_keeps_unicode_case() {
    let root = fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
    let line = root
        .lines()
        .find(|l| l.trim_start().starts_with("regex ="))
        .expect("workspace regex dependency");
    assert!(line.contains("\"unicode-case\""), "{line}");
}

/// The shipped agent panics on an integer overflow instead of wrapping
/// (maintainer decision of 2026-11-07); panics stay catchable (`unwind`),
/// which the per-connector and per-record isolation needs.
#[test]
fn release_profile_checks_overflows_and_unwinds() {
    let root = fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
    let profile: Vec<&str> = root
        .lines()
        .skip_while(|l| l.trim() != "[profile.release]")
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    assert!(profile.contains(&"overflow-checks = true"), "{profile:?}");
    assert!(
        !profile.iter().any(|l| l.starts_with("panic")),
        "{profile:?}"
    );
    assert!(
        !root.contains("[profile.release.package"),
        "per-package override"
    );
}

#[test]
fn lockfile_has_no_openssl_native_tls_or_aws_lc() {
    let lock = fs::read_to_string(workspace_root().join("Cargo.lock")).unwrap();
    for banned in [
        "openssl",
        "openssl-sys",
        "openssl-src",
        "native-tls",
        "aws-lc-rs",
        "aws-lc-sys",
    ] {
        let entry = format!("name = \"{banned}\"");
        assert!(!lock.contains(&entry), "Cargo.lock contains {banned}");
    }
}

#[test]
fn manifest_parser_catches_tables_and_renames() {
    let manifest = r#"
[package]
name = "reqwest-lookalike"

[dependencies]
tokio.workspace = true
http = { package = "reqwest", version = "0.12" }

[dependencies.hyper]
version = "1"

[target.'cfg(unix)'.dependencies.client]
package = "ureq"
"#;
    let banned: Vec<String> = declared_dependencies(manifest)
        .into_iter()
        .filter(|(key, pkg)| is_banned(key, pkg.as_deref()))
        .map(|(key, _)| key)
        .collect();
    assert_eq!(banned, ["http", "hyper", "client"]);
}

#[test]
fn connectors_do_not_depend_on_http_clients_or_protocol_types() {
    let aliases = banned_workspace_aliases();
    for connector in CONNECTORS {
        let manifest = fs::read_to_string(
            workspace_root()
                .join("crates")
                .join(connector)
                .join("Cargo.toml"),
        )
        .unwrap();
        for (key, pkg) in declared_dependencies(&manifest) {
            assert!(
                !is_banned(&key, pkg.as_deref()) && !aliases.contains(&key),
                "{connector} depends on {key} ({pkg:?})"
            );
        }
    }
}

#[test]
fn connectors_do_not_reference_the_uplink() {
    for connector in CONNECTORS {
        let krate = workspace_root().join("crates").join(connector);
        let mut sources = Vec::new();
        for dir in ["src", "tests", "examples", "benches"] {
            rust_sources(&krate.join(dir), &mut sources);
        }
        for source in sources {
            let text = fs::read_to_string(&source).unwrap();
            assert!(
                !code_lines(&text).any(|l| l.contains("uplink")
                    || l.contains("Uplink")
                    || l.contains("databastion_protocol")),
                "{} references the uplink or the protocol types",
                source.display()
            );
        }
    }
}

#[test]
fn no_listening_socket_in_agent_code() {
    for source in all_crate_sources() {
        let text = fs::read_to_string(&source).unwrap();
        for banned in BANNED_SOCKET_APIS {
            assert!(
                !code_lines(&text).any(|l| l.contains(banned)),
                "{} uses {banned} (I1: the agent opens no inbound port)",
                source.display()
            );
        }
    }
}

/// Runs `cargo metadata --locked` with a 120 s timeout. Not `--offline`:
/// the full resolve covers every platform, so it may need crates (e.g.
/// Windows / UEFI targets of `getrandom`) that a host build never fetched.
fn cargo_metadata() -> serde_json::Value {
    cargo_metadata_with(&[])
}

/// [`cargo_metadata`] with extra arguments (`--filter-platform …`).
fn cargo_metadata_with(extra: &[&str]) -> serde_json::Value {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let out_path = std::env::temp_dir().join(format!(
        "databastion-arch-metadata-{}-{n}.json",
        std::process::id()
    ));
    let out_file = fs::File::create(&out_path).unwrap();
    let mut child = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked"])
        .args(extra)
        .current_dir(workspace_root())
        .stdout(out_file)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("cargo metadata timed out");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "cargo metadata failed");
    let text = fs::read_to_string(&out_path).unwrap();
    fs::remove_file(&out_path).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// In the resolved graph, the only crate with a normal (non-dev, non-build)
/// dependency on `databastion-protocol` is `databastion-core`, whose
/// crate-private uplink is the only user of the generated types. Complements
/// the manifest text guard above.
/// The CAS connector reads local files only and opens no network
/// connection of any kind (ADR-0041 decisions 2 and 13): no TLS crate, no
/// tokio `net` feature, no socket type in its sources.
#[test]
fn cas_connector_opens_no_network_connection() {
    let krate = workspace_root().join("crates").join("connector-cas");
    let manifest = fs::read_to_string(krate.join("Cargo.toml")).unwrap();
    for (key, _) in declared_dependencies(&manifest) {
        assert!(
            !key.contains("rustls") && !key.contains("tls") && key != "socket2",
            "connector-cas depends on {key}"
        );
    }
    for line in code_lines(&manifest).filter(|l| l.starts_with("tokio")) {
        assert!(
            !line.contains("\"net\""),
            "connector-cas enables tokio's net feature"
        );
    }
    let mut sources = Vec::new();
    rust_sources(&krate.join("src"), &mut sources);
    for source in sources {
        let text = fs::read_to_string(&source).unwrap();
        for api in [
            "TcpStream",
            "UnixStream",
            "tokio::net",
            "std::net::Tcp",
            "ToSocketAddrs",
        ] {
            assert!(
                !code_lines(&text).any(|l| l.contains(api)),
                "{} uses {api}",
                source.display()
            );
        }
    }
}

#[test]
fn only_core_depends_on_protocol_types() {
    let metadata = cargo_metadata();
    let packages = metadata["packages"].as_array().unwrap();
    let name_of = |id: &str| {
        packages
            .iter()
            .find(|p| p["id"] == id)
            .and_then(|p| p["name"].as_str())
            .unwrap()
            .to_owned()
    };
    let mut dependents = Vec::new();
    for node in metadata["resolve"]["nodes"].as_array().unwrap() {
        for dep in node["deps"].as_array().unwrap() {
            let is_protocol = name_of(dep["pkg"].as_str().unwrap()) == "databastion-protocol";
            let normal = dep["dep_kinds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k["kind"].is_null());
            if is_protocol && normal {
                dependents.push(name_of(node["id"].as_str().unwrap()));
            }
        }
    }
    assert_eq!(dependents, ["databastion-core"]);
}

/// The test switches that accept files owned by the agent's own user (the
/// core tailer's, end-of-phase-4 review L4, and the CAS connector's file
/// checks, ADR-0041 decision 3) are only called from test code: the
/// connectors' integration-test modules (compiled under `#[cfg(test)]`),
/// `mod tests` modules and the agent's runtime test. The functions
/// themselves only exist for tests and the `test-support` features, which
/// the agent binary's normal dependencies never enable.
#[test]
fn agent_owned_logs_are_allowed_in_tests_only() {
    const SWITCHES: [&str; 4] = [
        "allow_agent_owned_logs_for_tests(",
        "allow_agent_owned_files_for_tests(",
        "set_reader_executable_for_tests(",
        "set_reader_credentials_for_tests(",
    ];
    const TEST_ONLY: [&str; 8] = [
        "connector-postgres/src/it.rs",
        "connector-mysql/src/it/audit_it.rs",
        "connector-mongodb/src/it_audit.rs",
        "connector-firebird/src/it_audit.rs",
        // `#[cfg(test)] #[path = "audit_ckpt_tests.rs"] mod ckpt_tests;`
        "connector-firebird/src/audit_ckpt_tests.rs",
        "core/tests/",
        "agent/tests/cas_runtime.rs",
        "agent/tests/sqlite_reader.rs",
    ];
    for source in all_crate_sources() {
        let text = fs::read_to_string(&source).unwrap();
        let shown = source.display().to_string();
        for switch in SWITCHES {
            let calls: Vec<usize> = code_lines(&text)
                .enumerate()
                .filter(|(_, l)| l.contains(switch) && !l.contains("fn "))
                .map(|(i, _)| i)
                .collect();
            if calls.is_empty() {
                continue;
            }
            // Inside a `mod tests` (compiled under `#[cfg(test)]`).
            if let Some(tests_at) = code_lines(&text).position(|l| l.trim() == "mod tests {")
                && calls.iter().all(|i| *i > tests_at)
            {
                continue;
            }
            assert!(
                TEST_ONLY.iter().any(|t| shown.contains(t)),
                "{shown} calls {switch}…) outside test code"
            );
        }
    }
    // The binary's own dependencies never enable a `test-support` feature.
    let manifest = fs::read_to_string(
        workspace_root()
            .join("crates")
            .join("agent")
            .join("Cargo.toml"),
    )
    .unwrap();
    let normal = manifest
        .split("[dev-dependencies]")
        .next()
        .unwrap_or_default();
    assert!(
        !code_lines(normal).any(|l| l.contains("test-support")),
        "the agent binary enables a test-support feature"
    );
}

/// ADR-0051 refinement item 7 (M4): the SQL Server connector never reads
/// module bodies or definition-bearing columns. Its statements are a
/// reviewed allow-list (`connector-sqlserver/src/sql.rs`, `STATEMENTS`);
/// every text is checked on its skeleton (quoted identifiers and literals
/// emptied, as the session checks each text it sends at run time) against
/// this list **and** the crate's own `DENIED`, which must contain it.
#[cfg(feature = "sqlserver")]
#[test]
fn sqlserver_statements_never_read_definitions() {
    const DENIED: [&str; 14] = [
        "sql_modules",
        "syscomments",
        "numbered_procedures",
        "object_definition",
        "sp_helptext",
        "computed_columns",
        "check_constraints",
        "default_constraints",
        "partition_range_values",
        "predicate_definition",
        "filter_definition",
        "provider_string",
        "data_source",
        "server_audits",
    ];
    let shared = databastion_connector_sqlserver::statement_deny_list();
    for d in DENIED {
        assert!(shared.contains(&d), "sql::DENIED lacks {d}");
    }
    let list = databastion_connector_sqlserver::statement_allow_list();
    assert!(list.len() >= 20, "allow-list looks empty");
    for (name, text) in list {
        let skeleton = databastion_connector_sqlserver::statement_skeleton(text);
        for d in shared.iter().chain(DENIED.iter()) {
            // The one exempt text: the exact one-bit password_hash probe.
            if *name == "password_hash_probe" && (*d == "password_hash") {
                continue;
            }
            assert!(!skeleton.contains(d), "{name} names {d}");
        }
        assert!(
            databastion_connector_sqlserver::statement_checked(text),
            "{name}"
        );
    }
    // The skeleton ignores names: a user's column called `definition` is
    // sampled, a catalog read of it is not.
    assert!(databastion_connector_sqlserver::statement_checked(
        "SELECT TOP (1) CONVERT(nvarchar(4000), LEFT([definition], 4000)) FROM [d].[s].[t]"
    ));
    assert!(!databastion_connector_sqlserver::statement_checked(
        "SELECT definition FROM sys.sql_modules"
    ));
}

/// ADR-0060 decisions 1, 4 and 5: the Firebird connector's statements are
/// a closed allow-list of constant texts (`connector-firebird/src/sql.rs`),
/// each read-only (no word of the crate's deny-list outside quotes: no
/// write, no DDL, no PSQL, no `EXECUTE STATEMENT … ON EXTERNAL`, no
/// `RDB$SET_CONTEXT`), and none reads a source text (`*_SOURCE` columns:
/// literals and credentials) nor an external file's path (Discovery only
/// tests whether it is set: `RDB$EXTERNAL_FILE IS NULL`, and joins a
/// column to its base field on `RDB$FIELD_SOURCE`, a field name, decision
/// 5).
#[cfg(feature = "firebird")]
#[test]
fn firebird_statements_are_closed_and_read_only() {
    let list = databastion_connector_firebird::statement_allow_list();
    assert!(list.len() >= 20, "allow-list looks empty");
    for (name, text) in &list {
        assert!(
            !databastion_connector_firebird::statement_has_denied_word(text),
            "{name}: {text}"
        );
        let lower = text
            .to_ascii_lowercase()
            .replace("r.rdb$external_file is null", "")
            .replace("f.rdb$field_name = rf.rdb$field_source", "");
        for d in [
            "_source",
            "rdb$external_file",
            "on external",
            "execute statement",
        ] {
            assert!(!lower.contains(d), "{name} names {d}");
        }
        assert!(
            databastion_connector_firebird::statement_checked(text),
            "{name}"
        );
    }
    for denied in [
        "UPDATE CUSTOMERS SET EMAIL = NULL",
        "EXECUTE BLOCK AS BEGIN END",
        "SELECT RDB$SET_CONTEXT('USER_SESSION', 'A', 'B') FROM RDB$DATABASE",
        "SELECT 1 FROM T FOR UPDATE",
    ] {
        assert!(
            databastion_connector_firebird::statement_has_denied_word(denied),
            "{denied}"
        );
        assert!(!databastion_connector_firebird::statement_checked(denied));
    }
}

/// ADR-0060 decision 1 and Consequences: no Firebird driver crate nor C
/// client in the graph, and the connector's big integers are
/// `crypto-bigint` (constant time), never `num-bigint`.
#[test]
fn the_firebird_connector_has_its_own_client_only() {
    let metadata = cargo_metadata();
    let nodes = resolved_nodes(&metadata);
    for (name, _, deps, _) in &nodes {
        assert!(
            !name.starts_with("rsfbclient") && name != "firebirust" && !name.contains("fbclient"),
            "{name} is in the graph"
        );
        if name == "databastion-connector-firebird" {
            for (d, normal, _) in deps {
                assert!(
                    !(*normal && (d == "num-bigint" || d == "num-bigint-dig" || d == "rug")),
                    "connector-firebird depends on {d}"
                );
            }
            assert!(
                deps.iter()
                    .any(|(d, normal, _)| d == "crypto-bigint" && *normal),
                "connector-firebird lost crypto-bigint"
            );
        }
    }
}

/// ADR-0060 refinement of 2026-10-31, R52 item 5 (security review N4):
/// the agent image ships nothing under `/run/databastion`, the directory of
/// the default declared host identity files. The image build checks the
/// base image's tree in its `image-check` stage, which the runtime stage
/// depends on; here, that the stage is there and wired, and that no
/// `COPY` / `ADD` / `WORKDIR` / `VOLUME` of the runtime stage writes
/// under `/run`.
#[test]
fn the_agent_image_ships_nothing_under_run_databastion() {
    let dockerfile = std::fs::read_to_string(workspace_root().join("Dockerfile")).unwrap();
    let lines: Vec<&str> = dockerfile
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .collect();
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("FROM build AS image-check"))
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("RUN test ! -e /image-root/run/databastion")),
        "the image check is gone"
    );
    let runtime = lines
        .iter()
        .position(|l| l.starts_with("FROM ") && l.ends_with(" AS runtime"))
        .expect("a runtime stage");
    let stage = &lines[runtime..];
    assert!(
        stage
            .iter()
            .any(|l| l.starts_with("COPY --from=image-check ")
                && l.ends_with("/usr/local/bin/databastion-agent")),
        "the runtime stage must take its binary from the checked stage"
    );
    for l in stage {
        let mut words = l.split_whitespace();
        let Some(op) = words.next() else { continue };
        if !["COPY", "ADD", "WORKDIR", "VOLUME", "RUN"].contains(&op) {
            continue;
        }
        assert!(
            op != "RUN",
            "a RUN step in the shell-less runtime stage: {l}"
        );
        let dest = l.split_whitespace().last().unwrap_or_default();
        let dest = dest.trim_matches(|c| c == '[' || c == ']' || c == '"');
        assert!(
            !dest.starts_with("/run") && !dest.starts_with("/var/run") && dest != "/",
            "the runtime stage writes {dest}"
        );
    }
}

/// The resolved graph: `(package name, links, [(dependency name, normal,
/// build)]], resolved features)` per node.
type Node = (
    String,
    Option<String>,
    Vec<(String, bool, bool)>,
    Vec<String>,
);

fn resolved_nodes(metadata: &serde_json::Value) -> Vec<Node> {
    let packages = metadata["packages"].as_array().unwrap();
    let package = |id: &str| packages.iter().find(|p| p["id"] == id).unwrap();
    metadata["resolve"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| {
            let p = package(node["id"].as_str().unwrap());
            let deps = node["deps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| {
                    let kinds = d["dep_kinds"].as_array().unwrap();
                    let name = package(d["pkg"].as_str().unwrap())["name"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    (
                        name,
                        kinds.iter().any(|k| k["kind"].is_null()),
                        kinds.iter().any(|k| k["kind"] == "build"),
                    )
                })
                .collect();
            let features = node["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap().to_owned())
                .collect();
            (
                p["name"].as_str().unwrap().to_owned(),
                p["links"].as_str().map(str::to_owned),
                deps,
                features,
            )
        })
        .collect()
}

/// The packages the shipped binary is built from: `databastion-agent` and
/// everything it reaches through normal and build edges (build scripts
/// compile C into the crates they build), never dev-dependencies.
fn shipped(nodes: &[Node]) -> Vec<&Node> {
    let mut seen: Vec<&str> = vec!["databastion-agent"];
    let mut i = 0;
    while let Some(name) = seen.get(i).copied() {
        for n in nodes.iter().filter(|n| n.0 == name) {
            for (d, normal, build) in &n.2 {
                if (*normal || *build) && !seen.contains(&d.as_str()) {
                    seen.push(d);
                }
            }
        }
        i += 1;
    }
    nodes
        .iter()
        .filter(|n| seen.contains(&n.0.as_str()))
        .collect()
}

/// ADR-0059 decision 1 (security review L7): "no C client library" made
/// mechanical. On each release target, every package of the shipped
/// binary's graph with a
/// `links` key or a build dependency on `cc`, `cmake`, `bindgen`,
/// `pkg-config`, `autotools` or `vcpkg` is in a closed list: `ring` and
/// `libsqlite3-sys` (with its expected build dependencies). Any new C code
/// needs this list changed, so a review.
#[test]
fn c_code_is_allow_listed() {
    const BUILD_TOOLS: [&str; 6] = ["cc", "cmake", "bindgen", "pkg-config", "autotools", "vcpkg"];
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        let metadata = cargo_metadata_with(&["--filter-platform", target]);
        let nodes = resolved_nodes(&metadata);
        let mut found = Vec::new();
        for (name, links, deps, _) in shipped(&nodes).into_iter().cloned() {
            let mut tools: Vec<String> = deps
                .iter()
                .filter(|(d, _, build)| *build && BUILD_TOOLS.contains(&d.as_str()))
                .map(|(d, _, _)| d.clone())
                .collect();
            tools.sort();
            if links.is_none() && tools.is_empty() {
                continue;
            }
            match name.as_str() {
                "ring" => {
                    assert!(
                        links
                            .as_deref()
                            .is_some_and(|l| l.starts_with("ring_core_")),
                        "{target}: ring links {links:?}"
                    );
                    assert_eq!(tools, ["cc"], "{target}: ring");
                }
                "libsqlite3-sys" => {
                    assert_eq!(links.as_deref(), Some("sqlite3"), "{target}");
                    assert_eq!(
                        tools,
                        ["cc", "pkg-config", "vcpkg"],
                        "{target}: libsqlite3-sys"
                    );
                }
                other => panic!(
                    "{target}: {other} builds C code (links {links:?}, build tools {tools:?}): \
                     the agent links no other C library (ADR-0039 decision 4, ADR-0059 decision 1)"
                ),
            }
            found.push(name);
        }
        found.sort();
        found.dedup();
        if cfg!(feature = "sqlite") {
            assert_eq!(found, ["libsqlite3-sys", "ring"], "{target}");
        }
    }
}

/// Review L11: no shipped crate links a library through `#[link(` or a
/// `rustc-link-lib` directive outside a closed list, so C code cannot come
/// in through a prebuilt or system library either. Scans `src/` and
/// `build.rs` of every package the shipped binary is built from, on both
/// release targets.
#[test]
fn linked_libraries_are_allow_listed() {
    const ALLOWED: [(&str, &str); 9] = [
        ("libc", "bindings of the platform C library"),
        (
            "getrandom",
            "the platform random source on other operating systems",
        ),
        ("whoami", "platform user APIs on other operating systems"),
        (
            "ring",
            "its own C and assembly objects (c_code_is_allow_listed)",
        ),
        (
            "libsqlite3-sys",
            "the bundled SQLite (c_code_is_allow_listed)",
        ),
        (
            "cc",
            "a build tool emitting the directives of the crates above",
        ),
        (
            "pkg-config",
            "a build tool (libsqlite3-sys, unused by the bundled build)",
        ),
        (
            "vcpkg",
            "a build tool (libsqlite3-sys, unused by the bundled build)",
        ),
        ("find-msvc-tools", "cc's Windows support, a build tool"),
    ];
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        let metadata = cargo_metadata_with(&["--filter-platform", target]);
        let nodes = resolved_nodes(&metadata);
        let shipped: Vec<String> = shipped(&nodes).iter().map(|n| n.0.clone()).collect();
        for p in metadata["packages"].as_array().unwrap() {
            let name = p["name"].as_str().unwrap();
            if !shipped.iter().any(|s| s == name) {
                continue;
            }
            let dir = Path::new(p["manifest_path"].as_str().unwrap())
                .parent()
                .unwrap()
                .to_owned();
            let mut sources = Vec::new();
            rust_sources(&dir.join("src"), &mut sources);
            if dir.join("build.rs").is_file() {
                sources.push(dir.join("build.rs"));
            }
            let links = sources.iter().any(|f| {
                let text = fs::read_to_string(f).unwrap_or_default();
                text.contains("#[link(") || text.contains("rustc-link-lib")
            });
            if links {
                assert!(
                    ALLOWED.iter().any(|(n, _)| *n == name),
                    "{target}: {name} links a library (#[link( or rustc-link-lib): review it \
                     and extend the allow-list (ADR-0059 decision 1)"
                );
            }
        }
    }
}

/// ADR-0059 decision 1: the reviewed features of the SQLite crates in the
/// resolved graph (the fuzz workspace, which enables `with-asan`, has its
/// own lock and is not checked here).
#[cfg(feature = "sqlite")]
#[test]
fn sqlite_features_are_the_reviewed_ones() {
    let metadata = cargo_metadata();
    let nodes = resolved_nodes(&metadata);
    let features = |crate_name: &str| -> Vec<String> {
        let mut f: Vec<String> = nodes
            .iter()
            .filter(|n| n.0 == crate_name)
            .flat_map(|n| n.3.clone())
            .collect();
        f.sort();
        f.dedup();
        f
    };
    assert_eq!(
        features("rusqlite"),
        // `wal`: implied by `hooks` since rusqlite 0.41 (agent/deny.toml).
        ["bundled", "hooks", "limits", "modern_sqlite", "wal"],
        "rusqlite features"
    );
    let sys = features("libsqlite3-sys");
    assert!(sys.iter().any(|f| f == "bundled"), "{sys:?}");
    for off in [
        "with-asan",
        "loadable_extension",
        "buildtime_bindgen",
        "bundled-sqlcipher",
        "bundled-sqlcipher-vendored-openssl",
        "sqlcipher",
        "session",
        "preupdate_hook",
        "column_metadata",
    ] {
        assert!(
            !sys.iter().any(|f| f == off),
            "libsqlite3-sys has {off}: {sys:?}"
        );
    }
}

/// ADR-0059 decisions 1 and 4: in the resolved graph, the only normal
/// dependent of `rusqlite` and of the sandbox crates is the SQLite
/// connector, and the only one of `libsqlite3-sys` is `rusqlite`.
#[test]
fn only_connector_sqlite_uses_rusqlite() {
    let metadata = cargo_metadata();
    let nodes = resolved_nodes(&metadata);
    let dependents = |dep: &str| -> Vec<String> {
        let mut v: Vec<String> = nodes
            .iter()
            .filter(|n| n.2.iter().any(|(d, normal, _)| d == dep && *normal))
            .map(|n| n.0.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    for dep in ["rusqlite", "landlock", "seccompiler", "nix"] {
        let d = dependents(dep);
        assert!(
            d.is_empty() || d == ["databastion-connector-sqlite"],
            "{dep} is used by {d:?}"
        );
    }
    let d = dependents("libsqlite3-sys");
    assert!(
        d.is_empty() || d == ["rusqlite"],
        "libsqlite3-sys is used by {d:?}"
    );
}

/// The source files of the SQLite connector, with their code lines (no
/// comment lines) before the first `mod tests {`.
fn sqlite_sources() -> Vec<(PathBuf, Vec<String>)> {
    let krate = workspace_root().join("crates").join("connector-sqlite");
    let mut sources = Vec::new();
    rust_sources(&krate.join("src"), &mut sources);
    assert!(sources.len() >= 10, "source discovery looks broken");
    sources
        .into_iter()
        .map(|p| {
            let text = fs::read_to_string(&p).unwrap();
            let lines: Vec<String> = code_lines(&text)
                .take_while(|l| !l.trim_end().ends_with("mod tests {"))
                .map(str::to_owned)
                .collect();
            (p, lines)
        })
        .collect()
}

fn is_test_file(p: &Path) -> bool {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name == "it.rs" || name == "testing.rs"
}

/// ADR-0059 decisions 1 and 4, I1 (the CAS test's twin): the SQLite
/// connector opens no network connection: no TLS crate, no tokio `net`
/// feature, no TCP type, and `UnixStream` only as `UnixStream::pair` in
/// the IPC module, never connected.
#[test]
fn sqlite_connector_opens_no_network_connection() {
    let krate = workspace_root().join("crates").join("connector-sqlite");
    let manifest = fs::read_to_string(krate.join("Cargo.toml")).unwrap();
    for (key, _) in declared_dependencies(&manifest) {
        assert!(
            !key.contains("rustls") && !key.contains("tls") && key != "socket2",
            "connector-sqlite depends on {key}"
        );
    }
    for line in code_lines(&manifest).filter(|l| l.starts_with("tokio")) {
        assert!(
            !line.contains("\"net\""),
            "connector-sqlite enables tokio's net feature"
        );
    }
    for (source, lines) in sqlite_sources() {
        let shown = source.display().to_string();
        let ipc = shown.ends_with("connector-sqlite/src/ipc.rs");
        for l in &lines {
            for api in [
                "TcpStream",
                "tokio::net",
                "std::net::Tcp",
                "ToSocketAddrs",
                ".connect(",
            ] {
                assert!(!l.contains(api), "{shown} uses {api}");
            }
            if l.contains("UnixStream") {
                assert!(ipc, "{shown} uses UnixStream outside the IPC module");
                let calls: Vec<&str> = l.split("UnixStream::").skip(1).collect();
                assert!(
                    calls.iter().all(|c| c.starts_with("pair(")),
                    "{shown}: UnixStream other than UnixStream::pair: {l}"
                );
            }
        }
    }
}

/// ADR-0059 decision 5: the statements are a closed list of templates;
/// none reaches beyond reading; every sampling template keeps the planner
/// on the table's own b-tree (`NOT INDEXED`); and no source line reaches
/// SQLite's C API, its log callback or extension loading.
#[cfg(feature = "sqlite")]
#[test]
fn sqlite_connector_statements_are_closed() {
    const BANNED: [&str; 21] = [
        "attach",
        "load_extension",
        "writable_schema",
        "immutable",
        "nolock",
        "mode=rw",
        "insert",
        "update",
        "delete",
        "replace",
        "create",
        "drop",
        "alter",
        "vacuum",
        "reindex",
        "analyze",
        "begin",
        "savepoint",
        "table_list",
        "pragma_",
        "sqlite_dbpage",
    ];
    let list = databastion_connector_sqlite::statement_allow_list();
    assert!(list.len() >= 15, "allow-list looks empty");
    for (name, text) in list {
        let lower = text.to_ascii_lowercase();
        for b in BANNED {
            assert!(!lower.contains(b), "statement {name} contains {b}");
        }
    }
    for t in databastion_connector_sqlite::sql::sampling_templates() {
        assert!(t.contains("NOT INDEXED"), "{t}");
    }
    for (source, lines) in sqlite_sources() {
        if is_test_file(&source) {
            continue;
        }
        let shown = source.display().to_string();
        for l in &lines {
            let version_constant = shown.ends_with("connector-sqlite/src/db.rs")
                && (l.contains("rusqlite::ffi::SQLITE_VERSION")
                    || l.contains("rusqlite::ffi::SQLITE_SOURCE_ID"));
            if !version_constant {
                assert!(!l.contains("rusqlite::ffi"), "{shown}: {l}");
            }
            for banned in [
                "libsqlite3_sys",
                "config_log",
                "load_extension",
                "Connection::handle",
                ".handle()",
                // rusqlite 0.41's `wal` feature (implied by `hooks`).
                "wal_checkpoint",
                "wal_hook",
                "rusqlite::wal",
            ] {
                assert!(!l.contains(banned), "{shown} names {banned}");
            }
        }
    }
}

/// ADR-0059 decision 5 (security review L1): no `rusqlite::Error` is ever
/// formatted. Only the `db` module names `rusqlite` (the test support and
/// in-process tests aside); its code has no formatting, logging or
/// `to_string` at all, so an error it maps can never be printed; and the
/// crate's `clippy.toml` bans `ToString::to_string`.
#[test]
fn sqlite_errors_are_never_formatted() {
    for (source, lines) in sqlite_sources() {
        let shown = source.display().to_string();
        let db = shown.ends_with("connector-sqlite/src/db.rs");
        if !db && !is_test_file(&source) {
            for l in &lines {
                assert!(
                    !l.contains("rusqlite"),
                    "{shown} names rusqlite outside db.rs: {l}"
                );
            }
        }
        if db {
            for l in &lines {
                for banned in [
                    "format!(",
                    "write!(",
                    "writeln!(",
                    "print",
                    "tracing",
                    ".to_string()",
                    "{:?}",
                    "{e",
                    "{err",
                    "?e",
                    "%e",
                    "panic!(",
                    ".unwrap()",
                    ".expect(",
                    "dbg!(",
                ] {
                    assert!(!l.contains(banned), "db.rs: {banned} in {l}");
                }
            }
        }
    }
    let clippy = fs::read_to_string(
        workspace_root()
            .join("crates")
            .join("connector-sqlite")
            .join("clippy.toml"),
    )
    .unwrap();
    assert!(
        clippy.contains("std::string::ToString::to_string"),
        "{clippy}"
    );
}

/// ADR-0059 decision 4: the only process the agent's code starts is its
/// own binary, in the SQLite reader mode (`/proc/self/exe sqlite-reader`):
/// one `Command::new` in the crates' code, test code aside, and no other
/// line that names a process `Command` or calls `.spawn()` (a process can
/// be started from a `Command` built elsewhere; security review L1 of
/// #413). The SQLite fuzz entry points (`connector-sqlite/src/fuzz.rs`,
/// whose `-shm` helper is started from a `Command` its fuzz target builds)
/// are exempt only while that module is compiled for tests and the
/// `fuzzing` feature alone, a feature the agent never enables
/// ([`the_agent_never_enables_connector_fuzzing`]).
#[test]
fn the_only_spawned_process_is_the_sqlite_reader() {
    let starts_a_process = |l: &str| {
        l.contains("Command::new")
            || l.contains(".spawn()")
            || (l.contains("process::") && l.contains("Command"))
    };
    let lib =
        fs::read_to_string(workspace_root().join("crates/connector-sqlite/src/lib.rs")).unwrap();
    let lib_lines: Vec<&str> = code_lines(&lib).map(str::trim).collect();
    let fuzz_mod = lib_lines
        .iter()
        .position(|l| *l == "pub mod fuzz;")
        .expect("connector-sqlite declares `pub mod fuzz;`");
    let attributes: Vec<&str> = lib_lines[..fuzz_mod]
        .iter()
        .rev()
        .take_while(|l| l.starts_with("#["))
        .copied()
        .collect();
    assert!(
        attributes.contains(&"#[cfg(any(test, feature = \"fuzzing\"))]"),
        "`pub mod fuzz` must be compiled for tests and the fuzzing feature only: {attributes:?}"
    );
    let mut found = Vec::new();
    for source in all_crate_sources() {
        let shown = source.display().to_string();
        if shown.contains("/tests/")
            || shown.contains("/it/")
            || shown.contains("/it.rs")
            || shown.contains("/it_")
            || shown.contains("testserver")
            || shown.ends_with("connector-sqlite/src/fuzz.rs")
        {
            continue;
        }
        let text = fs::read_to_string(&source).unwrap();
        for l in code_lines(&text).take_while(|l| !l.trim_end().ends_with("mod tests {")) {
            if starts_a_process(l) {
                found.push((shown.clone(), l.trim().to_owned()));
            }
        }
    }
    for (file, _) in &found {
        assert!(
            file.ends_with("connector-sqlite/src/process.rs"),
            "{found:?}"
        );
    }
    let lines: Vec<&str> = found.iter().map(|(_, l)| l.as_str()).collect();
    assert_eq!(
        lines,
        [
            "let mut command = tokio::process::Command::new(executable());",
            "let child = command.spawn().map_err(|_| Death::Spawn)?;",
        ],
        "{found:?}"
    );
    let process =
        fs::read_to_string(workspace_root().join("crates/connector-sqlite/src/process.rs"))
            .unwrap();
    assert!(process.contains("PathBuf::from(\"/proc/self/exe\")"));
    assert!(process.contains(".env_clear()"));
}

/// Security review L1 of #413, generalized by note 2 of the review of #420:
/// no crate of the agent workspace enables the `fuzzing` feature of a crate
/// that has one (the connectors' fuzz entry points and test hooks: the
/// SQLite `-shm` helper, Firebird's `Ledger::credit_at` and `register_at`,
/// and the like), neither in the resolved graph nor through a declared
/// dependency or a feature of its own; only the fuzz workspace
/// (`agent/fuzz`, outside this one) does.
#[test]
fn the_agent_never_enables_connector_fuzzing() {
    let metadata = cargo_metadata();
    let packages = metadata["packages"].as_array().unwrap();
    let members: Vec<&str> = metadata["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap())
        .collect();
    let crates: Vec<&str> = packages
        .iter()
        .filter(|p| members.contains(&p["id"].as_str().unwrap()))
        .filter(|p| p["features"].get("fuzzing").is_some())
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    for must in [
        "databastion-connector-sqlite",
        "databastion-connector-firebird",
        "databastion-connector-mongodb",
        "databastion-connector-sqlserver",
    ] {
        assert!(
            crates.contains(&must),
            "{must} has no fuzzing feature: {crates:?}"
        );
    }
    let nodes = resolved_nodes(&metadata);
    #[cfg(feature = "sqlite")]
    assert!(nodes.iter().any(|n| n.0 == "databastion-connector-sqlite"));
    #[cfg(feature = "firebird")]
    assert!(
        nodes
            .iter()
            .any(|n| n.0 == "databastion-connector-firebird")
    );
    for krate in &crates {
        let resolved: Vec<&String> = nodes
            .iter()
            .filter(|n| n.0 == *krate)
            .flat_map(|n| n.3.iter())
            .collect();
        assert!(
            !resolved.iter().any(|f| *f == "fuzzing"),
            "{krate} resolved with {resolved:?}"
        );
        for p in packages {
            let name = p["name"].as_str().unwrap();
            if name == *krate {
                continue;
            }
            for d in p["dependencies"].as_array().unwrap() {
                if d["name"] == *krate {
                    let f = d["features"].as_array().unwrap();
                    assert!(
                        !f.iter().any(|x| x == "fuzzing"),
                        "{name} depends on {krate} with {f:?}"
                    );
                }
            }
            for (feature, enables) in p["features"].as_object().unwrap() {
                for e in enables.as_array().unwrap() {
                    let e = e.as_str().unwrap();
                    assert!(
                        e != format!("{krate}/fuzzing") && e != format!("{krate}?/fuzzing"),
                        "{name} feature {feature} enables {e}"
                    );
                }
            }
        }
    }
}

/// The code lines of a source outside its test modules: a `#[cfg(test)]`
/// attribute whose item is an inline `mod tests { … }` (other attributes
/// may stand between them) skips that module's brace-balanced body, and
/// the scan goes on after it (#416 final review N-L1: code placed after the
/// test module is still checked); `#[cfg(test)] mod tests;` is a
/// declaration, skipped alone (its file is scanned as a source of its own).
/// A bare `mod tests {` is scanned (security review L1 of #416).
fn lines_outside_cfg_test_mods(text: &str) -> Vec<&str> {
    let lines: Vec<&str> = code_lines(text).collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == "#[cfg(test)]" {
            let item = lines[i + 1..]
                .iter()
                .position(|l| {
                    let l = l.trim();
                    !l.is_empty() && !l.starts_with("#[")
                })
                .map(|k| i + 1 + k);
            if let Some(at) = item {
                let l = lines[at].trim();
                let l = l.strip_prefix("pub(crate) ").unwrap_or(l);
                if l.starts_with("mod tests;") {
                    i = at + 1;
                    continue;
                }
                if l.starts_with("mod tests ") || l.starts_with("mod tests{") {
                    i = match module_end(&lines, at) {
                        Some(end) => end + 1,
                        // Unbalanced: nothing after it is taken as test code.
                        None => at + 1,
                    };
                    continue;
                }
            }
        }
        out.push(lines[i]);
        i += 1;
    }
    out
}

/// The index of the line that closes the brace-balanced item starting at
/// line `start` (braces inside string and character literals, and after a
/// `//`, are not counted); `None` when it never closes.
fn module_end(lines: &[&str], start: usize) -> Option<usize> {
    let mut depth = 0i64;
    let mut opened = false;
    let mut in_str = false;
    for (k, line) in lines.iter().enumerate().skip(start) {
        let b = line.as_bytes();
        let mut j = 0;
        while j < b.len() {
            let c = b[j];
            if in_str {
                match c {
                    b'\\' => j += 1,
                    b'"' => in_str = false,
                    _ => {}
                }
            } else {
                match c {
                    b'/' if b.get(j + 1) == Some(&b'/') => break,
                    b'"' => in_str = true,
                    // A character literal (`'{'`, `'\''`), not a lifetime.
                    b'\'' if b.get(j + 2) == Some(&b'\'') => j += 2,
                    b'\'' if b.get(j + 1) == Some(&b'\\') => {
                        // To its closing quote, after the escaped character.
                        j += b
                            .get(j + 3..)
                            .and_then(|r| r.iter().position(|x| *x == b'\''))
                            .map_or(0, |p| p + 3);
                    }
                    b'{' => {
                        depth += 1;
                        opened = true;
                    }
                    b'}' => depth -= 1,
                    _ => {}
                }
            }
            j += 1;
        }
        if opened && depth <= 0 {
            return Some(k);
        }
    }
    None
}

/// Every identifier-like token of `line` (`[A-Za-z0-9_]+`) that names
/// `openat2` in any form: the call, a path (`fcntl::openat2`), an import
/// or alias (`use rustix::fs::openat2 as o`, `let f = rustix::fs::openat2;`),
/// the syscall number (`SYS_openat2`), whatever follows it.
fn openat2_tokens(line: &str) -> usize {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| t.to_ascii_lowercase().contains("openat2"))
        .count()
}

/// The attributes right above each `mod <name>;` / `#[path = …] mod …;`
/// declaration of `file` in the crate's other sources, with the declaring
/// file. Empty when `file` is declared nowhere (then it counts as not
/// test-only).
fn module_declarations(file: &Path, crate_sources: &[PathBuf]) -> Vec<(PathBuf, Vec<String>)> {
    let stem = file.file_stem().unwrap().to_str().unwrap();
    let dir = file.parent().unwrap();
    let mut found = Vec::new();
    for decl in crate_sources {
        if decl == file {
            continue;
        }
        let ddir = decl.parent().unwrap();
        let dname = decl.file_stem().unwrap().to_str().unwrap();
        // The directory where `decl`'s child modules live.
        let children = if ["lib", "main", "mod"].contains(&dname) {
            ddir.to_path_buf()
        } else {
            ddir.join(dname)
        };
        let text = fs::read_to_string(decl).unwrap();
        let lines: Vec<&str> = code_lines(&text).map(str::trim).collect();
        for (i, l) in lines.iter().enumerate() {
            let item = l
                .trim_start_matches("pub(crate) ")
                .trim_start_matches("pub ");
            let Some(rest) = item.strip_prefix("mod ") else {
                continue;
            };
            let Some(module) = rest.strip_suffix(';') else {
                continue;
            };
            let attrs: Vec<String> = lines[..i]
                .iter()
                .rev()
                .take_while(|a| a.starts_with("#["))
                .map(|a| (*a).to_owned())
                .collect();
            let path_attr = attrs
                .iter()
                .find_map(|a| a.strip_prefix("#[path = \"")?.strip_suffix("\"]"));
            let declares = match path_attr {
                Some(p) => ddir.join(p) == file,
                None => module.trim() == stem && children == dir,
            };
            if declares {
                found.push((decl.clone(), attrs));
            }
        }
    }
    found
}

/// Whether `file` is compiled for tests only: each of its declarations is
/// under `#[cfg(test)]` (or `#[cfg(all(test, …))]`), or in a file that is
/// itself test-only.
fn declared_under_cfg_test(file: &Path, crate_sources: &[PathBuf], depth: usize) -> bool {
    let decls = module_declarations(file, crate_sources);
    !decls.is_empty()
        && depth < 8
        && decls.iter().all(|(decl, attrs)| {
            attrs
                .iter()
                .any(|a| a == "#[cfg(test)]" || a.starts_with("#[cfg(all(test,"))
                || declared_under_cfg_test(decl, crate_sources, depth + 1)
        })
}

/// The `openat2` mentions of the agent's non-test code, per file.
fn openat2_outside_tests() -> Vec<(String, String)> {
    let mut by_crate: std::collections::BTreeMap<PathBuf, Vec<PathBuf>> = Default::default();
    let crates = workspace_root().join("crates");
    for source in all_crate_sources() {
        let krate = crates.join(source.strip_prefix(&crates).unwrap().iter().next().unwrap());
        by_crate.entry(krate).or_default().push(source);
    }
    let mut found = Vec::new();
    for (krate, sources) in &by_crate {
        let src: Vec<PathBuf> = sources
            .iter()
            .filter(|p| p.starts_with(krate.join("src")))
            .cloned()
            .collect();
        for source in sources {
            // Integration tests are compiled as tests only.
            if source.starts_with(krate.join("tests")) {
                continue;
            }
            let shown = source.display().to_string();
            let name = source.file_name().unwrap().to_str().unwrap();
            let test_named =
                name == "it.rs" || name.starts_with("it_") || name.ends_with("_tests.rs");
            if test_named && declared_under_cfg_test(source, &src, 0) {
                continue;
            }
            let text = fs::read_to_string(source).unwrap();
            for l in lines_outside_cfg_test_mods(&text) {
                if openat2_tokens(l) > 0 {
                    found.push((shown.clone(), l.trim().to_owned()));
                }
            }
        }
    }
    found
}

/// Security review F1 (the Firebird lot) and #415: every path opened with
/// no symbolic link followed goes through `databastion_core::fs`, whose
/// `open_no_links` falls back to a component walk where `openat2` answers
/// `ENOSYS` (the agent's systemd unit, `RestrictSUIDSGID=yes`). Test code
/// aside (a crate's `tests/`, a `#[cfg(test)] mod tests`, and `it.rs`,
/// `it_*.rs` or `*_tests.rs` files only when declared under
/// `#[cfg(test)]`), `openat2` is named in that module only, once, in any
/// form (call, path, import, alias, syscall number; security review L1 of
/// #416), and both the SQLite grant and the Firebird host identity files
/// use it; the module logs and formats nothing (I2: it is handed paths of
/// host files).
#[test]
fn openat2_only_through_core_fs() {
    let core_fs = workspace_root().join("crates/core/src/fs.rs");
    let found = openat2_outside_tests();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].0 == core_fs.display().to_string() && found[0].1 == "match rustix::fs::openat2(",
        "openat2 outside core::fs: {found:?}"
    );
    for user in [
        "crates/connector-sqlite/src/sandbox.rs",
        "crates/connector-firebird/src/host_identity.rs",
    ] {
        let text = fs::read_to_string(workspace_root().join(user)).unwrap();
        assert!(
            code_lines(&text).any(|l| l.contains("databastion_core::fs::open_no_links(")),
            "{user} does not use databastion_core::fs::open_no_links"
        );
    }
    let text = fs::read_to_string(&core_fs).unwrap();
    for l in lines_outside_cfg_test_mods(&text) {
        for banned in [
            "tracing",
            "log::",
            "print",
            "format!(",
            "write!(",
            "dbg!(",
            "panic!(",
            ".unwrap()",
            ".expect(",
        ] {
            assert!(!l.contains(banned), "core/src/fs.rs: {banned} in {l}");
        }
    }
}

/// The helpers of [`openat2_only_through_core_fs`] on their own: every
/// form of the name is seen, a bare `mod tests {` does not end the scan,
/// and the known test-only files are recognized as such.
#[test]
fn openat2_rule_helpers() {
    for l in [
        "rustix::fs::openat2(CWD, p, f, m, r)",
        "let f = rustix::fs::openat2;",
        "use rustix::fs::openat2 as o;",
        "use rustix::fs::{openat2, Mode};",
        "nix::fcntl::openat2 (dirfd, p, how)",
        "const N: i64 = libc::SYS_openat2;",
        "let n = libc::SYS_OPENAT2;",
    ] {
        assert_eq!(openat2_tokens(l), 1, "{l}");
    }
    assert_eq!(openat2_tokens("rustix::fs::openat(CWD, p, f, m)"), 0);
    let text = "fn a() {}\nmod tests {\nfn b() { openat2(); }\n}\n";
    assert_eq!(lines_outside_cfg_test_mods(text).len(), 4);
    let text = "fn a() {}\n#[cfg(test)]\n#[allow(dead_code)]\nmod tests {\nfn b() {}\n}\n";
    assert_eq!(lines_outside_cfg_test_mods(text), ["fn a() {}"]);
    let text = "#[cfg(test)]\nfn helper() {}\nfn c() {}\n";
    assert_eq!(lines_outside_cfg_test_mods(text).len(), 3);
    // #416 final review N-L1: a function after the inline test module is
    // scanned, the module's body (braces in literals included) is not.
    let text = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn b() {\n        let s = \"}}\";\n        let c = '}';\n        let q = '\\'';\n        openat2(); // }\n    }\n}\nfn after() { openat2(); }\n";
    assert_eq!(
        lines_outside_cfg_test_mods(text),
        ["fn a() {}", "fn after() { openat2(); }"]
    );
    let found: usize = lines_outside_cfg_test_mods(text)
        .iter()
        .map(|l| openat2_tokens(l))
        .sum();
    assert_eq!(found, 1);
    // `#[cfg(test)] mod tests;` is a declaration, not a cut-off.
    let text = "fn a() {}\n#[cfg(test)]\nmod tests;\nfn after() { openat2(); }\n";
    assert_eq!(
        lines_outside_cfg_test_mods(text),
        ["fn a() {}", "fn after() { openat2(); }"]
    );
    // A one-line module, and a `pub(crate)` one.
    let text = "#[cfg(test)]\nmod tests { fn t() {} }\n#[cfg(test)]\npub(crate) mod tests {\n}\nfn z() {}\n";
    assert_eq!(lines_outside_cfg_test_mods(text), ["fn z() {}"]);
    // Never closed: the rest is scanned (fail closed).
    let text = "#[cfg(test)]\nmod tests {\nfn y() { openat2(); }\n";
    assert_eq!(lines_outside_cfg_test_mods(text).len(), 1);
    let fb = workspace_root().join("crates/connector-firebird/src");
    let mut src = Vec::new();
    rust_sources(&fb, &mut src);
    for test_only in [
        "it.rs",
        "it_unit.rs",
        "it_host_identity.rs",
        "host_identity_tests.rs",
        "stream_tests.rs",
    ] {
        assert!(
            declared_under_cfg_test(&fb.join(test_only), &src, 0),
            "{test_only} is not seen as test-only"
        );
    }
    for shipped in ["host_identity.rs", "fsread.rs", "lib.rs"] {
        assert!(
            !declared_under_cfg_test(&fb.join(shipped), &src, 0),
            "{shipped} is seen as test-only"
        );
    }
}
