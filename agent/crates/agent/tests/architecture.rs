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

const CONNECTORS: [&str; 4] = [
    "connector-postgres",
    "connector-mysql",
    "connector-mongodb",
    "connector-openldap",
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

#[test]
fn lockfile_has_no_openssl_or_native_tls() {
    let lock = fs::read_to_string(workspace_root().join("Cargo.lock")).unwrap();
    for banned in ["openssl", "openssl-sys", "openssl-src", "native-tls"] {
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
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let out_path = std::env::temp_dir().join(format!(
        "databastion-arch-metadata-{}.json",
        std::process::id()
    ));
    let out_file = fs::File::create(&out_path).unwrap();
    let mut child = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked"])
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

/// The tailer's test switch that accepts log files owned by the agent's
/// own user (end-of-phase-4 review L4) is only called from test code: the
/// connectors' integration-test modules (compiled under `#[cfg(test)]`)
/// and the tests module of the tailer itself.
#[test]
fn agent_owned_logs_are_allowed_in_tests_only() {
    const SWITCH: &str = "allow_agent_owned_logs_for_tests(";
    const TEST_ONLY: [&str; 4] = [
        "connector-postgres/src/it.rs",
        "connector-mysql/src/it/audit_it.rs",
        "connector-mongodb/src/it_audit.rs",
        "core/tests/",
    ];
    for source in all_crate_sources() {
        let text = fs::read_to_string(&source).unwrap();
        let shown = source.display().to_string();
        let calls: Vec<usize> = code_lines(&text)
            .enumerate()
            .filter(|(_, l)| l.contains(SWITCH) && !l.contains("fn "))
            .map(|(i, _)| i)
            .collect();
        if calls.is_empty() {
            continue;
        }
        if shown.ends_with("core/src/audit/tail.rs") {
            // Only inside its `mod tests`.
            let tests_at = code_lines(&text)
                .position(|l| l.trim() == "mod tests {")
                .expect("tail.rs has a tests module");
            assert!(calls.iter().all(|i| *i > tests_at), "{shown}");
            continue;
        }
        assert!(
            TEST_ONLY.iter().any(|t| shown.contains(t)),
            "{shown} calls {SWITCH}…) outside test code"
        );
    }
}
