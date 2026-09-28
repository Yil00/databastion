//! Architecture guards, run by `cargo test` in CI.
//!
//! - rustls only: no OpenSSL / native-tls in the dependency graph.
//! - Connectors never depend on an HTTP client nor reference the uplink
//!   (AGENTS.md: no direct uplink access from a connector; I2).
//! - No listening socket in agent code (I1). The future opt-in
//!   `metrics.local_listen` (127.0.0.1 only) will be the single allowlisted
//!   exception.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

const CONNECTORS: [&str; 4] = [
    "connector-postgres",
    "connector-mysql",
    "connector-mongodb",
    "connector-openldap",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn all_crate_sources() -> Vec<PathBuf> {
    let mut sources = Vec::new();
    for entry in fs::read_dir(workspace_root().join("crates")).unwrap() {
        let src = entry.unwrap().path().join("src");
        if src.is_dir() {
            rust_sources(&src, &mut sources);
        }
    }
    assert!(!sources.is_empty());
    sources
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
fn connectors_do_not_depend_on_http_clients() {
    for connector in CONNECTORS {
        let manifest = fs::read_to_string(
            workspace_root()
                .join("crates")
                .join(connector)
                .join("Cargo.toml"),
        )
        .unwrap();
        for banned in ["reqwest", "hyper", "ureq", "databastion-agent"] {
            assert!(
                !manifest.lines().any(|l| l.trim_start().starts_with(banned)),
                "{connector} depends on {banned}"
            );
        }
    }
}

#[test]
fn connectors_do_not_reference_the_uplink() {
    for connector in CONNECTORS {
        let mut sources = Vec::new();
        rust_sources(
            &workspace_root().join("crates").join(connector).join("src"),
            &mut sources,
        );
        for source in sources {
            let text = fs::read_to_string(&source).unwrap();
            assert!(
                !text.contains("uplink") && !text.contains("Uplink"),
                "{} references the uplink",
                source.display()
            );
        }
    }
}

#[test]
fn no_listening_socket_in_agent_code() {
    for source in all_crate_sources() {
        let text = fs::read_to_string(&source).unwrap();
        for banned in ["TcpListener", "UdpSocket", "UnixListener"] {
            assert!(
                !text.contains(banned),
                "{} uses {banned} (I1: the agent opens no inbound port)",
                source.display()
            );
        }
    }
}
