//! Architecture guard (#252 review L1): only `connector-redis` calls
//! `OwnAccount::routine_within`, the own-read budget scaled by the
//! Redis / Valkey rule of ADR-0052 (refinement of 2026-10-16). Any other
//! caller, in another connector, in the agent or in a fuzz target, needs an
//! accepted ADR first (the method's own documentation says so). The core
//! defines it in `core/src/audit/own.rs`, which is the one other file
//! allowed to name it.
//!
//! A text-level guard over every crate of the workspace and the fuzz
//! targets, line comments left out: it catches an honest mistake, not a
//! determined author. Kept in this crate so the guard needs no change to
//! the core or to the agent's own architecture tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

const METHOD: &str = "routine_within";

/// The files allowed to name the method, relative to `agent/`.
const ALLOWED: [&str; 2] = ["crates/core/src/audit/own.rs", "crates/connector-redis/"];

fn agent_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            // Build output and checked-out dependencies are not sources.
            if name == "target" || name.starts_with('.') {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The code of each line, without its line comment.
fn code(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(|l| l.split_once("//").map_or(l, |(c, _)| c))
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn only_connector_redis_uses_the_scaled_own_read_budget() {
    let root = agent_root().canonicalize().unwrap();
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    rust_files(&root.join("fuzz"), &mut files);
    let mut defined = false;
    let mut called_here = false;
    let mut offenders = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        if !code(&text).any(|l| l.contains(METHOD)) {
            continue;
        }
        let rel = relative(&file, &root);
        if rel == "crates/core/src/audit/own.rs" {
            defined |= code(&text).any(|l| l.contains("pub fn routine_within("));
        } else if rel.starts_with("crates/connector-redis/src/") {
            called_here = true;
        }
        if !ALLOWED.iter().any(|a| rel.starts_with(a)) {
            offenders.push(rel);
        }
    }
    // The guard is not vacuous: it sees the definition and this crate's
    // call.
    assert!(defined, "OwnAccount::routine_within not found in the core");
    assert!(
        called_here,
        "connector-redis no longer calls routine_within"
    );
    assert!(
        offenders.is_empty(),
        "OwnAccount::routine_within is reserved to connector-redis (ADR-0052 \
         refinement of 2026-10-16; #252 review L1); a new caller needs an \
         accepted ADR: {offenders:?}"
    );
}

#[test]
fn the_comment_filter_keeps_code() {
    let text = "a.routine_within(x) // note\n// routine_within in a comment\n";
    let lines: Vec<&str> = code(text).collect();
    assert!(lines[0].contains(METHOD));
    assert!(!lines[1].contains(METHOD));
}
