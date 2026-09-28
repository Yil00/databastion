//! Guards the **production** feature set of the `regex` crate.
//!
//! The detector patterns need `unicode-case` (`(?i)`), `unicode-perl`
//! (`\b`, `\s`, `\d`) and `unicode-gencat` (`\p{L}`). Unit tests cannot see
//! a missing feature: dev-dependencies (proptest pulls `regex-syntax` with
//! every Unicode feature) are unified into the test build, so a pattern that
//! compiles in tests may fail in the shipped agent. This test asks Cargo for
//! the features resolved **without** dev-dependencies.
//!
//! `detect::check_patterns` (called at agent startup) fails loudly if a
//! pattern does not compile; this test catches the cause before release.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

/// `regex-syntax` features the detector patterns need.
const REQUIRED: &[&str] = &["unicode-case", "unicode-perl", "unicode-gencat"];

#[test]
fn production_regex_features_cover_the_detector_patterns() {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--manifest-path",
            manifest,
            "-p",
            "databastion-classifiers",
            "--edges",
            "no-dev",
            "--invert",
            "regex-syntax",
            "--depth",
            "0",
            "--format",
            "{p} {f}",
            "--offline",
            "--locked",
        ])
        .output()
        .expect("cargo tree runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = stdout
        .lines()
        .find(|l| l.starts_with("regex-syntax "))
        .unwrap_or_else(|| panic!("regex-syntax not in the production tree: {stdout}"));
    let features: Vec<&str> = line
        .split_whitespace()
        .nth(2)
        .unwrap_or("")
        .split(',')
        .collect();
    for f in REQUIRED {
        assert!(
            features.contains(f),
            "regex-syntax feature {f} missing from the production build ({line}): \
             enable it on the classifiers' `regex` dependency"
        );
    }
}
