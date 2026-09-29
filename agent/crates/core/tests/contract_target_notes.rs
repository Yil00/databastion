//! The agent's target-note vocabulary must match the contract registry
//! (`shared/protocol/target-notes.json`), as `contract_signals.rs` does for
//! signals (ADR-0022 decision 9):
//! - every code the agent can send (`NoteCode::ALL`) is registered, so the
//!   agent never sends a code whose meaning the contract does not define;
//! - every registered code of an engine whose connector produces notes is
//!   in `NoteCode`, so the registry does not promise a note the agent can
//!   never produce.
//!
//! The `TargetNoteCode` schema only checks the form of a code (an older
//! console must accept a code registered later), so this test is where
//! registration is enforced on the agent side.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use databastion_core::NoteCode;

const REGISTRY: &str = include_str!("../../../../shared/protocol/target-notes.json");

/// Engines (contract `Engine` values) whose connector produces notes. Add
/// an engine here in the change that makes its connector produce notes.
const NOTE_ENGINES: &[&str] = &["postgres", "mysql", "mariadb"];

/// Registered engines and description of each code.
fn registry() -> BTreeMap<String, (Vec<String>, String)> {
    let value: serde_json::Value =
        serde_json::from_str(REGISTRY).expect("target-notes.json is JSON");
    let map = value
        .as_object()
        .expect("target-notes.json is a map of code -> entry");
    map.iter()
        .map(|(code, entry)| {
            let engines = entry
                .get("engines")
                .and_then(serde_json::Value::as_array)
                .unwrap_or_else(|| panic!("target-notes.json entry {code} has no engines list"))
                .iter()
                .map(|e| {
                    e.as_str()
                        .unwrap_or_else(|| panic!("entry {code}: engine is not a string"))
                        .to_owned()
                })
                .collect();
            let description = entry
                .get("description")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("entry {code} has no description"))
                .to_owned();
            (code.clone(), (engines, description))
        })
        .collect()
}

#[test]
fn every_agent_note_code_is_registered() {
    let registry = registry();
    for c in NoteCode::ALL {
        assert!(
            registry.contains_key(c.as_str()),
            "note code {} can be sent by the agent but is missing from \
             shared/protocol/target-notes.json: register it (compatible contract change) first",
            c.as_str()
        );
    }
}

#[test]
fn every_registered_code_of_a_producing_engine_is_in_the_enum() {
    let known: BTreeSet<&str> = NoteCode::ALL.iter().map(|c| c.as_str()).collect();
    for (code, (engines, _)) in registry() {
        if engines.iter().any(|e| NOTE_ENGINES.contains(&e.as_str())) {
            assert!(
                known.contains(code.as_str()),
                "target-notes.json registers {code} for an engine whose connector produces \
                 notes, but NoteCode cannot express it"
            );
        }
    }
}

#[test]
fn note_codes_are_unique() {
    let mut seen = BTreeSet::new();
    for c in NoteCode::ALL {
        assert!(seen.insert(c.as_str()), "{} listed twice", c.as_str());
    }
}

#[test]
fn registry_codes_and_engines_match_the_generated_contract_types() {
    for (code, (engines, description)) in registry() {
        databastion_protocol::TargetNoteCode::try_from(code.as_str())
            .unwrap_or_else(|_| panic!("registry code {code} is not a contract TargetNoteCode"));
        for engine in engines {
            serde_json::from_value::<databastion_protocol::Engine>(serde_json::Value::from(
                engine.as_str(),
            ))
            .unwrap_or_else(|_| panic!("registry engine {engine} of {code} is not an Engine"));
        }
        // ADR-0023: MySQL / MariaDB never reach Full, and no phrase of theirs
        // may promise it.
        assert!(
            !description.contains("Full") || !code_is_mysql_only(&code),
            "{code}: MySQL / MariaDB descriptions must not promise Full (ADR-0023)"
        );
    }
}

fn code_is_mysql_only(code: &str) -> bool {
    registry()
        .get(code)
        .is_some_and(|(engines, _)| engines.iter().all(|e| e == "mysql" || e == "mariadb"))
}
