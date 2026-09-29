//! The agent's signal vocabulary must match the contract signal registry
//! (`shared/protocol/signals.json`):
//! - every signal the agent can emit (`Signal::ALL`) is registered, so the
//!   agent never sends an id whose meaning the contract does not define;
//! - every registered signal of an engine whose Audit connector is
//!   implemented can be emitted, so the registry does not promise a signal
//!   the agent never produces.
//!
//! The `Signal` schema only checks the form of an id (an older console must
//! accept a signal registered later), so this test is where registration is
//! enforced on the agent side.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use databastion_classifiers::masking::Signal;

const REGISTRY: &str = include_str!("../../../../shared/protocol/signals.json");

/// Engines (contract `Engine` values) whose Audit connector is implemented.
/// Add an engine here in the change that implements its Audit connector,
/// together with its signals in `Signal` and in `signals.json`.
const AUDIT_ENGINES: &[&str] = &["postgres", "mysql", "mariadb", "mongodb"];

/// Registered engines of each signal id. The registry schema
/// (`signals.schema.json`) is checked by the protocol tests; here only the
/// shape this test needs is read.
fn registry() -> BTreeMap<String, Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(REGISTRY).expect("signals.json is JSON");
    let map = value
        .as_object()
        .expect("signals.json is a map of id -> entry");
    map.iter()
        .map(|(id, entry)| {
            let engines = entry
                .get("engines")
                .and_then(serde_json::Value::as_array)
                .unwrap_or_else(|| panic!("signals.json entry {id} has no engines list"))
                .iter()
                .map(|e| {
                    e.as_str()
                        .unwrap_or_else(|| {
                            panic!("signals.json entry {id}: engine is not a string")
                        })
                        .to_owned()
                })
                .collect();
            (id.clone(), engines)
        })
        .collect()
}

#[test]
fn every_agent_signal_is_registered() {
    let registry = registry();
    for s in Signal::ALL {
        assert!(
            registry.contains_key(s.as_str()),
            "signal {} is emitted by the agent but missing from shared/protocol/signals.json: \
             register it (compatible contract change) before emitting it",
            s.as_str()
        );
    }
}

#[test]
fn every_registered_signal_of_an_implemented_engine_is_emittable() {
    let emitted: BTreeSet<&str> = Signal::ALL.iter().map(|s| s.as_str()).collect();
    for (id, engines) in registry() {
        if engines.iter().any(|e| AUDIT_ENGINES.contains(&e.as_str())) {
            assert!(
                emitted.contains(id.as_str()),
                "signals.json registers {id} for an engine with an Audit connector, \
                 but the agent's Signal enum cannot emit it"
            );
        }
    }
}

#[test]
fn registry_ids_and_engines_match_the_generated_contract_types() {
    for (id, engines) in registry() {
        databastion_protocol::Signal::try_from(id.as_str())
            .unwrap_or_else(|_| panic!("registry id {id} is not a contract Signal"));
        for engine in engines {
            serde_json::from_value::<databastion_protocol::Engine>(serde_json::Value::from(
                engine.as_str(),
            ))
            .unwrap_or_else(|_| {
                panic!("registry engine {engine} of {id} is not a contract Engine")
            });
        }
    }
    for engine in AUDIT_ENGINES {
        serde_json::from_value::<databastion_protocol::Engine>(serde_json::Value::from(*engine))
            .unwrap_or_else(|_| panic!("{engine} is not a contract Engine"));
    }
}
