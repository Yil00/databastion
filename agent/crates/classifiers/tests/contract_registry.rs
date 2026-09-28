//! The compiled classifier set must match the contract classifier registry
//! (`shared/protocol/classifiers.json`): the console rejects findings whose
//! `classifiers_version` or classifier id is not registered there (`400`
//! `enum`), so a drift would get every finding of the agent dropped.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use databastion_classifiers::id::{CLASSIFIERS_VERSION, ClassifierId};

const REGISTRY: &str = include_str!("../../../../shared/protocol/classifiers.json");

fn registry() -> BTreeMap<String, Vec<String>> {
    serde_json::from_str(REGISTRY).expect("classifiers.json is a map of version -> ids")
}

#[test]
fn compiled_classifier_set_is_registered_in_the_contract() {
    let registry = registry();
    let Some(registered) = registry.get(CLASSIFIERS_VERSION) else {
        panic!(
            "CLASSIFIERS_VERSION {CLASSIFIERS_VERSION} is missing from shared/protocol/classifiers.json: \
             a new classifier set version needs a (compatible) contract change first"
        );
    };
    let compiled: Vec<&str> = ClassifierId::ALL.iter().map(|c| c.as_str()).collect();
    let mut compiled_sorted = compiled.clone();
    compiled_sorted.sort_unstable();
    assert_eq!(
        compiled_sorted, *registered,
        "the ids of CLASSIFIERS_VERSION {CLASSIFIERS_VERSION} differ from shared/protocol/classifiers.json; \
         a published version is never modified: bump CLASSIFIERS_VERSION and register the new set"
    );
}

#[test]
fn registry_entries_match_the_generated_contract_types() {
    for (version, ids) in registry() {
        databastion_protocol::ClassifiersVersion::try_from(version.as_str())
            .unwrap_or_else(|_| panic!("registry version {version} is not a ClassifiersVersion"));
        for id in ids {
            databastion_protocol::ClassifierId::try_from(id.as_str())
                .unwrap_or_else(|_| panic!("registry id {id} is not a ClassifierId"));
        }
    }
}
