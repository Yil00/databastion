//! Fuzz target (differential, ADR-0046): on every CAS YAML service definition the pre-scan accepts,
//! the crate's own YAML parser and `serde_yaml_ng` 0.10 (the oracle, never linked into the agent
//! through `connector-cas`) must read the same values and the same definition, or both fail.
#![no_main]

use libfuzzer_sys::fuzz_target;

struct SerdeYamlNg;

impl databastion_connector_cas::fuzz::YamlOracle for SerdeYamlNg {
    type De<'a> = serde_yaml_ng::Deserializer<'a>;

    fn deserializer<'a>(&self, text: &'a [u8]) -> Self::De<'a> {
        serde_yaml_ng::Deserializer::from_slice(text)
    }
}

fuzz_target!(|data: &[u8]| {
    databastion_connector_cas::fuzz::registry_yaml_diff(data, &SerdeYamlNg);
});
