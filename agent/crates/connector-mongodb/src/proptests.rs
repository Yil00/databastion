//! Property tests of the parsers a hostile server feeds (BSON, `OP_MSG`,
//! SCRAM) and of the field-path normalization (I2: no key that looks like
//! a value survives in a path).

use databastion_classifiers::names;
use proptest::prelude::*;

use crate::bson::{Doc, DocBuf, Value};
use crate::paths::{self, Collector};
use crate::scram::Scram;
use crate::wire;

/// Walks every element of a document, depth-bounded, without panicking.
fn walk(doc: Doc<'_>, depth: usize) {
    for element in doc.iter() {
        let Ok((_, value)) = element else {
            return;
        };
        match value {
            Value::Doc(d) | Value::Array(d) if depth < 40 => walk(d, depth + 1),
            other => {
                let _ = paths::leaf_text(other);
            }
        }
    }
}

/// A key: a plain word, or one that embeds a value (e-mail, phone
/// number, long id).
fn key() -> impl Strategy<Value = (String, bool)> {
    prop_oneof![
        "[a-z][a-zA-Z_]{0,11}".prop_map(|k| (k, false)),
        "[a-z]{2,8}\\.[a-z]{2,8}@example\\.(com|org|net)".prop_map(|k| (k, true)),
        "(06|07|33)[0-9]{8}".prop_map(|k| (k, true)),
        "0[67] [0-9]{2} [0-9]{2} [0-9]{2} [0-9]{2}".prop_map(|k| (k, true)),
        "[0-9a-f]{24}".prop_map(|k| (k, true)),
    ]
}

/// A document of nested keys (at most three levels) with string leaves,
/// and the keys that embed values.
fn document() -> impl Strategy<Value = (Vec<u8>, Vec<String>)> {
    prop::collection::vec((key(), key(), key(), 0u8..3), 1..8).prop_map(|entries| {
        let mut values = Vec::new();
        let mut doc = DocBuf::new();
        let mut seen = std::collections::HashSet::new();
        for ((k1, v1), (k2, v2), (k3, v3), depth) in entries {
            // Distinct top-level keys.
            if !seen.insert(k1.clone()) {
                continue;
            }
            for (k, is_value) in [(&k1, v1), (&k2, v2), (&k3, v3)] {
                if is_value {
                    values.push(k.clone());
                }
            }
            let top = k1;
            doc = match depth {
                0 => doc.str(&top, "leaf"),
                1 => doc.doc(&top, DocBuf::new().str(&k2, "leaf")),
                _ => doc.doc(&top, DocBuf::new().doc(&k2, DocBuf::new().str(&k3, "leaf"))),
            };
        }
        (doc.finish(), values)
    })
}

proptest! {
    #[test]
    fn the_bson_reader_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(doc) = Doc::new(&bytes) {
            walk(doc, 0);
            let mut c = Collector::new(10);
            let _ = c.add_document(doc);
            for (name, _) in c.into_paths() {
                prop_assert!(names::conforms(name.as_str()), "{}", name.as_str());
            }
        }
        let _ = Doc::prefix(&bytes);
    }

    #[test]
    fn the_bson_reader_never_panics_on_mutated_documents(
        (doc, _) in document(),
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        let mut bytes = doc;
        let i = at.index(bytes.len());
        bytes[i] = byte;
        if let Ok(d) = Doc::new(&bytes) {
            walk(d, 0);
            let mut c = Collector::new(10);
            let _ = c.add_document(d);
        }
    }

    #[test]
    fn op_msg_framing_never_panics(
        header in prop::array::uniform16(any::<u8>()),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = wire::check_header(&header, 1);
        let _ = wire::parse(&payload);
    }

    #[test]
    fn scram_never_panics_on_server_messages(
        message in prop::collection::vec(any::<u8>(), 0..300),
        tail in "[!-+--~]{1,20}",
    ) {
        let (scram, _) = Scram::with_nonce("u", "abc");
        let _ = scram.client_final(&message, "pw");
        // A well-formed nonce with a random tail and iteration count below
        // the minimum: refused before any key derivation.
        let msg = format!("r=abc{tail},s=c2FsdA==,i=10");
        prop_assert!(scram.client_final(msg.as_bytes(), "pw").is_err());
    }

    #[test]
    fn value_conversions_never_panic(bytes in prop::array::uniform16(any::<u8>()), ms in any::<i64>(), d in any::<f64>()) {
        if let Some(s) = paths::decimal128(bytes) {
            prop_assert!(s.len() <= 90);
        }
        if let Some(s) = paths::date(ms) {
            prop_assert_eq!(s.len(), 10);
        }
        let _ = paths::double_digits(d);
    }

    /// No key that embeds a value survives in a normalized field path, and
    /// every path conforms to the contract `Identifier`.
    #[test]
    fn field_paths_never_carry_value_keys((doc, values) in document()) {
        let mut c = Collector::new(10);
        c.add_document(Doc::new(&doc).unwrap()).unwrap();
        for (name, _) in c.into_paths() {
            let name = name.as_str();
            prop_assert!(names::conforms(name), "{}", name);
            for v in &values {
                prop_assert!(!name.contains(v.as_str()), "{} kept {}", name, v);
            }
            prop_assert!(!name.contains('@'), "{}", name);
        }
    }
}
