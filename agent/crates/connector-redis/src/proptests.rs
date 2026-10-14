//! Property tests of the reply decoder (ADR-0052 decision 1): round trips
//! of generated replies, every split of a valid stream into chunks, and
//! arbitrary bytes that never panic nor buffer past the limits.

use proptest::prelude::*;

use crate::resp::{Bytes, Decoder, Limits, Value, decode_all};

const L: Limits = Limits {
    bulk: 256,
    items: 16,
    skip_oversized: false,
    reply: 64 * 1024,
};

/// Serializes a value as a server would (RESP3).
fn wire(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Str(b) => {
            out.extend_from_slice(format!("${}\r\n", b.as_slice().len()).as_bytes());
            out.extend_from_slice(b.as_slice());
            out.extend_from_slice(b"\r\n");
        }
        Value::Int(n) => out.extend_from_slice(format!(":{n}\r\n").as_bytes()),
        Value::Null => out.extend_from_slice(b"_\r\n"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"#t\r\n" } else { b"#f\r\n" }),
        Value::Number => out.extend_from_slice(b",1.5\r\n"),
        Value::Error(w) => {
            out.extend_from_slice(format!("-{} some text\r\n", w.as_str()).as_bytes())
        }
        Value::Array(items) => {
            out.extend_from_slice(format!("*{}\r\n", items.len()).as_bytes());
            for i in items {
                wire(i, out);
            }
        }
        Value::Map(pairs) => {
            out.extend_from_slice(format!("%{}\r\n", pairs.len()).as_bytes());
            for (k, v) in pairs {
                wire(k, out);
                wire(v, out);
            }
        }
        Value::Skipped => {}
    }
}

fn bytes_value() -> impl Strategy<Value = Value> {
    prop::collection::vec(any::<u8>(), 0..64).prop_map(|b| {
        let mut v = Bytes::default();
        // Built through the decoder, the only constructor.
        let mut w = format!("${}\r\n", b.len()).into_bytes();
        w.extend_from_slice(&b);
        w.extend_from_slice(b"\r\n");
        if let Ok(Some(Value::Str(s))) = decode_all(&w, L) {
            v = s;
        }
        Value::Str(v)
    })
}

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        bytes_value(),
        any::<i64>().prop_map(Value::Int),
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Number),
        Just(Value::Error(crate::resp::ErrorWord::Noperm)),
    ];
    leaf.prop_recursive(3, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::vec((inner.clone(), inner), 0..3).prop_map(Value::Map),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn round_trip_in_any_chunks(v in value(), cuts in prop::collection::vec(1usize..17, 0..64)) {
        let mut w = Vec::new();
        wire(&v, &mut w);
        w.extend_from_slice(b"+NEXT\r\n");
        let mut d = Decoder::new(L);
        let mut pos = 0;
        let mut got = Vec::new();
        let mut cuts = cuts.into_iter().cycle();
        while pos < w.len() {
            let end = (pos + cuts.next().unwrap_or(1)).min(w.len());
            let mut off = pos;
            while off < end {
                let (used, done) = d.feed(&w[off..end]).unwrap();
                off += used;
                if let Some(v) = done {
                    got.push(v);
                }
            }
            pos = end;
        }
        prop_assert_eq!(got.len(), 2);
        prop_assert_eq!(&got[0], &v);
    }

    #[test]
    fn arbitrary_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..512), skip in any::<bool>()) {
        let limits = Limits { skip_oversized: skip, ..L };
        let mut d = Decoder::new(limits);
        let mut off = 0;
        while off < data.len() {
            match d.feed(&data[off..]) {
                Ok((used, _)) if used > 0 => off += used,
                _ => break,
            }
        }
    }

    #[test]
    fn announced_sizes_are_never_allocated(n in 257usize..usize::MAX / 4, ty in prop::sample::select(vec!['$', '*', '%', '~', '='])) {
        let w = format!("{ty}{n}\r\n");
        prop_assert!(decode_all(w.as_bytes(), L).is_err());
    }
}

#[cfg(feature = "fuzzing")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The fuzz entry points on arbitrary input (a short local smoke run;
    /// the coverage-guided runs are in `agent/fuzz`).
    #[test]
    fn fuzz_entry_points_never_panic(data in prop::collection::vec(any::<u8>(), 0..256)) {
        crate::fuzz::resp_decoder(&data);
        crate::fuzz::info(&data);
        crate::fuzz::key_pattern(&data);
    }
}
