//! Property tests of the parsers (ADR-0051 decision 1): no panic and
//! progress on any input, values bounded, the password never written
//! outside the `LOGIN7` buffer.

use proptest::prelude::*;

use crate::tds;
use crate::token::tests::{build, decode_all};
use crate::token::{Decoder, Event, Limits, Value, tok};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn token_stream_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        crate::fuzz_entry::token_stream(&data);
        crate::fuzz_entry::packets(&data);
        crate::fuzz_entry::plp(&data);
    }

    #[test]
    fn text_rows_round_trip_in_any_split(
        values in proptest::collection::vec(proptest::option::of("\\PC{0,40}"), 1..6),
        step in 1usize..50,
    ) {
        let cols: Vec<(&str, u16)> = values.iter().map(|_| ("c", 4000)).collect();
        let mut s = build::colmeta_nvarchar(&cols);
        let refs: Vec<Option<&str>> = values.iter().map(|v| v.as_deref()).collect();
        s.extend(build::row_text(&refs));
        s.extend(build::done(tok::DONE, 0x10, 1));
        let mut d = Decoder::new(Limits::default());
        let ev = decode_all(&mut d, &s, step).unwrap();
        let got: Vec<Option<String>> = ev.iter().filter_map(|e| match e {
            Event::Value(_, Value::Text(t)) => Some(Some(t.clone())),
            Event::Value(_, Value::Null) => Some(None),
            _ => None,
        }).collect();
        prop_assert_eq!(got, values);
    }

    #[test]
    fn password_stays_in_the_login_buffer(pw in "~[ -~]{7,63}", user in "[a-z]{1,20}") {
        let msg = tds::login7(&user, &pw).unwrap();
        let clear = tds::utf16(&pw);
        prop_assert!(!msg.windows(clear.len()).any(|w| w == clear.as_slice()));
        let framed = tds::frame(tds::ptype::LOGIN7, &msg, 512);
        prop_assert!(!framed.windows(clear.len()).any(|w| w == clear.as_slice()));
    }

    #[test]
    fn utf16_decoding_is_total(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let s = crate::token::utf16_lossy(&bytes);
        prop_assert!(s.chars().count() <= bytes.len() / 2 + 1);
    }
}
