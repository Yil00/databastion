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
        crate::fuzz_entry::prelogin_wrap(&data);
        crate::fuzz_entry::tsql(&data);
        crate::fuzz_entry::audit_records(&data);
        crate::fuzz_entry::xe_event_xml(&data);
        crate::fuzz_entry::xe_records(&data);
    }

    /// The Extended Events XML reader on text (not bytes): never panics,
    /// keeps a statement of any content exactly (entities and CDATA
    /// decoded), and never keeps more than its bounds.
    #[test]
    fn xe_statement_round_trips(stmt in "\\PC{0,300}") {
        let esc = stmt.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        let x = format!(
            "<event name=\"sql_statement_completed\"><data name=\"statement\"><value>{esc}</value></data></event>"
        );
        let e = crate::audit::xe::xml::parse(&x).unwrap();
        prop_assert_eq!(e.statement.as_deref().map(String::as_str), Some(stmt.as_str()));
        // CDATA keeps the text as is, split around `]]>`.
        let cdata = stmt.replace("]]>", "]]]]><![CDATA[>");
        let x = format!(
            "<event name=\"sp_statement_completed\"><data name=\"statement\"><value><![CDATA[{cdata}]]></value></data></event>"
        );
        let e = crate::audit::xe::xml::parse(&x).unwrap();
        prop_assert_eq!(e.statement.as_deref().map(String::as_str), Some(stmt.as_str()));
    }

    /// The poll's byte slices joined and decoded once give back the event
    /// exactly, wherever the 8 000-byte boundaries fall in it (security
    /// review of lot 3, M2: surrogate pairs included).
    #[test]
    fn xe_slices_join_exactly(stmt in "\\PC{0,40}", pad in 3900usize..4100, reps in 1usize..3) {
        let stmt = format!("{}{}", "\u{1F600}y".repeat(pad * reps / 3), stmt);
        let esc = stmt.replace('&', "&amp;").replace('<', "&lt;");
        let x = format!(
            "<event name=\"sql_statement_completed\"><data name=\"statement\"><value>{esc}</value></data></event>"
        );
        let units: Vec<u16> = x.encode_utf16().collect();
        let row = crate::audit::xe::events::tests::row_of("sql_statement_completed", &units, units.len() * 2);
        let r = crate::audit::xe::events::XeRecord::from_row(row).unwrap();
        let e = r.event.unwrap();
        if !e.statement_cut {
            prop_assert_eq!(e.statement.as_deref().map(String::as_str), Some(stmt.as_str()));
        }
    }

    /// Whatever the statement text, the conversion never puts it in an
    /// event: the JSON of the event holds no part of a literal.
    #[test]
    fn xe_events_never_carry_literals(secret in "[A-Za-z0-9]{12,24}", which in 0usize..6) {
        let text = [
            format!("SELECT id FROM crm.customers WHERE email = N'{secret}'"),
            format!("UPDATE crm.customers SET note = '{secret}' WHERE id = 1"),
            format!("EXEC sp_addlogin jane, {secret}"),
            format!("CREATE LOGIN jane WITH PASSWORD = '{secret}'"),
            format!("SELECT ENCRYPTBYPASSPHRASE('{secret}', a) FROM crm.customers"),
            format!("EXEC crm.p @a = N'{secret}'"),
        ][which].clone();
        let r = crate::audit::xe::events::tests::stmt("sql_statement_completed", &text, 1, "51");
        if let Some((ev, _)) = crate::audit::xe::events::convert(&r) {
            let key = std::sync::Arc::new(databastion_classifiers::masking::HmacKey::new(&[7u8; 32]).unwrap());
            let json = databastion_core::test_support::contract_events_json(&[ev], &key);
            prop_assert!(!json.contains(&secret));
        }
    }

    /// The template matcher accepts a statement of the closed set filled
    /// with any database name, and nothing else in its slots.
    #[test]
    fn own_templates_hold_any_quoted_name(db in "\\PC{1,40}", junk in "\\PC{1,20}") {
        prop_assume!(!db.chars().any(char::is_control));
        for t in [crate::sql::DATABASE_GRANTS, crate::sql::DATABASE_ROLES, crate::sql::COLUMN_COUNTS] {
            let text = crate::sql::in_database(t, &db).unwrap();
            prop_assert!(crate::sql::matches_template(t, &text));
            prop_assert_eq!(crate::sql::own_text(&text), crate::sql::OwnText::Exact);
            let changed = text.replacen(&crate::sql::quote_ident(&db).unwrap(), &format!("[x]{junk}"), 1);
            prop_assert!(!crate::sql::matches_template(t, &changed) || changed == text);
        }
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

/// Hostile catalog names (security review C1): placeholders, brackets,
/// quotes and comment openers.
fn hostile_name() -> impl Strategy<Value = String> {
    let parts = prop_oneof![
        Just("{from}".to_owned()),
        Just("{dbname}".to_owned()),
        Just("{select}".to_owned()),
        Just("{sample}".to_owned()),
        Just("{col}".to_owned()),
        Just("{db}".to_owned()),
        Just("{n}".to_owned()),
        Just("]".to_owned()),
        Just("[".to_owned()),
        Just("'".to_owned()),
        Just("--".to_owned()),
        Just("/*".to_owned()),
        Just("*/".to_owned()),
        Just(";".to_owned()),
        "[a-zA-Z0-9 _.@é]{1,8}",
    ];
    proptest::collection::vec(parts, 1..8).prop_map(|v| v.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Whatever the names, a statement differs from the one built with
    /// benign names only inside quoted identifiers and literals.
    #[test]
    fn names_never_change_the_statement_skeleton(
        db in hostile_name(),
        schema in hostile_name(),
        table in hostile_name(),
        col in hostile_name(),
        col2 in hostile_name(),
    ) {
        use crate::sql::{self, Sampled, unquoted};
        let benign = "x";
        let cols = [(col.as_str(), Sampled::Text), (col2.as_str(), Sampled::LargeText)];
        let plain = [(benign, Sampled::Text), (benign, Sampled::LargeText)];
        let a = sql::sample_statement(&db, &schema, &table, &cols, 10, Some(1.5)).unwrap();
        let b = sql::sample_statement(benign, benign, benign, &plain, 10, Some(1.5)).unwrap();
        prop_assert_eq!(unquoted(&a), unquoted(&b));
        let a = sql::ticket_type_counts(&db, &schema, &table, &col).unwrap();
        let b = sql::ticket_type_counts(benign, benign, benign, benign).unwrap();
        prop_assert_eq!(unquoted(&a), unquoted(&b));
        prop_assert_eq!(unquoted(&sql::tables(&db, 5).unwrap()), unquoted(&sql::tables(benign, 5).unwrap()));
        prop_assert_eq!(unquoted(&sql::columns(&db, 7).unwrap()), unquoted(&sql::columns(benign, 7).unwrap()));
        for (name, template) in sql::STATEMENTS {
            if let Some(a) = sql::in_database(template, &db) {
                let b = sql::in_database(template, benign).unwrap();
                prop_assert_eq!(unquoted(&a), unquoted(&b), "{}", name);
            }
        }
    }
}

/// Re-review R5: the `PreloginWrap` fuzz entry over a well-formed exchange
/// (both oracles see data), then a refused header.
#[test]
fn prelogin_wrap_fuzz_entry_runs_a_handshake() {
    use crate::tds;
    let hello = tds::frame(tds::ptype::PRELOGIN, b"server-hello", 512);
    let mut input = vec![4u8];
    input.extend([2, u8::try_from(hello.len()).unwrap()]);
    input.extend(&hello);
    input.extend([3, 5, 3, 20]);
    input.extend([0, 12]);
    input.extend(b"client-hello");
    input.extend([1, 0, 4, 2]);
    input.extend([5, 0, 0, 3]);
    input.extend(b"raw");
    input.extend([1, 0, 4, 1]);
    // Review L4: the handshake bytes went through, both ways, then the raw
    // bytes after the handshake.
    let run = crate::fuzz_entry::prelogin_wrap(&input);
    assert_eq!(run.read, b"server-hello");
    assert_eq!(run.sent, b"client-hello");
    assert_eq!(run.raw, b"raw");
    // A packet of another type: the read fails and the run ends.
    let mut input = vec![4u8, 2, 8, 0x17, 3, 3, 0, 20, 0, 0, 0, 3, 7];
    input.extend([0, 1, b'x']);
    let run = crate::fuzz_entry::prelogin_wrap(&input);
    assert!(run.read.is_empty() && run.sent.is_empty());
}

/// Release gate G1 (end-of-phase-9 review): the input of the nightly ASan
/// fuzz run 39014225515 (`sqlserver_xe_records`, exit 77) on dev 2d969a4.
#[test]
fn xe_records_fuzz_crash_g1() {
    let input: [u8; 61] = [
        1, 0, 1, 97, 112, 112, 108, 121, 91, 115, 74, 155, 0, 155, 0, 155, 155, 1, 182, 105, 110,
        115, 101, 114, 116, 47, 34, 91, 93, 255, 255, 248, 164, 93, 0, 1, 91, 1, 93, 61, 0, 1, 91,
        227, 227, 227, 1, 0, 4, 91, 93, 0, 1, 91, 1, 93, 61, 91, 93, 91, 249,
    ];
    crate::fuzz_entry::xe_records(&input);
}

/// The input of the nightly ASan fuzz run 39021675369
/// (`sqlserver_xe_records`): a name of 256 characters with lossy U+FFFD
/// (3 bytes each) is within the contract's 256 characters; the oracle
/// counted bytes.
#[test]
fn xe_records_fuzz_identifier_chars_not_bytes() {
    let input: [u8; 147] = [
        43, 106, 111, 105, 110, 91, 112, 97, 97, 103, 119, 52, 63, 116, 101, 110, 101, 109, 163,
        163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163,
        163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163,
        163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163,
        163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163,
        163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163,
        163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163,
        163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 116, 98, 76, 76, 101, 93, 76,
        76,
    ];
    crate::fuzz_entry::xe_records(&input);
}
