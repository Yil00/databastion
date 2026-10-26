//! Property tests (ADR-0060 decision 1, robustness duties): no parser
//! panics or reads past its bounds on any input, the peer lookup finds the
//! right row or none, SRP agrees with the server side for any account,
//! password and salt, and the password never appears in what the client
//! sends.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use proptest::prelude::*;
use zeroize::Zeroizing;

use crate::fuzz_entry as fuzz;
use crate::peer::{Lookup, scan};
use crate::sql::{self, Column};
use crate::wire::{self, Keys, Phase};
use crate::xdr::Reader;

fn columns() -> impl Strategy<Value = Vec<Column>> {
    prop::collection::vec(
        prop_oneof![
            (1u32..64).prop_map(|len| Column {
                sqltype: sql::sqltype::VARYING,
                sub_type: sql::charset::UTF8,
                scale: 0,
                length: len,
            }),
            (1u32..64).prop_map(|len| Column {
                sqltype: sql::sqltype::VARYING,
                sub_type: sql::charset::OCTETS,
                scale: 0,
                length: len,
            }),
            Just(Column {
                sqltype: sql::sqltype::LONG,
                sub_type: 0,
                scale: 0,
                length: 4,
            }),
            Just(Column {
                sqltype: sql::sqltype::INT64,
                sub_type: 0,
                scale: 0,
                length: 8,
            }),
            Just(Column {
                sqltype: sql::sqltype::BOOLEAN,
                sub_type: 0,
                scale: 0,
                length: 1,
            }),
        ],
        1..12,
    )
}

fn hex_le(ip: Ipv4Addr) -> String {
    format!("{:08X}", u32::from_ne_bytes(ip.octets()))
}

fn line(local: SocketAddr, remote: SocketAddr, state: &str, uid: u32) -> String {
    let (IpAddr::V4(l), IpAddr::V4(r)) = (local.ip(), remote.ip()) else {
        unreachable!()
    };
    format!(
        "  1: {}:{:04X} {}:{:04X} {state} 00000000:00000000 00:00000000 00000000 {uid:>5} 0 1 1",
        hex_le(l),
        local.port(),
        hex_le(r),
        remote.port()
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn xdr_items_are_bounded(bytes in prop::collection::vec(any::<u8>(), 0..256), max in 0usize..64) {
        let mut r = Reader::new(&bytes);
        if let Ok(item) = r.opaque(max) {
            prop_assert!(item.len() <= max);
            prop_assert!(r.pos() <= bytes.len());
        }
        let _ = Reader::new(&bytes).short();
    }

    #[test]
    fn server_messages_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512), phase in 0u8..3) {
        let phase = [Phase::Connect, Phase::Auth, Phase::Session][usize::from(phase)];
        let mut r = Reader::new(&bytes);
        if wire::parse(&mut r, phase).is_ok() {
            prop_assert!(r.pos() <= bytes.len());
        }
        let mut input = vec![phase as u8, 7];
        input.extend_from_slice(&bytes);
        fuzz::messages(&input);
    }

    #[test]
    fn describe_answers_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(d) = sql::parse_describe(&bytes) {
            prop_assert!(d.columns.len() <= sql::MAX_COLUMNS);
        }
        fuzz::describe_and_rows(&bytes);
    }

    #[test]
    fn rows_respect_their_columns(cols in columns(), bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut r = Reader::new(&bytes);
        if let Ok(row) = sql::parse_row(&mut r, &cols) {
            prop_assert_eq!(row.len(), cols.len());
            for (v, c) in row.iter().zip(&cols) {
                match v {
                    sql::Value::Text(t) => prop_assert!(t.len() <= c.length as usize),
                    sql::Value::Bytes(b) => prop_assert!(b.len() <= c.length as usize),
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn rows_round_trip(cols in columns(), seed in any::<u64>()) {
        let values: Vec<sql::Value> = cols
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let pick = seed.rotate_left(i as u32) % 4;
                if pick == 0 {
                    return sql::Value::Null;
                }
                match c.sqltype {
                    sql::sqltype::VARYING if c.sub_type == sql::charset::UTF8 => {
                        sql::Value::Text(Zeroizing::new("é".repeat((c.length / 2).min(3) as usize)))
                    }
                    sql::sqltype::VARYING => sql::Value::Bytes(Zeroizing::new(vec![0xAB; (c.length as usize).min(5)])),
                    sql::sqltype::BOOLEAN => sql::Value::Bool(pick == 1),
                    sql::sqltype::LONG => sql::Value::Int(i64::from(seed as i32)),
                    _ => sql::Value::Int(seed as i64),
                }
            })
            .collect();
        let bytes = crate::fake::row(&cols, &values);
        let mut r = Reader::new(&bytes);
        let row = sql::parse_row(&mut r, &cols).unwrap();
        prop_assert_eq!(row, values);
        prop_assert_eq!(r.pos(), bytes.len());
    }

    #[test]
    fn keys_never_choose_arc4(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        let mut k = Keys::default();
        if k.add(&bytes).is_ok()
            && let Some((plugin, _)) = k.choose()
        {
            prop_assert!(plugin.name() != "Arc4");
        }
        fuzz::keys(&bytes);
    }

    #[test]
    fn srp_data_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = crate::srp::ServerData::parse(&bytes);
    }

    /// Decision 3 (L1): any table content, with or without the server side
    /// of the connection among other rows: the right row or none.
    #[test]
    fn the_peer_lookup_finds_the_right_row_or_none(
        others in prop::collection::vec((any::<[u8; 4]>(), any::<u16>(), any::<[u8; 4]>(), any::<u16>(), 0u8..12, any::<u32>()), 0..40),
        present in any::<bool>(),
        uid in 1u32..65_000,
        client_port in 1024u16..65_000,
        garbage in prop::collection::vec("[ -~]{0,80}", 0..5),
    ) {
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3050);
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), client_port);
        let mut lines: Vec<String> = others
            .iter()
            .filter(|(l, lp, r, rp, _, _)| {
                // Not the server side of this connection.
                !(Ipv4Addr::from(*l) == Ipv4Addr::LOCALHOST && *lp == 3050
                    && Ipv4Addr::from(*r) == Ipv4Addr::LOCALHOST && *rp == client_port)
            })
            .map(|(l, lp, r, rp, st, u)| {
                line(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*l)), *lp),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*r)), *rp),
                    &format!("{st:02X}"),
                    *u,
                )
            })
            .collect();
        lines.extend(garbage);
        // The client's own end of the connection, which must not match.
        lines.push(line(client, server, "01", 1000));
        if present {
            lines.insert(lines.len() / 2, line(server, client, "01", uid));
        }
        let mut out = Lookup::default();
        scan(lines.into_iter(), server, client, None, &mut out);
        if present {
            prop_assert_eq!(out.verdict(uid), Ok(()));
        } else {
            prop_assert!(out.verdict(uid).is_err());
        }
    }

    #[test]
    fn proc_net_tcp_contents_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        fuzz::proc_net_tcp(&bytes);
    }
}

proptest! {
    // Each case runs three 1024-bit exponentiations and a 2048-bit one.
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// SRP agrees with the server side for any account, password and
    /// salt; the password never appears in a client message.
    #[test]
    fn srp_agrees_and_the_password_stays_inside(
        login in "[A-Za-z][A-Za-z0-9_]{0,20}",
        password in "[ -~]{8,40}",
        salt in "[0-9A-F]{2,64}",
        seed in 1u64..1_000_000,
    ) {
        let client = crate::srp::Client::with_private(Zeroizing::new(crate::srp::server::private(seed)));
        let b = crate::srp::server::private(seed.wrapping_add(7));
        let b_public = crate::srp::server::public(&login, password.as_bytes(), salt.as_bytes(), &b);
        let data = crate::srp::server::data(salt.as_bytes(), &b_public);
        let parsed = crate::srp::ServerData::parse(&data).unwrap();
        let proof = client.proof(&login, password.as_bytes(), &parsed).unwrap();
        let server_key = crate::srp::server::session_key(&login, password.as_bytes(), salt.as_bytes(), &client.public(), &b_public, &b);
        prop_assert_eq!(&proof.key[..], &server_key[..]);
        let connect = wire::connect("app", &login.to_ascii_uppercase(), &client.public_hex());
        let cont = wire::cont_auth(&proof.hex);
        let attach = wire::attach("app", &login.to_ascii_uppercase());
        for msg in [connect.as_slice(), cont.as_slice(), attach.as_slice()] {
            prop_assert!(!msg.windows(password.len()).any(|w| w == password.as_bytes()));
        }
    }

}

fn identifier() -> impl Strategy<Value = String> {
    // Any characters, quotes and keywords included: 1 to 63, no NUL, no
    // trailing space (the catalog's names after the trim).
    prop::collection::vec(
        prop_oneof![
            any::<char>(),
            Just('"'),
            Just('\''),
            Just(' '),
            Just(';'),
            Just('-'),
        ],
        1..63,
    )
    .prop_map(|c| c.into_iter().filter(|c| *c != '\0').collect::<String>())
    .prop_map(|s| s.trim_end_matches(' ').to_owned())
    .prop_filter("non-empty", |s| !s.is_empty())
}

fn conv() -> impl Strategy<Value = sql::Conv> {
    prop_oneof![
        Just(sql::Conv::Text),
        Just(sql::Conv::Octets),
        Just(sql::Conv::Number),
        Just(sql::Conv::Float),
        Just(sql::Conv::Date),
    ]
}

/// The statement skeleton with every quoted identifier emptied and runs
/// of quotes collapsed: what a name could change if it escaped its quotes.
fn skeleton(text: &str) -> String {
    let s = sql::unquoted(text);
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '"' && out.ends_with("\"\"") {
            continue;
        }
        if c == '"' && out.ends_with('"') {
            out.push('"');
            continue;
        }
        out.push(c);
    }
    out.replace("\"\"\"", "\"\"")
}

proptest! {
    /// Discovery's built statements (decision 5): whatever the catalog
    /// names, the statement stays the same read with only its identifiers
    /// changed, no string literal and no denied word; the bounds hold.
    #[test]
    fn built_statements_cannot_be_escaped_by_a_name(
        table in identifier(),
        cols in prop::collection::vec((identifier(), conv()), 1..=4),
        n in 1u32..10_000,
    ) {
        let named: Vec<(&str, sql::Conv)> = cols.iter().map(|(c, v)| (c.as_str(), *v)).collect();
        let plain: Vec<(&str, sql::Conv)> = cols.iter().map(|(_, v)| ("A", *v)).collect();
        let built = sql::sample_statement(&table, &named, n).unwrap();
        let reference = sql::sample_statement("T", &plain, n).unwrap();
        prop_assert_eq!(skeleton(built.text()), skeleton(reference.text()));
        prop_assert!(!sql::has_denied_word(built.text()));
        prop_assert!(!sql::unquoted(built.text()).contains('\''));
        let tickets = sql::ticket_type_counts(&table, &cols[0].0).unwrap();
        let reference = sql::ticket_type_counts("T", "A").unwrap();
        prop_assert_eq!(skeleton(tickets.text()), skeleton(reference.text()));
    }

    /// Column batches keep every column once, in order, within the bounds.
    #[test]
    fn column_batches_are_bounded(convs in prop::collection::vec(conv(), 0..700)) {
        let cols: Vec<(usize, sql::Conv)> = convs.iter().copied().enumerate().collect();
        let batches = crate::catalog::batches(&cols);
        let flat: Vec<(usize, sql::Conv)> = batches.iter().flatten().copied().collect();
        prop_assert_eq!(flat, cols);
        for b in &batches {
            prop_assert!(!b.is_empty() && b.len() <= sql::MAX_STATEMENT_COLUMNS);
            prop_assert!(b.iter().map(|(_, c)| c.row_bytes()).sum::<usize>() <= sql::MAX_ROW_BYTES);
            let names: Vec<String> = b.iter().map(|(i, _)| format!("C{i}")).collect();
            let named: Vec<(&str, sql::Conv)> = names.iter().zip(b).map(|(n, (_, c))| (n.as_str(), *c)).collect();
            prop_assert!(sql::sample_statement("T", &named, 1).is_some());
        }
    }

    /// Sampled values (decision 5): never a panic; octets kept only as
    /// UTF-8 text without control characters (tab and line breaks
    /// allowed), floating values only as integer digits, `CHAR` padding
    /// dropped.
    #[test]
    fn sampled_values_are_kept_only_as_decided(
        bytes in prop::collection::vec(any::<u8>(), 0..64),
        text in ".{0,40}",
        padded in any::<bool>(),
    ) {
        let v = crate::catalog::value_text(sql::Value::Bytes(Zeroizing::new(bytes)), sql::Conv::Octets, padded);
        if let Some(t) = v {
            prop_assert!(!t.chars().any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r')));
            prop_assert!(!t.is_empty());
        }
        let v = crate::catalog::value_text(sql::Value::Text(Zeroizing::new(text.clone())), sql::Conv::Float, false);
        if let Some(t) = v {
            prop_assert!(t.trim_start_matches('-').bytes().all(|b| b.is_ascii_digit()), "{t}");
        }
        let v = crate::catalog::value_text(sql::Value::Text(Zeroizing::new(text)), sql::Conv::Text, padded);
        if let (Some(t), true) = (v, padded) {
            prop_assert!(!t.ends_with(' '));
        }
    }

    /// The catalog reads on any cells: never a panic; a relation or a
    /// column is kept only with a name that can be quoted.
    #[test]
    fn catalog_rows_never_panic(
        rows in prop::collection::vec(prop::collection::vec(prop_oneof![
            Just(sql::Value::Null),
            any::<i64>().prop_map(sql::Value::Int),
            any::<bool>().prop_map(sql::Value::Bool),
            ".{0,70}".prop_map(|s| sql::Value::Text(Zeroizing::new(s))),
        ], 0..12), 0..8),
    ) {
        if let Some(rels) = crate::catalog::relations(&rows) {
            prop_assert!(rels.iter().all(|r| sql::identifier_ok(&r.name)));
        }
        if let Some(cols) = crate::catalog::columns(&rows) {
            prop_assert!(cols.iter().all(|c| sql::identifier_ok(&c.name) && sql::identifier_ok(&c.relation)));
            for c in &cols {
                let _ = c.conv();
            }
        }
    }
}
