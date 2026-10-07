//! Property tests of the protocol layer (security review L6): every parser
//! and the two exchanges driven by the server (authentication, result
//! sets) on arbitrary input. Invariants: no panic, bounded allocation, and
//! the password is never written on a channel that may not carry it.

use std::time::Duration;

use proptest::prelude::*;
use tokio::io::{AsyncWriteExt, DuplexStream};

use crate::auth::{self, Channel};
use crate::conn::{Flow, login, read_result};
use crate::proto::{self, PacketIo, Reader, cap};

const PASSWORD: &[u8] = b"pw-PROPTEST-marker-FAKE";

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn channels() -> impl Strategy<Value = Channel> {
    prop_oneof![
        Just(Channel::Tls),
        Just(Channel::Unix),
        Just(Channel::LoopbackPlain),
        Just(Channel::NetworkPlain),
    ]
}

/// Server packets biased toward the headers the client interprets.
fn server_packet() -> impl Strategy<Value = Vec<u8>> {
    let plugin = prop_oneof![
        Just(b"caching_sha2_password".to_vec()),
        Just(b"mysql_native_password".to_vec()),
        Just(b"mysql_clear_password".to_vec()),
        Just(b"dialog".to_vec()),
        Just(b"sha256_password".to_vec()),
        proptest::collection::vec(any::<u8>(), 0..24),
    ];
    prop_oneof![
        Just(vec![0x01, auth::FAST_AUTH_OK]),
        Just(vec![0x01, auth::PERFORM_FULL_AUTH]),
        Just(vec![0x01, 0x02]),
        Just(vec![0x00, 0, 0, 2, 0, 0, 0]),
        Just(vec![0xFE]),
        (plugin, proptest::collection::vec(any::<u8>(), 0..32)).prop_map(|(p, d)| {
            let mut v = vec![0xFE];
            v.extend(p);
            v.push(0);
            v.extend(d);
            v
        }),
        proptest::collection::vec(any::<u8>(), 0..64).prop_map(|mut v| {
            v.insert(0, 0xFF);
            v
        }),
        proptest::collection::vec(any::<u8>(), 0..64),
    ]
}

/// Plays `packets` as the server (with consistent sequence ids), and
/// returns every byte the client sent.
async fn scripted_server(mut server: PacketIo<DuplexStream>, packets: Vec<Vec<u8>>) -> Vec<u8> {
    let mut sent = Vec::new();
    for p in packets {
        if server.write(&p).await.is_err() {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(5), server.read_small()).await {
            Ok(Ok(answer)) => sent.extend_from_slice(&answer),
            Ok(Err(_)) => break,
            Err(_) => {}
        }
    }
    drop(server);
    sent
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512), n in 0usize..8) {
        let _ = proto::parse_handshake(&bytes);
        let _ = proto::parse_err(&bytes);
        let _ = proto::parse_ok(&bytes);
        let _ = proto::eof_status(&bytes);
        let _ = proto::column_type(&bytes);
        if let Ok(row) = proto::parse_row(&bytes, n) {
            prop_assert_eq!(row.len(), n);
            let total: usize = row.iter().map(|v| v.map_or(0, <[u8]>::len)).sum();
            prop_assert!(total <= bytes.len());
        }
        let mut r = Reader::new(&bytes);
        while r.lenenc_bytes().is_ok() {}
        if let Ok(h) = proto::parse_handshake(&bytes) {
            prop_assert_eq!(h.nonce.len(), 20);
            prop_assert!(h.plugin.len() <= 64 && h.server_version.len() <= 128);
        }
    }

    #[test]
    fn lenenc_roundtrips(n in any::<u64>()) {
        let mut b = Vec::new();
        proto::put_lenenc(&mut b, n);
        prop_assert_eq!(Reader::new(&b).lenenc().unwrap(), n);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    /// Arbitrary bytes as a packet stream: no panic, the packet within its
    /// bound, the buffer never much larger than what arrived.
    #[test]
    fn packet_reads_are_bounded(bytes in proptest::collection::vec(any::<u8>(), 0..4096), small in any::<bool>()) {
        runtime().block_on(async {
            let (a, mut b) = tokio::io::duplex(1 << 16);
            b.write_all(&bytes).await.unwrap();
            drop(b);
            let mut io = PacketIo::new(a);
            let max = if small { proto::MAX_SMALL } else { proto::MAX_LOGICAL };
            while let Ok(p) = io.read_max(max).await {
                prop_assert!(p.len() <= max && p.len() <= bytes.len());
                prop_assert!(p.capacity() <= 2 * p.len().max(64 * 1024) + 64 * 1024);
            }
            Ok(())
        })?;
    }

    /// Arbitrary authentication exchanges: no panic, and the password never
    /// leaves on a channel that may not carry it.
    #[test]
    fn login_never_leaks_the_password(
        channel in channels(),
        default_native in any::<bool>(),
        packets in proptest::collection::vec(server_packet(), 0..8),
    ) {
        let sent = runtime().block_on(async move {
            let (a, b) = tokio::io::duplex(1 << 16);
            let mut client = PacketIo::new(a);
            let mut server = PacketIo::new(b);
            server.write(b"\x0a").await.unwrap();
            let _ = client.read_small().await.unwrap();
            let handshake = proto::Handshake {
                server_version: "8.4.11".to_owned(),
                connection_id: 1,
                capabilities: cap::WANTED,
                nonce: b"abcdefghijklmnopqrst".to_vec(),
                plugin: if default_native { auth::NATIVE } else { auth::CACHING_SHA2 }.to_vec(),
            };
            let srv = tokio::spawn(async move {
                let mut sent = server.read_small().await.map(|p| p.to_vec()).unwrap_or_default();
                sent.extend(scripted_server(server, packets).await);
                sent
            });
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                login(&mut client, &handshake, cap::WANTED, "agent", PASSWORD, channel),
            )
            .await;
            drop(client);
            srv.await.unwrap()
        });
        if !channel.may_send_password() {
            prop_assert!(!sent.windows(PASSWORD.len()).any(|w| w == PASSWORD));
        }
    }

    /// Arbitrary result sets: no panic, never more rows than packets.
    #[test]
    fn result_reads_never_panic(packets in proptest::collection::vec(
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..48),
            Just(vec![1]),
            Just(vec![0xFE, 0, 0, 2, 0]),
            Just(vec![0xFB]),
        ],
        0..12,
    )) {
        let n = packets.len();
        let rows = runtime().block_on(async move {
            let (a, b) = tokio::io::duplex(1 << 16);
            let mut client = PacketIo::new(a);
            let mut server = PacketIo::new(b);
            let srv = tokio::spawn(async move {
                let _ = server.read_small().await;
                for p in packets {
                    if server.write(&p).await.is_err() {
                        break;
                    }
                }
            });
            let mut rows = 0usize;
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                read_result(&mut client, "SELECT 1", |_| {
                    rows += 1;
                    Flow::Continue
                }),
            )
            .await;
            drop(client);
            let _ = srv.await;
            rows
        });
        prop_assert!(rows <= n);
    }
}

/// The harness does capture a password sent where it is allowed (so the
/// property above can fail).
#[test]
fn the_harness_sees_a_password_sent_over_tls() {
    let sent = runtime().block_on(async {
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut client = PacketIo::new(a);
        let mut server = PacketIo::new(b);
        server.write(b"\x0a").await.unwrap();
        let _ = client.read_small().await.unwrap();
        let handshake = proto::Handshake {
            server_version: "8.4.11".to_owned(),
            connection_id: 1,
            capabilities: cap::WANTED,
            nonce: b"abcdefghijklmnopqrst".to_vec(),
            plugin: auth::CACHING_SHA2.to_vec(),
        };
        let srv = tokio::spawn(async move {
            let _ = server.read_small().await;
            scripted_server(
                server,
                vec![
                    vec![0x01, auth::PERFORM_FULL_AUTH],
                    vec![0x00, 0, 0, 2, 0, 0, 0],
                ],
            )
            .await
        });
        login(
            &mut client,
            &handshake,
            cap::WANTED,
            "agent",
            PASSWORD,
            Channel::Tls,
        )
        .await
        .unwrap();
        srv.await.unwrap()
    });
    assert!(sent.windows(PASSWORD.len()).any(|w| w == PASSWORD));
}

/// A backtick-quoted identifier holding any text (backticks doubled).
fn quoted(name: &str) -> String {
    format!("`{}`", name.replace('`', "``"))
}

proptest! {
    /// `SHOW GRANTS` lines (P4-D role evaluation): arbitrary text never
    /// panics the parser.
    #[test]
    fn grant_lines_never_panic(line in "\\PC{0,200}") {
        let _ = crate::grants::parse_line(&line);
        // The CAS store guard's reading of the same line never panics and
        // understands no line `parse_line` refuses.
        let selects = crate::grants::select_grants(&line);
        if crate::grants::parse_line(&line).is_none() {
            prop_assert_eq!(selects, None);
        } else {
            // A line `parse_line` reads always has its `SELECT` grants read
            // (else the CAS store guard reports not evaluated).
            prop_assert!(selects.is_some());
        }
    }

    /// Grant lines of every form the servers print: whenever `parse_line`
    /// reads privileges, `select_grants` reads them too (PR #141 review M1).
    #[test]
    fn privilege_lines_always_have_select_grants_read(
        privs in proptest::collection::vec(prop_oneof![
            Just("SELECT".to_owned()),
            Just("INSERT".to_owned()),
            Just("ALL PRIVILEGES".to_owned()),
            Just("SHOW VIEW".to_owned()),
            Just("PROXY".to_owned()),
            "\\PC{1,12}".prop_map(|c| format!("SELECT ({})", quoted(&c))),
            "\\PC{1,12}".prop_map(|c| format!("UPDATE ({}, `x`)", quoted(&c))),
        ], 1..4),
        target in prop_oneof![
            Just("*.*".to_owned()),
            Just("*".to_owned()),
            Just("''@''".to_owned()),
            Just("`app`@`%`".to_owned()),
            "\\PC{1,12}".prop_map(|d| format!("{}.*", quoted(&d))),
            ("\\PC{1,12}", "\\PC{1,12}").prop_map(|(d, t)| format!("{}.{}", quoted(&d), quoted(&t))),
            ("(TABLE|PROCEDURE|FUNCTION|PACKAGE|PACKAGE BODY)", "\\PC{1,12}")
                .prop_map(|(k, t)| format!("{k} `db`.{}", quoted(&t))),
            "\\PC{1,12}".prop_map(|t| quoted(&t)),
        ],
        option in prop_oneof![Just(""), Just(" WITH GRANT OPTION")],
    ) {
        let line = format!("GRANT {} ON {target} TO `u`@`%`{option}", privs.join(", "));
        if matches!(
            crate::grants::parse_line(&line),
            Some(crate::grants::Line::Privileges { .. })
        ) {
            prop_assert!(crate::grants::select_grants(&line).is_some(), "{}", line);
        }
    }

    /// The CAS store guard's `SELECT` grants keep the quoted table and
    /// column names as data, whatever they hold.
    #[test]
    fn select_grants_keep_quoted_names(
        db in "\\PC{1,24}",
        table in "\\PC{1,24}",
        column in "\\PC{1,24}",
    ) {
        let line = format!(
            "GRANT INSERT, SELECT ({}) ON {}.{} TO `u`@`%`",
            quoted(&column),
            quoted(&db),
            quoted(&table),
        );
        prop_assert_eq!(
            crate::grants::select_grants(&line),
            Some(vec![crate::grants::SelectGrant {
                db: Some(db),
                table: Some(table),
                columns: Some(vec![column]),
            }])
        );
    }

    /// Names are data: whatever a quoted database, table, grantee or
    /// column name holds (keywords, quotes, `;`), the line parses to the
    /// same privileges and scope, and a grant option is never read from a
    /// name.
    #[test]
    fn quoted_names_never_change_a_grant_line(
        db in "\\PC{1,24}",
        table in "\\PC{1,24}",
        column in "\\PC{1,24}",
        grantee in "\\PC{1,24}",
        grantable in any::<bool>(),
    ) {
        use crate::grants::{Line, Scope};
        let line = format!(
            "GRANT SELECT ({}), INSERT ON {}.{} TO {}@`%`{}",
            quoted(&column),
            quoted(&db),
            quoted(&table),
            quoted(&grantee),
            if grantable { " WITH GRANT OPTION" } else { "" }
        );
        prop_assert_eq!(
            crate::grants::parse_line(&line),
            Some(Line::Privileges {
                privileges: vec!["SELECT".to_owned(), "INSERT".to_owned()],
                scope: Scope::Database(db),
                grantable,
            })
        );
    }
}
