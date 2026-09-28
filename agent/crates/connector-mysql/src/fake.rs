//! Protocol tests against a scripted server over an in-memory stream (no
//! listening socket, I1): authentication refusals that no dev server
//! produces on demand, a `LOCAL INFILE` request, and result-set parsing.

use tokio::io::DuplexStream;

use crate::auth::{self, Channel, KnownPlugin, Refusal};
use crate::conn::{AuthFail, Flow, Streamed, login, read_result};
use crate::discover::{MAX_SAMPLE_BYTES, RowSampler, VALUE_OVERHEAD};
use crate::proto::{self, PacketIo, ProtoError, cap};

const PASSWORD: &[u8] = b"dev-only-fake-PASSWORD";
const NONCE: &[u8] = b"abcdefghijklmnopqrst";

fn handshake(plugin: &[u8]) -> proto::Handshake {
    proto::Handshake {
        server_version: "8.4.11".to_owned(),
        connection_id: 7,
        capabilities: cap::WANTED | cap::SSL,
        nonce: NONCE.to_vec(),
        plugin: plugin.to_vec(),
    }
}

fn pair() -> (PacketIo<DuplexStream>, PacketIo<DuplexStream>) {
    let (a, b) = tokio::io::duplex(1 << 16);
    (PacketIo::new(a), PacketIo::new(b))
}

fn auth_switch(plugin: &[u8], data: &[u8]) -> Vec<u8> {
    let mut p = vec![0xFE];
    p.extend_from_slice(plugin);
    p.push(0);
    p.extend_from_slice(data);
    p
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Runs a login against a scripted server: `script` gets the server end
/// after the handshake response and returns every byte the client sent
/// afterwards.
async fn run<F, Fut>(plugin: &[u8], channel: Channel, script: F) -> (Result<(), AuthFail>, Vec<u8>)
where
    F: FnOnce(PacketIo<DuplexStream>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Vec<u8>> + Send,
{
    let (mut client, mut server) = pair();
    let h = handshake(plugin);
    let server_task = tokio::spawn(async move {
        // Handshake (sequence 0; its content is `h`), then the response.
        server.write(b"\x0a").await.unwrap();
        let response = server.read().await.unwrap();
        let mut sent = response.to_vec();
        sent.extend(script(server).await);
        sent
    });
    let _ = client.read().await.unwrap();
    let r = login(&mut client, &h, cap::WANTED, "agent", PASSWORD, channel).await;
    drop(client);
    (r, server_task.await.unwrap())
}

/// The bytes a client could have sent (collects until the stream closes).
async fn drain(mut server: PacketIo<DuplexStream>) -> Vec<u8> {
    let mut out = Vec::new();
    while let Ok(p) = server.read().await {
        out.extend_from_slice(&p);
    }
    out
}

#[tokio::test]
async fn cleartext_and_dialog_switches_are_refused_without_sending_the_password() {
    for (plugin, known) in [
        (&b"mysql_clear_password"[..], KnownPlugin::ClearPassword),
        (b"dialog", KnownPlugin::Dialog),
        (b"sha256_password", KnownPlugin::Sha256Password),
        (b"client_ed25519", KnownPlugin::Ed25519),
    ] {
        for channel in [Channel::Tls, Channel::Unix, Channel::LoopbackPlain] {
            let (r, sent) = run(auth::CACHING_SHA2, channel, move |mut s| async move {
                // PAM's `dialog` sends a prompt; the others a nonce.
                let data: &[u8] = if plugin == b"dialog" {
                    b"\x04Password: "
                } else {
                    NONCE
                };
                s.write(&auth_switch(plugin, data)).await.unwrap();
                drain(s).await
            })
            .await;
            assert!(
                matches!(r, Err(AuthFail::Refused(Refusal::Plugin(k))) if k == known),
                "{plugin:?} {channel:?}: {r:?}"
            );
            assert!(!contains(&sent, PASSWORD), "password sent for {plugin:?}");
        }
    }
    // Pre-4.1 switch (a lone 0xFE).
    let (r, _) = run(auth::CACHING_SHA2, Channel::Tls, |mut s| async move {
        s.write(&[0xFE]).await.unwrap();
        drain(s).await
    })
    .await;
    assert!(matches!(
        r,
        Err(AuthFail::Refused(Refusal::Plugin(KnownPlugin::OldPassword)))
    ));
}

#[tokio::test]
async fn full_authentication_needs_tls_or_a_unix_socket() {
    for (channel, allowed) in [
        (Channel::Tls, true),
        (Channel::Unix, true),
        (Channel::LoopbackPlain, false),
        (Channel::NetworkPlain, false),
    ] {
        let (r, sent) = run(auth::CACHING_SHA2, channel, |mut s| async move {
            s.write(&[0x01, auth::PERFORM_FULL_AUTH]).await.unwrap();
            let mut out = Vec::new();
            if let Ok(p) = s.read().await {
                out.extend_from_slice(&p);
                s.write(&[0, 0, 0, 2, 0, 0, 0]).await.unwrap();
            }
            out
        })
        .await;
        if allowed {
            assert!(r.is_ok(), "{channel:?}: {r:?}");
            assert!(contains(&sent, PASSWORD));
        } else {
            assert!(
                matches!(r, Err(AuthFail::Refused(Refusal::FullAuthWithoutTls))),
                "{channel:?}: {r:?}"
            );
            // Neither the password nor a public-key request (0x02).
            assert!(!contains(&sent, PASSWORD));
            assert!(!sent.ends_with(&[0x02]));
        }
    }
}

#[tokio::test]
async fn fast_auth_and_unsolicited_public_keys() {
    let (r, _) = run(
        auth::CACHING_SHA2,
        Channel::NetworkPlain,
        |mut s| async move {
            s.write(&[0x01, auth::FAST_AUTH_OK]).await.unwrap();
            s.write(&[0, 0, 0, 2, 0, 0, 0]).await.unwrap();
            drain(s).await
        },
    )
    .await;
    assert!(r.is_ok(), "{r:?}");
    // A server pushing a PEM key (as after a 0x02 request) is refused.
    let (r, sent) = run(
        auth::CACHING_SHA2,
        Channel::LoopbackPlain,
        |mut s| async move {
            s.write(b"\x01-----BEGIN PUBLIC KEY-----").await.unwrap();
            drain(s).await
        },
    )
    .await;
    assert!(
        matches!(r, Err(AuthFail::Refused(Refusal::Protocol))),
        "{r:?}"
    );
    assert!(!contains(&sent, PASSWORD));
}

#[tokio::test]
async fn native_password_is_refused_on_a_network_without_tls() {
    // The client announces caching_sha2_password; the server switches.
    let (r, sent) = run(auth::NATIVE, Channel::NetworkPlain, |mut s| async move {
        s.write(&auth_switch(auth::NATIVE, NONCE)).await.unwrap();
        drain(s).await
    })
    .await;
    assert!(
        matches!(r, Err(AuthFail::Refused(Refusal::NativeWithoutTls))),
        "{r:?}"
    );
    assert!(contains(&sent, auth::CACHING_SHA2));
    // Loopback without TLS: accepted, the scramble only.
    let (r, sent) = run(auth::NATIVE, Channel::LoopbackPlain, |mut s| async move {
        s.write(&[0, 0, 0, 2, 0, 0, 0]).await.unwrap();
        drain(s).await
    })
    .await;
    assert!(r.is_ok());
    assert!(contains(&sent, &auth::native_scramble(PASSWORD, NONCE)));
    assert!(!contains(&sent, PASSWORD));
}

#[tokio::test]
async fn server_errors_during_login_keep_no_text() {
    let (r, _) = run(auth::CACHING_SHA2, Channel::Tls, |mut s| async move {
        let mut e = vec![0xFF];
        e.extend_from_slice(&1045u16.to_le_bytes());
        e.extend_from_slice(b"#28000Access denied for user 'agent'@'10.1.2.3' SECRET");
        s.write(&e).await.unwrap();
        drain(s).await
    })
    .await;
    match r {
        Err(AuthFail::Proto(ProtoError::Server(e))) => {
            assert_eq!(e.errno, 1045);
            assert!(!format!("{e:?}").contains("SECRET"));
        }
        other => panic!("{other:?}"),
    }
}

fn column_def(name: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    for part in [&b"def"[..], b"s", b"t", b"t", name, name] {
        proto::put_lenenc(&mut p, part.len() as u64);
        p.extend_from_slice(part);
    }
    p.push(0x0c);
    p.extend_from_slice(&45u16.to_le_bytes());
    p.extend_from_slice(&255u32.to_le_bytes());
    p.push(0xFD);
    p.extend_from_slice(&0u16.to_le_bytes());
    p.push(0);
    p.extend_from_slice(&[0, 0]);
    p
}

const EOF: [u8; 5] = [0xFE, 0, 0, 2, 0];

#[tokio::test]
async fn result_sets_are_streamed_and_local_infile_is_refused() {
    let (mut client, mut server) = pair();
    let srv = tokio::spawn(async move {
        let q = server.read().await.unwrap();
        assert_eq!(&q[..], b"\x03SELECT a, b");
        server.write(&[2]).await.unwrap();
        server.write(&column_def(b"a")).await.unwrap();
        server.write(&column_def(b"b")).await.unwrap();
        server.write(&EOF).await.unwrap();
        server.write(&[1, b'x', 0xFB]).await.unwrap();
        server.write(&[2, b'y', b'z', 1, b'w']).await.unwrap();
        server.write(&EOF).await.unwrap();
        // LOCAL INFILE request for a local file.
        server.reset_seq();
        let _ = server.read().await.unwrap();
        server
            .write(b"\xFB/etc/databastion/agent.yaml")
            .await
            .unwrap();
        // Nothing may come back but the connection closing.
        server.read().await.err()
    });
    let mut rows = Vec::new();
    let r = read_result(&mut client, "SELECT a, b", |row| {
        rows.push(
            row.iter()
                .map(|v| v.map(<[u8]>::to_vec))
                .collect::<Vec<_>>(),
        );
        Flow::Continue
    })
    .await
    .unwrap();
    assert_eq!(r, Streamed::Complete);
    assert_eq!(
        rows,
        vec![
            vec![Some(b"x".to_vec()), None],
            vec![Some(b"yz".to_vec()), Some(b"w".to_vec())]
        ]
    );
    let r = read_result(&mut client, "SELECT 1", |_| Flow::Continue).await;
    assert!(matches!(r, Err(ProtoError::Malformed)));
    drop(client);
    assert!(
        srv.await.unwrap().is_some(),
        "the client answered the LOCAL INFILE request"
    );
}

#[tokio::test]
async fn a_consumer_can_stop_and_errors_end_the_result() {
    let (mut client, mut server) = pair();
    tokio::spawn(async move {
        let _ = server.read().await.unwrap();
        server.write(&[1]).await.unwrap();
        server.write(&column_def(b"a")).await.unwrap();
        server.write(&EOF).await.unwrap();
        server.write(&[1, b'1']).await.unwrap();
        server.write(&[1, b'2']).await.unwrap();
    });
    let mut n = 0;
    let r = read_result(&mut client, "SELECT a", |_| {
        n += 1;
        Flow::Stop
    })
    .await
    .unwrap();
    assert_eq!((r, n), (Streamed::Stopped, 1));
    let (mut client2, mut server2) = pair();
    tokio::spawn(async move {
        let _ = server2.read().await.unwrap();
        server2.write(&[1]).await.unwrap();
        server2.write(&column_def(b"a")).await.unwrap();
        server2.write(&EOF).await.unwrap();
        let mut e = vec![0xFF];
        e.extend_from_slice(&3024u16.to_le_bytes());
        e.extend_from_slice(b"#HY000Query execution was interrupted SECRET");
        server2.write(&e).await.unwrap();
    });
    match read_result(&mut client2, "SELECT a", |_| Flow::Continue).await {
        Err(ProtoError::Server(e)) => assert_eq!(e.errno, 3024),
        other => panic!("{other:?}"),
    }
    drop(client);
}

/// A hostile server that ignores the `LIMIT` and streams rows of empty
/// values: the sampler stops at the limit, and empty values still count
/// against the byte budget (M1).
#[tokio::test]
async fn a_server_ignoring_the_limit_is_stopped() {
    let (mut client, mut server) = pair();
    tokio::spawn(async move {
        let _ = server.read().await.unwrap();
        server.write(&[2]).await.unwrap();
        server.write(&column_def(b"a")).await.unwrap();
        server.write(&column_def(b"b")).await.unwrap();
        server.write(&EOF).await.unwrap();
        // Unbounded rows of an empty string and a NULL.
        loop {
            if server.write(&[0, 0xFB]).await.is_err() {
                break;
            }
        }
    });
    let mut values = vec![Vec::new(), Vec::new()];
    let mut sampler = RowSampler::new(200, 0, &mut values);
    let r = read_result(&mut client, "SELECT a, b", |row| sampler.accept(row))
        .await
        .unwrap();
    assert_eq!(r, Streamed::Stopped);
    assert_eq!(sampler.rows, 200);
    assert_eq!(sampler.bytes, 200 * 2 * VALUE_OVERHEAD);
    assert_eq!(
        sampler.stop,
        Some("the server sent more rows than the LIMIT")
    );
    assert_eq!(values[0].len(), 200);
    assert!(values[1].is_empty());

    // Empty values alone reach the byte budget.
    let mut values = vec![Vec::new()];
    let mut sampler = RowSampler::new(u32::MAX, MAX_SAMPLE_BYTES - 3 * VALUE_OVERHEAD, &mut values);
    for _ in 0..3 {
        assert_eq!(sampler.accept(&[Some(&b""[..])]), Flow::Continue);
    }
    assert_eq!(sampler.accept(&[None]), Flow::Stop);
    assert_eq!(sampler.stop, Some("sample byte budget reached"));
}
