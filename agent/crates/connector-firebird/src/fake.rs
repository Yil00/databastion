//! A scripted fake Firebird server for unit tests (as
//! `connector-sqlserver/src/fake.rs`): the server side of the handshake
//! (SRP-256 with [`crate::srp::server`], the wire keys, `op_crypt` and the
//! encrypted session) and canned answers to the connector's statements,
//! with hostile variants at each step. It parses the client's messages
//! itself (independently of the client's builders), so the tests also
//! check what the client sends.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use crypto_bigint::U1024;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::crypt::Cipher;
use crate::sql::{Column, Value, charset, sqltype};
use crate::srp;
use crate::wire::{CryptPlugin, op};
use crate::xdr::{Reader, Writer, XdrError};

/// The fake account.
pub(crate) const LOGIN: &str = "AGENT";
/// Its fake password.
pub(crate) const PASSWORD: &[u8] = b"fake-password-0123456789abcdefgh";
const SALT: &[u8] = b"5A1700112233445566778899AABBCCDDEEFF00112233445566778899AABBCC";

/// How the server answers `op_connect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Accept {
    /// `op_cond_accept`, protocol 16, `Srp256`, the server data.
    Good,
    /// `op_cond_accept` naming another protocol version (as a short).
    Version(u32),
    /// `op_cond_accept` with another `p_acpt_type` (flags included).
    Type(u32),
    /// `op_reject` (what a Firebird 3.0 server answers).
    Reject,
    /// `op_accept`, no authentication data.
    Plain,
    /// `op_accept_data` reporting the client authenticated already.
    AuthenticatedEarly,
    /// `op_cond_accept` naming another plugin.
    Plugin(&'static str),
    /// `op_cond_accept` with these bytes as the SRP data.
    Data(Vec<u8>),
    /// `op_crypt_key_callback`.
    KeyCallback,
    /// `op_response` with this GDS code.
    Error(u32),
    /// Raw bytes instead of an answer.
    Raw(Vec<u8>),
}

/// How the server answers `op_cont_auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Auth {
    /// Success, with these key clumplets as `p_resp_data`.
    Keys(Vec<u8>),
    /// `op_response` with `isc_login`.
    LoginFailed,
    /// Another `op_cont_auth` round.
    Again,
}

/// How the server answers `op_crypt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Crypt {
    /// The encrypted success response, then the session.
    Good,
    /// The success response in clear (a server that did not enable the
    /// cipher, or an impersonator).
    Plain,
    /// The response encrypted with another key (a server that does not
    /// know the verifier).
    WrongKey,
    /// An encrypted error response.
    Error,
}

/// A canned statement result.
#[derive(Debug, Clone)]
pub(crate) struct Canned {
    pub(crate) text: &'static str,
    pub(crate) columns: Vec<Column>,
    pub(crate) rows: Vec<Vec<Value>>,
    /// The GDS code of an error at prepare instead.
    pub(crate) error: Option<u32>,
}

/// The script of one connection.
#[derive(Debug, Clone)]
pub(crate) struct Script {
    pub(crate) accept: Accept,
    pub(crate) auth: Auth,
    pub(crate) crypt: Crypt,
    pub(crate) statements: Vec<Canned>,
    /// Never answer `op_execute`, only the `op_cancel` that follows.
    pub(crate) stall_execute: bool,
    /// Answer `op_fetch` with this many rows of the first row in one
    /// batch, whatever was asked.
    pub(crate) flood_rows: Option<u32>,
    /// Answer `op_attach` with this message instead of a success.
    pub(crate) attach_answer: Option<Vec<u8>>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            accept: Accept::Good,
            auth: Auth::Keys(keys(true, true, true)),
            crypt: Crypt::Good,
            statements: Vec::new(),
            stall_execute: false,
            flood_rows: None,
            attach_answer: None,
        }
    }
}

fn item(out: &mut Vec<u8>, tag: u8, data: &[u8]) {
    out.push(tag);
    out.push(u8::try_from(data.len()).unwrap());
    out.extend_from_slice(data);
}

/// The fake ChaCha64 nonce and ChaCha nonce + counter.
const NONCE64: &[u8] = b"n0nce-64";
const NONCE: &[u8] = b"nonce-chacha\0\0\0\0";

/// Key clumplets as the 5.0.4 server sends them, with the plugins chosen.
pub(crate) fn keys(chacha64: bool, chacha: bool, arc4: bool) -> Vec<u8> {
    let mut list = Vec::new();
    if chacha64 {
        list.push("ChaCha64");
    }
    if chacha {
        list.push("ChaCha");
    }
    if arc4 {
        list.push("Arc4");
    }
    let mut out = Vec::new();
    item(&mut out, 0, b"Symmetric");
    item(&mut out, 1, list.join(" ").as_bytes());
    if chacha64 {
        item(&mut out, 3, &[b"ChaCha64\0".as_slice(), NONCE64].concat());
    }
    if chacha {
        item(&mut out, 3, &[b"ChaCha\0".as_slice(), NONCE].concat());
    }
    if arc4 {
        item(&mut out, 3, b"Arc4\0");
    }
    out
}

/// `op_response`.
pub(crate) fn response(object: u32, data: &[u8], gds: Option<u32>) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(op::RESPONSE).u32(object).u32(0).u32(0).opaque(data);
    match gds {
        Some(code) => {
            w.u32(1).u32(code);
            // A string argument, as the server writes names and values.
            w.u32(2).opaque(b"value 'secret@example.test'");
        }
        None => {
            w.u32(1).u32(0);
        }
    }
    w.u32(0);
    w.as_slice().to_vec()
}

fn cond_accept(
    version: u32,
    ptype: u32,
    data: &[u8],
    plugin: &[u8],
    authenticated: u32,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(if authenticated == 0 {
        op::COND_ACCEPT
    } else {
        op::ACCEPT_DATA
    })
    .u32(version)
    .u32(1)
    .u32(ptype)
    .opaque(data)
    .opaque(plugin)
    .u32(authenticated)
    .opaque(b"");
    w.as_slice().to_vec()
}

/// A describe answer for `columns`.
pub(crate) fn describe(columns: &[Column]) -> Vec<u8> {
    let mut out = Vec::new();
    let val = |out: &mut Vec<u8>, item: u8, v: i32| {
        out.push(item);
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&v.to_le_bytes());
    };
    val(&mut out, 21, 1);
    out.push(4);
    val(&mut out, 7, i32::try_from(columns.len()).unwrap());
    for (i, c) in columns.iter().enumerate() {
        val(&mut out, 9, i32::try_from(i + 1).unwrap());
        val(&mut out, 11, c.sqltype | 1);
        val(&mut out, 12, c.sub_type);
        val(&mut out, 13, c.scale);
        val(&mut out, 14, i32::try_from(c.length).unwrap());
        out.push(8);
    }
    out.push(5);
    val(&mut out, 7, 0);
    out.push(1);
    out
}

/// One row in the protocol 13+ form.
pub(crate) fn row(columns: &[Column], values: &[Value]) -> Vec<u8> {
    let mut bitmap = vec![0u8; columns.len().div_ceil(8)];
    for (i, v) in values.iter().enumerate() {
        if *v == Value::Null {
            bitmap[i / 8] |= 1 << (i % 8);
        }
    }
    let mut w = Writer::new();
    let mut out = bitmap.clone();
    out.resize(bitmap.len().div_ceil(4) * 4, 0);
    for (c, v) in columns.iter().zip(values) {
        match (c.sqltype, v) {
            (_, Value::Null) => {}
            (sqltype::VARYING, Value::Text(t)) => {
                w.opaque(t.as_bytes());
            }
            (sqltype::VARYING, Value::Bytes(b)) => {
                w.opaque(b);
            }
            (sqltype::INT64, Value::Int(i)) => {
                w.u32((*i >> 32) as u32).u32(*i as u32);
            }
            (_, Value::Int(i)) => {
                w.u32(*i as u32);
            }
            (_, Value::Bool(b)) => {
                w.u32(if *b { 0x0100_0000 } else { 0 });
            }
            _ => panic!("fake row: {c:?} {v:?}"),
        }
    }
    out.extend_from_slice(w.as_slice());
    out
}

/// A `VARCHAR(n) CHARACTER SET UTF8` column of `n` bytes.
pub(crate) fn text_col(bytes: u32) -> Column {
    Column {
        sqltype: sqltype::VARYING,
        sub_type: charset::UTF8,
        scale: 0,
        length: bytes,
    }
}

/// An `INTEGER` column.
pub(crate) fn int_col() -> Column {
    Column {
        sqltype: sqltype::LONG,
        sub_type: 0,
        scale: 0,
        length: 4,
    }
}

/// What the fake server saw.
#[derive(Debug, Default, Clone)]
pub(crate) struct Seen {
    /// The operation codes received, in order.
    pub(crate) ops: Vec<u32>,
    /// The protocol versions offered by `op_connect`.
    pub(crate) versions: Vec<u32>,
    /// The plugin named by `op_crypt`.
    pub(crate) crypt_plugin: Option<String>,
    /// The statement texts prepared.
    pub(crate) prepared: Vec<String>,
    /// The CNCT codes of the user identification.
    pub(crate) cnct: Vec<u8>,
    /// The timeout of each `op_execute`.
    pub(crate) timeouts: Vec<u32>,
}

/// A client message, as the fake parses it.
enum Msg {
    Connect { public: Vec<u8> },
    ContAuth,
    Crypt { plugin: String },
    Attach,
    Transaction,
    Allocate,
    Prepare { text: String },
    Execute { timeout: u32 },
    Fetch { count: u32 },
    Free,
    Simple,
    Cancel,
    Disconnect,
}

fn parse_client(r: &mut Reader<'_>, seen: &mut Seen) -> Result<Msg, XdrError> {
    let code = r.u32()?;
    let msg = match code {
        op::CONNECT => {
            let _operation = r.u32()?;
            let _cversion = r.u32()?;
            let _arch = r.u32()?;
            let _file = r.opaque(4096)?;
            let count = r.u32()?;
            let user = r.opaque(4096)?.to_vec();
            let mut versions = Vec::new();
            for _ in 0..count.min(16) {
                versions.push(r.u32()?);
                r.u32()?;
                r.u32()?;
                r.u32()?;
                r.u32()?;
            }
            let mut public = Vec::new();
            let mut cnct = Vec::new();
            let mut i = 0;
            while i + 1 < user.len() {
                let (c, len) = (user[i], usize::from(user[i + 1]));
                if c == 7 {
                    public.extend_from_slice(&user[i + 3..i + 2 + len]);
                }
                cnct.push(c);
                i += 2 + len;
            }
            seen.versions = versions;
            seen.cnct = cnct;
            Msg::Connect { public }
        }
        op::CONT_AUTH => {
            r.opaque(4096)?;
            r.opaque(64)?;
            r.opaque(64)?;
            r.opaque(64)?;
            Msg::ContAuth
        }
        op::CRYPT => {
            let plugin = String::from_utf8(r.opaque(64)?.to_vec()).unwrap();
            r.opaque(64)?;
            Msg::Crypt { plugin }
        }
        op::ATTACH => {
            r.u32()?;
            r.opaque(4096)?;
            r.opaque(4096)?;
            Msg::Attach
        }
        op::TRANSACTION => {
            r.u32()?;
            r.opaque(64)?;
            Msg::Transaction
        }
        op::ALLOCATE_STATEMENT => {
            r.u32()?;
            Msg::Allocate
        }
        op::PREPARE_STATEMENT => {
            r.u32()?;
            r.u32()?;
            r.u32()?;
            let text = String::from_utf8(r.opaque(1 << 16)?.to_vec()).unwrap();
            r.opaque(256)?;
            r.u32()?;
            Msg::Prepare { text }
        }
        op::EXECUTE => {
            r.u32()?;
            r.u32()?;
            r.opaque(1024)?;
            r.u32()?;
            r.u32()?;
            let timeout = r.u32()?;
            Msg::Execute { timeout }
        }
        op::FETCH => {
            r.u32()?;
            r.opaque(4096)?;
            r.u32()?;
            let count = r.u32()?;
            Msg::Fetch { count }
        }
        op::FREE_STATEMENT => {
            r.u32()?;
            r.u32()?;
            Msg::Free
        }
        op::COMMIT | op::ROLLBACK | op::DETACH => {
            r.u32()?;
            Msg::Simple
        }
        op::CANCEL => {
            r.u32()?;
            Msg::Cancel
        }
        op::DISCONNECT => Msg::Disconnect,
        _ => return Err(XdrError::Bound),
    };
    seen.ops.push(code);
    Ok(msg)
}

/// The server's end of the connection.
struct Server {
    io: DuplexStream,
    rx: Vec<u8>,
    rx_cipher: Option<Cipher>,
    tx_cipher: Option<Cipher>,
}

impl Server {
    async fn next(&mut self, seen: &mut Seen) -> Option<Msg> {
        loop {
            let mut r = Reader::new(&self.rx);
            match parse_client(&mut r, seen) {
                Ok(m) => {
                    let n = r.pos();
                    self.rx.drain(..n);
                    return Some(m);
                }
                Err(XdrError::Bound) => return None,
                Err(XdrError::Incomplete) => {}
            }
            let mut buf = vec![0u8; 65_536];
            let n =
                match tokio::time::timeout(Duration::from_secs(20), self.io.read(&mut buf)).await {
                    Ok(Ok(n)) if n > 0 => n,
                    _ => return None,
                };
            if let Some(c) = self.rx_cipher.as_mut() {
                c.apply(&mut buf[..n]).unwrap();
            }
            self.rx.extend_from_slice(&buf[..n]);
        }
    }

    async fn send(&mut self, bytes: &[u8]) -> bool {
        let mut b = bytes.to_vec();
        if let Some(c) = self.tx_cipher.as_mut() {
            c.apply(&mut b).unwrap();
        }
        self.io.write_all(&b).await.is_ok()
    }
}

/// Serves one connection by `script`; returns what it saw.
pub(crate) async fn serve(io: DuplexStream, script: Script) -> Seen {
    let mut seen = Seen::default();
    let mut s = Server {
        io,
        rx: Vec::new(),
        rx_cipher: None,
        tx_cipher: None,
    };
    let b = srp::server::private(42);
    let b_public = srp::server::public(LOGIN, PASSWORD, SALT, &b);
    let mut a_public = U1024::ZERO;
    let mut prepared: Option<Canned> = None;
    let mut cursor = 0usize;
    while let Some(msg) = s.next(&mut seen).await {
        let answer: Vec<u8> = match msg {
            Msg::Connect { public } => {
                let hex = std::str::from_utf8(&public).unwrap();
                let mut bytes = [0u8; 128];
                let raw: Vec<u8> = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect();
                bytes[128 - raw.len()..].copy_from_slice(&raw);
                a_public = U1024::from_be_slice(&bytes);
                let data = srp::server::data(SALT, &b_public);
                match &script.accept {
                    Accept::Good => cond_accept(0xFFFF_8010, 3, &data, b"Srp256", 0),
                    Accept::Version(v) => cond_accept(*v, 3, &data, b"Srp256", 0),
                    Accept::Type(t) => cond_accept(0xFFFF_8010, *t, &data, b"Srp256", 0),
                    Accept::Reject => op::REJECT.to_be_bytes().to_vec(),
                    Accept::Plain => {
                        let mut w = Writer::new();
                        w.u32(op::ACCEPT).u32(0xFFFF_8010).u32(1).u32(3);
                        w.as_slice().to_vec()
                    }
                    Accept::AuthenticatedEarly => cond_accept(0xFFFF_8010, 3, &data, b"Srp256", 1),
                    Accept::Plugin(p) => cond_accept(0xFFFF_8010, 3, &data, p.as_bytes(), 0),
                    Accept::Data(d) => cond_accept(0xFFFF_8010, 3, d, b"Srp256", 0),
                    Accept::KeyCallback => {
                        let mut w = Writer::new();
                        w.u32(op::CRYPT_KEY_CALLBACK).opaque(b"key?").u32(0);
                        w.as_slice().to_vec()
                    }
                    Accept::Error(code) => response(0, b"", Some(*code)),
                    Accept::Raw(bytes) => bytes.clone(),
                }
            }
            Msg::ContAuth => match &script.auth {
                Auth::Keys(k) => response(0, k, None),
                Auth::LoginFailed => response(0, b"", Some(crate::error::gds::LOGIN)),
                Auth::Again => {
                    let mut w = Writer::new();
                    w.u32(op::CONT_AUTH)
                        .opaque(b"more")
                        .opaque(b"Srp256")
                        .opaque(b"")
                        .opaque(b"");
                    w.as_slice().to_vec()
                }
            },
            Msg::Crypt { plugin } => {
                seen.crypt_plugin = Some(plugin.clone());
                let key = srp::server::session_key(LOGIN, PASSWORD, SALT, &a_public, &b_public, &b);
                let (p, nonce) = if plugin == "ChaCha64" {
                    (CryptPlugin::ChaCha64, NONCE64)
                } else {
                    (CryptPlugin::ChaCha, NONCE)
                };
                s.rx_cipher = Cipher::new(p, &key, nonce);
                match script.crypt {
                    Crypt::Good => {
                        s.tx_cipher = Cipher::new(p, &key, nonce);
                        response(0, b"", None)
                    }
                    Crypt::Plain => response(0, b"", None),
                    Crypt::WrongKey => {
                        s.tx_cipher = Cipher::new(p, &[9u8; 20], nonce);
                        response(0, b"", None)
                    }
                    Crypt::Error => {
                        s.tx_cipher = Cipher::new(p, &key, nonce);
                        response(0, b"", Some(crate::error::gds::WIRECRYPT_KEY))
                    }
                }
            }
            Msg::Attach => script
                .attach_answer
                .clone()
                .unwrap_or_else(|| response(0, b"", None)),
            Msg::Transaction => response(1, b"", None),
            Msg::Allocate => response(2, b"", None),
            Msg::Prepare { text } => {
                seen.prepared.push(text.clone());
                match script.statements.iter().find(|c| c.text == text) {
                    Some(c) if c.error.is_some() => {
                        prepared = None;
                        response(0, b"", c.error)
                    }
                    Some(c) => {
                        prepared = Some(c.clone());
                        cursor = 0;
                        response(0, &describe(&c.columns), None)
                    }
                    None => {
                        prepared = None;
                        response(0, b"", Some(crate::error::gds::DSQL_RELATION_ERR))
                    }
                }
            }
            Msg::Execute { timeout } => {
                seen.timeouts.push(timeout);
                if script.stall_execute {
                    continue;
                }
                response(0, b"", None)
            }
            Msg::Cancel => response(0, b"", Some(crate::error::gds::CANCELLED)),
            Msg::Fetch { count } => {
                let mut out = Vec::new();
                let mut end = true;
                if let Some(c) = &prepared {
                    let rows: Vec<Vec<Value>> = match script.flood_rows {
                        Some(n) => (0..n).map(|_| c.rows[0].clone()).collect(),
                        None => {
                            let take = usize::try_from(count).unwrap();
                            let batch: Vec<Vec<Value>> =
                                c.rows.iter().skip(cursor).take(take).cloned().collect();
                            cursor += batch.len();
                            end = cursor >= c.rows.len();
                            batch
                        }
                    };
                    for r in &rows {
                        let mut w = Writer::new();
                        w.u32(op::FETCH_RESPONSE).u32(0).u32(1);
                        out.extend_from_slice(w.as_slice());
                        out.extend_from_slice(&row(&c.columns, r));
                    }
                }
                let mut w = Writer::new();
                w.u32(op::FETCH_RESPONSE)
                    .u32(if end { 100 } else { 0 })
                    .u32(0);
                out.extend_from_slice(w.as_slice());
                out
            }
            Msg::Free | Msg::Simple => response(0, b"", None),
            Msg::Disconnect => break,
        };
        if !s.send(&answer).await {
            break;
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use databastion_core::FailureCode;
    use tokio::time::Instant;

    use super::*;
    use crate::conn::{self, Session};
    use crate::error::{Detail, FbError, Stage};
    use crate::sql::Col;

    async fn fails(script: Script) -> (FbError, Seen) {
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(serve(server, script));
        let deadline = Instant::now() + Duration::from_secs(10);
        let e = conn::handshake(
            Box::new(client),
            LOGIN,
            PASSWORD,
            "app",
            deadline,
            Duration::from_millis(300),
        )
        .await
        .err()
        .expect("the handshake must fail");
        (e, server.await.unwrap())
    }

    async fn session(script: Script) -> (Session, tokio::task::JoinHandle<Seen>) {
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(serve(server, script));
        let deadline = Instant::now() + Duration::from_secs(10);
        let s = conn::handshake(
            Box::new(client),
            LOGIN,
            PASSWORD,
            "app",
            deadline,
            Duration::from_millis(300),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
        (s, server)
    }

    #[tokio::test]
    async fn the_good_handshake_chooses_chacha64_and_attaches() {
        let (s, server) = session(Script::default()).await;
        assert_eq!(s.plugin_name(), "ChaCha64");
        s.close().await;
        let seen = server.await.unwrap();
        // op_connect offered protocol 16 only, with no OS user or host.
        assert_eq!(seen.versions, [0x8010]);
        assert_eq!(seen.cnct, [9, 8, 10, 7, 7, 11]);
        assert_eq!(seen.crypt_plugin.as_deref(), Some("ChaCha64"));
        assert_eq!(
            seen.ops,
            [
                op::CONNECT,
                op::CONT_AUTH,
                op::CRYPT,
                op::ATTACH,
                op::DETACH,
                op::DISCONNECT
            ]
        );
    }

    #[tokio::test]
    async fn chacha_without_chacha64_and_never_arc4() {
        let (s, server) = session(Script {
            auth: Auth::Keys(keys(false, true, true)),
            ..Script::default()
        })
        .await;
        assert_eq!(s.plugin_name(), "ChaCha");
        s.close().await;
        assert_eq!(
            server.await.unwrap().crypt_plugin.as_deref(),
            Some("ChaCha")
        );
        // Arc4 only, or no key at all: refused before op_crypt.
        for k in [keys(false, false, true), Vec::new()] {
            let (e, seen) = fails(Script {
                auth: Auth::Keys(k),
                ..Script::default()
            })
            .await;
            assert_eq!(e.code, FailureCode::TargetUnreachable);
            assert_eq!((e.stage, e.detail), (Stage::Tls, Some(Detail::NoChacha)));
            assert!(!seen.ops.contains(&op::CRYPT), "{:?}", seen.ops);
        }
    }

    #[tokio::test]
    async fn the_protocol_must_be_16_exactly() {
        for accept in [
            Accept::Version(0xFFFF_800F),
            Accept::Version(0xFFFF_8013),
            Accept::Type(5),
            Accept::Type(0x103),
            Accept::Reject,
        ] {
            let (e, seen) = fails(Script {
                accept: accept.clone(),
                ..Script::default()
            })
            .await;
            assert_eq!(e.code, FailureCode::Unsupported, "{accept:?}");
            assert_eq!(e.detail, Some(Detail::ProtocolVersion), "{accept:?}");
            // Nothing derived from the password was sent.
            assert_eq!(seen.ops, [op::CONNECT], "{accept:?}");
        }
        // A sign extension that does not match the short.
        let (e, _) = fails(Script {
            accept: Accept::Version(0x0001_8010),
            ..Script::default()
        })
        .await;
        assert_eq!(e.detail, Some(Detail::Protocol));
    }

    #[tokio::test]
    async fn srp_must_complete_with_srp256() {
        for (accept, detail) in [
            (Accept::Plain, Detail::AuthPlugin),
            (Accept::AuthenticatedEarly, Detail::AuthenticatedEarly),
            (Accept::Plugin("Srp"), Detail::AuthPlugin),
            (Accept::Plugin("Legacy_Auth"), Detail::AuthPlugin),
            (
                Accept::Data(b"\x01\x00s\x02\x00g!".to_vec()),
                Detail::SrpData,
            ),
            (Accept::Data(Vec::new()), Detail::SrpData),
        ] {
            let (e, seen) = fails(Script {
                accept: accept.clone(),
                ..Script::default()
            })
            .await;
            assert_eq!(e.code, FailureCode::AuthenticationFailed, "{accept:?}");
            assert_eq!(e.detail, Some(detail), "{accept:?}");
            assert_eq!(seen.ops, [op::CONNECT], "{accept:?}");
        }
        let (e, _) = fails(Script {
            auth: Auth::LoginFailed,
            ..Script::default()
        })
        .await;
        assert_eq!(
            (e.code, e.stage, e.gds),
            (
                FailureCode::AuthenticationFailed,
                Stage::Auth,
                Some(crate::error::gds::LOGIN)
            )
        );
        let (e, _) = fails(Script {
            auth: Auth::Again,
            ..Script::default()
        })
        .await;
        assert_eq!(e.detail, Some(Detail::Protocol));
        let (e, seen) = fails(Script {
            accept: Accept::KeyCallback,
            ..Script::default()
        })
        .await;
        assert_eq!(e.detail, Some(Detail::CryptKeyCallback));
        assert_eq!(seen.ops, [op::CONNECT]);
        let (e, _) = fails(Script {
            accept: Accept::Error(crate::error::gds::LOGIN),
            ..Script::default()
        })
        .await;
        assert_eq!(e.code, FailureCode::AuthenticationFailed);
    }

    #[tokio::test]
    async fn the_key_is_confirmed_before_any_encrypted_byte() {
        for crypt in [Crypt::Plain, Crypt::WrongKey, Crypt::Error] {
            let (e, seen) = fails(Script {
                crypt: crypt.clone(),
                ..Script::default()
            })
            .await;
            assert_eq!(e.code, FailureCode::TargetUnreachable, "{crypt:?}");
            assert_eq!(
                (e.stage, e.detail),
                (Stage::Tls, Some(Detail::KeyConfirmation)),
                "{crypt:?}"
            );
            // The client sent nothing after op_crypt.
            assert_eq!(*seen.ops.last().unwrap(), op::CRYPT, "{crypt:?}");
        }
    }

    #[tokio::test]
    async fn hostile_lengths_and_unknown_operations_end_the_connection() {
        // An op_response whose data claims 2 GiB: refused before reading.
        let mut huge = Writer::new();
        huge.u32(op::RESPONSE).u32(0).u32(0).u32(0).u32(0x7FFF_FFFF);
        // An unknown operation, an event, an inline blob.
        for raw in [
            huge.as_slice().to_vec(),
            1000u32.to_be_bytes().to_vec(),
            52u32.to_be_bytes().to_vec(),
            114u32.to_be_bytes().to_vec(),
        ] {
            let (e, seen) = fails(Script {
                accept: Accept::Raw(raw),
                ..Script::default()
            })
            .await;
            assert_eq!(e.detail, Some(Detail::Protocol));
            assert_eq!(seen.ops, [op::CONNECT]);
        }
        // The same after the session is encrypted: the attach answer.
        let mut w = Writer::new();
        w.u32(op::RESPONSE).u32(0).u32(0).u32(0).u32(0x00FF_FFFF);
        let (e, _) = fails(Script {
            attach_answer: Some(w.as_slice().to_vec()),
            ..Script::default()
        })
        .await;
        assert_eq!(
            (e.stage, e.detail),
            (Stage::SessionSetup, Some(Detail::Protocol))
        );
        // A failed attach: the closed table, no server text.
        let (e, _) = fails(Script {
            attach_answer: Some(response(0, b"", Some(crate::error::gds::IO_ERROR))),
            ..Script::default()
        })
        .await;
        assert_eq!(e.code, FailureCode::UnknownTarget);
    }

    fn canned(text: &'static str, columns: Vec<Column>, rows: Vec<Vec<Value>>) -> Canned {
        Canned {
            text,
            columns,
            rows,
            error: None,
        }
    }

    fn v(s: &str) -> Value {
        Value::Text(zeroize::Zeroizing::new(s.to_owned()))
    }

    #[tokio::test]
    async fn statements_run_in_read_only_transactions_with_timeouts() {
        let (mut s, server) = session(Script {
            statements: vec![canned(
                crate::sql::VERSION,
                vec![text_col(128)],
                vec![vec![v("5.0.4")]],
            )],
            ..Script::default()
        })
        .await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let rows = s
            .query(crate::sql::VERSION, &[Col::Text(128)], 1, deadline)
            .await
            .unwrap();
        assert_eq!(rows.rows[0][0].as_text(), Some("5.0.4"));
        assert!(!rows.cut);
        // A text outside the closed set is never sent.
        let e = s
            .query("SELECT 1 FROM RDB$DATABASE", &[Col::Int], 1, deadline)
            .await
            .unwrap_err();
        assert_eq!(e.code, FailureCode::Internal);
        // Another shape than the caller's: refused, the session unusable.
        let e = s
            .query(crate::sql::VERSION, &[Col::Int], 1, deadline)
            .await
            .unwrap_err();
        assert_eq!(e.detail, Some(Detail::Protocol));
        assert!(
            s.query(crate::sql::VERSION, &[Col::Text(128)], 1, deadline)
                .await
                .is_err()
        );
        s.close().await;
        let seen = server.await.unwrap();
        assert_eq!(seen.timeouts, [300]);
        assert!(seen.ops.contains(&op::TRANSACTION));
        assert!(!seen.prepared.iter().any(|t| t.contains("SELECT 1")));
    }

    #[tokio::test]
    async fn rows_past_the_bound_are_cut_and_floods_refused() {
        let script = Script {
            statements: vec![canned(
                crate::sql::ROLE_MEMBERSHIPS,
                vec![text_col(252), int_col(), text_col(252), int_col()],
                (0..10)
                    .map(|i| vec![v(&format!("U{i}")), Value::Int(8), v("R"), Value::Int(0)])
                    .collect(),
            )],
            ..Script::default()
        };
        let (mut s, server) = session(script.clone()).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let shape = [Col::Text(252), Col::Int, Col::Text(252), Col::Int];
        let rows = s
            .query(crate::sql::ROLE_MEMBERSHIPS, &shape, 4, deadline)
            .await
            .unwrap();
        assert_eq!(rows.rows.len(), 4);
        assert!(rows.cut);
        s.close().await;
        server.await.unwrap();
        // More rows in one answer than asked for: a protocol violation.
        let (mut s, server) = session(Script {
            flood_rows: Some(100),
            ..script
        })
        .await;
        let e = s
            .query(crate::sql::ROLE_MEMBERSHIPS, &shape, 4, deadline)
            .await
            .unwrap_err();
        assert_eq!(e.detail, Some(Detail::Protocol));
        s.close().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_statement_past_its_deadline_is_cancelled() {
        let (mut s, server) = session(Script {
            statements: vec![canned(
                crate::sql::VERSION,
                vec![text_col(128)],
                vec![vec![v("5.0.4")]],
            )],
            stall_execute: true,
            ..Script::default()
        })
        .await;
        let started = Instant::now();
        let e = s
            .query(
                crate::sql::VERSION,
                &[Col::Text(128)],
                1,
                started + Duration::from_secs(10),
            )
            .await
            .unwrap_err();
        assert_eq!(e.code, FailureCode::Timeout);
        // The statement timeout (300 ms) plus the client's margin.
        assert!(started.elapsed() < Duration::from_secs(4));
        s.close().await;
        let seen = server.await.unwrap();
        assert!(seen.ops.contains(&op::CANCEL), "{:?}", seen.ops);
    }

    #[tokio::test]
    async fn a_permission_error_leaves_the_session_usable() {
        let (mut s, server) = session(Script {
            statements: vec![
                Canned {
                    text: crate::sql::PROBES[0].1,
                    columns: vec![int_col()],
                    rows: vec![],
                    error: Some(crate::error::gds::NO_PRIV),
                },
                canned(
                    crate::sql::VERSION,
                    vec![text_col(128)],
                    vec![vec![v("4.0.7")]],
                ),
            ],
            ..Script::default()
        })
        .await;
        let deadline = Instant::now() + Duration::from_secs(5);
        let e = s
            .query(crate::sql::PROBES[0].1, &[Col::Int], 1, deadline)
            .await
            .unwrap_err();
        assert_eq!(e.code, FailureCode::PermissionDenied);
        assert!(!e.fatal);
        let rows = s
            .query(crate::sql::VERSION, &[Col::Text(128)], 1, deadline)
            .await
            .unwrap();
        assert_eq!(rows.rows[0][0].as_text(), Some("4.0.7"));
        s.close().await;
        server.await.unwrap();
    }
}
