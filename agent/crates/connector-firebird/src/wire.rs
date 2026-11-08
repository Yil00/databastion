//! The closed subset of the Firebird remote protocol 16 the connector
//! speaks (ADR-0060 decision 1): the client messages it builds and the
//! server messages it parses. Every other operation from the server ends
//! the connection (XDR has no framing beyond its own items, so an unknown
//! operation cannot be skipped safely).
//!
//! Constants are protocol facts (`protocol.h`, `consts_pub.h`), checked
//! against the pinned 5.0.4 and 4.0.7 images.

use crate::xdr::{Reader, Writer, XdrError};

/// Operation codes.
pub(crate) mod op {
    pub(crate) const CONNECT: u32 = 1;
    pub(crate) const ACCEPT: u32 = 3;
    pub(crate) const REJECT: u32 = 4;
    pub(crate) const DISCONNECT: u32 = 6;
    pub(crate) const RESPONSE: u32 = 9;
    pub(crate) const ATTACH: u32 = 19;
    pub(crate) const DETACH: u32 = 21;
    pub(crate) const TRANSACTION: u32 = 29;
    pub(crate) const COMMIT: u32 = 30;
    pub(crate) const ROLLBACK: u32 = 31;
    pub(crate) const ALLOCATE_STATEMENT: u32 = 62;
    pub(crate) const EXECUTE: u32 = 63;
    pub(crate) const FETCH: u32 = 65;
    pub(crate) const FETCH_RESPONSE: u32 = 66;
    pub(crate) const FREE_STATEMENT: u32 = 67;
    pub(crate) const PREPARE_STATEMENT: u32 = 68;
    pub(crate) const DUMMY: u32 = 71;
    pub(crate) const CANCEL: u32 = 91;
    pub(crate) const CONT_AUTH: u32 = 92;
    pub(crate) const ACCEPT_DATA: u32 = 94;
    pub(crate) const CRYPT: u32 = 96;
    pub(crate) const CRYPT_KEY_CALLBACK: u32 = 97;
    pub(crate) const COND_ACCEPT: u32 = 98;
}

/// `PROTOCOL_VERSION16` (`FB_PROTOCOL_FLAG | 16`): the only version
/// offered (decision 1).
pub(crate) const PROTOCOL_VERSION16: u16 = 0x8010;
/// `CONNECT_VERSION3`: the user identification is UTF-8.
const CONNECT_VERSION3: u32 = 3;
/// `arch_generic`: canonical (big-endian) forms.
pub(crate) const ARCH_GENERIC: u32 = 1;
/// `ptype_batch_send`: batch sends, no asynchrony, no deferred answers.
pub(crate) const PTYPE_BATCH_SEND: u32 = 3;
/// `ptype_MASK` and `pflag_compress` of `p_acpt_type`.
const PTYPE_MASK: u32 = 0xFF;
/// The only authentication plugin offered (decision 3).
pub(crate) const SRP256: &[u8] = b"Srp256";
/// `WIRE_CRYPT_REQUIRED` in `CNCT_client_crypt`.
const WIRE_CRYPT_REQUIRED: u32 = 2;

/// `CNCT_*` items of the user identification.
mod cnct {
    pub(super) const SPECIFIC_DATA: u8 = 7;
    pub(super) const PLUGIN_NAME: u8 = 8;
    pub(super) const LOGIN: u8 = 9;
    pub(super) const PLUGIN_LIST: u8 = 10;
    pub(super) const CLIENT_CRYPT: u8 = 11;
}

/// Bounds of the server's items (decision 1).
pub(crate) mod bound {
    /// `p_acpt_data` and `op_cont_auth` data: the SRP data is at most
    /// `(32 + 128 + 2) * 2` = 324 bytes.
    pub(crate) const AUTH_DATA: usize = 1024;
    /// Plugin names.
    pub(crate) const NAME: usize = 64;
    /// Plugin lists and key buffers.
    pub(crate) const KEYS: usize = 4096;
    /// `p_resp_data`: an info buffer requested with at most 64 KiB.
    pub(crate) const RESPONSE_DATA: usize = 65_536;
    /// Entries of a status vector.
    pub(crate) const STATUS_ITEMS: usize = 64;
    /// One status-vector string (skipped, never kept).
    pub(crate) const STATUS_STRING: usize = 65_536;
    /// GDS codes kept from a status vector.
    pub(crate) const STATUS_CODES: usize = 16;
    /// Key clumplets accumulated over the handshake.
    pub(crate) const KEY_ENTRIES: usize = 32;
}

/// A status vector reduced while parsing to its GDS codes (decision 1):
/// strings (`isc_arg_string`, `isc_arg_cstring`, `isc_arg_interpreted`,
/// `isc_arg_sql_state`) are skipped by length, never stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Status {
    /// The non-zero `isc_arg_gds` codes, in order (at most 16).
    pub(crate) codes: Vec<u32>,
}

impl Status {
    /// Whether the vector reports a failure.
    pub(crate) fn failed(&self) -> bool {
        !self.codes.is_empty()
    }
}

/// `isc_arg_*` tags.
mod arg {
    pub(super) const END: u32 = 0;
    pub(super) const GDS: u32 = 1;
    pub(super) const STRING: u32 = 2;
    pub(super) const CSTRING: u32 = 3;
    pub(super) const INTERPRETED: u32 = 5;
    pub(super) const WARNING: u32 = 18;
    pub(super) const SQL_STATE: u32 = 19;
}

fn status(r: &mut Reader<'_>) -> Result<Status, XdrError> {
    let mut out = Status::default();
    let mut warning = false;
    for i in 0..bound::STATUS_ITEMS {
        let tag = r.u32()?;
        match tag {
            arg::END => return Ok(out),
            arg::GDS => {
                let code = r.u32()?;
                // A vector that starts with a warning carries warnings
                // only (a success); its codes are not failures.
                if code != 0 && !warning && out.codes.len() < bound::STATUS_CODES {
                    out.codes.push(code);
                }
            }
            arg::WARNING => {
                if i == 0 {
                    warning = true;
                }
                r.u32()?;
            }
            arg::STRING | arg::CSTRING | arg::INTERPRETED | arg::SQL_STATE => {
                r.skip_opaque(bound::STATUS_STRING)?;
            }
            // `isc_arg_number` and the operating-system codes: a 32-bit
            // value.
            _ => {
                r.u32()?;
            }
        }
    }
    Err(XdrError::Bound)
}

/// `op_response`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Response {
    pub(crate) object: u16,
    pub(crate) blob_id: i64,
    pub(crate) data: Vec<u8>,
    pub(crate) status: Status,
}

/// `op_accept` / `op_accept_data` / `op_cond_accept`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Accept {
    pub(crate) conditional: bool,
    pub(crate) with_data: bool,
    pub(crate) version: u16,
    pub(crate) arch: u32,
    pub(crate) ptype: u32,
    pub(crate) data: Vec<u8>,
    pub(crate) plugin: Vec<u8>,
    pub(crate) authenticated: u32,
    pub(crate) keys: Vec<u8>,
}

impl Accept {
    /// Whether the accepted protocol is exactly what was offered:
    /// version 16, generic architecture, `ptype_batch_send`, no flag
    /// (compression, Win_SSPI).
    pub(crate) fn is_protocol_16(&self) -> bool {
        self.version == PROTOCOL_VERSION16
            && self.arch == ARCH_GENERIC
            && self.ptype == PTYPE_BATCH_SEND
    }
}

/// A server message of the closed set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Server {
    Accept(Accept),
    Reject,
    Response(Response),
    ContAuth {
        data: Vec<u8>,
        name: Vec<u8>,
        keys: Vec<u8>,
    },
    FetchResponse {
        status: u32,
        count: u32,
    },
    /// The server asks the client for a database encryption key: refused
    /// (decision 1), so its payload is not parsed.
    CryptKeyCallback,
}

/// Which server operations are acceptable now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// After `op_connect`.
    Connect,
    /// During `op_cont_auth`.
    Auth,
    /// The session: responses, and fetch responses.
    Session,
}

/// Parses one server message, `op_dummy` keep-alives skipped. An
/// operation outside the closed set of `phase` is [`XdrError::Bound`].
pub(crate) fn parse(r: &mut Reader<'_>, phase: Phase) -> Result<Server, XdrError> {
    loop {
        let code = r.u32()?;
        let allowed = match code {
            op::DUMMY => continue,
            op::RESPONSE => true,
            op::ACCEPT | op::ACCEPT_DATA | op::COND_ACCEPT | op::REJECT => phase == Phase::Connect,
            op::CONT_AUTH => phase == Phase::Auth,
            op::FETCH_RESPONSE => phase == Phase::Session,
            op::CRYPT_KEY_CALLBACK => phase != Phase::Session,
            _ => false,
        };
        if !allowed {
            return Err(XdrError::Bound);
        }
        return match code {
            op::RESPONSE => Ok(Server::Response(response(r)?)),
            op::ACCEPT | op::ACCEPT_DATA | op::COND_ACCEPT => {
                let version = r.short()?;
                let arch = r.u32()?;
                let ptype = r.u32()?;
                let mut a = Accept {
                    conditional: code == op::COND_ACCEPT,
                    with_data: code != op::ACCEPT,
                    version,
                    arch,
                    // The type and its flags: a flag makes it differ from
                    // `ptype_batch_send`, which [`Accept::is_protocol_16`]
                    // refuses.
                    ptype: if ptype & !PTYPE_MASK == 0 {
                        ptype
                    } else {
                        u32::MAX
                    },
                    data: Vec::new(),
                    plugin: Vec::new(),
                    authenticated: 0,
                    keys: Vec::new(),
                };
                if a.with_data {
                    a.data = r.opaque(bound::AUTH_DATA)?.to_vec();
                    a.plugin = r.opaque(bound::NAME)?.to_vec();
                    a.authenticated = r.u32()?;
                    a.keys = r.opaque(bound::KEYS)?.to_vec();
                }
                Ok(Server::Accept(a))
            }
            op::REJECT => Ok(Server::Reject),
            op::CONT_AUTH => {
                let data = r.opaque(bound::AUTH_DATA)?.to_vec();
                let name = r.opaque(bound::NAME)?.to_vec();
                r.skip_opaque(bound::KEYS)?;
                let keys = r.opaque(bound::KEYS)?.to_vec();
                Ok(Server::ContAuth { data, name, keys })
            }
            op::FETCH_RESPONSE => {
                let status = r.u32()?;
                let count = r.u32()?;
                Ok(Server::FetchResponse { status, count })
            }
            _ => Ok(Server::CryptKeyCallback),
        };
    }
}

fn response(r: &mut Reader<'_>) -> Result<Response, XdrError> {
    let object = r.short()?;
    let blob_id = r.i64()?;
    let data = r.opaque(bound::RESPONSE_DATA)?.to_vec();
    let status = status(r)?;
    Ok(Response {
        object,
        blob_id,
        data,
        status,
    })
}

/// `op_connect` with the user identification of decision 1: the login,
/// `Srp256` as the plugin and the plugin list, the SRP public value `A`
/// (hex) as `CNCT_specific_data`, wire encryption required. No
/// `CNCT_user` (the OS user) and no `CNCT_host`. `attach` is sent in
/// clear (`p_cnct_file`): the server chooses its per-database
/// authentication and wire-crypt settings from it.
pub(crate) fn connect(attach: &str, login: &str, public_hex: &[u8]) -> Writer {
    let mut user = Vec::new();
    push_item(&mut user, cnct::LOGIN, login.as_bytes());
    push_item(&mut user, cnct::PLUGIN_NAME, SRP256);
    push_item(&mut user, cnct::PLUGIN_LIST, SRP256);
    // The multipart form: parts of at most 254 bytes, each after its
    // sequence number.
    for (step, part) in public_hex.chunks(254).enumerate() {
        let mut item = Vec::with_capacity(part.len() + 1);
        item.push(u8::try_from(step).unwrap_or(u8::MAX));
        item.extend_from_slice(part);
        push_item(&mut user, cnct::SPECIFIC_DATA, &item);
    }
    push_item(
        &mut user,
        cnct::CLIENT_CRYPT,
        &WIRE_CRYPT_REQUIRED.to_le_bytes(),
    );
    let mut w = Writer::new();
    w.u32(op::CONNECT)
        .u32(op::ATTACH)
        .u32(CONNECT_VERSION3)
        .u32(ARCH_GENERIC)
        .opaque(attach.as_bytes())
        .u32(1)
        .opaque(&user)
        // One protocol: version 16, generic, min and max type
        // `ptype_batch_send`, weight 2.
        .u32(u32::from(PROTOCOL_VERSION16))
        .u32(ARCH_GENERIC)
        .u32(PTYPE_BATCH_SEND)
        .u32(PTYPE_BATCH_SEND)
        .u32(2);
    w
}

/// An item `code`, length byte, data; data longer than 255 bytes is cut
/// (every caller's data is shorter).
fn push_item(out: &mut Vec<u8>, code: u8, data: &[u8]) {
    let len = data.len().min(255);
    out.push(code);
    out.push(u8::try_from(len).unwrap_or(u8::MAX));
    out.extend_from_slice(&data[..len]);
}

/// `op_cont_auth` with the client proof (hex) of `Srp256`.
pub(crate) fn cont_auth(proof_hex: &[u8]) -> Writer {
    let mut w = Writer::new();
    w.u32(op::CONT_AUTH)
        .opaque(proof_hex)
        .opaque(SRP256)
        .opaque(SRP256)
        .opaque(b"");
    w
}

/// `op_crypt`: the chosen plugin with the `Symmetric` key.
pub(crate) fn crypt(plugin: &str) -> Writer {
    let mut w = Writer::new();
    w.u32(op::CRYPT).opaque(plugin.as_bytes()).opaque(SYMMETRIC);
    w
}

/// The key type every wire-crypt plugin of the connector uses.
pub(crate) const SYMMETRIC: &[u8] = b"Symmetric";

/// `isc_dpb_*` items.
mod dpb {
    pub(super) const VERSION1: u8 = 1;
    pub(super) const USER_NAME: u8 = 28;
    pub(super) const LC_CTYPE: u8 = 48;
    pub(super) const SQL_DIALECT: u8 = 63;
    pub(super) const PROCESS_NAME: u8 = 74;
    pub(super) const UTF8_FILENAME: u8 = 77;
    pub(super) const SESSION_TIME_ZONE: u8 = 91;
}

/// The process name the agent declares (decision 3).
pub(crate) const PROCESS_NAME: &str = "databastion-agent";

/// `op_attach` with the DPB of decision 3: the account name, `UTF8`,
/// dialect 3, the process name, the `UTC` session time zone, and the
/// attach string as UTF-8. Never a role, a password, nor the
/// administrator-only items.
pub(crate) fn attach(attach: &str, login: &str) -> Writer {
    let mut d = vec![dpb::VERSION1];
    push_item(&mut d, dpb::USER_NAME, login.as_bytes());
    push_item(&mut d, dpb::LC_CTYPE, b"UTF8");
    push_item(&mut d, dpb::SQL_DIALECT, &3u32.to_le_bytes());
    push_item(&mut d, dpb::PROCESS_NAME, PROCESS_NAME.as_bytes());
    push_item(&mut d, dpb::SESSION_TIME_ZONE, b"UTC");
    push_item(&mut d, dpb::UTF8_FILENAME, b"");
    let mut w = Writer::new();
    w.u32(op::ATTACH)
        .u32(0)
        .opaque(attach.as_bytes())
        .opaque(&d);
    w
}

/// The transaction parameter buffer of decision 4: `isc_tpb_version3,
/// isc_tpb_read, isc_tpb_read_committed, isc_tpb_read_consistency,
/// isc_tpb_nowait`. The only TPB the connector sends.
pub(crate) const TPB: &[u8] = &[3, 8, 15, 22, 7];

pub(crate) fn transaction() -> Writer {
    let mut w = Writer::new();
    w.u32(op::TRANSACTION).u32(0).opaque(TPB);
    w
}

pub(crate) fn release(code: u32, object: u16) -> Writer {
    let mut w = Writer::new();
    w.u32(code).u32(u32::from(object));
    w
}

/// `op_allocate_statement`.
pub(crate) fn allocate() -> Writer {
    release(op::ALLOCATE_STATEMENT, 0)
}

/// `op_prepare_statement` in dialect 3 with the describe items `items`
/// and an answer of at most `buffer` bytes.
pub(crate) fn prepare(tx: u16, stmt: u16, sql: &str, items: &[u8], buffer: u32) -> Writer {
    let mut w = Writer::new();
    w.u32(op::PREPARE_STATEMENT)
        .u32(u32::from(tx))
        .u32(u32::from(stmt))
        .u32(3)
        .opaque(sql.as_bytes())
        .opaque(items)
        .u32(buffer);
    w
}

/// `op_execute` without parameters, with the statement timeout of
/// protocol 16 (never 0, decision 4).
pub(crate) fn execute(stmt: u16, tx: u16, timeout_ms: u32) -> Writer {
    let mut w = Writer::new();
    w.u32(op::EXECUTE)
        .u32(u32::from(stmt))
        .u32(u32::from(tx))
        .opaque(b"")
        .u32(0)
        .u32(0)
        .u32(timeout_ms.max(1));
    w
}

/// `op_fetch` of at most `count` rows with the output BLR.
pub(crate) fn fetch(stmt: u16, blr: &[u8], count: u32) -> Writer {
    let mut w = Writer::new();
    w.u32(op::FETCH)
        .u32(u32::from(stmt))
        .opaque(blr)
        .u32(0)
        .u32(count);
    w
}

/// `DSQL_drop`.
pub(crate) const DSQL_DROP: u32 = 2;

/// `op_free_statement`.
pub(crate) fn free(stmt: u16, option: u32) -> Writer {
    let mut w = Writer::new();
    w.u32(op::FREE_STATEMENT).u32(u32::from(stmt)).u32(option);
    w
}

/// `fb_cancel_raise`: cancel the running operation.
pub(crate) const CANCEL_RAISE: u32 = 3;

pub(crate) fn cancel() -> Writer {
    let mut w = Writer::new();
    w.u32(op::CANCEL).u32(CANCEL_RAISE);
    w
}

pub(crate) fn disconnect() -> Writer {
    let mut w = Writer::new();
    w.u32(op::DISCONNECT);
    w
}

/// Server key clumplet tags.
mod tag {
    pub(super) const KEY_TYPE: u8 = 0;
    pub(super) const KEY_PLUGINS: u8 = 1;
    pub(super) const KNOWN_PLUGINS: u8 = 2;
    pub(super) const PLUGIN_SPECIFIC: u8 = 3;
}

/// A wire-crypt plugin the connector accepts (decision 1): never Arc4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptPlugin {
    /// ChaCha20 with an 8-byte nonce and a 64-bit counter.
    ChaCha64,
    /// ChaCha20 with a 12-byte nonce and a 32-bit counter.
    ChaCha,
}

impl CryptPlugin {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ChaCha64 => "ChaCha64",
            Self::ChaCha => "ChaCha",
        }
    }
}

/// The keys the server announced, accumulated over the handshake.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Keys {
    /// Plugins listed for the `Symmetric` key type.
    plugins: Vec<Vec<u8>>,
    /// Plugin-specific data of the `Symmetric` key type, by plugin.
    specific: Vec<(Vec<u8>, Vec<u8>)>,
    entries: usize,
}

impl Keys {
    /// Adds a key buffer (`p_acpt_keys`, `p_keys`, `p_resp_data` of the
    /// authentication answer): untagged clumplets, a tag byte, a length
    /// byte and the data.
    pub(crate) fn add(&mut self, buf: &[u8]) -> Result<(), XdrError> {
        let mut i = 0;
        let mut symmetric = false;
        while i < buf.len() {
            let tag = buf[i];
            let len = usize::from(*buf.get(i + 1).ok_or(XdrError::Bound)?);
            let data = buf.get(i + 2..i + 2 + len).ok_or(XdrError::Bound)?;
            i += 2 + len;
            self.entries += 1;
            if self.entries > bound::KEY_ENTRIES {
                return Err(XdrError::Bound);
            }
            match tag {
                tag::KEY_TYPE => symmetric = data == SYMMETRIC,
                tag::KEY_PLUGINS if symmetric => {
                    for p in data
                        .split(|b| matches!(b, b' ' | b'\t' | b',' | b';'))
                        .filter(|p| !p.is_empty())
                    {
                        self.plugins.push(p.to_vec());
                    }
                }
                tag::PLUGIN_SPECIFIC if symmetric => {
                    if let Some(sep) = data.iter().position(|b| *b == 0)
                        && sep > 0
                    {
                        self.specific
                            .push((data[..sep].to_vec(), data[sep + 1..].to_vec()));
                    }
                }
                tag::KEY_PLUGINS | tag::KNOWN_PLUGINS | tag::PLUGIN_SPECIFIC => {}
                _ => return Err(XdrError::Bound),
            }
        }
        Ok(())
    }

    /// The strongest acceptable plugin with its plugin-specific data
    /// (`ChaCha64` first, then `ChaCha`, decision 1), or `None`: Arc4 and
    /// no encryption are never chosen.
    pub(crate) fn choose(&self) -> Option<(CryptPlugin, &[u8])> {
        for plugin in [CryptPlugin::ChaCha64, CryptPlugin::ChaCha] {
            let name = plugin.name().as_bytes();
            if !self.plugins.iter().any(|p| p == name) {
                continue;
            }
            if let Some((_, data)) = self.specific.iter().find(|(n, _)| n == name) {
                let ok = match plugin {
                    CryptPlugin::ChaCha64 => data.len() == 8,
                    CryptPlugin::ChaCha => data.len() == 12 || data.len() == 16,
                };
                if ok {
                    return Some((plugin, data));
                }
            }
        }
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A server `op_response` as the 5.0.4 server writes it.
    pub(crate) fn response_bytes(object: u32, data: &[u8], codes: &[u32]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(op::RESPONSE).u32(object).u32(0).u32(0).opaque(data);
        if codes.is_empty() {
            w.u32(arg::GDS).u32(0);
        }
        for c in codes {
            w.u32(arg::GDS).u32(*c);
            w.u32(arg::STRING).opaque(b"a quoted value 'x@y.z'");
        }
        w.u32(arg::END);
        w.as_slice().to_vec()
    }

    #[test]
    fn responses_keep_codes_and_drop_strings() {
        let bytes = response_bytes(0xFFFF_FFFF, b"abc", &[335_544_352, 335_545_254]);
        let mut r = Reader::new(&bytes);
        let Server::Response(resp) = parse(&mut r, Phase::Session).unwrap() else {
            panic!()
        };
        assert_eq!(resp.object, 0xFFFF);
        assert_eq!(resp.data, b"abc");
        assert_eq!(resp.status.codes, [335_544_352, 335_545_254]);
        assert!(resp.status.failed());
        assert_eq!(r.remaining(), 0);
        // The success vector of the server: `isc_arg_gds, 0, isc_arg_end`.
        let ok = response_bytes(1, b"", &[]);
        let Server::Response(resp) = parse(&mut Reader::new(&ok), Phase::Session).unwrap() else {
            panic!()
        };
        assert!(!resp.status.failed());
        // A warning-only vector is a success.
        let mut w = Writer::new();
        w.u32(op::RESPONSE).u32(0).u32(0).u32(0).opaque(b"");
        w.u32(arg::WARNING).u32(335_544_352).u32(arg::END);
        let Server::Response(resp) = parse(&mut Reader::new(w.as_slice()), Phase::Session).unwrap()
        else {
            panic!()
        };
        assert!(!resp.status.failed());
    }

    #[test]
    fn operations_outside_the_closed_set_end_the_connection() {
        for code in [
            op::CONNECT,
            52, /* op_event */
            90, /* op_trusted_auth */
            114,
            1000,
        ] {
            let bytes = code.to_be_bytes();
            for phase in [Phase::Connect, Phase::Auth, Phase::Session] {
                assert_eq!(
                    parse(&mut Reader::new(&bytes), phase),
                    Err(XdrError::Bound),
                    "{code}"
                );
            }
        }
        // Accept is only valid after op_connect, fetch responses only in
        // the session, op_cont_auth only during authentication.
        let accept = op::ACCEPT.to_be_bytes();
        assert_eq!(
            parse(&mut Reader::new(&accept), Phase::Session),
            Err(XdrError::Bound)
        );
        let fetch = op::FETCH_RESPONSE.to_be_bytes();
        assert_eq!(
            parse(&mut Reader::new(&fetch), Phase::Connect),
            Err(XdrError::Bound)
        );
        // A key callback is refused by the caller, not parsed.
        let cb = op::CRYPT_KEY_CALLBACK.to_be_bytes();
        assert_eq!(
            parse(&mut Reader::new(&cb), Phase::Connect),
            Ok(Server::CryptKeyCallback)
        );
        // Dummies are skipped.
        let mut w = Writer::new();
        w.u32(op::DUMMY).u32(op::DUMMY).u32(op::REJECT);
        assert_eq!(
            parse(&mut Reader::new(w.as_slice()), Phase::Connect),
            Ok(Server::Reject)
        );
    }

    #[test]
    fn accept_versions_and_flags() {
        let accept = |version: u32, ptype: u32| {
            let mut w = Writer::new();
            w.u32(op::COND_ACCEPT)
                .u32(version)
                .u32(ARCH_GENERIC)
                .u32(ptype)
                .opaque(b"data")
                .opaque(SRP256)
                .u32(0)
                .opaque(b"");
            let Server::Accept(a) = parse(&mut Reader::new(w.as_slice()), Phase::Connect).unwrap()
            else {
                panic!()
            };
            a
        };
        // The server writes the version as a sign-extended short.
        let a = accept(0xFFFF_8010, PTYPE_BATCH_SEND);
        assert!(a.is_protocol_16() && a.conditional && a.with_data);
        assert_eq!(a.plugin, SRP256);
        assert!(!accept(0xFFFF_800F, PTYPE_BATCH_SEND).is_protocol_16());
        assert!(!accept(0xFFFF_8013, PTYPE_BATCH_SEND).is_protocol_16());
        assert!(!accept(0xFFFF_8010, 5).is_protocol_16());
        // Compression acknowledged: refused.
        assert!(!accept(0xFFFF_8010, 0x100 | PTYPE_BATCH_SEND).is_protocol_16());
    }

    #[test]
    fn the_connect_message_offers_protocol_16_and_srp256_only() {
        let hex = vec![b'A'; 256];
        let w = connect("appalias", "DATABASTION_AGENT", &hex);
        let bytes = w.as_slice();
        let mut r = Reader::new(bytes);
        assert_eq!(r.u32(), Ok(op::CONNECT));
        assert_eq!(r.u32(), Ok(op::ATTACH));
        assert_eq!(r.u32(), Ok(CONNECT_VERSION3));
        assert_eq!(r.u32(), Ok(ARCH_GENERIC));
        assert_eq!(r.opaque(64), Ok(&b"appalias"[..]));
        assert_eq!(r.u32(), Ok(1));
        let user = r.opaque(1024).unwrap();
        assert_eq!(r.u32(), Ok(0x8010));
        assert_eq!(r.u32(), Ok(ARCH_GENERIC));
        assert_eq!(r.u32(), Ok(PTYPE_BATCH_SEND));
        assert_eq!(r.u32(), Ok(PTYPE_BATCH_SEND));
        assert_eq!(r.u32(), Ok(2));
        assert_eq!(r.remaining(), 0);
        // The items: login, plugin name and list, two parts of the public
        // value, the crypt level; no CNCT_user (1) nor CNCT_host (4).
        let mut i = 0;
        let mut codes = Vec::new();
        let mut public = Vec::new();
        while i < user.len() {
            let (code, len) = (user[i], usize::from(user[i + 1]));
            let data = &user[i + 2..i + 2 + len];
            if code == cnct::SPECIFIC_DATA {
                assert_eq!(usize::from(data[0]), public.len() / 254);
                public.extend_from_slice(&data[1..]);
            }
            codes.push(code);
            i += 2 + len;
        }
        assert_eq!(codes, [9, 8, 10, 7, 7, 11]);
        assert_eq!(public, hex);
        assert!(!codes.contains(&1) && !codes.contains(&4));
    }

    #[test]
    fn keys_choose_chacha64_then_chacha_never_arc4() {
        // As the 5.0.4 server sends them in the authentication answer.
        let mut buf = Vec::new();
        push_item(&mut buf, tag::KEY_TYPE, b"Symmetric");
        push_item(&mut buf, tag::KEY_PLUGINS, b"ChaCha64 ChaCha Arc4");
        push_item(&mut buf, tag::PLUGIN_SPECIFIC, b"ChaCha64\0abcdefgh");
        push_item(
            &mut buf,
            tag::PLUGIN_SPECIFIC,
            b"ChaCha\0abcdefghijkl\0\0\0\0",
        );
        let mut keys = Keys::default();
        keys.add(&buf).unwrap();
        assert_eq!(
            keys.choose(),
            Some((CryptPlugin::ChaCha64, &b"abcdefgh"[..]))
        );
        let mut buf = Vec::new();
        push_item(&mut buf, tag::KEY_TYPE, b"Symmetric");
        push_item(&mut buf, tag::KEY_PLUGINS, b"ChaCha, Arc4");
        push_item(&mut buf, tag::PLUGIN_SPECIFIC, b"ChaCha\0abcdefghijkl");
        let mut keys = Keys::default();
        keys.add(&buf).unwrap();
        assert_eq!(keys.choose().unwrap().0, CryptPlugin::ChaCha);
        // Arc4 only, a wrong nonce length, another key type: nothing.
        for (kind, list, specific) in [
            (&b"Symmetric"[..], &b"Arc4"[..], &b"Arc4\0x"[..]),
            (b"Symmetric", b"ChaCha64", b"ChaCha64\0short"),
            (b"Other", b"ChaCha64", b"ChaCha64\0abcdefgh"),
        ] {
            let mut buf = Vec::new();
            push_item(&mut buf, tag::KEY_TYPE, kind);
            push_item(&mut buf, tag::KEY_PLUGINS, list);
            push_item(&mut buf, tag::PLUGIN_SPECIFIC, specific);
            let mut keys = Keys::default();
            keys.add(&buf).unwrap();
            assert_eq!(keys.choose(), None);
        }
        // Truncated clumplets and unknown tags end the connection.
        assert!(Keys::default().add(&[0, 9, b'S']).is_err());
        assert!(Keys::default().add(&[7, 0]).is_err());
        assert!(Keys::default().add(&[0]).is_err());
    }
}
