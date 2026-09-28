//! The subset of the MySQL client/server protocol the connector speaks
//! (text protocol only), shared by MySQL 8 and MariaDB.
//!
//! Why a purpose-built client instead of a driver crate (security review
//! notes, P2-C):
//! - the connector chooses the capability flags: never `CLIENT_LOCAL_FILES`
//!   (a server could otherwise ask the agent for any local file with
//!   `LOAD DATA LOCAL INFILE`), never `CLIENT_MULTI_STATEMENTS`, never
//!   compression; a `LOCAL INFILE` request is refused even if sent anyway;
//! - it chooses the authentication exchanges (`auth`): no cleartext
//!   password plugin, no RSA public-key retrieval, no password on a
//!   network connection without TLS except through a challenge-response;
//! - server error packets are reduced to their error number and SQLSTATE
//!   while parsing: the message text is never stored;
//! - rows are read one packet at a time, so a per-relation byte budget can
//!   stop reading and have the statement killed.
//!
//! Every parser works on a bounded buffer and fails closed on malformed
//! input.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// Largest payload of one physical packet.
const MAX_PHYSICAL: usize = 0xFF_FFFF;
/// Largest logical packet (a row) accepted from the server. A larger row is
/// a protocol error: the statement is killed and the session dropped.
pub(crate) const MAX_LOGICAL: usize = 40 * 1024 * 1024;
/// `max_packet_size` announced to the server.
const CLIENT_MAX_PACKET: u32 = 64 * 1024 * 1024;
/// `utf8mb4_general_ci`: exists on MySQL 5.5.3+ and every MariaDB.
pub(crate) const UTF8MB4_GENERAL_CI: u8 = 45;

/// Capability flags (`CLIENT_*`).
pub(crate) mod cap {
    pub(crate) const LONG_PASSWORD: u32 = 1;
    pub(crate) const LONG_FLAG: u32 = 1 << 2;
    // Never requested (checked by a test).
    #[cfg(test)]
    pub(crate) const CONNECT_WITH_DB: u32 = 1 << 3;
    // Never requested (checked by a test).
    #[cfg(test)]
    pub(crate) const COMPRESS: u32 = 1 << 5;
    // Never requested (checked by a test).
    #[cfg(test)]
    pub(crate) const LOCAL_FILES: u32 = 1 << 7;
    pub(crate) const PROTOCOL_41: u32 = 1 << 9;
    pub(crate) const SSL: u32 = 1 << 11;
    pub(crate) const TRANSACTIONS: u32 = 1 << 13;
    pub(crate) const SECURE_CONNECTION: u32 = 1 << 15;
    // Never requested (checked by a test).
    #[cfg(test)]
    pub(crate) const MULTI_STATEMENTS: u32 = 1 << 16;
    // Never requested (checked by a test).
    #[cfg(test)]
    pub(crate) const MULTI_RESULTS: u32 = 1 << 17;
    pub(crate) const PLUGIN_AUTH: u32 = 1 << 19;
    pub(crate) const CONNECT_ATTRS: u32 = 1 << 20;
    pub(crate) const PLUGIN_AUTH_LENENC_DATA: u32 = 1 << 21;
    // Never requested (checked by a test).
    #[cfg(test)]
    pub(crate) const DEPRECATE_EOF: u32 = 1 << 24;

    /// Capabilities the connector may ask for. Everything else (local
    /// files, multi-statements, compression, `CONNECT_WITH_DB`, session
    /// tracking, query attributes…) is never set.
    pub(crate) const WANTED: u32 = LONG_PASSWORD
        | LONG_FLAG
        | PROTOCOL_41
        | TRANSACTIONS
        | SECURE_CONNECTION
        | PLUGIN_AUTH
        | CONNECT_ATTRS
        | PLUGIN_AUTH_LENENC_DATA;
    /// Required from the server.
    pub(crate) const REQUIRED: u32 = PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH;
}

/// Server status flags (`SERVER_STATUS_*`).
pub(crate) mod status {
    pub(crate) const IN_TRANS: u16 = 1;
    pub(crate) const IN_TRANS_READONLY: u16 = 0x2000;
}

/// Protocol failure (no server text).
#[derive(Debug)]
pub(crate) enum ProtoError {
    /// Transport error or closed connection.
    Io(io::ErrorKind),
    /// Malformed or unexpected packet, or out-of-order sequence id.
    Malformed,
    /// A logical packet larger than [`MAX_LOGICAL`].
    TooLarge,
    /// An error packet: error number and SQLSTATE (message discarded).
    Server(ServerError),
}

impl From<io::Error> for ProtoError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// Error number and SQLSTATE of an error packet. The message is never
/// kept (it can quote values, statement text or host names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerError {
    pub(crate) errno: u16,
    pub(crate) sqlstate: Option<[u8; 5]>,
}

impl ServerError {
    pub(crate) fn sqlstate(&self) -> Option<&str> {
        self.sqlstate
            .as_ref()
            .and_then(|s| std::str::from_utf8(s).ok())
    }
}

/// Parses an error packet (`0xFF`, errno, optional `#` + SQLSTATE,
/// message). Only a SQLSTATE of five `[0-9A-Z]` is kept.
pub(crate) fn parse_err(payload: &[u8]) -> Result<ServerError, ProtoError> {
    let mut r = Reader::new(payload);
    if r.u8()? != 0xFF {
        return Err(ProtoError::Malformed);
    }
    let errno = r.u16()?;
    let mut sqlstate = None;
    if r.peek() == Some(b'#') {
        r.u8()?;
        let s = r.take(5)?;
        if s.iter()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
        {
            let mut out = [0u8; 5];
            out.copy_from_slice(s);
            sqlstate = Some(out);
        }
    }
    // The rest is the message: not read.
    Ok(ServerError { errno, sqlstate })
}

/// A bounded little-endian reader.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.pos.checked_add(n).ok_or(ProtoError::Malformed)?;
        let s = self.buf.get(self.pos..end).ok_or(ProtoError::Malformed)?;
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ProtoError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ProtoError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Length-encoded integer. `0xFB` (NULL) and `0xFF` are not integers.
    pub(crate) fn lenenc(&mut self) -> Result<u64, ProtoError> {
        match self.u8()? {
            n @ 0..=0xFA => Ok(u64::from(n)),
            0xFC => Ok(u64::from(self.u16()?)),
            0xFD => {
                let b = self.take(3)?;
                Ok(u64::from(b[0]) | u64::from(b[1]) << 8 | u64::from(b[2]) << 16)
            }
            0xFE => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                Ok(u64::from_le_bytes(a))
            }
            _ => Err(ProtoError::Malformed),
        }
    }

    /// Length-encoded string (bytes).
    pub(crate) fn lenenc_bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let n = usize::try_from(self.lenenc()?).map_err(|_| ProtoError::Malformed)?;
        self.take(n)
    }

    /// NUL-terminated string (bytes, without the NUL).
    pub(crate) fn nul_bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let rest = &self.buf[self.pos..];
        let n = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(ProtoError::Malformed)?;
        self.pos += n + 1;
        Ok(&rest[..n])
    }
}

/// Appends a length-encoded integer.
pub(crate) fn put_lenenc(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xFA => out.push(u8::try_from(n).unwrap_or(0)),
        0xFB..=0xFFFF => {
            out.push(0xFC);
            out.extend_from_slice(&u16::try_from(n).unwrap_or(0).to_le_bytes());
        }
        0x1_0000..=0xFF_FFFF => {
            out.push(0xFD);
            out.extend_from_slice(&u32::try_from(n).unwrap_or(0).to_le_bytes()[..3]);
        }
        _ => {
            out.push(0xFE);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// The server's initial handshake (protocol version 10).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Handshake {
    pub(crate) server_version: String,
    pub(crate) connection_id: u32,
    pub(crate) capabilities: u32,
    /// Authentication nonce (20 bytes).
    pub(crate) nonce: Vec<u8>,
    pub(crate) plugin: Vec<u8>,
}

impl std::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handshake")
            .field("connection_id", &self.connection_id)
            .field("capabilities", &format_args!("{:#x}", self.capabilities))
            .finish_non_exhaustive()
    }
}

/// Parses the initial handshake. An error packet (host blocked, too many
/// connections) is returned as [`ProtoError::Server`].
pub(crate) fn parse_handshake(payload: &[u8]) -> Result<Handshake, ProtoError> {
    if payload.first() == Some(&0xFF) {
        return Err(ProtoError::Server(parse_err(payload)?));
    }
    let mut r = Reader::new(payload);
    if r.u8()? != 10 {
        return Err(ProtoError::Malformed);
    }
    let version = r.nul_bytes()?;
    if version.len() > 128 {
        return Err(ProtoError::Malformed);
    }
    // Printable ASCII only (a version string, e.g. `11.4.13-MariaDB-ubu2404`).
    let server_version = version
        .iter()
        .map(|&b| {
            if (0x20..0x7F).contains(&b) {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect();
    let connection_id = r.u32()?;
    let mut nonce = r.take(8)?.to_vec();
    r.u8()?; // filler
    let mut capabilities = u32::from(r.u16()?);
    if r.remaining() == 0 {
        return Err(ProtoError::Malformed);
    }
    r.u8()?; // character set
    r.u16()?; // status flags
    capabilities |= u32::from(r.u16()?) << 16;
    let auth_len = usize::from(r.u8()?);
    r.take(10)?; // reserved (MariaDB: extended capabilities)
    if capabilities & cap::SECURE_CONNECTION != 0 {
        let n = auth_len.saturating_sub(8).max(13);
        let part2 = r.take(n)?;
        // The last byte is a NUL terminator.
        let part2 = part2.strip_suffix(&[0]).unwrap_or(part2);
        nonce.extend_from_slice(part2);
    }
    let plugin = if capabilities & cap::PLUGIN_AUTH != 0 {
        // Some servers omit the final NUL.
        let rest = r.rest();
        rest.strip_suffix(&[0]).unwrap_or(rest).to_vec()
    } else {
        Vec::new()
    };
    if nonce.len() != 20 || plugin.len() > 64 {
        return Err(ProtoError::Malformed);
    }
    Ok(Handshake {
        server_version,
        connection_id,
        capabilities,
        nonce,
        plugin,
    })
}

/// `SSLRequest`: the first 32 bytes of a handshake response, with
/// `CLIENT_SSL`.
pub(crate) fn ssl_request(capabilities: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&capabilities.to_le_bytes());
    out.extend_from_slice(&CLIENT_MAX_PACKET.to_le_bytes());
    out.push(UTF8MB4_GENERAL_CI);
    out.extend_from_slice(&[0u8; 23]);
    out
}

/// `HandshakeResponse41`. `auth` is the plugin's first answer (a
/// scramble, never the password). Connection attributes identify the
/// agent (`program_name`).
pub(crate) fn handshake_response(
    capabilities: u32,
    user: &str,
    auth: &[u8],
    plugin: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(ssl_request(capabilities));
    out.extend_from_slice(user.as_bytes());
    out.push(0);
    put_lenenc(&mut out, auth.len() as u64);
    out.extend_from_slice(auth);
    out.extend_from_slice(plugin);
    out.push(0);
    if capabilities & cap::CONNECT_ATTRS != 0 {
        let mut attrs = Vec::new();
        for (k, v) in [
            ("_client_name", "databastion-agent"),
            ("program_name", "databastion-agent"),
        ] {
            put_lenenc(&mut attrs, k.len() as u64);
            attrs.extend_from_slice(k.as_bytes());
            put_lenenc(&mut attrs, v.len() as u64);
            attrs.extend_from_slice(v.as_bytes());
        }
        put_lenenc(&mut out, attrs.len() as u64);
        out.extend_from_slice(&attrs);
    }
    out
}

/// An OK packet's status flags.
pub(crate) fn parse_ok(payload: &[u8]) -> Result<u16, ProtoError> {
    let mut r = Reader::new(payload);
    let header = r.u8()?;
    if header != 0x00 && header != 0xFE {
        return Err(ProtoError::Malformed);
    }
    r.lenenc()?; // affected rows
    r.lenenc()?; // last insert id
    r.u16()
}

/// Whether a packet is an EOF packet (`0xFE`, shorter than 9 bytes); a row
/// can start with `0xFE` (an 8-byte length prefix) but is then longer.
pub(crate) fn is_eof(payload: &[u8]) -> bool {
    payload.first() == Some(&0xFE) && payload.len() < 9
}

/// Status flags of an EOF packet.
pub(crate) fn eof_status(payload: &[u8]) -> Result<u16, ProtoError> {
    let mut r = Reader::new(payload);
    r.u8()?;
    r.u16()?; // warnings
    r.u16()
}

/// Column type byte of a column definition packet (`ColumnDefinition41`).
pub(crate) fn column_type(payload: &[u8]) -> Result<u8, ProtoError> {
    let mut r = Reader::new(payload);
    for _ in 0..6 {
        // catalog, schema, table, org_table, name, org_name
        r.lenenc_bytes()?;
    }
    if r.lenenc()? < 10 {
        return Err(ProtoError::Malformed);
    }
    r.u16()?; // character set
    r.u32()?; // column length
    r.u8()
}

/// Splits a text-protocol row into `columns` values (`None` = NULL).
pub(crate) fn parse_row(payload: &[u8], columns: usize) -> Result<Vec<Option<&[u8]>>, ProtoError> {
    let mut r = Reader::new(payload);
    let mut out = Vec::with_capacity(columns);
    for _ in 0..columns {
        if r.peek() == Some(0xFB) {
            r.u8()?;
            out.push(None);
        } else {
            out.push(Some(r.lenenc_bytes()?));
        }
    }
    if r.remaining() != 0 {
        return Err(ProtoError::Malformed);
    }
    Ok(out)
}

/// Packet framing with sequence ids over a byte stream.
pub(crate) struct PacketIo<S> {
    pub(crate) stream: S,
    seq: u8,
}

impl<S: AsyncRead + AsyncWrite + Unpin> PacketIo<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self { stream, seq: 0 }
    }

    /// Starts a new command (sequence id 0).
    pub(crate) fn reset_seq(&mut self) {
        self.seq = 0;
    }

    /// Reads one logical packet (joining `0xFFFFFF`-byte continuations).
    /// The buffer is zeroized on drop (rows carry sampled values).
    pub(crate) async fn read(&mut self) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
        let mut out = Zeroizing::new(Vec::new());
        loop {
            let mut header = [0u8; 4];
            self.stream.read_exact(&mut header).await?;
            let len =
                usize::from(header[0]) | usize::from(header[1]) << 8 | usize::from(header[2]) << 16;
            if header[3] != self.seq {
                return Err(ProtoError::Malformed);
            }
            self.seq = self.seq.wrapping_add(1);
            if out.len() + len > MAX_LOGICAL {
                return Err(ProtoError::TooLarge);
            }
            let start = out.len();
            out.resize(start + len, 0);
            self.stream.read_exact(&mut out[start..]).await?;
            if len < MAX_PHYSICAL {
                return Ok(out);
            }
        }
    }

    /// Writes one logical packet (split in `0xFFFFFF`-byte packets).
    pub(crate) async fn write(&mut self, payload: &[u8]) -> Result<(), ProtoError> {
        let mut chunks = payload.chunks(MAX_PHYSICAL).peekable();
        let mut buf = Zeroizing::new(Vec::with_capacity(payload.len().min(MAX_PHYSICAL) + 4));
        loop {
            let chunk = chunks.next().unwrap_or(&[]);
            buf.clear();
            let len = u32::try_from(chunk.len()).map_err(|_| ProtoError::Malformed)?;
            buf.extend_from_slice(&len.to_le_bytes()[..3]);
            buf.push(self.seq);
            self.seq = self.seq.wrapping_add(1);
            buf.extend_from_slice(chunk);
            self.stream.write_all(&buf).await?;
            // A payload that is a multiple of the maximum ends with an
            // empty packet.
            if chunk.len() < MAX_PHYSICAL {
                break;
            }
        }
        self.stream.flush().await?;
        Ok(())
    }

    /// Sends a command packet (sequence id 0).
    pub(crate) async fn command(&mut self, command: u8, body: &[u8]) -> Result<(), ProtoError> {
        self.reset_seq();
        let mut payload = Vec::with_capacity(body.len() + 1);
        payload.push(command);
        payload.extend_from_slice(body);
        self.write(&payload).await
    }
}

/// `COM_QUIT`.
pub(crate) const COM_QUIT: u8 = 0x01;
/// `COM_QUERY`.
pub(crate) const COM_QUERY: u8 = 0x03;

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn handshake_bytes(plugin: &[u8], caps: u32, mariadb: bool) -> Vec<u8> {
        let mut p = vec![10];
        p.extend_from_slice(if mariadb {
            b"11.4.13-MariaDB-ubu2404\0"
        } else {
            b"8.4.11\0"
        });
        p.extend_from_slice(&42u32.to_le_bytes());
        p.extend_from_slice(b"abcdefgh");
        p.push(0);
        p.extend_from_slice(&u16::try_from(caps & 0xFFFF).unwrap().to_le_bytes());
        p.push(255);
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(&u16::try_from(caps >> 16).unwrap().to_le_bytes());
        p.push(21);
        p.extend_from_slice(&[0u8; 10]);
        p.extend_from_slice(b"ijklmnopqrst\0");
        p.extend_from_slice(plugin);
        p.push(0);
        p
    }

    #[test]
    fn handshake_is_parsed() {
        let caps = cap::WANTED | cap::SSL | cap::LOCAL_FILES;
        let h = parse_handshake(&handshake_bytes(b"caching_sha2_password", caps, false)).unwrap();
        assert_eq!(h.server_version, "8.4.11");
        assert_eq!(h.connection_id, 42);
        assert_eq!(h.nonce, b"abcdefghijklmnopqrst");
        assert_eq!(h.plugin, b"caching_sha2_password");
        assert_eq!(h.capabilities, caps);
        // Debug shows no nonce, no version.
        let d = format!("{h:?}");
        assert!(!d.contains("abcdefgh") && !d.contains("8.4"), "{d}");
    }

    #[test]
    fn malformed_handshakes_are_refused() {
        let good = handshake_bytes(b"mysql_native_password", cap::WANTED, true);
        for n in 0..good.len() - 1 {
            // Truncated anywhere before the plugin name.
            if n < good.len() - 23 {
                assert!(parse_handshake(&good[..n]).is_err(), "{n}");
            }
        }
        let mut v9 = good.clone();
        v9[0] = 9;
        assert!(parse_handshake(&v9).is_err());
        // Error packet instead of a handshake: errno kept, message dropped.
        let mut err = vec![0xFF];
        err.extend_from_slice(&1040u16.to_le_bytes());
        err.extend_from_slice(b"#08004Too many connections SECRET");
        match parse_handshake(&err) {
            Err(ProtoError::Server(e)) => {
                assert_eq!(e.errno, 1040);
                assert_eq!(e.sqlstate(), Some("08004"));
                assert!(!format!("{e:?}").contains("SECRET"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn error_packets_keep_only_errno_and_sqlstate() {
        let mut p = vec![0xFF];
        p.extend_from_slice(&1142u16.to_le_bytes());
        p.extend_from_slice(b"#42000SELECT command denied to user 'x'@'10.0.0.1'");
        let e = parse_err(&p).unwrap();
        assert_eq!(e.errno, 1142);
        assert_eq!(e.sqlstate(), Some("42000"));
        // Handshake-time errors have no SQLSTATE marker.
        let mut p = vec![0xFF];
        p.extend_from_slice(&1130u16.to_le_bytes());
        p.extend_from_slice(b"Host 'x' is not allowed");
        assert_eq!(parse_err(&p).unwrap().sqlstate, None);
        // A malformed SQLSTATE is dropped.
        let mut p = vec![0xFF];
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(b"#ab'cdrest");
        assert_eq!(parse_err(&p).unwrap().sqlstate, None);
    }

    #[test]
    fn lenenc_roundtrip() {
        for n in [
            0u64,
            250,
            251,
            0xFFFF,
            0x1_0000,
            0xFF_FFFF,
            0x100_0000,
            u64::MAX,
        ] {
            let mut b = Vec::new();
            put_lenenc(&mut b, n);
            assert_eq!(Reader::new(&b).lenenc().unwrap(), n, "{n}");
        }
        assert!(Reader::new(&[0xFB]).lenenc().is_err());
        assert!(Reader::new(&[0xFF]).lenenc().is_err());
        assert!(Reader::new(&[0xFE, 1, 2]).lenenc().is_err());
    }

    #[test]
    fn rows_are_split_with_nulls() {
        let row = [3, b'a', b'b', b'c', 0xFB, 0];
        let v = parse_row(&row, 3).unwrap();
        assert_eq!(v, vec![Some(&b"abc"[..]), None, Some(&b""[..])]);
        assert!(parse_row(&row, 2).is_err());
        assert!(parse_row(&row, 4).is_err());
        assert!(parse_row(&[5, b'a'], 1).is_err());
        assert!(is_eof(&[0xFE, 0, 0, 2, 0]));
        assert!(!is_eof(&[0xFE, 1, 0, 0, 0, 0, 0, 0, 0, b'x']));
    }

    #[test]
    fn handshake_response_never_asks_for_local_files_or_multi_statements() {
        for bad in [
            cap::LOCAL_FILES,
            cap::MULTI_STATEMENTS,
            cap::MULTI_RESULTS,
            cap::COMPRESS,
            cap::CONNECT_WITH_DB,
            cap::DEPRECATE_EOF,
        ] {
            assert_eq!(cap::WANTED & bad, 0);
        }
        let r = handshake_response(cap::WANTED, "agent", &[1, 2, 3], b"caching_sha2_password");
        let mut rd = Reader::new(&r);
        assert_eq!(rd.u32().unwrap(), cap::WANTED);
        rd.u32().unwrap();
        assert_eq!(rd.u8().unwrap(), UTF8MB4_GENERAL_CI);
        rd.take(23).unwrap();
        assert_eq!(rd.nul_bytes().unwrap(), b"agent");
        assert_eq!(rd.lenenc_bytes().unwrap(), &[1, 2, 3]);
        assert_eq!(rd.nul_bytes().unwrap(), b"caching_sha2_password");
        let attrs = rd.lenenc_bytes().unwrap();
        assert!(attrs.windows(17).any(|w| w == b"databastion-agent"));
        assert_eq!(rd.remaining(), 0);
    }

    #[tokio::test]
    async fn packets_are_framed_and_sequenced() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let mut client = PacketIo::new(a);
        let mut server = PacketIo::new(b);
        client.command(COM_QUERY, b"SELECT 1").await.unwrap();
        let p = server.read().await.unwrap();
        assert_eq!(&p[..], b"\x03SELECT 1");
        server.write(b"\x00\x00\x00\x02\x00\x00\x00").await.unwrap();
        let ok = client.read().await.unwrap();
        assert_eq!(parse_ok(&ok).unwrap(), 2);
        // Out-of-order sequence id.
        server.reset_seq();
        server.write(b"x").await.unwrap();
        assert!(matches!(client.read().await, Err(ProtoError::Malformed)));
    }

    #[tokio::test]
    async fn large_packets_are_joined_and_bounded() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let mut client = PacketIo::new(a);
        let mut server = PacketIo::new(b);
        let big = vec![7u8; MAX_PHYSICAL + 10];
        let writer = tokio::spawn(async move {
            server.write(&big).await.unwrap();
            server
        });
        let p = client.read().await.unwrap();
        assert_eq!(p.len(), MAX_PHYSICAL + 10);
        drop(writer.await.unwrap());
        // Over MAX_LOGICAL: refused before reading the payload.
        let (a, mut b) = tokio::io::duplex(64);
        let mut client = PacketIo::new(a);
        tokio::spawn(async move {
            for seq in 0u8..4 {
                let _ = b.write_all(&[0xFF, 0xFF, 0xFF, seq]).await;
                let _ = b.write_all(&vec![0u8; MAX_PHYSICAL]).await;
            }
        });
        assert!(matches!(client.read().await, Err(ProtoError::TooLarge)));
    }
}
