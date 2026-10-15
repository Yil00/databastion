//! TDS framing and the client messages (ADR-0051 decision 1): packet
//! headers and their reassembly, `PRELOGIN`, `LOGIN7` (SQL authentication
//! only), `SQLBatch`, `RPC` to `sp_executesql` only, and `ATTENTION`.
//!
//! Sans I/O: every function works on byte buffers, so the reassembly is
//! fuzzed and property-tested without a server.

use zeroize::Zeroizing;

/// Packet types.
pub(crate) mod ptype {
    pub(crate) const SQL_BATCH: u8 = 0x01;
    pub(crate) const RPC: u8 = 0x03;
    pub(crate) const TABULAR_RESULT: u8 = 0x04;
    pub(crate) const ATTENTION: u8 = 0x06;
    pub(crate) const LOGIN7: u8 = 0x10;
    pub(crate) const PRELOGIN: u8 = 0x12;
}

/// Packet header length.
pub(crate) const HEADER: usize = 8;
/// Status bit: last packet of the message.
pub(crate) const STATUS_EOM: u8 = 0x01;
/// Smallest and largest packet size the client accepts (decision 1).
pub(crate) const MIN_PACKET: usize = 512;
pub(crate) const MAX_PACKET: usize = 32_767;
/// The packet size the client asks for in `LOGIN7` and uses until the
/// server's `ENVCHANGE` confirms one.
pub(crate) const DEFAULT_PACKET: usize = 4096;
/// TDS 7.4, the version requested (SQL Server 2012 and later).
pub(crate) const TDS_74: u32 = 0x7400_0004;
/// The `AppName` of `LOGIN7` (decision 1).
pub(crate) const APP_NAME: &str = "databastion-agent";
/// Longest SQL text the client sends (a closed statement set; sampling
/// statements are bounded by their column batches).
pub(crate) const MAX_SQL_CHARS: usize = 64 * 1024;
/// `sp_executesql`'s well-known procedure id.
const SP_EXECUTESQL: u16 = 10;

/// A protocol error of the framing layer. No server bytes are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameError {
    /// A header with a length below the header or above the packet size.
    BadLength,
    /// A packet of a type the client does not expect.
    BadType,
    /// Input the client refuses to encode (too long, invalid).
    Encode,
}

/// Frames `payload` as a message of `ptype` in packets of at most
/// `packet_size` bytes, the last one with `EOM`.
pub(crate) fn frame(ptype: u8, payload: &[u8], packet_size: usize) -> Vec<u8> {
    let data = packet_size.clamp(MIN_PACKET, MAX_PACKET) - HEADER;
    let mut out = Vec::with_capacity(payload.len() + HEADER * (payload.len() / data + 1));
    let chunks: Vec<&[u8]> = if payload.is_empty() {
        vec![&[][..]]
    } else {
        payload.chunks(data).collect()
    };
    let last = chunks.len() - 1;
    for (i, chunk) in chunks.into_iter().enumerate() {
        let len = (chunk.len() + HEADER) as u16;
        out.push(ptype);
        out.push(if i == last { STATUS_EOM } else { 0 });
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&[0, 0]);
        out.push((i.wrapping_add(1) % 256) as u8);
        out.push(0);
        out.extend_from_slice(chunk);
    }
    out
}

/// Reassembles server packets: bytes read from the stream go in with
/// [`Reassembly::push`]; [`Reassembly::take`] moves the payloads of the
/// complete packets out, header checked before the body is buffered.
#[derive(Default)]
pub(crate) struct Reassembly {
    raw: Vec<u8>,
    /// The `EOM` packet of the current message was taken.
    pub(crate) eom: bool,
}

impl Reassembly {
    /// Bytes from the stream.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.raw.extend_from_slice(bytes);
    }

    /// Starts a new message (after the previous `EOM`).
    pub(crate) fn next_message(&mut self) {
        self.eom = false;
    }

    /// Moves the payload of every complete packet into `out`, up to the
    /// message's `EOM`, checking each header against `max_packet` and the
    /// accepted types. Bytes after the `EOM` stay buffered (none expected).
    pub(crate) fn take(
        &mut self,
        out: &mut Vec<u8>,
        max_packet: usize,
        accept: &[u8],
    ) -> Result<(), FrameError> {
        let mut pos = 0;
        while !self.eom {
            let Some(header) = self.raw.get(pos..pos + HEADER) else {
                break;
            };
            let (t, status) = (header[0], header[1]);
            let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
            if !accept.contains(&t) {
                return Err(FrameError::BadType);
            }
            if len < HEADER || len > max_packet.min(MAX_PACKET) {
                return Err(FrameError::BadLength);
            }
            let Some(body) = self.raw.get(pos + HEADER..pos + len) else {
                break;
            };
            out.extend_from_slice(body);
            pos += len;
            if status & STATUS_EOM != 0 {
                self.eom = true;
            }
        }
        if pos > 0 {
            zeroize::Zeroize::zeroize(&mut self.raw[..pos]);
            self.raw.drain(..pos);
        }
        Ok(())
    }

    /// Bytes buffered and not yet taken.
    pub(crate) fn pending(&self) -> usize {
        self.raw.len()
    }
}

impl Drop for Reassembly {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.raw);
    }
}

/// The `ENCRYPTION` values of `PRELOGIN`.
pub(crate) mod encrypt {
    #[cfg(test)]
    pub(crate) const OFF: u8 = 0x00;
    pub(crate) const ON: u8 = 0x01;
    #[cfg(test)]
    pub(crate) const NOT_SUP: u8 = 0x02;
    pub(crate) const REQ: u8 = 0x03;
}

/// The `PRELOGIN` request: `VERSION` (zeros), `ENCRYPTION` (`ENCRYPT_REQ`),
/// `INSTOPT` (empty), `THREADID` (zero), `MARS` (off). No
/// `FEDAUTHREQUIRED`, no nonce.
pub(crate) fn prelogin() -> Vec<u8> {
    // Option headers: 5 options × 5 bytes + terminator = 26.
    let options: [(u8, &[u8]); 5] = [
        (0x00, &[0, 0, 0, 0, 0, 0]),
        (0x01, &[encrypt::REQ]),
        (0x02, &[0]),
        (0x03, &[0, 0, 0, 0]),
        (0x04, &[0]),
    ];
    let mut head = Vec::new();
    let mut data = Vec::new();
    let base = options.len() * 5 + 1;
    for (token, value) in options {
        head.push(token);
        head.extend_from_slice(&((base + data.len()) as u16).to_be_bytes());
        head.extend_from_slice(&(value.len() as u16).to_be_bytes());
        data.extend_from_slice(value);
    }
    head.push(0xFF);
    head.extend_from_slice(&data);
    head
}

/// The `ENCRYPTION` value of a `PRELOGIN` response (the only field the
/// client reads: the response is untrusted before TDS 8.0, decision 2).
/// `None`: malformed or absent.
pub(crate) fn prelogin_encryption(payload: &[u8]) -> Option<u8> {
    let mut pos = 0;
    // At most 32 option headers.
    for _ in 0..32 {
        let token = *payload.get(pos)?;
        if token == 0xFF {
            return None;
        }
        let h = payload.get(pos + 1..pos + 5)?;
        let offset = usize::from(u16::from_be_bytes([h[0], h[1]]));
        let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
        let value = payload.get(offset..offset.checked_add(len)?)?;
        if token == 0x01 {
            return (len == 1).then(|| value[0]);
        }
        pos += 5;
    }
    None
}

/// UTF-16LE of `s`.
pub(crate) fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// The `LOGIN7` message of SQL authentication (decisions 1 and 2): no
/// `FEATUREEXT`, `fReadOnlyIntent` not set, `ClientID` zeros, `HostName`
/// empty, `AppName` [`APP_NAME`], the password obfuscated in place. The
/// buffer is zeroized on drop; the password is written nowhere else.
pub(crate) fn login7(user: &str, password: &str) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let n = |s: &str| s.encode_utf16().count();
    if n(user) == 0 || n(user) > 128 || n(password) > 128 {
        return Err(FrameError::Encode);
    }
    const FIXED: usize = 94;
    let mut buf = Zeroizing::new(vec![0u8; FIXED]);
    let put_u32 = |b: &mut [u8], at: usize, v: u32| b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    put_u32(&mut buf, 4, TDS_74);
    put_u32(&mut buf, 8, DEFAULT_PACKET as u32);
    // ClientProgVer, ClientPID, ConnectionID: zero.
    buf[24] = 0xE0; // fUseDB, fDatabase (fatal), fSetLang
    buf[25] = 0x03; // fLanguage (fatal), fODBC
    buf[26] = 0x00; // TypeFlags: fReadOnlyIntent never set
    buf[27] = 0x00; // OptionFlags3: no fExtension (no FEATUREEXT)
    put_u32(&mut buf, 32, 0x0409); // ClientLCID
    // Variable part: offsets from the start of the message.
    let mut fields: Vec<(usize, Vec<u8>, bool)> = Vec::new();
    let mut add = |at: usize, value: Vec<u8>, chars: bool| fields.push((at, value, chars));
    add(36, Vec::new(), true); // HostName: empty
    add(40, utf16(user), true);
    // Password: obfuscated below, in the message buffer only.
    add(44, Vec::new(), true);
    add(48, utf16(APP_NAME), true);
    add(52, Vec::new(), true); // ServerName
    add(56, Vec::new(), false); // Extension: none
    add(60, utf16("databastion"), true); // CltIntName
    add(64, Vec::new(), true); // Language
    add(68, Vec::new(), true); // Database: the login's default
    let mut offset = FIXED;
    for (at, value, chars) in &fields {
        let len = if *chars { value.len() / 2 } else { value.len() };
        if *at == 44 {
            continue;
        }
        buf[*at..*at + 2].copy_from_slice(&(offset as u16).to_le_bytes());
        buf[*at + 2..*at + 4].copy_from_slice(&(len as u16).to_le_bytes());
        buf.extend_from_slice(value);
        offset += value.len();
    }
    // Password, written straight into the buffer and obfuscated there.
    let pw_chars = n(password);
    buf[44..46].copy_from_slice(&(offset as u16).to_le_bytes());
    buf[46..48].copy_from_slice(&(pw_chars as u16).to_le_bytes());
    for unit in password.encode_utf16() {
        for b in unit.to_le_bytes() {
            buf.push(b.rotate_left(4) ^ 0xA5);
        }
    }
    offset += pw_chars * 2;
    // ClientID (72..78) zero; SSPI, AtchDBFile, ChangePassword empty.
    for at in [78usize, 82, 86] {
        buf[at..at + 2].copy_from_slice(&(offset as u16).to_le_bytes());
    }
    let total = buf.len() as u32;
    put_u32(&mut buf, 0, total);
    Ok(buf)
}

/// `ALL_HEADERS` with the transaction descriptor header (no transaction,
/// one outstanding request), required before batches and RPCs.
fn all_headers(out: &mut Vec<u8>) {
    out.extend_from_slice(&22u32.to_le_bytes());
    out.extend_from_slice(&18u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
}

/// A `SQLBatch` payload: one statement of the closed set.
pub(crate) fn sql_batch(sql: &str) -> Result<Vec<u8>, FrameError> {
    if sql.is_empty() || sql.encode_utf16().count() > MAX_SQL_CHARS {
        return Err(FrameError::Encode);
    }
    let mut out = Vec::with_capacity(22 + sql.len() * 2);
    all_headers(&mut out);
    out.extend_from_slice(&utf16(sql));
    Ok(out)
}

/// A typed `sp_executesql` parameter (the Audit polls of the third P9-A
/// lot; the encoder is tested here).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Param {
    /// `bigint`.
    BigInt(i64),
    /// `nvarchar(4000)`.
    NVarChar(String),
}

/// A collation for `NVARCHAR` parameters (`SQL_Latin1_General_CP1_CI_AS`;
/// UTF-16 does not depend on it).
const COLLATION: [u8; 5] = [0x09, 0x04, 0xD0, 0x00, 0x34];

fn nvarchar(out: &mut Vec<u8>, value: &str) -> Result<(), FrameError> {
    let bytes = utf16(value);
    if bytes.len() > 8000 {
        return Err(FrameError::Encode);
    }
    out.push(0xE7);
    out.extend_from_slice(&8000u16.to_le_bytes());
    out.extend_from_slice(&COLLATION);
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(&bytes);
    Ok(())
}

/// An `RPC` payload calling `sp_executesql` (procedure id 10) with a
/// constant `text` and typed parameters named `@p1`… (decision 6: the
/// Audit polls keep a constant text). No other procedure is ever called.
pub(crate) fn rpc_executesql(text: &str, params: &[Param]) -> Result<Vec<u8>, FrameError> {
    if params.len() > 8 {
        return Err(FrameError::Encode);
    }
    let mut out = Vec::new();
    all_headers(&mut out);
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&SP_EXECUTESQL.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    // @stmt (unnamed), then the declaration list.
    out.push(0);
    out.push(0);
    nvarchar(&mut out, text)?;
    if !params.is_empty() {
        let decl: Vec<String> = params
            .iter()
            .enumerate()
            .map(|(i, p)| match p {
                Param::BigInt(_) => format!("@p{} bigint", i + 1),
                Param::NVarChar(_) => format!("@p{} nvarchar(4000)", i + 1),
            })
            .collect();
        out.push(0);
        out.push(0);
        nvarchar(&mut out, &decl.join(","))?;
    }
    for (i, p) in params.iter().enumerate() {
        let name = utf16(&format!("@p{}", i + 1));
        out.push((name.len() / 2) as u8);
        out.extend_from_slice(&name);
        out.push(0);
        match p {
            Param::BigInt(v) => {
                out.extend_from_slice(&[0x26, 8, 8]);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Param::NVarChar(s) => nvarchar(&mut out, s)?,
        }
    }
    Ok(out)
}

/// The `ATTENTION` message: a header alone.
pub(crate) fn attention() -> Vec<u8> {
    frame(ptype::ATTENTION, &[], DEFAULT_PACKET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_and_reassembles() {
        let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let framed = frame(ptype::TABULAR_RESULT, &payload, 4096);
        let mut r = Reassembly::default();
        let mut out = Vec::new();
        for chunk in framed.chunks(7) {
            r.push(chunk);
            r.take(&mut out, 4096, &[ptype::TABULAR_RESULT]).unwrap();
        }
        assert!(r.eom);
        assert_eq!(out, payload);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn header_checked_before_the_body() {
        let mut r = Reassembly::default();
        // Length 40 000 > packet size: refused from the header alone.
        r.push(&[4, 1, 0x9C, 0x40, 0, 0, 1, 0]);
        let mut out = Vec::new();
        assert_eq!(
            r.take(&mut out, 4096, &[ptype::TABULAR_RESULT]),
            Err(FrameError::BadLength)
        );
        let mut r = Reassembly::default();
        r.push(&[4, 1, 0, 7, 0, 0, 1, 0]);
        assert_eq!(
            r.take(&mut out, 4096, &[ptype::TABULAR_RESULT]),
            Err(FrameError::BadLength)
        );
        let mut r = Reassembly::default();
        r.push(&[0x11, 1, 0, 8, 0, 0, 1, 0]);
        assert_eq!(
            r.take(&mut out, 4096, &[ptype::TABULAR_RESULT]),
            Err(FrameError::BadType)
        );
    }

    #[test]
    fn prelogin_round_trip() {
        let p = prelogin();
        assert_eq!(prelogin_encryption(&p), Some(encrypt::REQ));
        assert_eq!(prelogin_encryption(&[0xFF]), None);
        let off = [0x01, 0, 6, 0, 1, 0xFF, encrypt::OFF];
        assert_eq!(prelogin_encryption(&off), Some(encrypt::OFF));
        assert_ne!(encrypt::NOT_SUP, encrypt::ON);
        assert_eq!(prelogin_encryption(&[0x01, 0, 50, 0, 1]), None);
    }

    #[test]
    fn login7_obfuscates_the_password_and_sets_no_readonly_intent() {
        let pw = "Pa55-marker-éZ";
        let msg = login7("databastion", pw).unwrap();
        assert_eq!(
            u32::from_le_bytes(msg[0..4].try_into().unwrap()) as usize,
            msg.len()
        );
        assert_eq!(msg[26] & 0x20, 0, "fReadOnlyIntent");
        assert_eq!(msg[27] & 0x10, 0, "fExtension");
        assert_eq!(&msg[72..78], &[0; 6], "ClientID");
        assert_eq!(&msg[38..40], &[0, 0], "HostName empty");
        // The clear password appears nowhere, in UTF-16 or UTF-8.
        let clear = utf16(pw);
        assert!(!msg.windows(clear.len()).any(|w| w == clear.as_slice()));
        assert!(!msg.windows(pw.len()).any(|w| w == pw.as_bytes()));
        // De-obfuscated from its offset, it is the password.
        let off = usize::from(u16::from_le_bytes([msg[44], msg[45]]));
        let len = usize::from(u16::from_le_bytes([msg[46], msg[47]])) * 2;
        let back: Vec<u8> = msg[off..off + len]
            .iter()
            .map(|b| (b ^ 0xA5).rotate_right(4))
            .collect();
        assert_eq!(back, clear);
        assert!(login7("", pw).is_err());
    }

    #[test]
    fn rpc_calls_sp_executesql_by_id() {
        let p = rpc_executesql(
            "SELECT 1 WHERE @p1 = 1",
            &[Param::BigInt(1), Param::NVarChar("x".into())],
        )
        .unwrap();
        assert_eq!(&p[22..26], &[0xFF, 0xFF, 10, 0]);
        assert!(sql_batch("").is_err());
        assert_eq!(attention().len(), HEADER);
    }
}
