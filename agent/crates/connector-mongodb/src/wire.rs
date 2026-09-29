//! `OP_MSG` framing (ADR-0026 decision 1).
//!
//! Requests: one `OP_MSG` with a single body section, no flag (no
//! checksum, no `moreToCome`, no exhaust), no compression. Replies must be
//! `OP_MSG` answers to the request just sent; their length is checked on
//! the header before the body is read ([`MAX_REPLY`]), a `moreToCome`
//! reply or any unknown required flag bit is refused, a checksum is
//! skipped, and exactly one body section must fill the message. The reply
//! buffer is zeroized on drop: it holds sampled documents.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use crate::bson::{Doc, Malformed};

/// `OP_MSG` opcode.
pub(crate) const OP_MSG: i32 = 2013;
/// Largest reply accepted: the server's largest reply document (16 MiB)
/// plus room for framing and command fields.
pub(crate) const MAX_REPLY: usize = 16 * 1024 * 1024 + 64 * 1024;
/// Header: length, request id, response to, opcode.
const HEADER: usize = 16;
/// `OP_MSG` flag: a CRC-32C follows the sections.
const CHECKSUM_PRESENT: u32 = 1;
/// `OP_MSG` flag: another message follows without a request (exhaust).
const MORE_TO_COME: u32 = 1 << 1;
/// Bits 0 to 15 are required: an unknown one must be refused.
const REQUIRED_BITS: u32 = 0xFFFF;

/// A framing failure. No content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireError {
    /// I/O error or closed connection.
    Io(io::ErrorKind),
    /// A reply longer than [`MAX_REPLY`] (not read).
    TooLarge,
    /// Anything else that does not follow the protocol.
    Malformed,
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

impl From<Malformed> for WireError {
    fn from(_: Malformed) -> Self {
        Self::Malformed
    }
}

/// The body document of a reply, in a buffer zeroized on drop.
pub(crate) struct Reply {
    buf: Zeroizing<Vec<u8>>,
    start: usize,
    end: usize,
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("len", &(self.end - self.start))
            .finish()
    }
}

impl Reply {
    /// A copy of the body document (tests).
    #[cfg(test)]
    pub(crate) fn doc_bytes(&self) -> Vec<u8> {
        self.buf[self.start..self.end].to_vec()
    }

    /// The body document (checked when the reply was read).
    pub(crate) fn doc(&self) -> Doc<'_> {
        // Checked by `parse`; an empty document if it ever were not.
        Doc::new(&self.buf[self.start..self.end]).unwrap_or(Doc::EMPTY)
    }
}

/// Encodes one request.
pub(crate) fn encode(request_id: i32, body: &[u8]) -> Result<Vec<u8>, WireError> {
    let len = HEADER + 4 + 1 + body.len();
    let len32 = i32::try_from(len).map_err(|_| WireError::TooLarge)?;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&len32.to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&OP_MSG.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.push(0);
    out.extend_from_slice(body);
    Ok(out)
}

/// Checks a reply header: its total length (header included).
pub(crate) fn check_header(header: &[u8; HEADER], request_id: i32) -> Result<usize, WireError> {
    let field =
        |i: usize| i32::from_le_bytes([header[i], header[i + 1], header[i + 2], header[i + 3]]);
    let len = usize::try_from(field(0)).map_err(|_| WireError::Malformed)?;
    if len > MAX_REPLY {
        return Err(WireError::TooLarge);
    }
    // Header, flags, one section kind byte, the smallest document.
    if len < HEADER + 4 + 1 + 5 {
        return Err(WireError::Malformed);
    }
    if field(8) != request_id || field(12) != OP_MSG {
        return Err(WireError::Malformed);
    }
    Ok(len)
}

/// Parses a reply payload (after the header): the range of its body
/// document.
pub(crate) fn parse(payload: &[u8]) -> Result<(usize, usize), WireError> {
    let flags = u32::from_le_bytes(
        payload
            .get(..4)
            .ok_or(WireError::Malformed)?
            .try_into()
            .map_err(|_| WireError::Malformed)?,
    );
    if flags & MORE_TO_COME != 0 || flags & REQUIRED_BITS & !CHECKSUM_PRESENT != 0 {
        return Err(WireError::Malformed);
    }
    let end = if flags & CHECKSUM_PRESENT != 0 {
        payload.len().checked_sub(4).ok_or(WireError::Malformed)?
    } else {
        payload.len()
    };
    let sections = payload.get(4..end).ok_or(WireError::Malformed)?;
    // Exactly one body section (kind 0), filling the message.
    match sections.first() {
        Some(0) => {}
        _ => return Err(WireError::Malformed),
    }
    let (_, n) = Doc::prefix(&sections[1..])?;
    if 1 + n != sections.len() {
        return Err(WireError::Malformed);
    }
    Ok((4 + 1, 4 + 1 + n))
}

/// A connection speaking `OP_MSG`.
pub(crate) struct Wire<S> {
    stream: S,
    next_id: i32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Wire<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self { stream, next_id: 1 }
    }

    /// Sends `body` and reads its reply.
    pub(crate) async fn round_trip(&mut self, body: &[u8]) -> Result<Reply, WireError> {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let request = Zeroizing::new(encode(id, body)?);
        self.stream.write_all(&request).await?;
        self.stream.flush().await?;
        let mut header = [0u8; HEADER];
        self.stream.read_exact(&mut header).await?;
        let len = check_header(&header, id)?;
        let mut buf = Zeroizing::new(vec![0u8; len - HEADER]);
        self.stream.read_exact(&mut buf).await?;
        let (start, end) = parse(&buf)?;
        Ok(Reply { buf, start, end })
    }

    /// Closes the stream (best effort).
    pub(crate) async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bson::DocBuf;

    /// A reply to `request_id` with `flags` and `body`.
    pub(crate) fn reply(request_id: i32, flags: u32, body: &[u8], checksum: bool) -> Vec<u8> {
        let mut payload = flags.to_le_bytes().to_vec();
        payload.push(0);
        payload.extend_from_slice(body);
        if checksum {
            payload.extend_from_slice(&[0xAA; 4]);
        }
        let mut out = Vec::new();
        let len = i32::try_from(HEADER + payload.len()).unwrap();
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&99i32.to_le_bytes());
        out.extend_from_slice(&request_id.to_le_bytes());
        out.extend_from_slice(&OP_MSG.to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    #[tokio::test]
    async fn a_request_and_its_reply() {
        let (a, mut b) = tokio::io::duplex(1 << 16);
        let body = DocBuf::new().i32("ping", 1).finish();
        let server = tokio::spawn(async move {
            let mut header = [0u8; HEADER];
            b.read_exact(&mut header).await.unwrap();
            let len = i32::from_le_bytes(header[..4].try_into().unwrap());
            let id = i32::from_le_bytes(header[4..8].try_into().unwrap());
            let mut rest = vec![0u8; usize::try_from(len).unwrap() - HEADER];
            b.read_exact(&mut rest).await.unwrap();
            // No flag, one body section.
            assert_eq!(&rest[..5], &[0, 0, 0, 0, 0]);
            let ok = DocBuf::new().i32("ok", 1).finish();
            b.write_all(&reply(id, CHECKSUM_PRESENT, &ok, true))
                .await
                .unwrap();
            rest
        });
        let mut wire = Wire::new(a);
        let r = wire.round_trip(&body).await.unwrap();
        assert_eq!(r.doc().flag("ok").unwrap(), Some(true));
        let sent = server.await.unwrap();
        assert_eq!(&sent[5..], &body[..]);
    }

    #[test]
    fn headers_are_checked_before_reading() {
        let h = |len: i32, to: i32, op: i32| {
            let mut out = [0u8; HEADER];
            out[..4].copy_from_slice(&len.to_le_bytes());
            out[8..12].copy_from_slice(&to.to_le_bytes());
            out[12..].copy_from_slice(&op.to_le_bytes());
            out
        };
        assert_eq!(check_header(&h(100, 3, OP_MSG), 3), Ok(100));
        let too_large = i32::try_from(MAX_REPLY + 1).unwrap();
        assert_eq!(
            check_header(&h(too_large, 3, OP_MSG), 3),
            Err(WireError::TooLarge)
        );
        assert_eq!(
            check_header(&h(-1, 3, OP_MSG), 3),
            Err(WireError::Malformed)
        );
        assert_eq!(
            check_header(&h(20, 3, OP_MSG), 3),
            Err(WireError::Malformed)
        );
        // Another request's answer, or a legacy OP_REPLY / OP_COMPRESSED.
        assert_eq!(
            check_header(&h(100, 4, OP_MSG), 3),
            Err(WireError::Malformed)
        );
        assert_eq!(check_header(&h(100, 3, 1), 3), Err(WireError::Malformed));
        assert_eq!(check_header(&h(100, 3, 2012), 3), Err(WireError::Malformed));
    }

    #[test]
    fn payloads_need_one_body_section_and_known_flags() {
        let body = DocBuf::new().i32("ok", 1).finish();
        let payload = |flags: u32, extra: &[u8]| {
            let mut p = flags.to_le_bytes().to_vec();
            p.push(0);
            p.extend_from_slice(&body);
            p.extend_from_slice(extra);
            p
        };
        assert!(parse(&payload(0, &[])).is_ok());
        assert!(parse(&payload(CHECKSUM_PRESENT, &[1, 2, 3, 4])).is_ok());
        // Optional bits (16..31) are ignored.
        assert!(parse(&payload(1 << 16, &[])).is_ok());
        assert_eq!(
            parse(&payload(MORE_TO_COME, &[])),
            Err(WireError::Malformed)
        );
        assert_eq!(parse(&payload(1 << 5, &[])), Err(WireError::Malformed));
        // Trailing bytes, a second section, a document sequence.
        assert_eq!(parse(&payload(0, &[0])), Err(WireError::Malformed));
        assert_eq!(
            parse(&payload(0, &[0, 5, 0, 0, 0, 0])),
            Err(WireError::Malformed)
        );
        let mut seq = 0u32.to_le_bytes().to_vec();
        seq.push(1);
        seq.extend_from_slice(&body);
        assert_eq!(parse(&seq), Err(WireError::Malformed));
        assert_eq!(parse(&[0, 0]), Err(WireError::Malformed));
    }

    #[tokio::test]
    async fn an_answer_to_another_request_is_refused() {
        let (a, mut b) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let _ = b.read(&mut buf).await;
            let ok = DocBuf::new().i32("ok", 1).finish();
            let _ = b.write_all(&reply(12345, 0, &ok, false)).await;
        });
        let mut wire = Wire::new(a);
        let body = DocBuf::new().i32("ping", 1).finish();
        assert_eq!(
            wire.round_trip(&body).await.unwrap_err(),
            WireError::Malformed
        );
    }
}
