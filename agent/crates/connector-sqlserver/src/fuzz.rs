//! Fuzz target entry points (`agent/fuzz`, cargo-fuzz). Never enabled by
//! the agent binary (`fuzzing` feature).

use crate::tds::{self, Reassembly, ptype};
use crate::token::{Decoder, Limits};

/// The token stream decoder (with `COLMETADATA`, rows, `ENVCHANGE`,
/// `RETURNVALUE`, PLP), fed in slices of the first byte's size: it must
/// never panic, and every step makes progress.
pub fn token_stream(data: &[u8]) {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let step = usize::from(first % 61) + 1;
    let limits = Limits {
        max_columns: 64,
        plp_cap: if first & 0x80 != 0 { 4096 } else { 0 },
    };
    let mut dec = Decoder::new(limits);
    dec.discard = first & 0x40 != 0;
    let mut buf: Vec<u8> = Vec::new();
    let mut fed = 0;
    let mut guard = 0usize;
    loop {
        guard += 1;
        assert!(guard < 10 * rest.len() + 100, "no progress");
        match dec.next(&buf) {
            Err(_) => return,
            Ok(Some((_, n))) => {
                assert!(n <= buf.len());
                buf.drain(..n);
            }
            Ok(None) => {
                if fed >= rest.len() {
                    return;
                }
                let end = (fed + step).min(rest.len());
                buf.extend_from_slice(rest.get(fed..end).unwrap_or_default());
                fed = end;
            }
        }
    }
}

/// Packet reassembly and the `PRELOGIN` response parser.
pub fn packets(data: &[u8]) {
    let _ = tds::prelogin_encryption(data);
    let mut r = Reassembly::default();
    let mut out = Vec::new();
    for chunk in data.chunks(13) {
        r.push(chunk);
        if r.take(&mut out, 4096, &[ptype::TABULAR_RESULT, ptype::PRELOGIN])
            .is_err()
        {
            return;
        }
        assert!(out.len() <= data.len());
        if r.eom {
            r.next_message();
            out.clear();
        }
    }
}

/// The TLS-in-`PRELOGIN` header check.
pub fn prelogin_tls_framing(data: &[u8]) {
    if let Some(h) = data.get(..tds::HEADER) {
        let mut header = [0u8; tds::HEADER];
        header.copy_from_slice(h);
        if let Ok(n) = crate::tls::handshake_header(&header) {
            assert!(n > 0 && n <= tds::MAX_PACKET);
        }
    }
}

/// The TDS 7.x TLS handshake adapter ([`crate::tls::PreloginWrap`]),
/// driven over an in-memory duplex stream by the input (re-review R5):
/// a capacity byte, then operations of two bytes (operation, length), the
/// writes followed by their data:
///
/// - 0: the client writes `length` bytes through the adapter;
/// - 1: the client flushes;
/// - 2: the server sends `length` raw bytes (well-formed `PRELOGIN`
///   packets or not);
/// - 3: the client reads at most `length + 1` bytes through the adapter;
/// - 4: the server reads at most `16 * length + 1` bytes;
/// - 5: the handshake ends (`pass_through`).
///
/// Polled once per operation with a no-op waker (no runtime): `Pending`
/// is a valid outcome. It must never panic nor hang, and while the framing
/// is on, what the client reads is a prefix of the payloads of the
/// server's valid packets, and what the server receives is `PRELOGIN`
/// packets whose payloads are a prefix of what the client wrote.
///
/// Returns what went through (review L4: a test can check that a
/// handshake actually happened); the fuzz target ignores it.
pub fn prelogin_wrap(data: &[u8]) -> PreloginWrapRun {
    let mut run = PreloginWrapRun::default();
    prelogin_wrap_into(data, &mut run);
    run
}

/// What a [`prelogin_wrap`] run moved through the adapter.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PreloginWrapRun {
    /// Bytes the client read through the adapter while it framed.
    pub read: Vec<u8>,
    /// Payloads of the `PRELOGIN` packets the server received while the
    /// adapter framed.
    pub sent: Vec<u8>,
    /// Bytes the server received after the handshake ended.
    pub raw: Vec<u8>,
}

fn prelogin_wrap_into(data: &[u8], run: &mut PreloginWrapRun) {
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    let Some((&first, mut ops)) = data.split_first() else {
        return;
    };
    let (client, mut server) = tokio::io::duplex(16 + usize::from(first) * 64);
    let mut wrap = crate::tls::PreloginWrap::new(client);
    let mut cx = Context::from_waker(Waker::noop());
    // What the server sent, what the client read through the adapter,
    // what the client wrote into it and what reached the server.
    let mut fed = Vec::new();
    let read = &mut run.read;
    let mut written = Vec::new();
    let mut on_wire = Vec::new();
    let mut framing = true;
    while let [op, len, rest @ ..] = ops {
        let len = usize::from(*len);
        ops = rest;
        match op % 6 {
            0 | 2 => {
                let (chunk, tail) = ops.split_at(len.min(ops.len()));
                ops = tail;
                let polled = if op % 6 == 0 {
                    Pin::new(&mut wrap).poll_write(&mut cx, chunk)
                } else {
                    Pin::new(&mut server).poll_write(&mut cx, chunk)
                };
                match polled {
                    Poll::Ready(Ok(n)) => {
                        assert!(n <= chunk.len());
                        let done = chunk.get(..n).unwrap_or_default();
                        if op % 6 == 2 {
                            fed.extend_from_slice(done);
                        } else if framing {
                            written.extend_from_slice(done);
                        }
                    }
                    Poll::Ready(Err(_)) => return,
                    Poll::Pending => {}
                }
            }
            1 => {
                if let Poll::Ready(Err(_)) = Pin::new(&mut wrap).poll_flush(&mut cx) {
                    return;
                }
            }
            3 | 4 => {
                let mut space = vec![0u8; if op % 6 == 3 { len + 1 } else { 16 * len + 1 }];
                let mut buf = ReadBuf::new(&mut space);
                let polled = if op % 6 == 3 {
                    Pin::new(&mut wrap).poll_read(&mut cx, &mut buf)
                } else {
                    Pin::new(&mut server).poll_read(&mut cx, &mut buf)
                };
                match polled {
                    // A refused packet header: the session is dropped.
                    Poll::Ready(Err(_)) => return,
                    Poll::Ready(Ok(())) if op % 6 == 3 => {
                        if framing {
                            read.extend_from_slice(buf.filled());
                        }
                    }
                    Poll::Ready(Ok(())) if framing => on_wire.extend_from_slice(buf.filled()),
                    Poll::Ready(Ok(())) => run.raw.extend_from_slice(buf.filled()),
                    Poll::Pending => {}
                }
            }
            _ => {
                wrap.pass_through();
                framing = false;
            }
        }
        if framing {
            assert!(
                unwrapped(&fed).starts_with(read),
                "read bytes that are not packet payloads"
            );
            let sent = sent_payloads(&on_wire);
            assert!(
                written.starts_with(&sent),
                "sent bytes that were not written"
            );
            run.sent = sent;
        }
    }
}

/// The payloads of the valid handshake packets at the start of `wire` (a
/// last packet may be partial), up to the first invalid header.
fn unwrapped(wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = wire;
    while let Some(h) = rest.get(..tds::HEADER) {
        let mut header = [0u8; tds::HEADER];
        header.copy_from_slice(h);
        let Ok(n) = crate::tls::handshake_header(&header) else {
            break;
        };
        let body = rest.get(tds::HEADER..).unwrap_or_default();
        out.extend_from_slice(body.get(..n.min(body.len())).unwrap_or_default());
        rest = body.get(n..).unwrap_or_default();
    }
    out
}

/// The payloads of the packets the adapter sent: every packet must be a
/// `PRELOGIN` packet of at most the default packet size, with a payload.
fn sent_payloads(wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = wire;
    while let Some(h) = rest.get(..tds::HEADER) {
        let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
        assert_eq!(h[0], ptype::PRELOGIN, "a handshake packet of another type");
        assert!(
            len > tds::HEADER && len <= tds::DEFAULT_PACKET,
            "a handshake packet of {len} bytes"
        );
        let body = rest.get(tds::HEADER..).unwrap_or_default();
        let n = len - tds::HEADER;
        out.extend_from_slice(body.get(..n.min(body.len())).unwrap_or_default());
        rest = body.get(n..).unwrap_or_default();
    }
    out
}

/// PLP reassembly: one `nvarchar(max)` column, the input as its PLP body.
pub fn plp(data: &[u8]) {
    let mut stream = vec![
        0x81, 1, 0, 0, 0, 0, 0, 1, 0, 0xE7, 0xFF, 0xFF, 9, 4, 0xD0, 0, 0x34, 0, 0xD1,
    ];
    stream.extend_from_slice(data);
    let mut with_cap = vec![0x80];
    with_cap.extend(stream);
    token_stream(&with_cap);
}
