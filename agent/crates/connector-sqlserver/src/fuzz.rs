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
