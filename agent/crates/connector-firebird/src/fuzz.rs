//! Fuzz target entry points (`agent/fuzz`, cargo-fuzz; ADR-0060 decision
//! 1). Never enabled by the agent binary (`fuzzing` feature). Each must
//! never panic nor hang on any input.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::sql::{self, Column};
use crate::wire::{self, Keys, Phase};
use crate::xdr::{Reader, XdrError};

/// The server messages of the closed set (`op_accept*`, `op_response`
/// with its status vector, `op_cont_auth`, `op_fetch_response`), in the
/// phase the first byte selects, fed in slices of the second byte's size
/// as they would arrive: every complete message makes progress, and a
/// bound or an operation outside the set ends the stream.
pub fn messages(data: &[u8]) {
    let [phase, step, rest @ ..] = data else {
        return;
    };
    let phase = match phase % 3 {
        0 => Phase::Connect,
        1 => Phase::Auth,
        _ => Phase::Session,
    };
    let step = usize::from(*step % 61) + 1;
    let mut buf: Vec<u8> = Vec::new();
    let mut fed = 0;
    let mut guard = 0usize;
    loop {
        guard += 1;
        assert!(guard < 4 * rest.len() + 100, "no progress");
        let mut r = Reader::new(&buf);
        match wire::parse(&mut r, phase) {
            Ok(_) => {
                let n = r.pos();
                assert!(n > 0 && n <= buf.len());
                buf.drain(..n);
            }
            Err(XdrError::Bound) => return,
            Err(XdrError::Incomplete) => {
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

/// The describe answer of `op_prepare_statement` (an info buffer), then
/// rows of the described columns: the first two bytes give the length of
/// the info buffer. Rows are decoded only for columns of the closed type
/// set, as the session does.
pub fn describe_and_rows(data: &[u8]) {
    let [a, b, rest @ ..] = data else {
        return;
    };
    let split = usize::from(u16::from_le_bytes([*a, *b])).min(rest.len());
    let (info, rows) = rest.split_at(split);
    let Ok(d) = sql::parse_describe(info) else {
        return;
    };
    let shape_ok = d.columns.iter().all(|c| {
        matches!(
            c.sqltype,
            sql::sqltype::SHORT
                | sql::sqltype::LONG
                | sql::sqltype::INT64
                | sql::sqltype::BOOLEAN
                | sql::sqltype::VARYING
        ) && c.length <= sql::MAX_COLUMN_BYTES
    });
    if !shape_ok {
        return;
    }
    let _ = sql::output_blr(&d.columns);
    rows_of(&d.columns, rows);
}

fn rows_of(columns: &[Column], rows: &[u8]) {
    let mut r = Reader::new(rows);
    for _ in 0..1024 {
        let before = r.pos();
        match sql::parse_row(&mut r, columns) {
            Ok(row) => {
                assert_eq!(row.len(), columns.len());
                if r.pos() == before {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// The described column of a closed shape.
fn described(shape: sql::Col) -> Column {
    match shape {
        sql::Col::Int => Column {
            sqltype: sql::sqltype::LONG,
            sub_type: 0,
            scale: 0,
            length: 4,
        },
        sql::Col::Bool => Column {
            sqltype: sql::sqltype::BOOLEAN,
            sub_type: 0,
            scale: 0,
            length: 1,
        },
        sql::Col::Text(n) => Column {
            sqltype: sql::sqltype::VARYING,
            sub_type: sql::charset::UTF8,
            scale: 0,
            length: n,
        },
        sql::Col::Octets(n) => Column {
            sqltype: sql::sqltype::VARYING,
            sub_type: sql::charset::OCTETS,
            scale: 0,
            length: n,
        },
    }
}

/// Discovery's reads (ADR-0060 decision 5): rows of the relation list,
/// the column list or a sampling statement (the first byte selects which;
/// the rest is the rows as the server sends them), through what Discovery
/// does with them: the catalog parsed, each column's conversion, the
/// column batches and the built statements, each sampled value kept or
/// dropped. Never a panic.
pub fn catalog(data: &[u8]) {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let convs = [
        sql::Conv::Text,
        sql::Conv::Octets,
        sql::Conv::Number,
        sql::Conv::Float,
        sql::Conv::Date,
    ];
    let shape: Vec<sql::Col> = match which % 3 {
        0 => crate::catalog::RELATIONS_SHAPE.to_vec(),
        1 => crate::catalog::COLUMNS_SHAPE.to_vec(),
        _ => convs.iter().map(|c| c.shape()).collect(),
    };
    let columns: Vec<Column> = shape.iter().map(|s| described(*s)).collect();
    let mut r = Reader::new(rest);
    let mut rows = Vec::new();
    for _ in 0..256 {
        let before = r.pos();
        match sql::parse_row(&mut r, &columns) {
            Ok(row) if r.pos() > before => rows.push(row),
            _ => break,
        }
    }
    match which % 3 {
        0 => {
            if let Some(rels) = crate::catalog::relations(&rows) {
                for rel in &rels {
                    assert!(sql::identifier_ok(&rel.name));
                    let _ = crate::catalog::never_sampled(&rel.name);
                }
            }
        }
        1 => {
            if let Some(cols) = crate::catalog::columns(&rows) {
                let picked: Vec<(&str, sql::Conv)> = cols
                    .iter()
                    .filter_map(|c| c.conv().map(|v| (c.name.as_str(), v)))
                    .collect();
                for batch in crate::catalog::batches(&picked) {
                    if let Some(table) = cols.first() {
                        let built = sql::sample_statement(&table.relation, &batch, 200);
                        assert!(built.is_some_and(|b| !sql::has_denied_word(b.text())));
                    }
                }
            }
        }
        _ => {
            for row in rows {
                for (v, conv) in row.into_iter().zip(convs) {
                    let _ = crate::catalog::value_text(v, conv, which & 0x80 != 0);
                }
            }
        }
    }
}

/// The server's SRP data (`p_acpt_data`): parsed with its checks, and,
/// when accepted, the client proof computed with a fixed private value.
pub fn srp_data(data: &[u8]) {
    let Ok(server) = crate::srp::ServerData::parse(data) else {
        return;
    };
    let client =
        crate::srp::Client::with_private(zeroize::Zeroizing::new(crate::srp::server::private(1)));
    if let Ok(proof) = client.proof("AGENT", b"fuzz", &server) {
        assert_eq!(proof.hex.len(), 64);
        assert_eq!(proof.key.len(), 20);
    }
}

/// The wire-crypt key clumplets, in pieces split at the first byte's
/// positions, then the plugin choice and the cipher it builds (never
/// Arc4).
pub fn keys(data: &[u8]) {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let mut keys = Keys::default();
    let cut = usize::from(first).min(rest.len());
    let (one, two) = rest.split_at(cut);
    if keys.add(one).is_err() || keys.add(two).is_err() {
        return;
    }
    if let Some((plugin, specific)) = keys.choose() {
        assert!(matches!(plugin.name(), "ChaCha64" | "ChaCha"));
        if let Some(mut c) = crate::crypt::Cipher::new(plugin, &[7u8; 20], specific) {
            let mut buf = [0u8; 64];
            let _ = c.apply(&mut buf);
        }
    }
}

/// `/proc/net/tcp{,6}` contents: the first 12 bytes give the server and
/// client endpoints (IPv4 address and port each), the rest is the table.
/// The lookup returns the right row or none, never a panic.
pub fn proc_net_tcp(data: &[u8]) {
    if data.len() < 12 {
        return;
    }
    let addr = |b: &[u8]| {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
            u16::from_be_bytes([b[4], b[5]]),
        )
    };
    let server = addr(&data[..6]);
    let client = addr(&data[6..12]);
    let text = String::from_utf8_lossy(&data[12..]);
    let mut out = crate::peer::Lookup::default();
    crate::peer::scan(
        text.lines().map(str::to_owned),
        server,
        client,
        None,
        &mut out,
    );
    let _ = out.verdict(84);
    assert!(out.matches == 0 || out.matches as usize <= text.lines().count());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entry points accept the empty input and short inputs, and the
    /// captured describe answer of the 5.0.4 server with a row.
    #[test]
    fn entry_points_run() {
        for f in [
            messages,
            describe_and_rows,
            srp_data,
            keys,
            proc_net_tcp,
            catalog,
        ] {
            f(&[]);
            f(&[0]);
            f(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
            f(&[0xFF; 400]);
        }
        let mut w = crate::xdr::Writer::new();
        w.u32(9)
            .u32(0)
            .u32(0)
            .u32(0)
            .opaque(b"")
            .u32(1)
            .u32(0)
            .u32(0);
        let mut input = vec![2, 5];
        input.extend_from_slice(w.as_slice());
        messages(&input);
    }
}
