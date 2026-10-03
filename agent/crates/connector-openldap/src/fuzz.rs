//! Entry points of the fuzz targets (`agent/fuzz`, cargo-fuzz). Built only
//! with the `fuzzing` feature, never by the agent binary.
//!
//! Each function feeds arbitrary bytes to a parser that a hostile server
//! controls: the BER reader, the `LDAPMessage` parser, the logged search
//! filter reducer and the `cn=accesslog` entry reduction (with the DN and
//! time helpers it relies on). They must never panic nor hang; results are
//! dropped at once, nothing is logged.

use zeroize::Zeroizing;

use crate::audit::{filter, records};
use crate::ber::Reader;
use crate::proto::{self, Attribute, Entry, Response};
use crate::{dn, time};

/// Deepest nesting walked.
const MAX_DEPTH: usize = 64;

fn walk(mut r: Reader<'_>, depth: usize) {
    while !r.is_empty() {
        let Ok((tag, content)) = r.tlv() else {
            return;
        };
        // Constructed encodings: walk their content too.
        if tag & 0x20 != 0 && depth < MAX_DEPTH {
            walk(Reader::new(content), depth + 1);
        } else {
            let _ = crate::ber::decode_int(content);
        }
    }
}

/// BER: the message length of a head, then every TLV walked.
pub fn ber(data: &[u8]) {
    let _ = crate::ber::message_len(data);
    walk(Reader::new(data), 0);
}

/// One `LDAPMessage` as the server sends it; a search result entry is
/// reduced as an accesslog entry too.
pub fn message(data: &[u8]) {
    if let Ok(m) = proto::parse(data)
        && let Response::Entry(e) = &m.op
    {
        reduce(e);
    }
}

/// One logged search filter (`reqFilter`, RFC 4515 text).
pub fn search_filter(data: &[u8]) {
    let _ = filter::facts(data);
}

/// Accesslog attributes, in the order the input's NUL-separated fields
/// fill them (a structured input: the fuzzer does not have to produce BER
/// to reach the record reduction).
const ACCESSLOG_ATTRIBUTES: [&str; 14] = [
    "reqType",
    "entryCSN",
    "reqDN",
    "reqFilter",
    "reqStart",
    "reqAuthzID",
    "reqResult",
    "reqScope",
    "reqAttr",
    "reqEntries",
    "reqSession",
    "reqMethod",
    "reqSizeLimit",
    "reqAttrsOnly",
];

/// One `cn=accesslog` entry built from NUL-separated attribute values
/// (see [`ACCESSLOG_ATTRIBUTES`]; a field may hold several values
/// separated by `0x01`).
pub fn accesslog(data: &[u8]) {
    let attributes = data
        .split(|b| *b == 0)
        .zip(ACCESSLOG_ATTRIBUTES)
        .map(|(field, name)| Attribute {
            name: name.to_owned(),
            values: field
                .split(|b| *b == 1)
                .map(|v| Zeroizing::new(v.to_vec()))
                .collect(),
        })
        .collect();
    let entry = Entry {
        dn: Zeroizing::new("reqStart=20260929202642.000003Z,cn=accesslog".to_owned()),
        attributes,
        skipped: 0,
    };
    reduce(&entry);
}

fn reduce(e: &Entry) {
    drop(records::parse(e));
    for v in e.values("reqFilter") {
        let _ = filter::facts(v);
    }
    for name in ["reqDN", "reqAuthzID"] {
        if let Some(s) = e.first_str(name) {
            drop(dn::canon(s).map(Zeroizing::new));
            let _ = dn::parent(s);
            let _ = dn::is_within(s, "dc=example,dc=org");
        }
    }
    for name in ["reqStart", "entryCSN"] {
        if let Some(s) = e.first_str(name) {
            let _ = time::parse_generalized(s);
            let _ = time::csn_time(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds() -> Vec<Vec<u8>> {
        let entry = proto::encode::entry(
            3,
            "reqStart=20260929202642.000003Z,cn=accesslog",
            &[
                ("reqType", &[b"search".as_slice()]),
                (
                    "entryCSN",
                    &[b"20260929202642.012954Z#000000#000#000000".as_slice()],
                ),
                ("reqDN", &[b"ou=people,dc=example,dc=org".as_slice()]),
                ("reqFilter", &[b"(&(objectClass=*)(mail=a*))".as_slice()]),
            ],
        );
        let structured = [
            "search",
            "20260929202642.012954Z#000000#000#000000",
            "ou=people,dc=example,dc=org",
            "(|(uid=j*)(cn=Jane\\2a))",
            "20260929202642.000003Z",
            "dn:cn=databastion,ou=services,dc=example,dc=org",
            "0",
            "sub",
            "mail\u{1}cn",
            "12",
        ]
        .join("\u{0}")
        .into_bytes();
        vec![
            entry,
            structured,
            Vec::new(),
            vec![0x30; 40],
            vec![0xff; 16],
        ]
    }

    /// Every entry point on the seeds and their truncations and byte
    /// flips: no panic (the fuzz targets go further).
    #[test]
    fn entry_points_do_not_panic_on_seeds_and_mutations() {
        let all: [fn(&[u8]); 4] = [ber, message, search_filter, accesslog];
        for seed in seeds() {
            for cut in 0..=seed.len() {
                let mut input = seed[..cut].to_vec();
                for f in all {
                    f(&input);
                }
                if let Some(b) = input.last_mut() {
                    *b ^= 0x5a;
                    for f in all {
                        f(&input);
                    }
                }
            }
        }
    }
}
