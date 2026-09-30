//! Entry points of the fuzz targets (`agent/fuzz`, cargo-fuzz). Built only
//! with the `fuzzing` feature, never by the agent binary.
//!
//! Each function feeds arbitrary bytes to a parser that a hostile server or
//! a hostile log writer controls: the BSON reader, the `OP_MSG` reply
//! framing, the `auditLog` and server log JSON records and the profiler
//! entries. They must never panic nor hang; results are dropped at once
//! (text values in zeroized buffers), nothing is logged.

use zeroize::Zeroizing;

use crate::audit::{profiler, records};
use crate::bson::{Doc, Value};
use crate::{paths, wire};

/// Deepest nesting walked (the reader itself bounds nothing on depth).
const MAX_DEPTH: usize = 64;

fn walk(doc: Doc<'_>, depth: usize) {
    for element in doc.iter() {
        let Ok((_, value)) = element else {
            return;
        };
        match value {
            Value::Doc(d) | Value::Array(d) if depth < MAX_DEPTH => walk(d, depth + 1),
            other => {
                drop(paths::leaf_text(other).map(Zeroizing::new));
            }
        }
    }
}

/// A BSON document (as the server sends in replies), every element walked.
pub fn bson(data: &[u8]) {
    if let Ok(doc) = Doc::new(data) {
        walk(doc, 0);
        let _ = doc.str("errmsg");
        let _ = doc.int("ok");
        let _ = doc.doc("cursor");
        let _ = doc.array("firstBatch");
        let _ = doc.flag("done");
    }
    if let Ok((doc, _)) = Doc::prefix(data) {
        walk(doc, 0);
    }
}

/// An `OP_MSG` reply: its 16-byte header (the `responseTo` field taken
/// from the input, so the header check goes on), then its payload and body.
pub fn op_msg(data: &[u8]) {
    let Some((head, payload)) = data.split_first_chunk::<16>() else {
        return;
    };
    let response_to = i32::from_le_bytes([head[8], head[9], head[10], head[11]]);
    // The payload is parsed whatever the header check says.
    let _ = wire::check_header(head, response_to);
    if let Ok((from, to)) = wire::parse(payload) {
        if let Some(body) = payload.get(from..to) {
            bson(body);
        }
    }
}

/// One `auditLog` JSON line (Enterprise / Percona Server for MongoDB).
pub fn audit_log(data: &[u8]) {
    drop(records::parse_audit_log(data));
}

/// One structured JSON server log line.
pub fn server_log(data: &[u8]) {
    drop(records::parse_server_log(data));
}

/// One profiler entry (a BSON document, as projected by the connector).
pub fn profiler(data: &[u8]) {
    if let Ok(doc) = Doc::new(data) {
        drop(profiler::record_of(&doc));
    }
    // The persisted profiler positions, read back from the state file.
    drop(profiler::decode_cursors(data, 1_790_000_000_000));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bson::DocBuf;

    fn seeds() -> Vec<Vec<u8>> {
        let doc = DocBuf::new()
            .str("op", "query")
            .str("ns", "app.customers")
            .date("ts", 1_790_000_000_000)
            .doc("command", DocBuf::new().str("find", "customers"))
            .i64("nreturned", 3)
            .finish();
        let reply = wire::encode(7, &doc).unwrap();
        vec![
            doc,
            reply,
            br#"{"t":{"$date":"2026-09-29T10:00:00.123+00:00"},"s":"I","c":"COMMAND","id":51803,"ctx":"conn12","msg":"Slow query","attr":{"type":"command","ns":"app.customers","command":{"find":"customers","filter":{},"$db":"app"},"nreturned":120,"remote":"172.18.0.1:53422"}}"#.to_vec(),
            br#"{"atype":"dropCollection","ts":{"$date":"2026-09-29T10:00:00.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[{"user":"alice","db":"admin"}],"param":{"ns":"app.customers"},"result":0}"#.to_vec(),
            Vec::new(),
            vec![0xff; 64],
        ]
    }

    /// Every entry point on the seeds and their truncations and byte
    /// flips: no panic (the fuzz targets go further).
    #[test]
    fn entry_points_do_not_panic_on_seeds_and_mutations() {
        for seed in seeds() {
            for cut in 0..=seed.len() {
                let mut input = seed[..cut].to_vec();
                for f in [bson, op_msg, audit_log, server_log, profiler] {
                    f(&input);
                }
                if let Some(b) = input.last_mut() {
                    *b ^= 0x5a;
                    for f in [bson, op_msg, audit_log, server_log, profiler] {
                        f(&input);
                    }
                }
            }
        }
    }
}
