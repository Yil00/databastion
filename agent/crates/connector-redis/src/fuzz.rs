//! Fuzz entry points (`agent/fuzz`, cargo-fuzz): the reply decoder fed in
//! arbitrary chunks under every request's limits, the `INFO` parser and
//! the key-name normalizer, the Audit log-entry parsers and the learned-
//! pattern matcher. Never panic, never allocate past the limits.

use crate::cmd::{Cmd, InfoSection};
use crate::resp::Decoder;

/// The reply decoder: `data[0]` picks a request's limits and a chunk size,
/// the rest is the server's bytes, fed chunk by chunk (several replies).
pub fn resp_decoder(data: &[u8]) {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    static KEY: [u8; 1] = *b"k";
    static FIELDS: [&[u8]; 3] = [b"a", b"b", b"c"];
    let cmds = [
        Cmd::Hello,
        Cmd::Info(InfoSection::Server),
        Cmd::Scan { cursor: 0 },
        Cmd::Type(&KEY),
        Cmd::GetRange(&KEY),
        Cmd::HRandField(&KEY),
        Cmd::HMGet(&KEY, &FIELDS),
        Cmd::SRandMember(&KEY),
        Cmd::XRevRange(&KEY),
        Cmd::ClientNoTouchOn,
    ];
    let cmd = cmds.get(usize::from(sel % 10)).unwrap_or(&Cmd::Hello);
    let chunk = usize::from(sel / 10).max(1);
    let mut d = Decoder::new(cmd.limits());
    let mut pos = 0;
    while pos < rest.len() {
        let end = (pos + chunk).min(rest.len());
        let Some(piece) = rest.get(pos..end) else {
            return;
        };
        let mut off = 0;
        while off < piece.len() {
            match d.feed(piece.get(off..).unwrap_or_default()) {
                Ok((used, Some(v))) => {
                    let _ = crate::conn::parse_hello(&v);
                    let _ = crate::acl::verdict(&v);
                    off += used;
                }
                Ok((used, None)) => off += used.max(piece.len() - off),
                Err(_) => return,
            }
        }
        pos = end;
    }
}

/// The `INFO` section parsers.
pub fn info(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = crate::info::server(text);
    let _ = crate::info::keyspace(text);
    let _ = crate::info::is_sentinel(text);
    let _ = crate::info::is_replica(text);
}

/// The key-name normalizer, the glob matcher and the CAS guard: the
/// emitted pattern always passes the contract gate.
pub fn key_pattern(data: &[u8]) {
    let p = databastion_classifiers::keys::fuzz_normalize(data);
    assert!(databastion_classifiers::keys::is_key_pattern(&p), "{p:?}");
    let (pat, name) = data.split_at(data.len() / 2);
    let _ = crate::glob::matches(pat, name);
    let _ = crate::glob::example(pat);
    let _ = crate::guard::key_guarded(data, None);
}

fn decode_reply(cmd: &Cmd<'_>, data: &[u8]) -> Option<crate::resp::Value> {
    let mut d = Decoder::new(cmd.limits());
    match d.feed(data) {
        Ok((_, v)) => v,
        Err(_) => None,
    }
}

fn learned() -> databastion_classifiers::keys::LearnedPatterns {
    databastion_classifiers::keys::LearnedPatterns::new([
        "user:*:email",
        "session:*",
        "cache:page:about",
        "order_*_*",
        "*:*",
    ])
}

/// Every object is `*` or a contract `KeyPattern` made of the learned
/// set's literals only (the H1 oracle, review L8).
fn assert_objects(objects: &[databastion_classifiers::names::NormalizedName]) {
    use databastion_classifiers::keys::pattern_tokens;
    let set = learned();
    let learned_tokens: std::collections::HashSet<&str> = set
        .patterns()
        .iter()
        .flat_map(|p| pattern_tokens(p))
        .collect();
    for o in objects {
        let o = o.as_str();
        assert!(
            o == "*" || databastion_classifiers::keys::is_key_pattern(o),
            "{o:?}"
        );
        for t in pattern_tokens(o) {
            assert!(
                t == "*" || learned_tokens.contains(t),
                "{t:?} not learned in {o:?}"
            );
        }
    }
}

/// A `SLOWLOG GET` / `COMMANDLOG GET` reply, decoded under its limits, each
/// entry reduced (ADR-0052 decision 8): every object is `*` or a contract
/// `KeyPattern`.
pub fn slowlog_entry(data: &[u8]) {
    let Some(v) = decode_reply(&Cmd::SlowlogGet, data) else {
        return;
    };
    let set = learned();
    let ctx = crate::audit::entries::Context {
        learned: &set,
        stores: None,
        dbs: &[],
    };
    let items = match &v {
        crate::resp::Value::Array(items) => items.as_slice(),
        other => std::slice::from_ref(other),
    };
    for item in items {
        if let Ok(e) = crate::audit::entries::parse_log_entry(item, &ctx) {
            assert_objects(&e.objects);
        }
    }
}

/// An `ACL LOG` reply (each entry, with its `client-info`), then the input
/// as a `CLIENT LIST` line.
pub fn acl_log_entry(data: &[u8]) {
    let _ = crate::audit::entries::parse_client(data);
    let Some(v) = decode_reply(&Cmd::AclLog, data) else {
        return;
    };
    let set = learned();
    let get = |_: Option<u16>| &set;
    let key = std::collections::hash_map::RandomState::new();
    let items = match &v {
        crate::resp::Value::Array(items) => items.as_slice(),
        other => std::slice::from_ref(other),
    };
    for item in items {
        if let Ok(e) = crate::audit::entries::parse_acl_entry(item, &get, None, &key) {
            assert_objects(std::slice::from_ref(&e.object));
        }
    }
    let _ = crate::audit::entries::parse_client_list(&v);
}

/// The learned-pattern matcher (`classifiers::keys::LearnedPatterns`): the
/// object always passes the contract gate.
pub fn learned_patterns(data: &[u8]) {
    let o = databastion_classifiers::keys::fuzz_learned(data);
    assert!(
        o == "*" || databastion_classifiers::keys::is_key_pattern(&o),
        "{o:?}"
    );
}
