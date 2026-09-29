//! Property tests of the parsers a hostile server feeds (BSON, `OP_MSG`,
//! SCRAM) and of the field-path normalization (I2: no key that looks like
//! a value survives in a path).

use databastion_classifiers::names;
use proptest::prelude::*;

use crate::bson::{Doc, DocBuf, Value};
use crate::paths::{self, Collector, Shape};
use crate::scram::Scram;
use crate::wire;

/// Walks every element of a document, depth-bounded, without panicking.
fn walk(doc: Doc<'_>, depth: usize) {
    for element in doc.iter() {
        let Ok((_, value)) = element else {
            return;
        };
        match value {
            Value::Doc(d) | Value::Array(d) if depth < 40 => walk(d, depth + 1),
            other => {
                let _ = paths::leaf_text(other);
            }
        }
    }
}

/// A key: a plain word, or one that embeds a value (e-mail, phone
/// number, long id).
fn key() -> impl Strategy<Value = (String, bool)> {
    prop_oneof![
        "[a-z][a-zA-Z_]{0,11}".prop_map(|k| (k, false)),
        "[a-z]{2,8}\\.[a-z]{2,8}@example\\.(com|org|net)".prop_map(|k| (k, true)),
        "(06|07|33)[0-9]{8}".prop_map(|k| (k, true)),
        "0[67] [0-9]{2} [0-9]{2} [0-9]{2} [0-9]{2}".prop_map(|k| (k, true)),
        "[0-9a-f]{24}".prop_map(|k| (k, true)),
    ]
}

/// A document of nested keys (at most three levels) with string leaves,
/// and the keys that embed values.
fn document() -> impl Strategy<Value = (Vec<u8>, Vec<String>)> {
    prop::collection::vec((key(), key(), key(), 0u8..3), 1..8).prop_map(|entries| {
        let mut values = Vec::new();
        let mut doc = DocBuf::new();
        let mut seen = std::collections::HashSet::new();
        for ((k1, v1), (k2, v2), (k3, v3), depth) in entries {
            // Distinct top-level keys.
            if !seen.insert(k1.clone()) {
                continue;
            }
            for (k, is_value) in [(&k1, v1), (&k2, v2), (&k3, v3)] {
                if is_value {
                    values.push(k.clone());
                }
            }
            let top = k1;
            doc = match depth {
                0 => doc.str(&top, "leaf"),
                1 => doc.doc(&top, DocBuf::new().str(&k2, "leaf")),
                _ => doc.doc(&top, DocBuf::new().doc(&k2, DocBuf::new().str(&k3, "leaf"))),
            };
        }
        (doc.finish(), values)
    })
}

proptest! {
    #[test]
    fn the_bson_reader_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(doc) = Doc::new(&bytes) {
            walk(doc, 0);
            let mut c = Collector::new(10);
            let _ = c.add_document(doc);
            for (name, _) in c.into_paths() {
                prop_assert!(names::conforms(name.as_str()), "{}", name.as_str());
            }
        }
        let _ = Doc::prefix(&bytes);
    }

    #[test]
    fn the_bson_reader_never_panics_on_mutated_documents(
        (doc, _) in document(),
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        let mut bytes = doc;
        let i = at.index(bytes.len());
        bytes[i] = byte;
        if let Ok(d) = Doc::new(&bytes) {
            walk(d, 0);
            let mut c = Collector::new(10);
            let _ = c.add_document(d);
        }
    }

    #[test]
    fn op_msg_framing_never_panics(
        header in prop::array::uniform16(any::<u8>()),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = wire::check_header(&header, 1);
        let _ = wire::parse(&payload);
    }

    #[test]
    fn scram_never_panics_on_server_messages(
        message in prop::collection::vec(any::<u8>(), 0..300),
        tail in "[!-+--~]{1,20}",
    ) {
        let (scram, _) = Scram::with_nonce("u", "abc");
        let _ = scram.client_final(&message, "pw");
        // A well-formed nonce with a random tail and iteration count below
        // the minimum: refused before any key derivation.
        let msg = format!("r=abc{tail},s=c2FsdA==,i=10");
        prop_assert!(scram.client_final(msg.as_bytes(), "pw").is_err());
    }

    #[test]
    fn value_conversions_never_panic(bytes in prop::array::uniform16(any::<u8>()), ms in any::<i64>(), d in any::<f64>()) {
        if let Some(s) = paths::decimal128(bytes) {
            prop_assert!(s.len() <= 90);
        }
        if let Some(s) = paths::date(ms) {
            prop_assert_eq!(s.len(), 10);
        }
        let _ = paths::double_digits(d);
    }

    /// No key that embeds a value survives in a normalized field path, and
    /// every path conforms to the contract `Identifier`.
    #[test]
    fn field_paths_never_carry_value_keys((doc, values) in document()) {
        let mut c = Collector::new(10);
        c.add_document(Doc::new(&doc).unwrap()).unwrap();
        for (name, _) in c.into_paths() {
            let name = name.as_str();
            prop_assert!(names::conforms(name), "{}", name);
            for v in &values {
                prop_assert!(!name.contains(v.as_str()), "{} kept {}", name, v);
            }
            prop_assert!(!name.contains('@'), "{}", name);
        }
    }

    /// Map keys that are ordinary lowercase words (logins, surnames), each
    /// in one document, never reach a path: the level collapses to `*`
    /// (security review M3).
    #[test]
    fn word_map_keys_never_reach_a_path(
        words in prop::collection::hash_set("[a-z]{3,10}", 2..12),
    ) {
        let words: Vec<String> = words
            .into_iter()
            .filter(|w| !["acl", "role", "admin"].contains(&w.as_str()))
            .collect();
        prop_assume!(words.len() >= 2);
        let docs: Vec<Vec<u8>> = words
            .iter()
            .map(|w| {
                DocBuf::new()
                    .doc("acl", DocBuf::new().doc(w, DocBuf::new().str("role", "admin")))
                    .finish()
            })
            .collect();
        let parsed: Vec<Doc<'_>> = docs.iter().map(|d| Doc::new(d).unwrap()).collect();
        let mut c = Collector::with_shape(10, Shape::learn(&parsed));
        for d in &parsed {
            c.add_document(*d).unwrap();
        }
        let paths: Vec<String> = c
            .into_paths()
            .into_iter()
            .map(|(n, _)| n.as_str().to_owned())
            .collect();
        // Two documents with one distinct key each are below the singleton
        // rule's minimum of 3 keys.
        if words.len() >= paths::MIN_SINGLETON_KEYS {
            prop_assert_eq!(paths.clone(), vec!["acl.*.role".to_owned()]);
            for p in &paths {
                for w in &words {
                    prop_assert!(!p.split('.').any(|seg| seg == w.as_str()), "{} kept {}", p, w);
                }
            }
        }
    }

    /// Random bodies inside a valid BSON length and terminator, and inside
    /// a valid OP_MSG section, reach the inner parsers (security review L3).
    #[test]
    fn framed_random_bodies_never_panic(body in prop::collection::vec(any::<u8>(), 0..400)) {
        let mut doc = Vec::with_capacity(body.len() + 5);
        doc.extend_from_slice(&i32::try_from(body.len() + 5).unwrap().to_le_bytes());
        doc.extend_from_slice(&body);
        doc.push(0);
        let parsed = Doc::new(&doc);
        prop_assert!(parsed.is_ok());
        if let Ok(d) = parsed {
            walk(d, 0);
            let mut c = Collector::with_shape(10, Shape::learn(&[d]));
            let _ = c.add_document(d);
            for (name, _) in c.into_paths() {
                prop_assert!(names::conforms(name.as_str()), "{}", name.as_str());
            }
        }
        let mut payload = 0u32.to_le_bytes().to_vec();
        payload.push(0);
        payload.extend_from_slice(&doc);
        prop_assert!(wire::parse(&payload).is_ok());
    }
}

// ---- Audit records (P5-B, P5-C, ADR-0027). ----

use databastion_classifiers::masking::EventSource;
use databastion_core::audit::own::{OwnAccount, SharedOwnUsage};

use crate::audit::events::EventBuilder;
use crate::audit::profiler;
use crate::audit::records::{self, iso_time, parse_audit_log, parse_server_log};

fn builder() -> EventBuilder {
    EventBuilder::new(
        OwnAccount::new(
            "databastion@admin",
            Some("databastion-agent"),
            None,
            200,
            SharedOwnUsage::default(),
        ),
        "databastion@admin".to_owned(),
        200,
    )
}

/// A literal a client could put in a command: marked so a leak is found.
fn literal() -> impl Strategy<Value = String> {
    "[A-Za-z0-9@. _-]{4,24}".prop_map(|s| format!("LEAK{s}"))
}

/// JSON-escapes a string (the literal may hold nothing to escape, but the
/// escaped form is what a log holds).
fn js(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// A command document holding `lit` in its filter (as a value and as a
/// key), a nested operator, a limit and a pipeline.
fn command(lit: &str, shape: u8) -> String {
    let l = js(lit);
    match shape % 4 {
        0 => format!(
            r#"{{"find":"users","filter":{{"email":{l},{l}:{{"$in":[{l},1,{{"x":{l}}}]}}}},"limit":5,"$db":"app"}}"#
        ),
        1 => format!(
            r#"{{"aggregate":"users","pipeline":[{{"$match":{{"k":{l}}}}},{{{l}:1}},{{"$project":{{{l}:1}}}}],"cursor":{{}},"$db":"app"}}"#
        ),
        2 => format!(
            r#"{{"update":"users","updates":[{{"q":{{"a":{l}}},"u":{{"$set":{{"b":{l}}}}}}}],"$db":"app"}}"#
        ),
        _ => format!(r#"{{"count":"users","query":{{"n":{l}}},"$db":"app"}}"#),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Hostile log lines and audit records never panic the parsers.
    #[test]
    fn hostile_log_lines_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_server_log(&bytes);
        let _ = parse_audit_log(&bytes);
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = iso_time(s);
            let _ = records::namespace(s);
            let _ = records::address(s);
        }
    }

    /// Structured JSON with arbitrary values in the fields the parsers
    /// read never panics either.
    #[test]
    fn hostile_field_types_never_panic(
        id in prop_oneof![Just(51803i64), Just(22943), Just(22944), Just(51800), Just(5_286_306), Just(5_286_307), any::<i64>()],
        atype in prop_oneof![Just("authCheck"), Just("authenticate"), Just("clientMetadata"), Just("dropCollection"), Just("createUser"), Just("x")],
        value in prop_oneof![
            Just("null".to_owned()), Just("1".to_owned()), Just("-1".to_owned()), Just("1e400".to_owned()),
            Just("[]".to_owned()), Just("{}".to_owned()), Just("\"x\"".to_owned()), Just("true".to_owned()),
            Just(r#"{"$date":"2026-99-99T00:00:00Z"}"#.to_owned()), Just(r#"{"$numberLong":"x"}"#.to_owned()),
        ],
    ) {
        for field in ["t", "ctx", "attr"] {
            let line = format!(r#"{{"t":{{"$date":"2026-09-29T10:00:00Z"}},"id":{id},"ctx":"conn1","attr":{{"type":"command","ns":"app.users","command":{{"find":"users"}}}},"{field}":{value}}}"#);
            let _ = parse_server_log(line.as_bytes());
        }
        for field in ["type", "ns", "appName", "command", "originatingCommand", "nreturned", "remote", "user", "db", "doc", "connectionId", "errCode"] {
            let line = format!(r#"{{"t":{{"$date":"2026-09-29T10:00:00Z"}},"id":{id},"ctx":"conn1","attr":{{"{field}":{value},"type":"command","command":{{"find":"users","filter":{value},"limit":{value},"pipeline":{value}}}}}}}"#);
            let _ = parse_server_log(line.as_bytes());
        }
        for field in ["ts", "remote", "users", "param", "result"] {
            let line = format!(r#"{{"atype":"{atype}","ts":{{"$date":"2026-09-29T10:00:00Z"}},"param":{{"command":"find","ns":"app.users","args":{{"find":"users","filter":{value}}},"user":"u","db":"admin"}},"{field}":{value}}}"#);
            let _ = parse_audit_log(line.as_bytes());
        }
    }

    /// I2: literals of command documents never reach a record nor an
    /// event, on either file source, whatever the command.
    #[test]
    fn command_literals_never_reach_records_or_events(lit in literal(), shape in any::<u8>()) {
        let cmd = command(&lit, shape);
        let errmsg = js(&format!("error near {lit}"));
        let slow = format!(
            r#"{{"t":{{"$date":"2026-09-29T10:00:00.000+00:00"}},"s":"I","c":"COMMAND","id":51803,"ctx":"conn4","msg":"Slow query","attr":{{"type":"command","ns":"app.users","appName":"mongodump","command":{cmd},"originatingCommand":{cmd},"planSummary":{errmsg},"errMsg":{errmsg},"nreturned":3,"remote":"10.0.0.9:5000"}}}}"#
        );
        let audit = format!(
            r#"{{"atype":"authCheck","ts":{{"$date":"2026-09-29T10:00:00.000Z"}},"remote":{{"ip":"10.0.0.9","port":5000}},"users":[{{"user":"alice","db":"admin"}}],"param":{{"command":"find","ns":"app.users","args":{cmd}}},"result":0}}"#
        );
        let app_msg = format!(
            r#"{{"atype":"applicationMessage","ts":{{"$date":"2026-09-29T10:00:00.000Z"}},"users":[],"param":{{"msg":{}}},"result":0}}"#,
            js(&lit)
        );
        let mut all = Vec::new();
        for (source, line, parse) in [
            (EventSource::MongodbLog, slow, parse_server_log as fn(&[u8]) -> Result<Option<records::Record>, ()>),
            (EventSource::MongodbAuditLog, audit, parse_audit_log),
            (EventSource::MongodbAuditLog, app_msg, parse_audit_log),
        ] {
            let parsed = parse(line.as_bytes());
            prop_assert!(parsed.is_ok(), "{}", line);
            if let Ok(Some(r)) = parsed {
                let debug = format!("{r:?}");
                prop_assert!(!debug.contains("LEAK"));
                prop_assert!(r.user.as_ref().is_none_or(|u| !u.contains("LEAK")));
                prop_assert!(r.app.as_deref().is_none_or(|u| !u.contains("LEAK")));
                prop_assert!(r.ns.as_ref().is_none_or(|(d, c)| !d.contains("LEAK") && c.as_deref().is_none_or(|c| !c.contains("LEAK"))));
                all.extend(builder().convert(vec![r], source, std::time::SystemTime::now()));
            }
        }
        for e in &all {
            let debug = format!("{e:?}");
            prop_assert!(!debug.contains("LEAK"), "{}", debug);
        }
    }

    /// Arbitrary profiler documents never panic the record reader.
    #[test]
    fn hostile_profiler_documents_never_panic(bytes in prop::collection::vec(any::<u8>(), 5..256)) {
        let mut b = bytes;
        let len = i32::try_from(b.len()).unwrap_or(i32::MAX);
        b[..4].copy_from_slice(&len.to_le_bytes());
        if let Some(last) = b.last_mut() {
            *last = 0;
        }
        if let Ok(doc) = Doc::new(&b) {
            let _ = profiler::record_of(&doc);
        }
    }
}
