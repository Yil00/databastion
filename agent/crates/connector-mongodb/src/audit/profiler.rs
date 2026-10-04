//! The profiler source (ADR-0027 decisions 3, 5 and 8): `system.profile`
//! of each database the account holds `find` on, polled over the agent's
//! connection.
//!
//! - One `find` per database and poll, built in code: `filter` on `ts`
//!   (a date from the connector), a fixed projection, `sort` in natural
//!   order, `limit` [`BATCH`], `singleBatch` (no cursor left open, no
//!   `getMore`), `maxTimeMS` (the session's statement timeout).
//! - **The projection computes the closed-shape facts on the server**:
//!   the command name, the number of filter keys, a numeric limit and the
//!   pipeline stage operators (from a closed list, anything else
//!   `other`). `command` and `originatingCommand`, which hold other users'
//!   literals, never cross the wire.
//! - **Truncated or odd commands** (end-of-phase-5 review I1): the server
//!   replaces a command document over its size limit with
//!   `{$truncated: "<text>", …}`. The projection flags it (`tr`), as it
//!   does a `command` or `originatingCommand` that is not an object, and
//!   the entry has an unknown shape (no whole-read signal from a filter
//!   that was cut off). A truncated command whose name is lost is still
//!   reported when it returned (a read) or wrote (a write) documents. A
//!   `command` that is not an object never makes the projection fail, and
//!   an entry that does not parse is skipped and counted, never failing
//!   the whole poll.
//! - The read position (last `ts` per database, and the entries already
//!   read at that millisecond, by a SHA-256 of their projected bytes) is
//!   persisted through the core (`mongodb_profiler` cursor: database
//!   names, times and hashes only), after the events of each poll are
//!   handed over, so an agent restart resumes where it stopped (what the
//!   capped collection still holds). A database without a saved position
//!   starts at its newest entry (no history replay). The profiler is a
//!   capped collection: entries overwritten between two polls (or while
//!   the agent is stopped) are lost, and an entry written after a later
//!   one with an older `ts` (a long operation) can be missed.

use std::collections::{HashMap, HashSet};

use databastion_classifiers::masking::ClientAddr;
use tokio::io::{AsyncRead, AsyncWrite};

use super::records::{
    Cmd, Filter, Kind, MAX_STAGES, Pipeline, Record, Shape, StageKind, address, bounded,
    millis_time, namespace,
};
use crate::bson::{Doc, DocBuf, Malformed, Value};
use crate::conn::{Kind as CmdKind, Session};
use crate::error::{MgError, Stage};

/// Entries read per database and poll.
pub(crate) const BATCH: i64 = 1000;
/// Databases polled at most.
pub(crate) const MAX_DATABASES: usize = 64;
/// Stage operators the projection keeps (anything else is `other`).
const STAGES: [&str; 9] = [
    "$project",
    "$addFields",
    "$set",
    "$unset",
    "$sort",
    "$replaceRoot",
    "$replaceWith",
    "$out",
    "$merge",
];

fn list(items: &[&str]) -> DocBuf {
    let mut d = DocBuf::new();
    for (i, v) in items.iter().enumerate() {
        d = d.str(&i.to_string(), v);
    }
    d
}

fn if_null(paths: &[&str], fallback: Option<DocBuf>) -> DocBuf {
    let mut items = list(paths);
    if let Some(f) = fallback {
        items = items.doc(&paths.len().to_string(), f);
    }
    DocBuf::new().list("$ifNull", items)
}

/// `{$let: {vars: {<var>: <value>}, in: <body>}}`.
fn let_in(var: &str, value: DocBuf, body: DocBuf) -> DocBuf {
    DocBuf::new().doc(
        "$let",
        DocBuf::new()
            .doc("vars", DocBuf::new().doc(var, value))
            .doc("in", body),
    )
}

/// `{$let: {vars: {<var>: <value>}, in: "<path>"}}`.
fn let_path(var: &str, value: DocBuf, path: &str) -> DocBuf {
    DocBuf::new().doc(
        "$let",
        DocBuf::new()
            .doc("vars", DocBuf::new().doc(var, value))
            .str("in", path),
    )
}

/// `{$arrayElemAt: [{$objectToArray: <obj>}, 0]}`.
fn first_pair(obj: DocBuf) -> DocBuf {
    DocBuf::new().list(
        "$arrayElemAt",
        DocBuf::new()
            .doc("0", DocBuf::new().doc("$objectToArray", obj))
            .i32("1", 0),
    )
}

fn first_pair_of(path: &str) -> DocBuf {
    DocBuf::new().list(
        "$arrayElemAt",
        DocBuf::new()
            .doc("0", DocBuf::new().str("$objectToArray", path))
            .i32("1", 0),
    )
}

/// `{$eq: [{$type: <path>}, <type>]}`.
fn is_type(path: &str, t: &str) -> DocBuf {
    DocBuf::new().list(
        "$eq",
        DocBuf::new()
            .doc("0", DocBuf::new().str("$type", path))
            .str("1", t),
    )
}

/// `{$cond: [<object at path>, <path>, {}]}`: the document at `path`
/// when it is an object, else an empty one (`$objectToArray` fails on
/// anything else, and would fail the whole `find`).
fn object_or_empty(path: &str) -> DocBuf {
    DocBuf::new().list(
        "$cond",
        DocBuf::new()
            .doc("0", is_type(path, "object"))
            .str("1", path)
            .doc("2", DocBuf::new().doc("$literal", DocBuf::new())),
    )
}

/// Whether the command at `path` is not a plain command document: present
/// but not an object, or an object carrying the server's `$truncated`
/// key.
fn odd_command(path: &str) -> DocBuf {
    let present_not_object = DocBuf::new().list(
        "$and",
        DocBuf::new()
            .doc(
                "0",
                DocBuf::new().list(
                    "$ne",
                    DocBuf::new()
                        .doc("0", DocBuf::new().str("$type", path))
                        .str("1", "missing"),
                ),
            )
            .doc(
                "1",
                DocBuf::new().list(
                    "$ne",
                    DocBuf::new()
                        .doc("0", DocBuf::new().str("$type", path))
                        .str("1", "object"),
                ),
            ),
    );
    // `$truncated` as a literal: a string starting with `$` is a field
    // path in an expression.
    let keys = DocBuf::new().doc(
        "$map",
        DocBuf::new()
            .doc(
                "input",
                DocBuf::new().doc("$objectToArray", object_or_empty(path)),
            )
            .str("as", "t")
            .str("in", "$$t.k"),
    );
    let truncated = DocBuf::new().list(
        "$in",
        DocBuf::new()
            .doc("0", DocBuf::new().str("$literal", "$truncated"))
            .doc("1", keys),
    );
    DocBuf::new().list(
        "$or",
        DocBuf::new()
            .doc("0", present_not_object)
            .doc("1", truncated),
    )
}

/// The fixed projection (see the module documentation).
pub(crate) fn projection() -> DocBuf {
    // Command name: the first key of `command` (none when it is not an
    // object).
    let cmd = let_path("f", first_pair(object_or_empty("$command")), "$$f.k");
    // The command or the opening one is truncated or not an object.
    let tr = DocBuf::new().list(
        "$or",
        DocBuf::new()
            .doc("0", odd_command("$command"))
            .doc("1", odd_command("$originatingCommand")),
    );
    // Filter keys: `filter` (find), `query` (count, distinct), or the
    // opening command's filter (getMore); -1 when not an object.
    let fk = let_in(
        "q",
        if_null(
            &[
                "$command.filter",
                "$command.query",
                "$originatingCommand.filter",
            ],
            Some(DocBuf::new()),
        ),
        DocBuf::new().list(
            "$cond",
            DocBuf::new()
                .doc("0", is_type("$$q", "object"))
                .doc(
                    "1",
                    DocBuf::new().doc("$size", DocBuf::new().str("$objectToArray", "$$q")),
                )
                .i32("2", -1),
        ),
    );
    // Limit: a number, else null.
    let lim = let_in(
        "l",
        if_null(&["$command.limit", "$originatingCommand.limit"], None),
        DocBuf::new().list(
            "$cond",
            DocBuf::new()
                .doc("0", DocBuf::new().str("$isNumber", "$$l"))
                .str("1", "$$l")
                .null("2"),
        ),
    );
    // Stage operators from the closed list, the rest `other`.
    let stage = DocBuf::new().list(
        "$cond",
        DocBuf::new()
            .doc("0", is_type("$$s", "object"))
            .doc(
                "1",
                let_in(
                    "e",
                    first_pair_of("$$s"),
                    DocBuf::new().list(
                        "$cond",
                        DocBuf::new()
                            .doc(
                                "0",
                                DocBuf::new().list(
                                    "$in",
                                    DocBuf::new()
                                        .str("0", "$$e.k")
                                        .doc("1", DocBuf::new().list("$literal", list(&STAGES))),
                                ),
                            )
                            .str("1", "$$e.k")
                            .str("2", "other"),
                    ),
                ),
            )
            .str("2", "other"),
    );
    let slice_len = i32::try_from(MAX_STAGES + 1).unwrap_or(i32::MAX);
    let st = let_in(
        "p",
        if_null(&["$command.pipeline", "$originatingCommand.pipeline"], None),
        DocBuf::new().list(
            "$cond",
            DocBuf::new()
                .doc("0", DocBuf::new().str("$isArray", "$$p"))
                .doc(
                    "1",
                    DocBuf::new().doc(
                        "$map",
                        DocBuf::new()
                            .doc(
                                "input",
                                DocBuf::new().list(
                                    "$slice",
                                    DocBuf::new().str("0", "$$p").i32("1", slice_len),
                                ),
                            )
                            .str("as", "s")
                            .doc("in", stage),
                    ),
                )
                .null("2"),
        ),
    );
    let mut p = DocBuf::new().i32("_id", 0);
    for field in [
        "ts",
        "op",
        "ns",
        "nreturned",
        "ninserted",
        "nModified",
        "ndeleted",
        "appName",
        "client",
        "user",
        "errCode",
    ] {
        p = p.i32(field, 1);
    }
    // The agent's own CAS store guard key probe, compared whole on the
    // server (the pipeline itself never crosses the wire).
    let kp = DocBuf::new().list(
        "$eq",
        DocBuf::new().str("0", "$command.pipeline").doc(
            "1",
            DocBuf::new().array("$literal", crate::discover::key_probe_pipeline()),
        ),
    );
    p.doc("cmd", cmd)
        .doc("tr", tr)
        .doc("kp", kp)
        .doc("fk", fk)
        .doc("lim", lim)
        .doc("st", st)
}

/// Where the next poll of one database starts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DbCursor {
    /// Last `ts` read (milliseconds).
    ts: i64,
    /// Hashes of the entries already read at `ts`.
    seen: HashSet<u64>,
    /// Read strictly after `ts` (first poll, or a millisecond holding more
    /// entries than a batch).
    strict: bool,
}

impl DbCursor {
    /// A cursor after `ts`.
    pub(crate) fn after(ts: i64) -> Self {
        Self {
            ts,
            seen: HashSet::new(),
            strict: true,
        }
    }
}

/// The poll command for a database.
pub(crate) fn poll_command(cursor: &DbCursor) -> DocBuf {
    let op = if cursor.strict { "$gt" } else { "$gte" };
    DocBuf::new()
        .str("find", "system.profile")
        .doc(
            "filter",
            DocBuf::new().doc("ts", DocBuf::new().date(op, cursor.ts)),
        )
        .doc("projection", projection())
        .doc("sort", DocBuf::new().i32("$natural", 1))
        .i64("limit", BATCH)
        .bool("singleBatch", true)
}

/// The command finding the newest entry of a database's profiler.
pub(crate) fn newest_command() -> DocBuf {
    DocBuf::new()
        .str("find", "system.profile")
        .doc("filter", DocBuf::new())
        .doc("projection", DocBuf::new().i32("_id", 0).i32("ts", 1))
        .doc("sort", DocBuf::new().i32("$natural", -1))
        .i64("limit", 1)
        .bool("singleBatch", true)
}

/// A stable hash of an entry's projected bytes (the same across agent
/// versions, since it is persisted; a collision cannot be chosen).
fn hash_of(bytes: &[u8]) -> u64 {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(bytes);
    let mut first = [0u8; 8];
    first.copy_from_slice(&d[..8]);
    u64::from_be_bytes(first)
}

/// Name of the persisted cursor.
pub(crate) const CURSOR: &str = "mongodb_profiler";
/// Version of the saved cursor.
const CURSOR_VERSION: u32 = 1;
/// Hashes saved per database at most; beyond, the database resumes
/// strictly after its last millisecond (an entry of that millisecond not
/// read yet is then missed, rather than entries read again).
const MAX_SAVED_SEEN: usize = 32;
/// A saved time this far ahead of the agent's clock is not trusted
/// (another server, a clock set back): the database starts at its newest
/// entry.
const MAX_AHEAD_MS: i64 = 24 * 3600 * 1000;

/// The saved cursor: per database, (name, last `ts`, strict, hashes).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Saved {
    v: u32,
    dbs: Vec<(String, i64, bool, Vec<u64>)>,
}

/// The saved form of `cursors` (sorted by database, bounded).
pub(crate) fn encode_cursors(cursors: &HashMap<String, DbCursor>) -> Option<Vec<u8>> {
    let mut dbs: Vec<(String, i64, bool, Vec<u64>)> = cursors
        .iter()
        .take(MAX_DATABASES)
        .map(|(db, c)| {
            let mut seen: Vec<u64> = c.seen.iter().copied().collect();
            seen.sort_unstable();
            if seen.len() > MAX_SAVED_SEEN {
                (db.clone(), c.ts, true, Vec::new())
            } else {
                (db.clone(), c.ts, c.strict, seen)
            }
        })
        .collect();
    dbs.sort();
    serde_json::to_vec(&Saved {
        v: CURSOR_VERSION,
        dbs,
    })
    .ok()
}

/// The cursors of a saved form; unknown or untrusted content is dropped.
pub(crate) fn decode_cursors(bytes: &[u8], now_ms: i64) -> HashMap<String, DbCursor> {
    let Ok(saved) = serde_json::from_slice::<Saved>(bytes) else {
        tracing::warn!("profiler cursor not understood: starting at the newest entries");
        return HashMap::new();
    };
    if saved.v != CURSOR_VERSION {
        return HashMap::new();
    }
    saved
        .dbs
        .into_iter()
        .take(MAX_DATABASES)
        .filter(|(_, ts, _, seen)| {
            *ts <= now_ms.saturating_add(MAX_AHEAD_MS) && seen.len() <= MAX_SAVED_SEEN
        })
        .map(|(db, ts, strict, seen)| {
            (
                db,
                DbCursor {
                    ts,
                    seen: seen.into_iter().collect(),
                    strict,
                },
            )
        })
        .collect()
}

fn count(doc: &Doc<'_>, key: &str) -> Result<Option<u64>, Malformed> {
    Ok(doc.int(key)?.and_then(|n| u64::try_from(n).ok()))
}

fn string(doc: &Doc<'_>, key: &str) -> Result<Option<String>, Malformed> {
    Ok(match doc.get(key)? {
        Some(Value::Str(s)) => std::str::from_utf8(s).ok().and_then(bounded),
        _ => None,
    })
}

/// One projected profiler entry as a record (`None`: an operation that
/// yields no event, or an entry without a time).
pub(crate) fn record_of(doc: &Doc<'_>) -> Result<Option<(i64, Record)>, Malformed> {
    let Some(Value::Date(ts)) = doc.get("ts")? else {
        return Ok(None);
    };
    let op = string(doc, "op")?.unwrap_or_default();
    // Truncated (or not an object): the shape is unknown.
    let odd = doc.flag("tr")?.unwrap_or(false);
    let key_probe = doc.flag("kp")?.unwrap_or(false);
    let written = [
        count(doc, "ninserted")?,
        count(doc, "nModified")?,
        count(doc, "ndeleted")?,
    ];
    let wrote = written.iter().flatten().any(|n| *n > 0);
    let returned = count(doc, "nreturned")?.is_some_and(|n| n > 0);
    let cmd = match op.as_str() {
        "query" => Cmd::Find,
        "getmore" => Cmd::GetMore,
        "insert" => Cmd::Insert,
        "update" => Cmd::Update,
        "remove" => Cmd::Delete,
        "command" => match string(doc, "cmd")?.map(|c| Cmd::from_name(&c)) {
            Some(c) if c != Cmd::Other => c,
            // A command whose name was cut off: reported by what it did
            // (a write, else a read of unknown shape), never dropped.
            _ if odd && wrote => Cmd::Update,
            _ if odd && returned => Cmd::Find,
            _ => Cmd::Other,
        },
        _ => Cmd::Other,
    };
    if cmd == Cmd::Other {
        return Ok(Some((ts, Record::new(Kind::Op(Cmd::Other)))));
    }
    let mut r = Record::new(Kind::Op(cmd));
    r.ts = millis_time(ts);
    r.ns = string(doc, "ns")?.as_deref().and_then(namespace);
    r.user = string(doc, "user")?
        .filter(|u| !u.is_empty())
        .map(zeroize::Zeroizing::new);
    r.app = string(doc, "appName")?;
    r.client = string(doc, "client")?
        .as_deref()
        .and_then(address)
        .map(|(ip, _)| ClientAddr::Ip(ip));
    r.failed = doc.int("errCode")?.is_some_and(|c| c != 0);
    r.rows = match cmd {
        Cmd::Insert | Cmd::Update | Cmd::Delete | Cmd::FindAndModify | Cmd::BulkWrite => written
            .iter()
            .flatten()
            .fold(None, |a: Option<u64>, n| {
                Some(a.unwrap_or(0).saturating_add(*n))
            })
            .or(count(doc, "nreturned")?),
        _ => count(doc, "nreturned")?,
    };
    r.shape = Shape {
        filter: match doc.int("fk")? {
            Some(n) if n >= 0 => Filter::Keys(u64::try_from(n).unwrap_or(u64::MAX)),
            Some(_) => Filter::Unknown,
            None => Filter::Absent,
        },
        limit: doc.int("lim")?,
        pipeline: match doc.array("st")? {
            Some(stages) => {
                let mut kinds = Vec::new();
                for (i, e) in stages.iter().enumerate() {
                    let (_, v) = e?;
                    if i >= MAX_STAGES {
                        kinds.push(StageKind::Other);
                        break;
                    }
                    kinds.push(match v {
                        Value::Str(s) => {
                            StageKind::from_operator(std::str::from_utf8(s).unwrap_or(""))
                        }
                        _ => StageKind::Other,
                    });
                }
                let mut p = Pipeline::from_stages(kinds);
                p.own_key_probe = key_probe;
                Some(p)
            }
            None => None,
        },
    };
    if odd {
        r.shape = Shape {
            filter: Filter::Unknown,
            limit: None,
            pipeline: None,
        };
    }
    if cmd == Cmd::GetMore {
        // The projection took the opening command's shape.
        r.origin = Some(r.shape);
    }
    Ok(Some((ts, r)))
}

/// Result of polling one database.
#[derive(Debug)]
pub(crate) struct Polled {
    pub(crate) records: Vec<Record>,
    /// Entries skipped because they do not parse (counted as dropped).
    pub(crate) dropped: u64,
    /// The batch was full: poll again at once.
    pub(crate) more: bool,
}

/// Reads the newest entry's time of `db`'s profiler (0 when empty).
pub(crate) async fn newest<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
    db: &str,
) -> Result<i64, MgError> {
    let reply = session
        .command(Stage::Audit, db, newest_command(), CmdKind::Read)
        .await?;
    let doc = reply.doc();
    let bad = |_| MgError::new(databastion_core::FailureCode::Internal, Stage::Audit);
    let batch = doc
        .doc("cursor")
        .map_err(bad)?
        .and_then(|c| c.array("firstBatch").ok().flatten());
    let Some(batch) = batch else {
        return Ok(0);
    };
    for e in batch.iter() {
        if let (_, Value::Doc(d)) = e.map_err(bad)?
            && let Some(Value::Date(ts)) = d.get("ts").map_err(bad)?
        {
            return Ok(ts);
        }
    }
    Ok(0)
}

/// Polls one database from `cursor` and advances it.
pub(crate) async fn poll<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<S>,
    db: &str,
    cursor: &mut DbCursor,
) -> Result<Polled, MgError> {
    let reply = session
        .command(Stage::Audit, db, poll_command(cursor), CmdKind::Read)
        .await?;
    let doc = reply.doc();
    let bad = |_| MgError::new(databastion_core::FailureCode::Internal, Stage::Audit);
    let c = doc
        .doc("cursor")
        .map_err(bad)?
        .ok_or_else(|| bad(Malformed))?;
    if let Some(id) = c.int("id").map_err(bad)?
        && id != 0
    {
        // `singleBatch` closes it; a server that did not is told to.
        session.kill_cursor(db, "system.profile", id).await;
    }
    let batch = c
        .array("firstBatch")
        .map_err(bad)?
        .ok_or_else(|| bad(Malformed))?;
    let mut records = Vec::new();
    let mut dropped = 0u64;
    let mut n = 0i64;
    let mut new_seen: HashMap<i64, HashSet<u64>> = HashMap::new();
    let mut last = cursor.ts;
    for e in batch.iter() {
        let (_, v) = e.map_err(bad)?;
        n += 1;
        // One odd entry never fails the whole poll: skipped and counted.
        let Value::Doc(d) = v else {
            dropped += 1;
            continue;
        };
        let h = hash_of(d.as_bytes());
        // Per-record isolation: an entry that makes the reader panic is
        // dropped alone (phase-7 review H1).
        let Some((ts, r)) = (match databastion_core::isolate(|| record_of(&d)) {
            Some(Ok(r)) => r,
            Some(Err(Malformed)) | None => {
                dropped += 1;
                continue;
            }
        }) else {
            continue;
        };
        // Already read (the server filters on `ts` too; this also guards
        // against a server that does not).
        if ts < cursor.ts || (ts == cursor.ts && (cursor.strict || cursor.seen.contains(&h))) {
            continue;
        }
        last = last.max(ts);
        new_seen.entry(ts).or_default().insert(h);
        records.push(r);
    }
    let more = n >= BATCH;
    if last == cursor.ts {
        let fresh = new_seen.remove(&last).unwrap_or_default();
        if fresh.is_empty() {
            if more {
                // A full batch of entries already read at one millisecond:
                // skip the rest of it rather than loop.
                *cursor = DbCursor::after(last);
            }
        } else {
            cursor.seen.extend(fresh);
        }
    } else {
        *cursor = DbCursor {
            ts: last,
            seen: new_seen.remove(&last).unwrap_or_default(),
            strict: false,
        };
    }
    Ok(Polled {
        records,
        dropped,
        more,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn projection_never_asks_for_command_documents() {
        let p = projection().finish();
        let doc = Doc::new(&p).unwrap();
        let mut keys = Vec::new();
        for e in doc.iter() {
            let (k, v) = e.unwrap();
            let k = std::str::from_utf8(k).unwrap().to_owned();
            // Plain inclusions are the closed list; `command` and
            // `originatingCommand` are only read inside expressions.
            if let Value::Int32(1) = v {
                assert!(!k.contains("ommand"), "{k}");
            }
            keys.push(k);
        }
        assert!(keys.contains(&"cmd".to_owned()) && keys.contains(&"st".to_owned()));
        assert!(keys.contains(&"tr".to_owned()));
        // `$objectToArray` never sees `command` or `originatingCommand`
        // unguarded (a string `command` would fail the whole `find`).
        let text = doc_text(&p);
        for path in ["$command", "$originatingCommand"] {
            assert!(!text.contains(&format!("$objectToArray{path}")), "{text}");
            assert!(
                text.contains(&format!("$objectToArray$cond$eq$type{path}{path}$literal")),
                "{text}"
            );
        }
        // `$truncated` is only ever a literal.
        assert!(text.contains("$literal$truncated"), "{text}");
        assert!(!keys.contains(&"command".to_owned()));
        assert!(!keys.contains(&"originatingCommand".to_owned()));
    }

    /// The keys and string values of a document, depth first, joined.
    fn doc_text(bytes: &[u8]) -> String {
        fn visit(d: Doc<'_>, out: &mut String) {
            for e in d.iter() {
                let (k, v) = e.unwrap();
                let k = std::str::from_utf8(k).unwrap();
                if k.starts_with('$') {
                    out.push_str(k);
                }
                match v {
                    Value::Doc(d) | Value::Array(d) => visit(d, out),
                    Value::Str(s) if s.starts_with(b"$") => {
                        out.push_str(std::str::from_utf8(s).unwrap());
                    }
                    _ => {}
                }
            }
        }
        let mut out = String::new();
        visit(Doc::new(bytes).unwrap(), &mut out);
        out
    }

    /// PR #141 E2E follow-up: the server compares the command pipeline
    /// with the agent's key probe (`kp`); only that flag marks the entry
    /// as the probe, and the projection asks for it.
    #[test]
    fn the_key_probe_is_flagged_by_the_server() {
        let entry = |kp: Option<bool>| {
            let mut d = DocBuf::new()
                .date("ts", 5)
                .str("op", "command")
                .str("ns", "app.customers")
                .i32("nreturned", 1)
                .str("user", "databastion@admin")
                .str("cmd", "aggregate")
                .i32("fk", -1)
                .null("lim")
                .list("st", DocBuf::new().str("0", "other").str("1", "$project"))
                .bool("tr", false);
            if let Some(kp) = kp {
                d = d.bool("kp", kp);
            }
            d.finish()
        };
        let probe = |kp| {
            let (_, r) = record_of(&Doc::new(&entry(kp)).unwrap()).unwrap().unwrap();
            assert_eq!(r.kind, Kind::Op(Cmd::Aggregate));
            r.shape.pipeline.unwrap().own_key_probe
        };
        assert!(probe(Some(true)));
        assert!(!probe(Some(false)));
        assert!(!probe(None));
        let projection = String::from_utf8_lossy(&projection().finish()).into_owned();
        assert!(projection.contains("kp") && projection.contains("$objectToArray"));
    }

    /// End-of-phase-5 review I1: a truncated command (or one that is not
    /// an object) has an unknown shape; one whose name was cut off is
    /// reported by what it did.
    #[test]
    fn truncated_commands_have_an_unknown_shape() {
        let entry = |op: &str, cmd: Option<&str>, tr: bool| {
            let mut d = DocBuf::new()
                .date("ts", 5)
                .str("op", op)
                .str("ns", "app.customers")
                .i32("nreturned", 20_000)
                .str("user", "alice@admin")
                .i32("fk", 0)
                .null("lim")
                .null("st")
                .bool("tr", tr);
            if let Some(c) = cmd {
                d = d.str("cmd", c);
            }
            d.finish()
        };
        // A `find` whose filter the server cut off: no whole-read shape.
        let (_, r) = record_of(&Doc::new(&entry("query", Some("$truncated"), true)).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Find));
        assert_eq!(r.shape.filter, Filter::Unknown);
        assert_eq!(r.rows, Some(20_000));
        // The same entry, not truncated: an empty filter.
        let (_, r) = record_of(&Doc::new(&entry("query", Some("find"), false)).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(r.shape.filter, Filter::Keys(0));
        // A command whose name was cut off, that returned documents: a
        // read of unknown shape.
        let (_, r) = record_of(&Doc::new(&entry("command", Some("$truncated"), true)).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Find));
        assert_eq!(r.shape.filter, Filter::Unknown);
        // No name at all (`command` not an object).
        let (_, r) = record_of(&Doc::new(&entry("command", None, true)).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Find));
        // A getMore of a truncated cursor: no shape either.
        let (_, r) = record_of(&Doc::new(&entry("getmore", None, true)).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(r.origin.unwrap().filter, Filter::Unknown);
        // Not truncated and not a known command: no event.
        let (_, r) = record_of(&Doc::new(&entry("command", Some("hello"), false)).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Other));
        // A truncated command that did nothing: no event.
        let nothing = DocBuf::new()
            .date("ts", 5)
            .str("op", "command")
            .str("cmd", "$truncated")
            .bool("tr", true)
            .finish();
        let (_, r) = record_of(&Doc::new(&nothing).unwrap()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Other));
    }

    #[test]
    fn entries_become_records() {
        let bytes = DocBuf::new()
            .date("ts", 1_790_676_000_000)
            .str("op", "query")
            .str("ns", "app.customers")
            .i32("nreturned", 150)
            .str("appName", "mongodump")
            .str("client", "10.0.0.9")
            .str("user", "alice@admin")
            .str("cmd", "find")
            .i32("fk", 0)
            .null("lim")
            .null("st")
            .finish();
        let (ts, r) = record_of(&Doc::new(&bytes).unwrap()).unwrap().unwrap();
        assert_eq!(ts, 1_790_676_000_000);
        assert_eq!(r.kind, Kind::Op(Cmd::Find));
        assert_eq!(r.rows, Some(150));
        assert_eq!(r.shape.filter, Filter::Keys(0));
        assert_eq!(r.client, ClientAddr::parse("10.0.0.9"));
        assert_eq!(r.user.as_ref().map(|u| u.as_str()), Some("alice@admin"));
        let bytes = DocBuf::new()
            .date("ts", 1)
            .str("op", "command")
            .str("ns", "app.customers")
            .str("cmd", "aggregate")
            .array_str("st", &["$project", "other"])
            .i32("fk", -1)
            .finish();
        let (_, r) = record_of(&Doc::new(&bytes).unwrap()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Aggregate));
        assert_eq!(r.shape.filter, Filter::Unknown);
        assert!(!r.shape.pipeline.unwrap().pass_through);
        let bytes = DocBuf::new()
            .date("ts", 1)
            .str("op", "getmore")
            .str("ns", "app.customers")
            .i32("fk", 0)
            .finish();
        let (_, r) = record_of(&Doc::new(&bytes).unwrap()).unwrap().unwrap();
        assert!(r.origin.is_some());
        // No time: skipped.
        let bytes = DocBuf::new().str("op", "query").finish();
        assert!(record_of(&Doc::new(&bytes).unwrap()).unwrap().is_none());
    }

    /// Phase 7: the profiler position is persisted (database names, times
    /// and stable hashes only) and restored across agent restarts.
    #[test]
    fn profiler_cursors_round_trip_bounded() {
        // The hash is stable across agent versions (SHA-256).
        assert_eq!(hash_of(b""), 0xe3b0_c442_98fc_1c14);
        let mut cursors = HashMap::new();
        cursors.insert(
            "app".to_owned(),
            DbCursor {
                ts: 1_700_000_000_000,
                seen: [1u64, 2, 3].into(),
                strict: false,
            },
        );
        cursors.insert(
            "busy".to_owned(),
            DbCursor {
                ts: 1_700_000_000_500,
                seen: (0..100u64).collect(),
                strict: false,
            },
        );
        cursors.insert("new".to_owned(), DbCursor::after(1_700_000_000_000));
        let bytes = encode_cursors(&cursors).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.len() < 64 * 1024, "{}", text.len());
        let back = decode_cursors(&bytes, 1_700_000_001_000);
        assert_eq!(back["app"], cursors["app"]);
        assert_eq!(back["new"], cursors["new"]);
        // Too many entries at the last millisecond: strictly after it.
        assert_eq!(back["busy"], DbCursor::after(1_700_000_000_500));
        // A position far ahead of the agent's clock is not trusted.
        let back = decode_cursors(&bytes, 1_600_000_000_000);
        assert!(back.is_empty());
        // Unknown content: nothing restored.
        assert!(decode_cursors(b"{\"v\":2,\"dbs\":[]}", 0).is_empty());
        assert!(decode_cursors(b"garbage", 0).is_empty());
    }

    #[test]
    fn the_worst_case_profiler_cursor_fits_the_cursor_bound() {
        let cursors: HashMap<String, DbCursor> = (0..MAX_DATABASES)
            .map(|i| {
                (
                    format!("{i:0>64}"),
                    DbCursor {
                        ts: i64::MIN,
                        seen: (0..MAX_SAVED_SEEN as u64).map(|n| u64::MAX - n).collect(),
                        strict: false,
                    },
                )
            })
            .collect();
        assert!(encode_cursors(&cursors).unwrap().len() <= 64 * 1024);
    }
}
