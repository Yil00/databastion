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
//! - The read position (last `ts` per database, and the entries already
//!   read at that millisecond) is in memory; the first poll starts at the
//!   newest entry (no history replay). The profiler is a capped
//!   collection: entries overwritten between two polls are lost, and an
//!   entry written after a later one with an older `ts` (a long operation)
//!   can be missed.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

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

/// The fixed projection (see the module documentation).
pub(crate) fn projection() -> DocBuf {
    // Command name: the first key of `command`.
    let cmd = let_path(
        "f",
        first_pair(if_null(&["$command"], Some(DocBuf::new()))),
        "$$f.k",
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
    p.doc("cmd", cmd)
        .doc("fk", fk)
        .doc("lim", lim)
        .doc("st", st)
}

/// Where the next poll of one database starts.
#[derive(Debug, Clone, Default)]
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

fn hash_of(bytes: &[u8]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
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
    let cmd = match op.as_str() {
        "query" => Cmd::Find,
        "getmore" => Cmd::GetMore,
        "insert" => Cmd::Insert,
        "update" => Cmd::Update,
        "remove" => Cmd::Delete,
        "command" => string(doc, "cmd")?.map_or(Cmd::Other, |c| Cmd::from_name(&c)),
        _ => Cmd::Other,
    };
    if cmd == Cmd::Other {
        return Ok(Some((ts, Record::new(Kind::Op(Cmd::Other)))));
    }
    let mut r = Record::new(Kind::Op(cmd));
    r.ts = millis_time(ts);
    r.ns = string(doc, "ns")?.as_deref().and_then(namespace);
    r.user = string(doc, "user")?.filter(|u| !u.is_empty());
    r.app = string(doc, "appName")?;
    r.client = string(doc, "client")?
        .as_deref()
        .and_then(address)
        .map(|(ip, _)| ClientAddr::Ip(ip));
    r.failed = doc.int("errCode")?.is_some_and(|c| c != 0);
    let written = [
        count(doc, "ninserted")?,
        count(doc, "nModified")?,
        count(doc, "ndeleted")?,
    ];
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
                Some(Pipeline::from_stages(kinds))
            }
            None => None,
        },
    };
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
        if let (_, Value::Doc(d)) = e.map_err(bad)? {
            if let Some(Value::Date(ts)) = d.get("ts").map_err(bad)? {
                return Ok(ts);
            }
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
    if let Some(id) = c.int("id").map_err(bad)? {
        if id != 0 {
            // `singleBatch` closes it; a server that did not is told to.
            session.kill_cursor(db, "system.profile", id).await;
        }
    }
    let batch = c
        .array("firstBatch")
        .map_err(bad)?
        .ok_or_else(|| bad(Malformed))?;
    let mut records = Vec::new();
    let mut n = 0i64;
    let mut new_seen: HashMap<i64, HashSet<u64>> = HashMap::new();
    let mut last = cursor.ts;
    for e in batch.iter() {
        let (_, v) = e.map_err(bad)?;
        n += 1;
        let Value::Doc(d) = v else {
            return Err(bad(Malformed));
        };
        let h = hash_of(d.as_bytes());
        let Some((ts, r)) = record_of(&d).map_err(bad)? else {
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
    Ok(Polled { records, more })
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
        assert!(!keys.contains(&"command".to_owned()));
        assert!(!keys.contains(&"originatingCommand".to_owned()));
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
        assert_eq!(r.user.as_deref(), Some("alice@admin"));
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
}
