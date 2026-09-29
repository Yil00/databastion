//! Audit records from the MongoDB log files (ADR-0027 decisions 3 and 4):
//! the Enterprise / Percona `auditLog` JSON file and the structured JSON
//! server log. The profiler builds the same [`Record`] (`profiler`).
//!
//! Only closed-shape fields are kept: the time, the command **kind**
//! ([`Cmd`], from a closed list of names), the namespace, the user
//! (`name@authdb`), the client address (an IP literal, the port only to
//! correlate `auditLog` records), the application name, document counts,
//! a failure flag, and three shape facts of the command ([`Shape`]): how
//! many keys its filter has, its numeric `limit`, and whether its
//! aggregation stages are all pass-through (or write with `$out` /
//! `$merge`).
//!
//! Command documents (`auditLog` `param.args`, the log's `command` and
//! `originatingCommand`) hold other users' literals: they are visited by a
//! `serde` reader that classifies keys without keeping them and skips every
//! value with `IgnoredAny` (no copy). `errMsg`, `planSummary`, the
//! `applicationMessage` text and every field not listed here are never
//! read. A record that does not parse is dropped (counted by the caller);
//! lines of the server log that are not audit-relevant are ignored.

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use databastion_classifiers::masking::ClientAddr;
use serde::Deserialize;
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use zeroize::Zeroizing;

/// Longest user, database, collection or application name kept, in bytes
/// (longer: the record is dropped).
pub(crate) const MAX_NAME_BYTES: usize = 1024;
/// Pipeline stages examined per command.
pub(crate) const MAX_STAGES: usize = 32;

/// What a command does, from its name (the first key of the command
/// document, or the `auditLog` `param.command`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cmd {
    Find,
    Aggregate,
    GetMore,
    Count,
    Distinct,
    MapReduce,
    Insert,
    Update,
    Delete,
    FindAndModify,
    BulkWrite,
    Ddl,
    Dcl,
    /// Metadata, session, authentication or unknown commands: no event.
    Other,
}

impl Cmd {
    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "find" => Self::Find,
            "aggregate" => Self::Aggregate,
            "getMore" => Self::GetMore,
            "count" => Self::Count,
            "distinct" => Self::Distinct,
            "mapReduce" | "mapreduce" => Self::MapReduce,
            "insert" => Self::Insert,
            "update" => Self::Update,
            "delete" => Self::Delete,
            "findAndModify" | "findandmodify" => Self::FindAndModify,
            "bulkWrite" => Self::BulkWrite,
            "create"
            | "drop"
            | "dropDatabase"
            | "createIndexes"
            | "dropIndexes"
            | "deleteIndexes"
            | "renameCollection"
            | "collMod"
            | "convertToCapped"
            | "cloneCollectionAsCapped" => Self::Ddl,
            "createUser"
            | "updateUser"
            | "dropUser"
            | "dropAllUsersFromDatabase"
            | "grantRolesToUser"
            | "revokeRolesFromUser"
            | "createRole"
            | "updateRole"
            | "dropRole"
            | "dropAllRolesFromDatabase"
            | "grantRolesToRole"
            | "revokeRolesFromRole"
            | "grantPrivilegesToRole"
            | "revokePrivilegesFromRole" => Self::Dcl,
            _ => Self::Other,
        }
    }

    /// A read that returns documents of a collection.
    pub(crate) fn returns_documents(self) -> bool {
        matches!(self, Self::Find | Self::Aggregate | Self::GetMore)
    }
}

/// The filter of a command.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Filter {
    /// No filter (absent).
    #[default]
    Absent,
    /// An object with this many top-level keys.
    Keys(u64),
    /// Not an object (a malformed command): shape unknown.
    Unknown,
}

impl Filter {
    /// Whether the filter selects every document.
    pub(crate) fn is_empty(self) -> bool {
        matches!(self, Self::Absent | Self::Keys(0))
    }
}

/// An aggregation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pipeline {
    /// Every stage is a pass-through stage (or there is none).
    pub(crate) pass_through: bool,
    /// A stage writes (`$out`, `$merge`).
    pub(crate) writes: bool,
}

/// A pipeline stage, classified by its operator (never kept as text).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageKind {
    PassThrough,
    Write,
    Other,
}

impl StageKind {
    pub(crate) fn from_operator(op: &str) -> Self {
        match op {
            "$project" | "$addFields" | "$set" | "$unset" | "$sort" | "$replaceRoot"
            | "$replaceWith" => Self::PassThrough,
            "$out" | "$merge" => Self::Write,
            _ => Self::Other,
        }
    }
}

impl Pipeline {
    pub(crate) fn from_stages(stages: impl IntoIterator<Item = StageKind>) -> Self {
        let mut p = Self {
            pass_through: true,
            writes: false,
        };
        for s in stages {
            match s {
                StageKind::PassThrough => {}
                StageKind::Write => p.writes = true,
                StageKind::Other => p.pass_through = false,
            }
        }
        p
    }
}

/// Shape facts of a command (never a value).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Shape {
    pub(crate) filter: Filter,
    /// Numeric `limit` (`None`: absent or not a number).
    pub(crate) limit: Option<i64>,
    pub(crate) pipeline: Option<Pipeline>,
}

/// Which connection a record belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ConnId {
    /// Server log `ctx` `conn<N>`.
    Log(u64),
    /// `auditLog` client address and port.
    Remote(IpAddr, u16),
}

/// What a record reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// An operation (a command on a namespace).
    Op(Cmd),
    /// An authentication (`ok`: it succeeded).
    Auth { ok: bool },
    /// The client's application name (`app`).
    ClientMeta,
    /// A connection was accepted (`client`).
    Accepted,
    /// A connection ended.
    Ended,
}

/// One audit record (see the module documentation).
#[derive(Clone)]
pub(crate) struct Record {
    pub(crate) ts: Option<SystemTime>,
    pub(crate) kind: Kind,
    pub(crate) conn: Option<ConnId>,
    /// `name@authdb` (zeroized: a failed authentication's name may be a
    /// mistyped password).
    pub(crate) user: Option<Zeroizing<String>>,
    pub(crate) client: Option<ClientAddr>,
    pub(crate) app: Option<String>,
    /// Database and collection (`None`: database-level command).
    pub(crate) ns: Option<(String, Option<String>)>,
    /// Documents returned (reads) or written (writes).
    pub(crate) rows: Option<u64>,
    /// The operation failed.
    pub(crate) failed: bool,
    pub(crate) shape: Shape,
    /// Shape of the command that opened the cursor (`getMore`).
    pub(crate) origin: Option<Shape>,
    /// The server's own activity (internal thread, system user).
    pub(crate) system: bool,
}

impl fmt::Debug for Record {
    // Names, users and application names are never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("kind", &self.kind)
            .field("rows", &self.rows)
            .field("failed", &self.failed)
            .field("shape", &self.shape)
            .finish_non_exhaustive()
    }
}

impl Record {
    pub(crate) fn new(kind: Kind) -> Self {
        Self {
            ts: None,
            kind,
            conn: None,
            user: None,
            client: None,
            app: None,
            ns: None,
            rows: None,
            failed: false,
            shape: Shape::default(),
            origin: None,
            system: false,
        }
    }
}

/// A name within [`MAX_NAME_BYTES`] and without NUL.
pub(crate) fn bounded(s: &str) -> Option<String> {
    (s.len() <= MAX_NAME_BYTES && !s.contains('\0')).then(|| s.to_owned())
}

/// `db.collection`: the database, and the collection unless the command is
/// database-level (`$cmd`) or has none.
pub(crate) fn namespace(ns: &str) -> Option<(String, Option<String>)> {
    let (db, coll) = match ns.split_once('.') {
        Some((db, coll)) => (db, Some(coll)),
        None => (ns, None),
    };
    if db.is_empty() {
        return None;
    }
    let coll = coll.filter(|c| !c.is_empty() && *c != "$cmd" && !c.starts_with("$cmd."));
    Some((
        bounded(db)?,
        coll.map(bounded).map_or(Some(None), |c| c.map(Some))?,
    ))
}

/// `name@db`, both non-empty.
pub(crate) fn user_at(user: &str, db: &str) -> Option<String> {
    (!user.is_empty() && !db.is_empty())
        .then(|| bounded(&format!("{user}@{db}")))
        .flatten()
}

/// An address as logged: `ip:port`, `[v6]:port`, or a bare IP literal.
/// Host names and Unix sockets give `None`.
pub(crate) fn address(raw: &str) -> Option<(IpAddr, Option<u16>)> {
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some((ip, None));
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let (ip, port) = rest.split_once("]:")?;
        return Some((ip.parse().ok()?, port.parse().ok()));
    }
    let (ip, port) = raw.rsplit_once(':')?;
    Some((
        ip.parse::<std::net::Ipv4Addr>().ok()?.into(),
        port.parse().ok(),
    ))
}

/// Days from 1970-01-01 to a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || !(1970..=9999).contains(&y) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn digits(s: &str) -> Option<u32> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM|±HHMM)`, as UTC.
pub(crate) fn iso_time(raw: &str) -> Option<SystemTime> {
    let b = raw.as_bytes();
    if !raw.is_ascii()
        || b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (h, mi, s) = (
        digits(&raw[11..13])?,
        digits(&raw[14..16])?,
        digits(&raw[17..19])?,
    );
    if h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(
        i64::from(digits(&raw[0..4])?),
        digits(&raw[5..7])?,
        digits(&raw[8..10])?,
    )?;
    let mut rest = &raw[19..];
    let mut millis = 0u64;
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 || n > 9 {
            return None;
        }
        let f = &frac[..n];
        millis = u64::from(digits(&format!("{f:0<3}")[..3])?);
        rest = &frac[n..];
    }
    let offset: i64 = match rest {
        "Z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let hm = rest[1..].replace(':', "");
            if hm.len() != 4 {
                return None;
            }
            let (oh, om) = (digits(&hm[..2])?, digits(&hm[2..])?);
            if oh > 18 || om > 59 {
                return None;
            }
            sign * (i64::from(oh) * 3600 + i64::from(om) * 60)
        }
    };
    let secs = days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(s) - offset;
    let secs = u64::try_from(secs).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs) + Duration::from_millis(millis))
}

/// Milliseconds since the epoch.
pub(crate) fn millis_time(ms: i64) -> Option<SystemTime> {
    let ms = u64::try_from(ms).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(ms))
}

/// Extended JSON date: `{"$date": "<ISO>"}`, `{"$date": <ms>}` or
/// `{"$date": {"$numberLong": "<ms>"}}`.
#[derive(Deserialize)]
struct DateField {
    #[serde(rename = "$date")]
    date: DateValue,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DateValue {
    Iso(String),
    Millis(i64),
    Long {
        #[serde(rename = "$numberLong")]
        n: String,
    },
}

impl DateField {
    fn time(&self) -> Option<SystemTime> {
        match &self.date {
            DateValue::Iso(s) => iso_time(s),
            DateValue::Millis(ms) => millis_time(*ms),
            DateValue::Long { n } => millis_time(n.parse().ok()?),
        }
    }
}

/// A count: a non-negative integer, or an integral double.
fn count_of(n: Option<&serde_json::Number>) -> Option<u64> {
    let n = n?;
    n.as_u64().or_else(|| {
        n.as_f64()
            .filter(|f| f.is_finite() && *f >= 0.0 && f.fract() == 0.0 && *f < 9.0e15)
            .map(|f| {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let v = f as u64;
                v
            })
    })
}

// ---- Command documents: keys classified, values skipped. ----

/// A command document's shape and kind.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct CommandShape {
    pub(crate) cmd: Option<Cmd>,
    pub(crate) shape: Shape,
}

/// The command name (first key), classified without being kept.
struct CmdKey(Cmd);

impl<'de> Deserialize<'de> for CmdKey {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = CmdKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a key")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<CmdKey, E> {
                Ok(CmdKey(Cmd::from_name(v)))
            }
        }
        d.deserialize_str(V)
    }
}

#[derive(Clone, Copy)]
enum FieldKey {
    Filter,
    Limit,
    Pipeline,
    Other,
}

impl<'de> Deserialize<'de> for FieldKey {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = FieldKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a key")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<FieldKey, E> {
                Ok(match v {
                    "filter" | "query" => FieldKey::Filter,
                    "limit" => FieldKey::Limit,
                    "pipeline" => FieldKey::Pipeline,
                    _ => FieldKey::Other,
                })
            }
        }
        d.deserialize_str(V)
    }
}

/// Counts the keys of an object, skipping its values.
struct KeyCount(Filter);

impl<'de> Deserialize<'de> for KeyCount {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = KeyCount;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<KeyCount, A::Error> {
                let mut n = 0u64;
                while map.next_key::<IgnoredAny>()?.is_some() {
                    map.next_value::<IgnoredAny>()?;
                    n = n.saturating_add(1);
                }
                Ok(KeyCount(Filter::Keys(n)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<KeyCount, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(KeyCount(Filter::Unknown))
            }
            fn visit_unit<E: de::Error>(self) -> Result<KeyCount, E> {
                Ok(KeyCount(Filter::Absent))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<KeyCount, E> {
                Ok(KeyCount(Filter::Unknown))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<KeyCount, E> {
                Ok(KeyCount(Filter::Unknown))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<KeyCount, E> {
                Ok(KeyCount(Filter::Unknown))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<KeyCount, E> {
                Ok(KeyCount(Filter::Unknown))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<KeyCount, E> {
                Ok(KeyCount(Filter::Unknown))
            }
        }
        d.deserialize_any(V)
    }
}

/// A numeric `limit`; anything else is `None` (skipped).
struct Limit(Option<i64>);

impl<'de> Deserialize<'de> for Limit {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Limit;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Limit, E> {
                Ok(Limit(Some(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Limit, E> {
                Ok(Limit(Some(i64::try_from(v).unwrap_or(i64::MAX))))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Limit, E> {
                #[allow(clippy::cast_possible_truncation)]
                Ok(Limit(
                    (v.is_finite() && v.abs() < 9.0e15).then_some(v.trunc() as i64),
                ))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Limit, A::Error> {
                while map.next_key::<IgnoredAny>()?.is_some() {
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(Limit(None))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Limit, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Limit(None))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Limit, E> {
                Ok(Limit(None))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Limit, E> {
                Ok(Limit(None))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Limit, E> {
                Ok(Limit(None))
            }
        }
        d.deserialize_any(V)
    }
}

/// A pipeline stage: its operator (first key) classified, values skipped.
struct Stage(StageKind);

impl<'de> Deserialize<'de> for Stage {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Op(StageKind);
        impl<'de> Deserialize<'de> for Op {
            fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl Visitor<'_> for V {
                    type Value = Op;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a key")
                    }
                    fn visit_str<E: de::Error>(self, v: &str) -> Result<Op, E> {
                        Ok(Op(StageKind::from_operator(v)))
                    }
                }
                d.deserialize_str(V)
            }
        }
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Stage;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Stage, A::Error> {
                let mut kind = StageKind::Other;
                let mut first = true;
                while first {
                    first = false;
                    if let Some(Op(k)) = map.next_key::<Op>()? {
                        kind = k;
                        map.next_value::<IgnoredAny>()?;
                    } else {
                        return Ok(Stage(StageKind::Other));
                    }
                }
                // A stage has one key; more make it unknown.
                if map.next_key::<IgnoredAny>()?.is_some() {
                    map.next_value::<IgnoredAny>()?;
                    kind = StageKind::Other;
                    while map.next_key::<IgnoredAny>()?.is_some() {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(Stage(kind))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Stage, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Stage(StageKind::Other))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Stage, E> {
                Ok(Stage(StageKind::Other))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Stage, E> {
                Ok(Stage(StageKind::Other))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Stage, E> {
                Ok(Stage(StageKind::Other))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Stage, E> {
                Ok(Stage(StageKind::Other))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Stage, E> {
                Ok(Stage(StageKind::Other))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Stage, E> {
                Ok(Stage(StageKind::Other))
            }
        }
        d.deserialize_any(V)
    }
}

/// A pipeline (array of stages); anything else is `None`.
struct PipelineField(Option<Pipeline>);

impl<'de> Deserialize<'de> for PipelineField {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = PipelineField;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<PipelineField, A::Error> {
                let mut stages = Vec::new();
                let mut more = false;
                while stages.len() < MAX_STAGES {
                    match seq.next_element::<Stage>()? {
                        Some(Stage(k)) => stages.push(k),
                        None => break,
                    }
                }
                while seq.next_element::<IgnoredAny>()?.is_some() {
                    more = true;
                }
                if more {
                    // Stages not examined: not a known pass-through.
                    stages.push(StageKind::Other);
                }
                Ok(PipelineField(Some(Pipeline::from_stages(stages))))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<PipelineField, A::Error> {
                while map.next_key::<IgnoredAny>()?.is_some() {
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(PipelineField(None))
            }
            fn visit_unit<E: de::Error>(self) -> Result<PipelineField, E> {
                Ok(PipelineField(None))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<PipelineField, E> {
                Ok(PipelineField(None))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<PipelineField, E> {
                Ok(PipelineField(None))
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<PipelineField, E> {
                Ok(PipelineField(None))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<PipelineField, E> {
                Ok(PipelineField(None))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<PipelineField, E> {
                Ok(PipelineField(None))
            }
        }
        d.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for CommandShape {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = CommandShape;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a command document")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<CommandShape, A::Error> {
                let mut out = CommandShape::default();
                if let Some(CmdKey(cmd)) = map.next_key::<CmdKey>()? {
                    out.cmd = Some(cmd);
                    map.next_value::<IgnoredAny>()?;
                }
                while let Some(k) = map.next_key::<FieldKey>()? {
                    match k {
                        FieldKey::Filter => out.shape.filter = map.next_value::<KeyCount>()?.0,
                        FieldKey::Limit => out.shape.limit = map.next_value::<Limit>()?.0,
                        FieldKey::Pipeline => {
                            out.shape.pipeline = map.next_value::<PipelineField>()?.0;
                        }
                        FieldKey::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_map(V)
    }
}

// ---- auditLog (Enterprise / Percona, JSON, schema `mongo`). ----

#[derive(Deserialize)]
struct AuditHead {
    atype: String,
    #[serde(default)]
    ts: Option<DateField>,
    #[serde(default)]
    remote: Option<Endpoint>,
    #[serde(default)]
    users: Option<Vec<UserRef>>,
    #[serde(default)]
    result: Option<i64>,
}

#[derive(Deserialize)]
struct Endpoint {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default, rename = "isSystemUser")]
    system: Option<bool>,
}

#[derive(Deserialize)]
struct UserRef {
    user: String,
    db: String,
}

#[derive(Deserialize)]
struct AuthCheckLine {
    param: AuthCheckParam,
}

#[derive(Deserialize)]
struct AuthCheckParam {
    command: String,
    #[serde(default)]
    ns: Option<String>,
    #[serde(default)]
    args: Option<CommandShape>,
}

#[derive(Deserialize)]
struct AuthenticateLine {
    param: AuthenticateParam,
}

#[derive(Deserialize)]
struct AuthenticateParam {
    user: String,
    db: String,
}

#[derive(Deserialize)]
struct NsLine {
    param: NsParam,
}

#[derive(Deserialize)]
struct NsParam {
    #[serde(default)]
    ns: Option<String>,
    #[serde(default)]
    old: Option<String>,
}

#[derive(Deserialize)]
struct ClientMetadataLine {
    param: ClientMetadataParam,
}

#[derive(Deserialize)]
struct ClientMetadataParam {
    #[serde(rename = "clientMetadata")]
    metadata: ClientDoc,
}

#[derive(Deserialize)]
struct ClientDoc {
    #[serde(default)]
    application: Option<Application>,
}

#[derive(Deserialize)]
struct Application {
    #[serde(default)]
    name: Option<String>,
}

const AUDIT_DDL: &[&str] = &[
    "createCollection",
    "createDatabase",
    "createIndex",
    "renameCollection",
    "dropCollection",
    "dropDatabase",
    "dropIndex",
];

const AUDIT_DCL: &[&str] = &[
    "createUser",
    "dropUser",
    "dropAllUsersFromDatabase",
    "updateUser",
    "grantRolesToUser",
    "revokeRolesFromUser",
    "createRole",
    "updateRole",
    "dropRole",
    "dropAllRolesFromDatabase",
    "grantRolesToRole",
    "revokeRolesFromRole",
    "grantPrivilegesToRole",
    "revokePrivilegesFromRole",
];

/// Parses one `auditLog` record. `Ok(None)`: a valid record that yields
/// nothing (another `atype`); `Err(())`: not a record (dropped, counted).
#[allow(clippy::result_unit_err)]
pub(crate) fn parse_audit_log(bytes: &[u8]) -> Result<Option<Record>, ()> {
    let head: AuditHead = serde_json::from_slice(bytes).map_err(|_| ())?;
    let (client, port, system) = match &head.remote {
        Some(e) => {
            let ip = e.ip.as_deref().and_then(|ip| ip.parse::<IpAddr>().ok());
            (ip, e.port, e.system == Some(true))
        }
        None => (None, None, false),
    };
    let user = head
        .users
        .as_ref()
        .and_then(|u| u.first())
        .and_then(|u| user_at(&u.user, &u.db))
        .map(Zeroizing::new);
    let base = |kind: Kind| {
        let mut r = Record::new(kind);
        r.ts = head.ts.as_ref().and_then(DateField::time);
        r.client = client.map(ClientAddr::Ip);
        r.conn = client.zip(port).map(|(ip, p)| ConnId::Remote(ip, p));
        r.user.clone_from(&user);
        r.system = system;
        r.failed = head.result.is_some_and(|c| c != 0);
        r
    };
    let atype = head.atype.as_str();
    Ok(match atype {
        "authCheck" => {
            let line: AuthCheckLine = serde_json::from_slice(bytes).map_err(|_| ())?;
            let cmd = Cmd::from_name(&line.param.command);
            // DDL and DCL come from their own records (decision 4).
            if matches!(cmd, Cmd::Ddl | Cmd::Dcl | Cmd::Other) {
                return Ok(None);
            }
            let mut r = base(Kind::Op(cmd));
            r.ns = match line.param.ns.as_deref() {
                Some(ns) => Some(namespace(ns).ok_or(())?),
                None => None,
            };
            if let Some(args) = line.param.args {
                r.shape = args.shape;
            }
            Some(r)
        }
        "authenticate" => {
            let line: AuthenticateLine = serde_json::from_slice(bytes).map_err(|_| ())?;
            let ok = head.result == Some(0);
            let mut r = base(Kind::Auth { ok });
            let name = Zeroizing::new(line.param.user);
            r.user = Some(Zeroizing::new(user_at(&name, &line.param.db).ok_or(())?));
            Some(r)
        }
        "clientMetadata" => {
            let line: ClientMetadataLine = serde_json::from_slice(bytes).map_err(|_| ())?;
            let mut r = base(Kind::ClientMeta);
            r.app = line
                .param
                .metadata
                .application
                .and_then(|a| a.name)
                .and_then(|n| bounded(&n));
            Some(r)
        }
        t if AUDIT_DDL.contains(&t) => {
            let line: NsLine = serde_json::from_slice(bytes).map_err(|_| ())?;
            let mut r = base(Kind::Op(Cmd::Ddl));
            let ns = line.param.ns.or(line.param.old).ok_or(())?;
            r.ns = Some(namespace(&ns).ok_or(())?);
            Some(r)
        }
        t if AUDIT_DCL.contains(&t) => Some(base(Kind::Op(Cmd::Dcl))),
        // An explicit logout, or (MongoDB 5.0+) the implicit one when the
        // client disconnects: the endpoint's application name is
        // forgotten (end-of-phase-5 review L4). No event.
        "logout" => Some(base(Kind::Ended)),
        _ => None,
    })
}

// ---- Structured JSON server log (MongoDB 4.4 and later). ----

/// Slow query.
const ID_SLOW_QUERY: i64 = 51803;
/// Connection accepted.
const ID_ACCEPTED: i64 = 22943;
/// Connection ended.
const ID_ENDED: i64 = 22944;
/// Client metadata.
const ID_CLIENT_METADATA: i64 = 51800;
/// Successfully authenticated (5.0+ / 4.4).
const ID_AUTH_OK: [i64; 2] = [5_286_306, 20250];
/// Failed to authenticate (5.0+ / 4.4).
const ID_AUTH_FAILED: [i64; 2] = [5_286_307, 20249];

#[derive(Deserialize)]
struct LogHead {
    id: i64,
    #[serde(default)]
    t: Option<DateField>,
    #[serde(default)]
    ctx: Option<String>,
}

#[derive(Deserialize)]
struct SlowLine {
    attr: SlowAttr,
}

#[derive(Deserialize)]
struct SlowAttr {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    ns: Option<String>,
    #[serde(default, rename = "appName")]
    app: Option<String>,
    #[serde(default)]
    command: Option<CommandShape>,
    #[serde(default, rename = "originatingCommand")]
    origin: Option<CommandShape>,
    #[serde(default)]
    nreturned: Option<serde_json::Number>,
    #[serde(default)]
    ninserted: Option<serde_json::Number>,
    #[serde(default, rename = "nModified")]
    modified: Option<serde_json::Number>,
    #[serde(default)]
    ndeleted: Option<serde_json::Number>,
    #[serde(default, rename = "nUpserted")]
    upserted: Option<serde_json::Number>,
    #[serde(default, rename = "errCode")]
    err_code: Option<serde_json::Number>,
    #[serde(default)]
    remote: Option<String>,
}

#[derive(Deserialize)]
struct AcceptedLine {
    attr: AcceptedAttr,
}

#[derive(Deserialize)]
struct AcceptedAttr {
    #[serde(default)]
    remote: Option<String>,
    #[serde(rename = "connectionId")]
    connection_id: u64,
}

#[derive(Deserialize)]
struct MetadataLine {
    attr: MetadataAttr,
}

#[derive(Deserialize)]
struct MetadataAttr {
    #[serde(default)]
    remote: Option<String>,
    doc: ClientDoc,
}

#[derive(Deserialize)]
struct AuthLine {
    attr: AuthAttr,
}

#[derive(Deserialize)]
struct AuthAttr {
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    db: Option<String>,
    #[serde(default, rename = "principalName")]
    principal: Option<String>,
    #[serde(default, rename = "authenticationDatabase")]
    auth_db: Option<String>,
    #[serde(default)]
    client: Option<String>,
    #[serde(default)]
    remote: Option<String>,
    #[serde(default, rename = "isClusterMember")]
    cluster_member: Option<bool>,
}

fn conn_of(ctx: Option<&str>) -> Option<u64> {
    ctx?.strip_prefix("conn")?.parse().ok()
}

fn client_of(raw: Option<&str>) -> Option<ClientAddr> {
    address(raw?).map(|(ip, _)| ClientAddr::Ip(ip))
}

fn sum(counts: &[Option<&serde_json::Number>]) -> Option<u64> {
    counts
        .iter()
        .filter_map(|n| count_of(*n))
        .fold(None, |acc: Option<u64>, n| {
            Some(acc.unwrap_or(0).saturating_add(n))
        })
}

/// Parses one server log line. `Ok(None)`: a log line that is not an
/// audit record (most lines); `Err(())`: not a log line, or an audit line
/// that does not parse (dropped, counted).
#[allow(clippy::result_unit_err)]
pub(crate) fn parse_server_log(bytes: &[u8]) -> Result<Option<Record>, ()> {
    let head: LogHead = serde_json::from_slice(bytes).map_err(|_| ())?;
    let conn = conn_of(head.ctx.as_deref());
    let base = |kind: Kind| {
        let mut r = Record::new(kind);
        r.ts = head.t.as_ref().and_then(DateField::time);
        r.conn = conn.map(ConnId::Log);
        // Internal threads (no client connection).
        r.system = conn.is_none();
        r
    };
    Ok(match head.id {
        ID_SLOW_QUERY => {
            let line: SlowLine = serde_json::from_slice(bytes).map_err(|_| ())?;
            let a = line.attr;
            // Per-statement write lines: the command line covers them.
            if a.kind.as_deref() != Some("command") {
                return Ok(None);
            }
            let Some(command) = a.command else {
                return Ok(None);
            };
            let cmd = command.cmd.unwrap_or(Cmd::Other);
            if cmd == Cmd::Other {
                return Ok(None);
            }
            let mut r = base(Kind::Op(cmd));
            r.ns = match a.ns.as_deref() {
                Some(ns) => Some(namespace(ns).ok_or(())?),
                None => None,
            };
            // A descriptive field that is not valid is dropped, never the
            // record (an application name with a NUL must not hide it).
            r.app = a.app.as_deref().and_then(bounded);
            r.client = client_of(a.remote.as_deref());
            r.shape = command.shape;
            r.origin = a.origin.map(|o| o.shape);
            r.rows = if matches!(
                cmd,
                Cmd::Insert | Cmd::Update | Cmd::Delete | Cmd::FindAndModify | Cmd::BulkWrite
            ) {
                sum(&[
                    a.ninserted.as_ref(),
                    a.modified.as_ref(),
                    a.ndeleted.as_ref(),
                    a.upserted.as_ref(),
                ])
                .or_else(|| count_of(a.nreturned.as_ref()))
            } else {
                count_of(a.nreturned.as_ref())
            };
            r.failed = a.err_code.as_ref().is_some_and(|c| c.as_i64() != Some(0));
            Some(r)
        }
        ID_ACCEPTED => {
            let line: AcceptedLine = serde_json::from_slice(bytes).map_err(|_| ())?;
            let mut r = base(Kind::Accepted);
            // The accept line is logged by the listener thread.
            r.conn = Some(ConnId::Log(line.attr.connection_id));
            r.system = false;
            r.client = client_of(line.attr.remote.as_deref());
            Some(r)
        }
        ID_ENDED => conn.map(|_| base(Kind::Ended)),
        ID_CLIENT_METADATA => {
            let line: MetadataLine = serde_json::from_slice(bytes).map_err(|_| ())?;
            let mut r = base(Kind::ClientMeta);
            r.client = client_of(line.attr.remote.as_deref());
            r.app = line
                .attr
                .doc
                .application
                .and_then(|a| a.name)
                .and_then(|n| bounded(&n));
            Some(r)
        }
        id if ID_AUTH_OK.contains(&id) || ID_AUTH_FAILED.contains(&id) => {
            let line: AuthLine = serde_json::from_slice(bytes).map_err(|_| ())?;
            let a = line.attr;
            let mut r = base(Kind::Auth {
                ok: ID_AUTH_OK.contains(&id),
            });
            let user = Zeroizing::new(a.user.or(a.principal).unwrap_or_default());
            let db = a.db.or(a.auth_db).unwrap_or_default();
            r.user = Some(Zeroizing::new(user_at(&user, &db).ok_or(())?));
            r.client = client_of(a.client.as_deref().or(a.remote.as_deref()));
            // Intra-cluster authentication (replication, sharding).
            r.system |= a.cluster_member == Some(true);
            Some(r)
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn secs(t: SystemTime) -> u64 {
        t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn iso_times_with_offsets() {
        let t = iso_time("2026-09-29T10:00:00.123+00:00").unwrap();
        assert_eq!(secs(t), 1_790_676_000);
        assert_eq!(
            t.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                % 1000,
            123
        );
        assert_eq!(
            secs(iso_time("2026-09-29T12:00:00.000+0200").unwrap()),
            1_790_676_000
        );
        assert_eq!(
            secs(iso_time("2026-09-29T10:00:00Z").unwrap()),
            1_790_676_000
        );
        assert_eq!(
            secs(iso_time("2026-09-29T05:30:00-04:30").unwrap()),
            1_790_676_000
        );
        for bad in [
            "",
            "2026-09-29T10:00:00",
            "2026-13-29T10:00:00Z",
            "2026-09-29T25:00:00Z",
            "2026-09-29T10:00:00+99:00",
            "2026-09-29T10:00:00.Z",
            "2026-09-29T10:00:00.1234567890Z",
            "1969-12-31T23:59:59Z",
            "2026-09-29T10:00:00é",
        ] {
            assert!(iso_time(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn namespaces_and_addresses() {
        assert_eq!(
            namespace("app.customers"),
            Some(("app".to_owned(), Some("customers".to_owned())))
        );
        assert_eq!(
            namespace("app.fs.files"),
            Some(("app".to_owned(), Some("fs.files".to_owned())))
        );
        assert_eq!(namespace("app.$cmd"), Some(("app".to_owned(), None)));
        assert_eq!(
            namespace("app.$cmd.aggregate"),
            Some(("app".to_owned(), None))
        );
        assert_eq!(namespace("app"), Some(("app".to_owned(), None)));
        assert_eq!(namespace(".x"), None);
        assert_eq!(
            address("172.18.0.1:53422"),
            Some(("172.18.0.1".parse().unwrap(), Some(53422)))
        );
        assert_eq!(
            address("[::1]:27017"),
            Some(("::1".parse().unwrap(), Some(27017)))
        );
        assert_eq!(
            address("10.0.0.5"),
            Some(("10.0.0.5".parse().unwrap(), None))
        );
        assert_eq!(address("db.example:27017"), None);
        assert_eq!(address("anonymous unix socket:27017"), None);
    }

    const SLOW_FIND: &str = r#"{"t":{"$date":"2026-09-29T10:00:00.123+00:00"},"s":"I","c":"COMMAND","id":51803,"ctx":"conn12","msg":"Slow query","attr":{"type":"command","ns":"app.customers","appName":"mongodump","command":{"find":"customers","filter":{},"lsid":{"id":{"$uuid":"0b1b7b36-0000-0000-0000-000000000000"}},"$db":"app"},"planSummary":"COLLSCAN","keysExamined":0,"docsExamined":120,"cursorExhausted":true,"numYields":0,"nreturned":120,"reslen":9000,"remote":"172.18.0.1:53422","protocol":"op_msg","durationMillis":0}}"#;

    #[test]
    fn server_log_slow_query() {
        let r = parse_server_log(SLOW_FIND.as_bytes()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Find));
        assert_eq!(r.conn, Some(ConnId::Log(12)));
        assert_eq!(r.app.as_deref(), Some("mongodump"));
        assert_eq!(r.rows, Some(120));
        assert_eq!(r.shape.filter, Filter::Keys(0));
        assert_eq!(r.client, ClientAddr::parse("172.18.0.1"));
        assert!(!r.system && !r.failed);
        // A filter with literals: only its key count is kept.
        let line = SLOW_FIND.replace(
            r#""filter":{}"#,
            r#""filter":{"email":"jane.doe@example.com","n":{"$gt":5}},"limit":20"#,
        );
        let r = parse_server_log(line.as_bytes()).unwrap().unwrap();
        assert_eq!(r.shape.filter, Filter::Keys(2));
        assert_eq!(r.shape.limit, Some(20));
        assert!(!format!("{r:?}").contains("jane"));
    }

    /// Security review M3: an invalid application name (a NUL) drops the
    /// name, never the record.
    #[test]
    fn an_invalid_application_name_does_not_hide_the_operation() {
        let line = SLOW_FIND.replace(r#""appName":"mongodump""#, r#""appName":"mongo\u0000dump""#);
        let r = parse_server_log(line.as_bytes()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Find));
        assert!(r.app.is_none());
        let long = SLOW_FIND.replace("mongodump", &"x".repeat(MAX_NAME_BYTES + 1));
        assert!(
            parse_server_log(long.as_bytes())
                .unwrap()
                .unwrap()
                .app
                .is_none()
        );
        // An invalid namespace still drops the record.
        let ns = SLOW_FIND.replace(r#""ns":"app.customers""#, r#""ns":"a\u0000b.c""#);
        assert!(parse_server_log(ns.as_bytes()).is_err());
    }

    #[test]
    fn server_log_other_lines() {
        let accepted = r#"{"t":{"$date":"2026-09-29T10:00:00.000+00:00"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"Connection accepted","attr":{"remote":"172.18.0.1:53422","isLoadBalanced":false,"uuid":{"uuid":{"$uuid":"0b1b7b36-0000-0000-0000-000000000000"}},"connectionId":12,"connectionCount":3}}"#;
        let r = parse_server_log(accepted.as_bytes()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Accepted);
        assert_eq!(r.conn, Some(ConnId::Log(12)));
        assert!(!r.system);
        let auth = r#"{"t":{"$date":"2026-09-29T10:00:00.000+00:00"},"s":"I","c":"ACCESS","id":5286306,"ctx":"conn12","msg":"Successfully authenticated","attr":{"client":"172.18.0.1:53422","isSpeculative":true,"isClusterMember":false,"mechanism":"SCRAM-SHA-256","user":"alice","db":"admin","result":0,"metrics":{"conversation_duration":{"micros":5000,"summary":{}}},"extraInfo":{}}}"#;
        let r = parse_server_log(auth.as_bytes()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Auth { ok: true });
        assert_eq!(r.user.as_ref().map(|u| u.as_str()), Some("alice@admin"));
        let failed = r#"{"t":{"$date":"2026-09-29T10:00:00.000+00:00"},"s":"I","c":"ACCESS","id":5286307,"ctx":"conn13","msg":"Failed to authenticate","attr":{"client":"10.0.0.9:1234","isSpeculative":false,"isClusterMember":false,"mechanism":"SCRAM-SHA-256","user":"hunter2-secret","db":"admin","error":"AuthenticationFailed: SCRAM authentication failed, storedKey mismatch","result":18}}"#;
        let r = parse_server_log(failed.as_bytes()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Auth { ok: false });
        let meta = r#"{"t":{"$date":"2026-09-29T10:00:00.000+00:00"},"s":"I","c":"NETWORK","id":51800,"ctx":"conn12","msg":"client metadata","attr":{"remote":"172.18.0.1:53422","client":"conn12","negotiatedCompressors":[],"doc":{"application":{"name":"mongoexport"},"driver":{"name":"mongo-go-driver","version":"1.12"},"os":{"type":"linux"}}}}"#;
        let r = parse_server_log(meta.as_bytes()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::ClientMeta);
        assert_eq!(r.app.as_deref(), Some("mongoexport"));
        let ended = r#"{"t":{"$date":"2026-09-29T10:00:00.000+00:00"},"s":"I","c":"NETWORK","id":22944,"ctx":"conn12","msg":"Connection ended","attr":{"remote":"172.18.0.1:53422","connectionId":12,"connectionCount":2}}"#;
        assert_eq!(
            parse_server_log(ended.as_bytes()).unwrap().unwrap().kind,
            Kind::Ended
        );
        // Unrelated lines are ignored, not dropped.
        let other = r#"{"t":{"$date":"2026-09-29T10:00:00.000+00:00"},"s":"I","c":"STORAGE","id":22430,"ctx":"Checkpointer","msg":"WiredTiger message","attr":{"message":{"ts_sec":1}}}"#;
        assert!(parse_server_log(other.as_bytes()).unwrap().is_none());
        // Internal threads are the server's own activity.
        let internal = SLOW_FIND.replace(r#""ctx":"conn12""#, r#""ctx":"TTLMonitor""#);
        assert!(
            parse_server_log(internal.as_bytes())
                .unwrap()
                .unwrap()
                .system
        );
        // Not a log line.
        assert!(parse_server_log(b"not json").is_err());
        assert!(parse_server_log(b"[1,2]").is_err());
    }

    #[test]
    fn pipelines_are_classified_by_their_operators() {
        let agg = |p: &str| {
            let line = SLOW_FIND.replace(
                r#""find":"customers","filter":{}"#,
                &format!(r#""aggregate":"customers","pipeline":{p},"cursor":{{}}"#),
            );
            parse_server_log(line.as_bytes()).unwrap().unwrap()
        };
        let r = agg(r#"[{"$project":{"email":1}},{"$sort":{"_id":1}}]"#);
        assert_eq!(r.kind, Kind::Op(Cmd::Aggregate));
        assert_eq!(
            r.shape.pipeline,
            Some(Pipeline {
                pass_through: true,
                writes: false
            })
        );
        let r = agg(r#"[{"$match":{"email":"jane@example.com"}}]"#);
        assert!(!r.shape.pipeline.unwrap().pass_through);
        let r = agg(r#"[{"$out":"copy"}]"#);
        assert!(r.shape.pipeline.unwrap().writes);
        let r = agg("[]");
        assert!(r.shape.pipeline.unwrap().pass_through);
        let many = format!(
            "[{}]",
            vec![r#"{"$set":{"a":1}}"#; MAX_STAGES + 1].join(",")
        );
        assert!(!agg(&many).shape.pipeline.unwrap().pass_through);
    }

    #[test]
    fn audit_log_records() {
        let find = r#"{ "atype" : "authCheck", "ts" : { "$date" : "2026-09-29T10:00:00.000+00:00" }, "uuid" : { "$binary" : "AAAA", "$type" : "04" }, "local" : { "ip" : "127.0.0.1", "port" : 27017 }, "remote" : { "ip" : "10.0.0.9", "port" : 51000 }, "users" : [ { "user" : "alice", "db" : "admin" } ], "roles" : [ { "role" : "readWrite", "db" : "app" } ], "param" : { "command" : "find", "ns" : "app.customers", "args" : { "find" : "customers", "filter" : { "iban" : "FR7630006000011234567890189" }, "$db" : "app" } }, "result" : 0 }"#;
        let r = parse_audit_log(find.as_bytes()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Find));
        assert_eq!(r.user.as_ref().map(|u| u.as_str()), Some("alice@admin"));
        assert_eq!(r.shape.filter, Filter::Keys(1));
        assert_eq!(
            r.conn,
            Some(ConnId::Remote("10.0.0.9".parse().unwrap(), 51000))
        );
        assert!(r.rows.is_none() && !r.failed);
        // Percona date form.
        let percona = find.replace(
            r#"{ "$date" : "2026-09-29T10:00:00.000+00:00" }"#,
            r#"{ "$date" : { "$numberLong" : "1790676000000" } }"#,
        );
        let r = parse_audit_log(percona.as_bytes()).unwrap().unwrap();
        assert_eq!(secs(r.ts.unwrap()), 1_790_676_000);
        // Refused: failed.
        let refused = find.replace(r#""result" : 0"#, r#""result" : 13"#);
        assert!(parse_audit_log(refused.as_bytes()).unwrap().unwrap().failed);
        // DDL through authCheck is skipped; the DDL record counts.
        let drop = find.replace(r#""command" : "find""#, r#""command" : "drop""#);
        assert!(parse_audit_log(drop.as_bytes()).unwrap().is_none());
        let ddl = r#"{"atype":"dropCollection","ts":{"$date":"2026-09-29T10:00:00.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[{"user":"alice","db":"admin"}],"param":{"ns":"app.customers"},"result":0}"#;
        let r = parse_audit_log(ddl.as_bytes()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Op(Cmd::Ddl));
        let dcl = r#"{"atype":"createUser","ts":{"$date":"2026-09-29T10:00:00.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[{"user":"alice","db":"admin"}],"param":{"user":"bob","db":"app","customData":{"note":"x"},"roles":[]},"result":0}"#;
        assert_eq!(
            parse_audit_log(dcl.as_bytes()).unwrap().unwrap().kind,
            Kind::Op(Cmd::Dcl)
        );
        let auth = r#"{"atype":"authenticate","ts":{"$date":"2026-09-29T10:00:00.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[],"param":{"user":"mallory","db":"admin","mechanism":"SCRAM-SHA-256"},"result":18}"#;
        let r = parse_audit_log(auth.as_bytes()).unwrap().unwrap();
        assert_eq!(r.kind, Kind::Auth { ok: false });
        assert_eq!(r.user.as_ref().map(|u| u.as_str()), Some("mallory@admin"));
        let meta = r#"{"atype":"clientMetadata","ts":{"$date":"2026-09-29T10:00:00.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[],"param":{"localEndpoint":{"ip":"127.0.0.1","port":27017},"clientMetadata":{"application":{"name":"mongodump"},"driver":{"name":"mongo-go-driver"}}},"result":0}"#;
        let r = parse_audit_log(meta.as_bytes()).unwrap().unwrap();
        assert_eq!(r.app.as_deref(), Some("mongodump"));
        // Free-text application messages are never parsed.
        let msg = r#"{"atype":"applicationMessage","ts":{"$date":"2026-09-29T10:00:00.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[],"param":{"msg":"card 4970101234567890"},"result":0}"#;
        assert!(parse_audit_log(msg.as_bytes()).unwrap().is_none());
        // The server's own user.
        let sys = find.replace(
            r#""remote" : { "ip" : "10.0.0.9", "port" : 51000 }"#,
            r#""remote" : { "isSystemUser" : true }"#,
        );
        assert!(parse_audit_log(sys.as_bytes()).unwrap().unwrap().system);
        // OCSF or garbage: dropped.
        assert!(parse_audit_log(br#"{"activity_id":1,"category_uid":3}"#).is_err());
        assert!(parse_audit_log(b"{\"atype\":").is_err());
    }
}
