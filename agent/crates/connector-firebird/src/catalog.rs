//! The catalog Discovery reads (ADR-0060 decision 5, refinement R3), and
//! what it decides from it: which relations are sampled, how each column
//! is converted, how a wide table is split into column batches.
//!
//! Nothing here holds a value of a table: names and types only.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use databastion_core::cas_guard::{self, StoreKind};
use tokio::time::Instant;

use crate::conn::Session;
use crate::error::FbError;
use crate::sql::{self, Col, Conv, Value};

/// Most relations read per database (decision 5).
pub(crate) const MAX_RELATIONS: usize = 16_384;
/// Most column rows read per database; past it, the relations whose
/// columns were cut are `skipped_limit`.
pub(crate) const MAX_COLUMNS: usize = 65_536;

/// The relation-list read's columns ([`sql::RELATIONS`]).
pub(crate) const RELATIONS_SHAPE: [Col; 5] =
    [Col::Octets(252), Col::Int, Col::Bool, Col::Bool, Col::Bool];
/// The column-list read's columns ([`sql::COLUMNS`]).
pub(crate) const COLUMNS_SHAPE: [Col; 10] = [
    Col::Octets(252),
    Col::Octets(252),
    Col::Int,
    Col::Int,
    Col::Int,
    Col::Int,
    Col::Int,
    Col::Int,
    Col::Bool,
    Col::Bool,
];

/// Relation names Discovery never samples, **whatever their system flag**
/// (decision 5, security review M5; refinement R3: `RDB$CONFIG` named):
/// every system relation of the tested images (Firebird 4.0.7 and 5.0.4;
/// the integration drift test fails on a system relation not listed) and
/// the security-database relations. A user relation with one of these
/// names is counted `skipped_unsupported`; the list, not the prefix,
/// decides.
pub(crate) const NEVER_SAMPLED: &[&str] = &[
    "MON$ATTACHMENTS",
    "MON$CALL_STACK",
    "MON$COMPILED_STATEMENTS",
    "MON$CONTEXT_VARIABLES",
    "MON$DATABASE",
    "MON$IO_STATS",
    "MON$MEMORY_USAGE",
    "MON$RECORD_STATS",
    "MON$STATEMENTS",
    "MON$TABLE_STATS",
    "MON$TRANSACTIONS",
    "PLG$SRP",
    "PLG$SRP_VIEW",
    "PLG$USERS",
    "PLG$VIEW_USERS",
    "RDB$AUTH_MAPPING",
    "RDB$BACKUP_HISTORY",
    "RDB$CHARACTER_SETS",
    "RDB$CHECK_CONSTRAINTS",
    "RDB$COLLATIONS",
    "RDB$CONFIG",
    "RDB$DATABASE",
    "RDB$DB_CREATORS",
    "RDB$DEPENDENCIES",
    "RDB$EXCEPTIONS",
    "RDB$FIELDS",
    "RDB$FIELD_DIMENSIONS",
    "RDB$FILES",
    "RDB$FILTERS",
    "RDB$FORMATS",
    "RDB$FUNCTIONS",
    "RDB$FUNCTION_ARGUMENTS",
    "RDB$GENERATORS",
    "RDB$INDEX_SEGMENTS",
    "RDB$INDICES",
    "RDB$KEYWORDS",
    "RDB$LOG_FILES",
    "RDB$PACKAGES",
    "RDB$PAGES",
    "RDB$PROCEDURES",
    "RDB$PROCEDURE_PARAMETERS",
    "RDB$PUBLICATIONS",
    "RDB$PUBLICATION_TABLES",
    "RDB$REF_CONSTRAINTS",
    "RDB$RELATIONS",
    "RDB$RELATION_CONSTRAINTS",
    "RDB$RELATION_FIELDS",
    "RDB$ROLES",
    "RDB$SECURITY_CLASSES",
    "RDB$TIME_ZONES",
    "RDB$TRANSACTIONS",
    "RDB$TRIGGERS",
    "RDB$TRIGGER_MESSAGES",
    "RDB$TYPES",
    "RDB$USER_PRIVILEGES",
    "RDB$VIEW_RELATIONS",
    "SEC$DB_CREATORS",
    "SEC$GLOBAL_AUTH_MAPPING",
    "SEC$USERS",
    "SEC$USER_ATTRIBUTES",
];

/// The profiler's tables and views (`PLG$PROF_*`, Firebird 5.0), never
/// sampled whatever their flag (decision 5).
pub(crate) const NEVER_SAMPLED_PREFIX: &str = "PLG$PROF_";

/// The prefixes of system names: a user table with one that is not on the
/// list is sampled, the prefix noted in the local detail.
const SYSTEM_PREFIXES: [&str; 4] = ["RDB$", "MON$", "SEC$", "PLG$"];

/// Whether Discovery never samples a relation of this name.
#[must_use]
pub(crate) fn never_sampled(name: &str) -> bool {
    NEVER_SAMPLED.contains(&name) || name.starts_with(NEVER_SAMPLED_PREFIX)
}

/// Whether a name carries a system prefix (for the local detail only).
#[must_use]
pub(crate) fn system_prefixed(name: &str) -> bool {
    SYSTEM_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Drops the trailing spaces of a catalog name (decision 5: catalog names
/// are padded `CHAR(63)`; trailing spaces are never significant in a
/// Firebird name, so this is not an alteration).
#[must_use]
pub(crate) fn trimmed(name: &str) -> &str {
    name.trim_end_matches(' ')
}

/// What a relation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A persistent table (`RDB$RELATION_TYPE = 0`, no view BLR, no
    /// external file).
    Table,
    /// A view (`coverage.views_not_sampled`).
    View,
    /// An external-file table (`coverage.external_file_tables`,
    /// `skipped_remote`).
    External,
    /// A global temporary table (types 4 and 5: their rows belong to other
    /// attachments; counted in the local detail).
    Temporary,
    /// Anything else (a virtual table): never sampled.
    Other,
}

/// One user relation of the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Relation {
    pub(crate) name: String,
    pub(crate) kind: Kind,
    /// The server's answer to "can the account read it" (a refusal at
    /// sampling counts the same).
    pub(crate) readable: bool,
}

/// One column of a persistent user table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Column {
    pub(crate) relation: String,
    pub(crate) name: String,
    pub(crate) field_type: i64,
    pub(crate) sub_type: i64,
    pub(crate) charset: i64,
    pub(crate) array: bool,
    pub(crate) computed: bool,
}

/// `RDB$FIELD_TYPE` values.
mod field {
    pub(super) const SMALLINT: i64 = 7;
    pub(super) const INTEGER: i64 = 8;
    pub(super) const FLOAT: i64 = 10;
    pub(super) const DATE: i64 = 12;
    pub(super) const CHAR: i64 = 14;
    pub(super) const BIGINT: i64 = 16;
    pub(super) const DECFLOAT16: i64 = 24;
    pub(super) const DECFLOAT34: i64 = 25;
    pub(super) const INT128: i64 = 26;
    pub(super) const DOUBLE: i64 = 27;
    pub(super) const TIMESTAMP_TZ: i64 = 29;
    pub(super) const TIMESTAMP: i64 = 35;
    pub(super) const VARCHAR: i64 = 37;
    pub(super) const CSTRING: i64 = 40;
    pub(super) const BLOB: i64 = 261;
}

/// Character set ids read as bytes (`NONE`, `OCTETS`; an unknown one).
const BYTE_CHARSETS: [i64; 3] = [-1, 0, 1];

impl Column {
    /// How the column is sampled; `None`: never (computed, array, a type
    /// outside the conversion list: `BOOLEAN`, `TIME`, blobs of sub-types
    /// other than 0 and 1…).
    #[must_use]
    pub(crate) fn conv(&self) -> Option<Conv> {
        if self.array || self.computed {
            return None;
        }
        let bytes = BYTE_CHARSETS.contains(&self.charset);
        Some(match self.field_type {
            field::CHAR | field::VARCHAR | field::CSTRING => {
                if bytes {
                    Conv::Octets
                } else {
                    Conv::Text
                }
            }
            field::BLOB => match self.sub_type {
                0 => Conv::Octets,
                1 if bytes => Conv::Octets,
                1 => Conv::Text,
                _ => return None,
            },
            field::SMALLINT
            | field::INTEGER
            | field::BIGINT
            | field::INT128
            | field::DECFLOAT16
            | field::DECFLOAT34 => Conv::Number,
            field::FLOAT | field::DOUBLE => Conv::Float,
            field::DATE | field::TIMESTAMP | field::TIMESTAMP_TZ => Conv::Date,
            _ => return None,
        })
    }

    /// Whether a value of the column is padded with spaces (`CHAR`).
    #[must_use]
    pub(crate) fn padded(&self) -> bool {
        self.field_type == field::CHAR
    }
}

/// A catalog name cell: the raw bytes of a padded `CHAR(63)` name
/// (`OCTETS`, [`sql::RELATIONS`]), trailing spaces dropped, then UTF-8 that
/// can be quoted ([`sql::identifier_ok`]); `None` otherwise. A text cell is
/// taken as is (tests).
#[must_use]
pub(crate) fn name_cell(v: &Value) -> Option<String> {
    let name = match v {
        Value::Bytes(b) => {
            let end = b.iter().rposition(|&c| c != b' ').map_or(0, |i| i + 1);
            std::str::from_utf8(b.get(..end)?).ok()?.to_owned()
        }
        Value::Text(t) => trimmed(t).to_owned(),
        Value::Null | Value::Int(_) | Value::Bool(_) => return None,
    };
    sql::identifier_ok(&name).then_some(name)
}

/// The relations of [`sql::RELATIONS`] rows, and how many rows were
/// dropped (review L3): a NULL key cell, or a name that is not UTF-8 or
/// cannot be quoted, drops that relation only (`skipped_error`), never
/// the list.
#[must_use]
pub(crate) fn relations(rows: &[Vec<Value>]) -> (Vec<Relation>, u64) {
    let mut dropped = 0u64;
    let list = rows
        .iter()
        .filter_map(|r| {
            let rel = relation(r);
            if rel.is_none() {
                dropped += 1;
            }
            rel
        })
        .collect();
    (list, dropped)
}

fn relation(r: &[Value]) -> Option<Relation> {
    let name = name_cell(r.first()?)?;
    let view = r.get(2)?.as_bool()?;
    let external = r.get(3)?.as_bool()?;
    let kind = match r.get(1)?.as_int()? {
        _ if view => Kind::View,
        _ if external => Kind::External,
        0 => Kind::Table,
        1 => Kind::View,
        2 => Kind::External,
        4 | 5 => Kind::Temporary,
        _ => Kind::Other,
    };
    Some(Relation {
        name,
        kind,
        readable: r.get(4)?.as_bool()?,
    })
}

/// The columns of [`sql::COLUMNS`] rows.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Columns {
    pub(crate) list: Vec<Column>,
    /// Relations with a column row dropped (a column name that is not
    /// UTF-8 or cannot be quoted, a NULL key cell): their column list is
    /// incomplete, so they are `skipped_error`, never sampled without it.
    pub(crate) incomplete: BTreeSet<String>,
    /// Column rows dropped whose relation name itself was unusable (that
    /// relation is dropped from the relation list too).
    pub(crate) unlinked: u64,
}

/// The columns of [`sql::COLUMNS`] rows (review L3: a bad row drops its
/// relation's column list only).
#[must_use]
pub(crate) fn columns(rows: &[Vec<Value>]) -> Columns {
    let mut out = Columns::default();
    for r in rows {
        let Some(relation) = r.first().and_then(name_cell) else {
            out.unlinked += 1;
            continue;
        };
        let col = (|| {
            Some(Column {
                name: name_cell(r.get(1)?)?,
                field_type: r.get(3)?.as_int()?,
                sub_type: r.get(4)?.as_int()?,
                charset: r.get(7)?.as_int()?,
                array: r.get(8)?.as_bool()?,
                computed: r.get(9)?.as_bool()?,
                relation: relation.clone(),
            })
        })();
        match col {
            Some(c) => out.list.push(c),
            None => {
                out.incomplete.insert(relation);
            }
        }
    }
    out
}

/// The column batches of one table (decision 5, security review N3): in
/// catalog order, each batch at most [`sql::MAX_STATEMENT_COLUMNS`]
/// columns and [`sql::MAX_ROW_BYTES`] declared bytes.
#[must_use]
pub(crate) fn batches<T: Copy>(columns: &[(T, Conv)]) -> Vec<Vec<(T, Conv)>> {
    let mut out: Vec<Vec<(T, Conv)>> = Vec::new();
    let mut bytes = 0usize;
    for &(c, conv) in columns {
        let b = conv.row_bytes();
        match out.last_mut() {
            Some(last)
                if last.len() < sql::MAX_STATEMENT_COLUMNS && bytes + b <= sql::MAX_ROW_BYTES =>
            {
                last.push((c, conv));
                bytes += b;
            }
            _ => {
                out.push(vec![(c, conv)]);
                bytes = b;
            }
        }
    }
    out
}

/// What the catalog of one database shows, for `check()`'s notes and the
/// local detail.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Counts {
    pub(crate) views: u64,
    pub(crate) external: u64,
    pub(crate) temporary: u64,
    pub(crate) computed: u64,
    pub(crate) without_select: u64,
}

/// [`Counts`] of a catalog.
#[must_use]
pub(crate) fn counts(relations: &[Relation], columns: &[Column]) -> Counts {
    let mut c = Counts::default();
    for r in relations {
        match r.kind {
            Kind::View => c.views += 1,
            Kind::External => c.external += 1,
            Kind::Temporary => c.temporary += 1,
            Kind::Table if !r.readable && !never_sampled(&r.name) => c.without_select += 1,
            Kind::Table | Kind::Other => {}
        }
    }
    c.computed = columns.iter().filter(|col| col.computed).count() as u64;
    c
}

/// The catalog of one database as read: `None` parts were not evaluated
/// (a read failed); `cut`: a bound was reached; `*_dropped`, `incomplete`:
/// rows that could not be used (review L3).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Catalog {
    pub(crate) relations: Option<Vec<Relation>>,
    pub(crate) relations_cut: bool,
    /// Relation rows dropped (`skipped_error` each).
    pub(crate) relations_dropped: u64,
    pub(crate) columns: Option<Columns>,
    /// The column list reached [`MAX_COLUMNS`]: the columns of its last
    /// relation, and of every relation after it, are incomplete.
    pub(crate) columns_cut: bool,
    /// The positions of each relation's columns, built once at first use
    /// (review L4).
    /// (Built from `columns`, never set by hand.)
    pub(crate) index: OnceLock<HashMap<String, Vec<usize>>>,
}

/// Why a relation's columns are not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Missing {
    /// The column list was cut at or before it (`skipped_limit`).
    Cut,
    /// The column list was not read, or a row of it was dropped
    /// (`skipped_error`).
    Error,
}

impl Catalog {
    /// Whether any row was dropped (the CAS store guard is then not
    /// evaluated completely: a dropped relation could be a ticket
    /// registry).
    #[must_use]
    pub(crate) fn dropped(&self) -> u64 {
        let cols = self
            .columns
            .as_ref()
            .map_or(0, |c| c.unlinked + c.incomplete.len() as u64);
        self.relations_dropped + cols
    }

    fn index(&self) -> Option<&HashMap<String, Vec<usize>>> {
        let all = &self.columns.as_ref()?.list;
        Some(self.index.get_or_init(|| {
            let mut map: HashMap<String, Vec<usize>> = HashMap::new();
            for (i, c) in all.iter().enumerate() {
                map.entry(c.relation.clone()).or_default().push(i);
            }
            map
        }))
    }

    /// The columns of `relation`, or why they are not usable.
    pub(crate) fn columns_of(&self, relation: &str) -> Result<Vec<&Column>, Missing> {
        let (Some(columns), Some(index)) = (self.columns.as_ref(), self.index()) else {
            return Err(Missing::Error);
        };
        if columns.incomplete.contains(relation) {
            return Err(Missing::Error);
        }
        let all = &columns.list;
        let cols: Vec<&Column> = index
            .get(relation)
            .map(|ix| ix.iter().filter_map(|&i| all.get(i)).collect())
            .unwrap_or_default();
        // Cut: complete only for a relation seen before the last one (the
        // list comes by relation; a relation not seen may come after).
        if self.columns_cut
            && (cols.is_empty() || all.last().is_some_and(|c| c.relation == relation))
        {
            return Err(Missing::Cut);
        }
        Ok(cols)
    }

    /// The CAS store guard's view of the catalog (ADR-0041 decision 6,
    /// for `privilege.ticket_credentials_readable`): how many readable
    /// tables recognized as a ticket registry or an audit trail have a
    /// credential column (Firebird grants `SELECT` per table, so every
    /// column of a readable table is readable), and whether every table
    /// was evaluated.
    #[must_use]
    pub(crate) fn cas_readable(&self) -> cas_guard::ReadableCheck {
        let mut out = cas_guard::ReadableCheck {
            readable: 0,
            complete: !self.relations_cut && self.dropped() == 0,
        };
        let Some(relations) = &self.relations else {
            out.complete = false;
            return out;
        };
        for r in relations.iter().filter(|r| r.kind == Kind::Table) {
            let Ok(cols) = self.columns_of(&r.name) else {
                out.complete = false;
                continue;
            };
            let names: Vec<&str> = cols.iter().map(|c| c.name.as_str()).collect();
            let Some(kind) = cas_guard::recognize(None, [r.name.as_str()], names.iter().copied())
            else {
                continue;
            };
            if kind == StoreKind::ServiceRegistry {
                continue;
            }
            if r.readable
                && names
                    .iter()
                    .any(|c| cas_guard::is_credential_column(kind, c))
            {
                out.readable += 1;
            }
        }
        out
    }
}

/// Reads the catalog of the attached database (two constant statements in
/// the session's read-only transaction, committed). A read the server
/// refuses leaves its part `None`; a fatal error ends the session.
pub(crate) async fn read(s: &mut Session, deadline: Instant) -> Result<Catalog, FbError> {
    let mut out = Catalog::default();
    match s
        .query(sql::RELATIONS, &RELATIONS_SHAPE, MAX_RELATIONS, deadline)
        .await
    {
        Ok(rows) => {
            out.relations_cut = rows.cut;
            let (list, dropped) = relations(&rows.rows);
            out.relations = Some(list);
            out.relations_dropped = dropped;
        }
        Err(e) if !e.fatal => {}
        Err(e) => return Err(e),
    }
    match s
        .query(sql::COLUMNS, &COLUMNS_SHAPE, MAX_COLUMNS, deadline)
        .await
    {
        Ok(rows) => {
            out.columns_cut = rows.cut;
            out.columns = Some(columns(&rows.rows));
        }
        Err(e) if !e.fatal => {}
        Err(e) => return Err(e),
    }
    s.commit(deadline).await?;
    Ok(out)
}

/// Converts one sampled value to the text the classifiers see: `None` to
/// drop it. `Octets` values are kept only when valid UTF-8 without control
/// characters (tab and line breaks allowed); `Float` values only when
/// integral; `CHAR` padding is dropped. Every dropped buffer is zeroized.
#[must_use]
pub(crate) fn value_text(value: Value, conv: Conv, padded: bool) -> Option<String> {
    use zeroize::Zeroize;
    let mut text = match value {
        Value::Text(mut t) => std::mem::take(&mut *t),
        Value::Bytes(mut b) => match String::from_utf8(std::mem::take(&mut *b)) {
            Ok(t) => t,
            Err(e) => {
                e.into_bytes().zeroize();
                return None;
            }
        },
        Value::Null | Value::Int(_) | Value::Bool(_) => return None,
    };
    let keep = match conv {
        Conv::Octets => !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r')),
        Conv::Float => match integral(&text) {
            Some(digits) => {
                text.zeroize();
                text = digits;
                true
            }
            None => false,
        },
        Conv::Text | Conv::Number | Conv::Date => true,
    };
    if padded {
        // The bytes cut off are spaces.
        let len = text.trim_end_matches(' ').len();
        text.truncate(len);
    }
    if !keep || text.is_empty() {
        text.zeroize();
        return None;
    }
    Some(text)
}

/// The integer digits of a floating value written by the server
/// (`33612345678.00000`, `1.5e+10`), when it is integral and exact
/// (at most 2^53).
fn integral(text: &str) -> Option<String> {
    let v: f64 = text.trim().parse().ok()?;
    let exact = 9_007_199_254_740_992.0_f64;
    (v.is_finite() && v.fract() == 0.0 && v.abs() <= exact).then(|| format!("{v:.0}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use zeroize::Zeroizing;

    fn t(s: &str) -> Value {
        Value::Text(Zeroizing::new(s.to_owned()))
    }

    fn col(field_type: i64, sub_type: i64, charset: i64) -> Column {
        Column {
            relation: "T".into(),
            name: "C".into(),
            field_type,
            sub_type,
            charset,
            array: false,
            computed: false,
        }
    }

    #[test]
    fn conversions_by_base_type() {
        assert_eq!(col(37, 0, 4).conv(), Some(Conv::Text));
        assert_eq!(col(14, 0, 53).conv(), Some(Conv::Text)); // WIN1252
        assert_eq!(col(37, 0, 0).conv(), Some(Conv::Octets)); // NONE
        assert_eq!(col(14, 0, 1).conv(), Some(Conv::Octets)); // OCTETS
        assert_eq!(col(261, 1, 4).conv(), Some(Conv::Text));
        assert_eq!(col(261, 1, 0).conv(), Some(Conv::Octets));
        assert_eq!(col(261, 0, -1).conv(), Some(Conv::Octets));
        for sub in [2, 3, 6, -1, 9] {
            assert_eq!(col(261, sub, 4).conv(), None, "{sub}");
        }
        for ft in [7, 8, 16, 26, 24, 25] {
            assert_eq!(col(ft, 1, -1).conv(), Some(Conv::Number), "{ft}");
        }
        assert_eq!(col(27, 0, -1).conv(), Some(Conv::Float));
        assert_eq!(col(10, 0, -1).conv(), Some(Conv::Float));
        for ft in [12, 35, 29] {
            assert_eq!(col(ft, 0, -1).conv(), Some(Conv::Date));
        }
        // BOOLEAN, TIME, TIME WITH TIME ZONE, QUAD, unknown: never.
        for ft in [23, 13, 28, 9, 45, 999] {
            assert_eq!(col(ft, 0, -1).conv(), None, "{ft}");
        }
        let mut c = col(37, 0, 4);
        c.computed = true;
        assert_eq!(c.conv(), None);
        let mut c = col(8, 0, -1);
        c.array = true;
        assert_eq!(c.conv(), None);
    }

    #[test]
    fn the_never_sampled_list_decides_not_the_prefix() {
        assert!(never_sampled("RDB$CONFIG"));
        assert!(never_sampled("PLG$SRP"));
        assert!(never_sampled("PLG$PROF_SESSIONS"));
        assert!(never_sampled("SEC$USERS"));
        assert!(!never_sampled("RDB$CUSTOMER_ARCHIVE"));
        assert!(system_prefixed("RDB$CUSTOMER_ARCHIVE"));
        assert!(!never_sampled("rdb$config"));
        assert!(!system_prefixed("CUSTOMERS"));
        let mut sorted = NEVER_SAMPLED.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, NEVER_SAMPLED);
    }

    #[test]
    fn relations_and_columns_parse_and_fail_closed() {
        let rows = vec![
            vec![
                t("CUSTOMERS   "),
                Value::Int(0),
                Value::Bool(false),
                Value::Bool(false),
                Value::Bool(true),
            ],
            vec![
                t("V"),
                Value::Int(1),
                Value::Bool(true),
                Value::Bool(false),
                Value::Bool(true),
            ],
            vec![
                t("EXT"),
                Value::Int(2),
                Value::Bool(false),
                Value::Bool(true),
                Value::Bool(false),
            ],
            vec![
                t("G"),
                Value::Int(4),
                Value::Bool(false),
                Value::Bool(false),
                Value::Bool(true),
            ],
            vec![
                t("NOGRANT"),
                Value::Int(0),
                Value::Bool(false),
                Value::Bool(false),
                Value::Bool(false),
            ],
        ];
        let (r, dropped) = relations(&rows);
        assert_eq!(dropped, 0);
        assert_eq!(r[0].name, "CUSTOMERS");
        assert_eq!(
            r.iter().map(|x| x.kind).collect::<Vec<_>>(),
            [
                Kind::Table,
                Kind::View,
                Kind::External,
                Kind::Temporary,
                Kind::Table
            ]
        );
        let c = counts(&r, &[]);
        assert_eq!(
            (c.views, c.external, c.temporary, c.without_select),
            (1, 1, 1, 1)
        );
        // A NULL key cell, a name that cannot be quoted: that relation
        // only is dropped (review L3).
        let mut bad = rows.clone();
        bad[1][4] = Value::Null;
        let (r, dropped) = relations(&bad);
        assert_eq!((r.len(), dropped), (4, 1));
        assert!(r.iter().all(|x| x.name != "V"));
        let mut bad = rows;
        bad[0][0] = t("A\0B");
        let (r, dropped) = relations(&bad);
        assert_eq!((r.len(), dropped), (4, 1));
        assert_eq!(r[0].name, "V");
        let crow = vec![
            t("T"),
            t("E-Mail "),
            Value::Int(1),
            Value::Int(37),
            Value::Int(0),
            Value::Int(0),
            Value::Int(400),
            Value::Int(4),
            Value::Bool(false),
            Value::Bool(true),
        ];
        let cols = columns(&[crow]).list;
        assert_eq!(cols[0].name, "E-Mail");
        assert!(cols[0].computed);
        assert_eq!(cols[0].conv(), None);
    }

    fn raw(b: &[u8]) -> Value {
        let mut v = b.to_vec();
        v.resize(v.len().max(63), b' ');
        Value::Bytes(Zeroizing::new(v))
    }

    fn rel_row(name: Value, readable: bool) -> Vec<Value> {
        vec![
            name,
            Value::Int(0),
            Value::Bool(false),
            Value::Bool(false),
            Value::Bool(readable),
        ]
    }

    fn col_row(rel: Value, name: Value) -> Vec<Value> {
        vec![
            rel,
            name,
            Value::Int(0),
            Value::Int(37),
            Value::Int(0),
            Value::Int(0),
            Value::Int(100),
            Value::Int(4),
            Value::Bool(false),
            Value::Bool(false),
        ]
    }

    #[test]
    fn name_cells_are_raw_padded_utf8() {
        assert_eq!(
            name_cell(&raw("CAFÉ_X".as_bytes())).as_deref(),
            Some("CAFÉ_X")
        );
        // Inner spaces and quotes are kept (quoted at use).
        assert_eq!(name_cell(&raw(b"A \"B")).as_deref(), Some("A \"B"));
        // Hostile bytes: not UTF-8, a NUL, all spaces, too long.
        assert_eq!(name_cell(&raw(&[b'B', 0xff, 0xfe])), None);
        assert_eq!(name_cell(&raw(b"A\0B")), None);
        assert_eq!(name_cell(&raw(b"")), None);
        assert_eq!(name_cell(&raw("é".repeat(64).as_bytes())), None);
        assert_eq!(name_cell(&Value::Null), None);
        assert_eq!(name_cell(&Value::Int(1)), None);
    }

    #[test]
    fn a_hostile_name_drops_its_relation_only() {
        let hostile = raw(&[b'T', 0xC3, 0x28, b'X']);
        let (rels, dropped) = relations(&[
            rel_row(raw(b"CUSTOMERS"), true),
            rel_row(hostile.clone(), true),
            rel_row(raw(b"ORDERS"), true),
        ]);
        assert_eq!(dropped, 1);
        assert_eq!(
            rels.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["CUSTOMERS", "ORDERS"]
        );
        let cols = columns(&[
            col_row(raw(b"CUSTOMERS"), raw(b"EMAIL")),
            col_row(hostile, raw(b"X")),
            col_row(raw(b"ORDERS"), raw(b"ID")),
            col_row(raw(b"ORDERS"), raw(&[0xff])),
        ]);
        assert_eq!(cols.unlinked, 1);
        assert_eq!(cols.incomplete.iter().collect::<Vec<_>>(), ["ORDERS"]);
        let catalog = Catalog {
            relations: Some(rels),
            relations_dropped: dropped,
            columns: Some(cols),
            ..Catalog::default()
        };
        assert_eq!(catalog.columns_of("CUSTOMERS").unwrap().len(), 1);
        assert_eq!(catalog.columns_of("ORDERS"), Err(Missing::Error));
        assert_eq!(catalog.dropped(), 3);
        // The CAS store guard: a dropped relation could be a ticket
        // registry, so the guard is not complete.
        assert!(!catalog.cas_readable().complete);
        let clean = Catalog {
            relations: Some(relations(&[rel_row(raw(b"CUSTOMERS"), true)]).0),
            columns: Some(columns(&[col_row(raw(b"CUSTOMERS"), raw(b"EMAIL"))])),
            ..Catalog::default()
        };
        assert!(clean.cas_readable().complete);
        // No column list at all: every table is an error, not a limit.
        let none = Catalog {
            relations: clean.relations.clone(),
            ..Catalog::default()
        };
        assert_eq!(none.columns_of("CUSTOMERS"), Err(Missing::Error));
    }

    #[test]
    fn columns_are_grouped_once_and_cut_as_before() {
        // 2 000 relations of 3 columns: grouped once, each lookup direct.
        let mut rows = Vec::new();
        for r in 0..2_000 {
            for c in 0..3 {
                rows.push(col_row(
                    raw(format!("T{r:05}").as_bytes()),
                    raw(format!("C{c}").as_bytes()),
                ));
            }
        }
        let mut catalog = Catalog {
            columns: Some(columns(&rows)),
            ..Catalog::default()
        };
        let started = std::time::Instant::now();
        for r in 0..2_000 {
            let cols = catalog.columns_of(&format!("T{r:05}")).unwrap();
            assert_eq!(
                cols.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
                ["C0", "C1", "C2"]
            );
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert_eq!(catalog.columns_of("ABSENT").unwrap().len(), 0);
        // Cut: the last relation and the ones not seen are incomplete.
        catalog.columns_cut = true;
        assert!(catalog.columns_of("T00000").is_ok());
        assert_eq!(catalog.columns_of("T01999"), Err(Missing::Cut));
        assert_eq!(catalog.columns_of("ABSENT"), Err(Missing::Cut));
    }

    #[test]
    fn wide_tables_are_split_into_bounded_batches() {
        let cols: Vec<(usize, Conv)> = (0..10).map(|i| (i, Conv::Text)).collect();
        let b = batches(&cols);
        assert_eq!(b.iter().map(Vec::len).collect::<Vec<_>>(), [4, 4, 2]);
        let cols: Vec<(usize, Conv)> = (0..600).map(|i| (i, Conv::Date)).collect();
        let b = batches(&cols);
        assert!(b.iter().all(|x| x.len() <= sql::MAX_STATEMENT_COLUMNS));
        assert_eq!(b.iter().map(Vec::len).sum::<usize>(), 600);
        for batch in &b {
            assert!(batch.iter().map(|(_, c)| c.row_bytes()).sum::<usize>() <= sql::MAX_ROW_BYTES);
        }
        assert!(batches::<usize>(&[]).is_empty());
    }

    #[test]
    fn values_are_kept_only_as_decided() {
        assert_eq!(
            value_text(t("a@example.test"), Conv::Text, false).as_deref(),
            Some("a@example.test")
        );
        assert_eq!(
            value_text(t("AB   "), Conv::Text, true).as_deref(),
            Some("AB")
        );
        assert_eq!(value_text(t("    "), Conv::Text, true), None);
        let bytes = |b: &[u8]| Value::Bytes(Zeroizing::new(b.to_vec()));
        assert_eq!(
            value_text(bytes(b"plain ascii"), Conv::Octets, false).as_deref(),
            Some("plain ascii")
        );
        assert_eq!(
            value_text(bytes(b"line\nbreak"), Conv::Octets, false).as_deref(),
            Some("line\nbreak")
        );
        assert_eq!(value_text(bytes(&[0xff, 0x41]), Conv::Octets, false), None);
        assert_eq!(value_text(bytes(b"A\x01B"), Conv::Octets, false), None);
        assert_eq!(
            value_text(t("33612345678.00000"), Conv::Float, false).as_deref(),
            Some("33612345678")
        );
        assert_eq!(
            value_text(t("1.5e+10"), Conv::Float, false).as_deref(),
            Some("15000000000")
        );
        assert_eq!(value_text(t("12.5"), Conv::Float, false), None);
        assert_eq!(value_text(t("1e300"), Conv::Float, false), None);
        assert_eq!(value_text(t("NaN"), Conv::Float, false), None);
        assert_eq!(value_text(Value::Null, Conv::Text, false), None);
        assert_eq!(
            value_text(t("123456789012345678901234567890"), Conv::Number, false).as_deref(),
            Some("123456789012345678901234567890")
        );
    }
}
