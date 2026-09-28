//! Introspection and sampling scope.
//!
//! Sampled: base tables (`BASE TABLE`, MariaDB `SYSTEM VERSIONED`) outside
//! the system schemas (`mysql`, `sys`, `information_schema`,
//! `performance_schema`) whose storage engine reads local data
//! ([`LOCAL_ENGINES`], an allow-list). A partitioned table is one table in
//! `information_schema.TABLES` (its partitions share its engine), so it is
//! sampled and reported once.
//!
//! Never sampled:
//! - views (`VIEW`, `SYSTEM VIEW`): reading one runs its definition with
//!   the definer's rights, possibly calling stored functions;
//! - tables of any other engine: remote-access engines (`FEDERATED`,
//!   `CONNECT`, `SPIDER`, `S3`, `SPHINX`, `ndbcluster`) make the server
//!   connect to another host (I5); `MRG_MYISAM` reads other tables (sampled
//!   directly); unknown engines fail closed;
//! - sequences (MariaDB).
//!
//! `information_schema` lists only the objects the account has a
//! privilege on: tables it cannot see at all cannot be counted as "not
//! covered" (unlike PostgreSQL's `pg_class`).

use crate::conn::ReadTx;
use crate::error::{MyError, Stage};
use crate::sql;

/// Engines whose tables hold local data and are read by the server
/// without user code or outbound connections.
pub(crate) const LOCAL_ENGINES: [&str; 7] = [
    "InnoDB", "MyISAM", "Aria", "MEMORY", "ARCHIVE", "ROCKSDB", "TokuDB",
];

/// Engines that reach another host or an external service.
const REMOTE_ENGINES: [&str; 7] = [
    "FEDERATED",
    "FEDERATEDX",
    "CONNECT",
    "SPIDER",
    "S3",
    "SPHINX",
    "ndbcluster",
];

/// A table or view from `information_schema` (raw names: never sent or
/// logged without normalization; `Debug` shows neither).
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Table {
    pub(crate) schema: String,
    pub(crate) name: String,
    pub(crate) kind: Kind,
    pub(crate) engine: Option<String>,
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// `TABLE_TYPE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Base,
    View,
    Sequence,
    Other,
}

impl Kind {
    fn of(table_type: &str) -> Self {
        match table_type {
            "BASE TABLE" | "SYSTEM VERSIONED" => Self::Base,
            "VIEW" | "SYSTEM VIEW" => Self::View,
            "SEQUENCE" => Self::Sequence,
            _ => Self::Other,
        }
    }
}

/// Why a table is not sampled because of its engine. Closed labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineSkip {
    /// Remote or external engine: reading it connects out (I5).
    Remote,
    /// `MRG_MYISAM`: a union of other tables, sampled directly.
    Merge,
    /// Any other engine (fail closed).
    Other,
}

impl EngineSkip {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Remote => "remote-access engine (never read, I5)",
            Self::Merge => "merge table (its tables are sampled directly)",
            Self::Other => "engine not in the local-data allow-list",
        }
    }
}

/// How an engine is handled: `None` = sampled. A table without an engine
/// (unreadable definition) is not sampled.
pub(crate) fn engine_skip(engine: Option<&str>) -> Option<EngineSkip> {
    let Some(e) = engine else {
        return Some(EngineSkip::Other);
    };
    if LOCAL_ENGINES.iter().any(|l| l.eq_ignore_ascii_case(e)) {
        None
    } else if REMOTE_ENGINES.iter().any(|r| r.eq_ignore_ascii_case(e)) {
        Some(EngineSkip::Remote)
    } else if e.eq_ignore_ascii_case("MRG_MYISAM") {
        Some(EngineSkip::Merge)
    } else {
        Some(EngineSkip::Other)
    }
}

/// Objects in the job's scope that are not sampled (raw names; logged
/// normalized).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Coverage {
    pub(crate) views: Vec<(String, String)>,
    pub(crate) engines: Vec<(String, String, EngineSkip)>,
    pub(crate) sequences: usize,
    pub(crate) other: usize,
    pub(crate) truncated: bool,
}

impl Coverage {
    pub(crate) fn not_covered(&self) -> usize {
        self.views.len() + self.engines.len()
    }
}

/// Reads the tables and views outside the system schemas. Rows whose names
/// are not UTF-8 are skipped by the session.
pub(crate) async fn introspect(tx: &mut ReadTx<'_>) -> Result<Vec<Table>, MyError> {
    let rows = tx.query(Stage::Introspection, sql::INTROSPECT).await?;
    let truncated = rows.len() >= usize::try_from(sql::MAX_TABLES).unwrap_or(usize::MAX);
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let mut it = row.into_iter();
        let (Some(Some(schema)), Some(Some(name)), Some(kind)) = (it.next(), it.next(), it.next())
        else {
            continue;
        };
        // Case-insensitive system schema check again, in Rust.
        if sql::SYSTEM_SCHEMAS
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&schema))
        {
            continue;
        }
        let engine = it.next().flatten();
        out.push(Table {
            schema,
            name,
            kind: Kind::of(kind.as_deref().unwrap_or("")),
            engine,
        });
    }
    if truncated {
        tracing::warn!(
            limit = sql::MAX_TABLES,
            "introspection reached its table limit; later tables are not covered"
        );
    }
    Ok(out)
}

/// Splits the tables in scope (`include(schema, name)`) into those to
/// sample and the coverage report.
pub(crate) fn plan(
    tables: &[Table],
    include: impl Fn(&str, &str) -> bool,
) -> (Vec<Table>, Coverage) {
    let mut units = Vec::new();
    let mut coverage = Coverage {
        truncated: tables.len() >= usize::try_from(sql::MAX_TABLES).unwrap_or(usize::MAX),
        ..Coverage::default()
    };
    for t in tables {
        if !include(&t.schema, &t.name) {
            continue;
        }
        match t.kind {
            Kind::View => coverage.views.push((t.schema.clone(), t.name.clone())),
            Kind::Sequence => coverage.sequences += 1,
            Kind::Other => coverage.other += 1,
            Kind::Base => match engine_skip(t.engine.as_deref()) {
                None => units.push(t.clone()),
                Some(skip) => {
                    coverage
                        .engines
                        .push((t.schema.clone(), t.name.clone(), skip));
                }
            },
        }
    }
    (units, coverage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(schema: &str, name: &str, kind: Kind, engine: Option<&str>) -> Table {
        Table {
            schema: schema.to_owned(),
            name: name.to_owned(),
            kind,
            engine: engine.map(str::to_owned),
        }
    }

    #[test]
    fn only_local_base_tables_are_sampled() {
        let tables = [
            t("hr", "employees", Kind::Base, Some("InnoDB")),
            t("hr", "legacy", Kind::Base, Some("MyISAM")),
            t("hr", "aria", Kind::Base, Some("Aria")),
            t("hr", "v_emp", Kind::View, None),
            t("hr", "fed", Kind::Base, Some("FEDERATED")),
            t("hr", "conn", Kind::Base, Some("CONNECT")),
            t("hr", "spider", Kind::Base, Some("SPIDER")),
            t("hr", "merged", Kind::Base, Some("MRG_MYISAM")),
            t("hr", "blackhole", Kind::Base, Some("BLACKHOLE")),
            t("hr", "noengine", Kind::Base, None),
            t("hr", "seq", Kind::Sequence, Some("InnoDB")),
            t("other", "x", Kind::Base, Some("InnoDB")),
        ];
        let (units, cov) = plan(&tables, |s, _| s == "hr");
        let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["employees", "legacy", "aria"]);
        assert_eq!(cov.views.len(), 1);
        assert_eq!(cov.sequences, 1);
        let skipped: Vec<(&str, EngineSkip)> = cov
            .engines
            .iter()
            .map(|(_, n, k)| (n.as_str(), *k))
            .collect();
        assert_eq!(
            skipped,
            [
                ("fed", EngineSkip::Remote),
                ("conn", EngineSkip::Remote),
                ("spider", EngineSkip::Remote),
                ("merged", EngineSkip::Merge),
                ("blackhole", EngineSkip::Other),
                ("noengine", EngineSkip::Other),
            ]
        );
        assert_eq!(engine_skip(Some("innodb")), None);
    }

    #[test]
    fn debug_shows_no_name() {
        let d = format!(
            "{:?}",
            t("jane.doe@example.com", "secret_t", Kind::Base, None)
        );
        assert!(!d.contains("jane") && !d.contains("secret_t"), "{d}");
    }
}
