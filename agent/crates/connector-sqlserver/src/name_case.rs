//! How a SQL Server compares names (ADR-0055 decision 4, security review
//! M2, M3, L4, L5), read at each `check()` with [`sql::DATABASE_COLLATIONS`]:
//!
//! - `databases`: database names compare under the server collation;
//! - `objects`: schema, object and column names compare under each
//!   database's catalog collation, by default the server collation's (new
//!   databases take it); each database whose value differs goes to
//!   `except` (the core merges, sorts and bounds them);
//! - a database's catalog collation: `catalog_collation_type` 0 is the
//!   database collation, or for a contained database the fixed
//!   `Latin1_General_100_CI_AS_KS_WS_SC` (case-insensitive); 2 is
//!   `SQL_Latin1_General_CP1_CI_AS` (case-insensitive); anything else is
//!   `unknown`, as the accepted ADR text says (security review M2 of the
//!   agent lot). Measured on 2022 (16.0.4305.5): a contained database
//!   reads 1, not 0, with `catalog_collation_type_desc`
//!   `Latin1_General_100_CI_AS_KS_WS_SC`, and refuses a second table whose
//!   name differs by case only (error 2714); so a contained database is
//!   `unknown` today, the stricter reading, until an ADR refinement maps
//!   1 on a contained database to `insensitive`. Without the column ([`sql::DATABASE_COLLATIONS_V0`]) the
//!   target reports `objects: unknown`;
//! - a collation compares with case when its `ComparisonStyle` lacks the
//!   ignore-case bit (1): every `_CS_` and binary collation. A `NULL`
//!   style (a database not online, or closed by `AUTO_CLOSE`) is
//!   `unknown`, except for an `AUTO_CLOSE` database that is online
//!   (`state` 0): it keeps its last known value for the same
//!   (`database_id`, `create_date`) on the same server run (M2);
//! - `objects: unknown`, without `except`, when the login lacks `VIEW ANY
//!   DATABASE` (the list may be partial) or the row bound is reached.
//!
//! The server run is the server name with `tempdb`'s `create_date`
//! (`tempdb` is created at every start and is always listed; the ADR's
//! `sqlserver_start_time` needs `VIEW SERVER STATE`, which the minimal
//! account does not hold). Values only, no collation name (I2); database
//! names go through the connector's normalization (ADR-0009).

use std::collections::HashMap;

use databastion_core::name_case::{NameCase, NameCaseReport};

use crate::conn::{Session, Shape};
use crate::error::{SsError, Stage};
use crate::sql;
use crate::token::Value;

/// The `ComparisonStyle` bit of a case-insensitive collation.
const IGNORE_CASE: i64 = 1;
/// `tempdb`'s `database_id`.
const TEMPDB_ID: i64 = 2;

/// A server run: the server name and `tempdb`'s `create_date`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerRun {
    server: String,
    tempdb_created: i64,
}

/// A database's identity across `AUTO_CLOSE` closes: `database_id` and
/// `create_date` (a database dropped and created again under the same id
/// is another).
type DbKey = (i64, i64);

/// Per target: the last value and what it was read from.
#[derive(Debug, Clone)]
pub(crate) struct Memory {
    /// The run of the last read (`None`: not known).
    run: Option<ServerRun>,
    /// The value last read (kept when a later check fails, decision 2).
    pub(crate) report: NameCaseReport,
    /// The last known collation value of the `AUTO_CLOSE` databases.
    auto_close: HashMap<DbKey, NameCase>,
}

/// One `sys.databases` row as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DbRow {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) created: i64,
    pub(crate) style: Option<i64>,
    pub(crate) contained: bool,
    pub(crate) auto_close: bool,
    pub(crate) state: Option<i64>,
    pub(crate) catalog: Option<i64>,
}

/// What [`sql::DATABASE_COLLATIONS`] returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Read {
    pub(crate) rows: Vec<DbRow>,
    pub(crate) server_style: Option<i64>,
    pub(crate) view_any_database: bool,
    pub(crate) server: Option<String>,
    /// `catalog_collation_type` exists (the first statement answered).
    pub(crate) catalog_column: bool,
}

/// The value of a `ComparisonStyle`.
pub(crate) fn of_style(style: Option<i64>) -> NameCase {
    match style {
        Some(s) if s >= 0 && s & IGNORE_CASE != 0 => NameCase::Insensitive,
        Some(s) if s >= 0 => NameCase::Sensitive,
        _ => NameCase::Unknown,
    }
}

/// Parses the rows of [`sql::DATABASE_COLLATIONS`]; `None` when there is
/// none, or a row has another shape or no id, name or creation date (not
/// understood: `unknown` for both parts).
pub(crate) fn parse(rows: &[Vec<Value>], catalog_column: bool) -> Option<Read> {
    let int = |r: &[Value], i: usize| r.get(i).and_then(Value::as_int);
    let first = rows.first()?;
    let mut out = Read {
        rows: Vec::with_capacity(rows.len()),
        server_style: int(first, 8),
        view_any_database: int(first, 9) == Some(1),
        server: first.get(10).and_then(Value::as_text).map(str::to_owned),
        catalog_column,
    };
    for r in rows {
        if r.len() != sql::DATABASE_COLLATIONS_COLUMNS {
            return None;
        }
        out.rows.push(DbRow {
            id: int(r, 0)?,
            name: r.get(1).and_then(Value::as_text)?.to_owned(),
            created: int(r, 2)?,
            style: int(r, 3),
            contained: int(r, 4).is_some_and(|c| c != 0),
            auto_close: int(r, 5) == Some(1),
            state: int(r, 6),
            catalog: int(r, 7),
        });
    }
    Some(out)
}

/// The value of `read` (see the module documentation), with the
/// `AUTO_CLOSE` memory of `previous` when it is the same server run, and
/// the memory to keep. `read` `None`: the list could not be read or
/// understood; `unknown` for both parts, the previous `AUTO_CLOSE` values
/// kept for a later read of the same run.
pub(crate) fn evaluate(read: Option<&Read>, previous: Option<&Memory>) -> Memory {
    let Some(read) = read else {
        return Memory {
            run: previous.and_then(|m| m.run.clone()),
            report: NameCaseReport::unknown(),
            auto_close: previous.map(|m| m.auto_close.clone()).unwrap_or_default(),
        };
    };
    let run = match (&read.server, read.rows.iter().find(|r| r.id == TEMPDB_ID)) {
        (Some(server), Some(tempdb)) if !server.is_empty() => Some(ServerRun {
            server: server.clone(),
            tempdb_created: tempdb.created,
        }),
        _ => None,
    };
    let remembered = previous
        .filter(|m| run.is_some() && m.run == run)
        .map(|m| &m.auto_close);
    let databases = of_style(read.server_style);
    let mut auto_close = HashMap::new();
    let mut except = Vec::with_capacity(read.rows.len());
    for r in &read.rows {
        let key = (r.id, r.created);
        let collation = match of_style(r.style) {
            NameCase::Unknown if r.auto_close && r.state == Some(0) => remembered
                .and_then(|m| m.get(&key).copied())
                .unwrap_or(NameCase::Unknown),
            v => v,
        };
        if r.auto_close && collation != NameCase::Unknown {
            auto_close.insert(key, collation);
        }
        let value = match r.catalog {
            Some(0) if r.contained => NameCase::Insensitive,
            Some(0) => collation,
            // 1 (a contained database on 2022, measured): `unknown` until
            // an ADR refinement decides (see the module documentation).
            Some(2) => NameCase::Insensitive,
            _ => NameCase::Unknown,
        };
        except.push((crate::discover::normalize(&r.name), value));
    }
    let whole = read.catalog_column
        && read.view_any_database
        && read.rows.len() <= sql::MAX_COLLATION_DATABASES;
    let report = if whole {
        NameCaseReport {
            databases,
            objects: databases,
            except,
        }
    } else {
        NameCaseReport {
            databases,
            objects: NameCase::Unknown,
            except: Vec::new(),
        }
    };
    Memory {
        run,
        report,
        auto_close,
    }
}

/// SQL Server error 207, "invalid column name": `catalog_collation_type`
/// does not exist on this server.
const INVALID_COLUMN: i32 = 207;

/// Reads the collations (decision 4): [`sql::DATABASE_COLLATIONS`], or
/// [`sql::DATABASE_COLLATIONS_V0`] when the server has no
/// `catalog_collation_type`. `Ok(None)`: refused or not understood
/// without ending the session; a fatal error is returned (the check
/// fails and the last value is kept, decision 2).
pub(crate) async fn read(s: &mut Session) -> Result<Option<Read>, SsError> {
    let shape = Shape::rows(
        sql::DATABASE_COLLATIONS_COLUMNS,
        sql::MAX_COLLATION_DATABASES + 1,
    );
    let (rows, catalog_column) = match s.rows(sql::DATABASE_COLLATIONS, Stage::Check, shape).await {
        Ok(rows) => (rows, true),
        Err(e) if !e.fatal && e.number == Some(INVALID_COLUMN) => {
            match s
                .rows(sql::DATABASE_COLLATIONS_V0, Stage::Check, shape)
                .await
            {
                Ok(rows) => (rows, false),
                Err(e) if !e.fatal => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        Err(e) if !e.fatal => {
            tracing::info!(
                number = e.number,
                "database collations not readable: names reported compared unknown"
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    Ok(parse(&rows, catalog_column))
}

/// A one-line local summary (counts only, never sent).
pub(crate) fn summary(m: &Memory) -> String {
    let word = |v: NameCase| match v {
        NameCase::Sensitive => "with case",
        NameCase::Insensitive => "without case",
        NameCase::Unknown => "unknown (treated as with case)",
    };
    let otherwise = m
        .report
        .except
        .iter()
        .filter(|(_, v)| *v != m.report.objects)
        .count();
    format!(
        "names: database names compared {}, object names {} by default, {otherwise} \
         database(s) otherwise",
        word(m.report.databases),
        word(m.report.objects),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ComparisonStyle` values: `Latin1_General_CI_AS` 196609, `_CS_AS`
    /// 196608, `_BIN2` 0 (ADR-0055), `_CI_AI` 196611.
    const CI_AS: i64 = 196_609;
    const CS_AS: i64 = 196_608;
    const BIN2: i64 = 0;

    fn row(id: i64, name: &str, style: Option<i64>) -> DbRow {
        DbRow {
            id,
            name: name.to_owned(),
            created: 1_000 + id,
            style,
            contained: false,
            auto_close: false,
            state: Some(0),
            catalog: Some(0),
        }
    }

    fn read(rows: Vec<DbRow>) -> Read {
        let mut all = vec![row(1, "master", Some(CI_AS)), row(2, "tempdb", Some(CI_AS))];
        all.extend(rows);
        Read {
            rows: all,
            server_style: Some(CI_AS),
            view_any_database: true,
            server: Some("mssql1".to_owned()),
            catalog_column: true,
        }
    }

    fn sent(m: &Memory) -> serde_json::Value {
        serde_json::to_value(databastion_core::name_case::to_protocol(&m.report)).unwrap()
    }

    #[test]
    fn comparison_styles_map_to_values() {
        assert_eq!(of_style(Some(CI_AS)), NameCase::Insensitive);
        assert_eq!(of_style(Some(196_611)), NameCase::Insensitive);
        assert_eq!(of_style(Some(CS_AS)), NameCase::Sensitive);
        assert_eq!(of_style(Some(BIN2)), NameCase::Sensitive);
        assert_eq!(of_style(Some(-1)), NameCase::Unknown);
        assert_eq!(of_style(None), NameCase::Unknown);
    }

    /// The decision 10 cases: `_CS_`, `_BIN2`, default, snapshot, offline,
    /// contained `_CS_` (`insensitive`), catalog collation type 2 and
    /// another value.
    #[test]
    fn databases_are_listed_by_their_catalog_collation() {
        let mut contained = row(8, "contained_cs", Some(CS_AS));
        contained.contained = true;
        // As measured on 2022: a contained database reads 1, `unknown`
        // under the accepted text.
        let mut contained_1 = row(13, "contained_cs_1", Some(CS_AS));
        contained_1.contained = true;
        contained_1.catalog = Some(1);
        let mut offline = row(9, "offline_db", None);
        offline.state = Some(6);
        let mut sql_catalog = row(10, "sql_catalog", Some(CS_AS));
        sql_catalog.catalog = Some(2);
        let mut odd = row(11, "odd_catalog", Some(CI_AS));
        odd.catalog = Some(7);
        let m = evaluate(
            Some(&read(vec![
                row(5, "crm_cs", Some(CS_AS)),
                row(6, "crm_bin2", Some(BIN2)),
                row(7, "crm", Some(CI_AS)),
                row(12, "crm_cs_snapshot", Some(CS_AS)),
                contained,
                contained_1,
                offline,
                sql_catalog,
                odd,
            ])),
            None,
        );
        assert_eq!(
            sent(&m),
            serde_json::json!({
                "databases": "insensitive",
                "objects": "insensitive",
                "except": [
                    {"database": "contained_cs_1", "objects": "unknown"},
                    {"database": "crm_bin2", "objects": "sensitive"},
                    {"database": "crm_cs", "objects": "sensitive"},
                    {"database": "crm_cs_snapshot", "objects": "sensitive"},
                    {"database": "odd_catalog", "objects": "unknown"},
                    {"database": "offline_db", "objects": "unknown"}
                ]
            })
        );
    }

    /// A case-sensitive server collation: database names and the default
    /// with case; an insensitive database listed.
    #[test]
    fn a_case_sensitive_server_collation_is_the_default() {
        let mut r = read(vec![
            row(5, "ci_db", Some(CI_AS)),
            row(6, "cs_db", Some(CS_AS)),
        ]);
        r.server_style = Some(BIN2);
        let m = evaluate(Some(&r), None);
        assert_eq!(
            sent(&m),
            serde_json::json!({
                "databases": "sensitive",
                "objects": "sensitive",
                "except": [
                    {"database": "ci_db", "objects": "insensitive"},
                    {"database": "master", "objects": "insensitive"},
                    {"database": "tempdb", "objects": "insensitive"}
                ]
            })
        );
        r.server_style = None;
        let v = sent(&evaluate(Some(&r), None));
        assert_eq!(
            (&v["databases"], &v["objects"]),
            (&"unknown".into(), &"unknown".into())
        );
    }

    /// `VIEW ANY DATABASE` revoked, the row bound, the missing column:
    /// `objects: unknown`, no `except`; `databases` still read.
    #[test]
    fn a_partial_list_makes_objects_unknown() {
        let base = read(vec![row(5, "crm_cs", Some(CS_AS))]);
        let mut no_view = base.clone();
        no_view.view_any_database = false;
        let mut cut = base.clone();
        cut.rows.extend(
            (100..100 + sql::MAX_COLLATION_DATABASES as i64).map(|i| row(i, "d", Some(CI_AS))),
        );
        let mut v0 = base.clone();
        v0.catalog_column = false;
        for r in [no_view, cut, v0] {
            assert_eq!(
                sent(&evaluate(Some(&r), None)),
                serde_json::json!({"databases": "insensitive", "objects": "unknown"})
            );
        }
        let mut exactly = base;
        exactly.rows.truncate(2);
        exactly.rows.extend(
            (100..98 + sql::MAX_COLLATION_DATABASES as i64).map(|i| row(i, "d", Some(CI_AS))),
        );
        assert_eq!(exactly.rows.len(), sql::MAX_COLLATION_DATABASES);
        assert_eq!(
            sent(&evaluate(Some(&exactly), None)),
            serde_json::json!({"databases": "insensitive", "objects": "insensitive"})
        );
        // Nothing read: unknown for both parts.
        assert_eq!(
            sent(&evaluate(None, None)),
            serde_json::json!({"databases": "unknown", "objects": "unknown"})
        );
    }

    /// Security review M2: an `AUTO_CLOSE` database closed between two
    /// checks keeps its value on the same server run (no flapping); after a
    /// restart, or for another database under the same id, or when it is
    /// not online, it is `unknown`.
    #[test]
    fn auto_close_databases_keep_their_last_value_within_a_run() {
        let mut open = row(5, "express_cs", Some(CS_AS));
        open.auto_close = true;
        let mut closed = open.clone();
        closed.style = None;
        let first = evaluate(Some(&read(vec![open.clone()])), None);
        let listed = serde_json::json!({
            "databases": "insensitive", "objects": "insensitive",
            "except": [{"database": "express_cs", "objects": "sensitive"}]
        });
        assert_eq!(sent(&first), listed);
        let second = evaluate(Some(&read(vec![closed.clone()])), Some(&first));
        assert_eq!(sent(&second), listed, "closed: no flapping");
        let third = evaluate(Some(&read(vec![closed.clone()])), Some(&second));
        assert_eq!(sent(&third), listed, "still closed");
        let unknown = serde_json::json!({
            "databases": "insensitive", "objects": "insensitive",
            "except": [{"database": "express_cs", "objects": "unknown"}]
        });
        // Never seen open: unknown.
        assert_eq!(
            sent(&evaluate(Some(&read(vec![closed.clone()])), None)),
            unknown
        );
        // Another server run (`tempdb` created again).
        let mut restarted = read(vec![closed.clone()]);
        restarted.rows[1].created += 1;
        assert_eq!(sent(&evaluate(Some(&restarted), Some(&first))), unknown);
        // Another server name.
        let mut other = read(vec![closed.clone()]);
        other.server = Some("mssql2".to_owned());
        assert_eq!(sent(&evaluate(Some(&other), Some(&first))), unknown);
        // Dropped and created again under the same id.
        let mut again = closed.clone();
        again.created += 1;
        assert_eq!(
            sent(&evaluate(Some(&read(vec![again])), Some(&first))),
            unknown
        );
        // Not online.
        let mut offline = closed.clone();
        offline.state = Some(6);
        assert_eq!(
            sent(&evaluate(Some(&read(vec![offline])), Some(&first))),
            unknown
        );
        // A failed read keeps the memory for the next read of the run.
        let failed = evaluate(None, Some(&first));
        assert_eq!(
            sent(&failed),
            serde_json::json!({"databases": "unknown", "objects": "unknown"})
        );
        assert_eq!(
            sent(&evaluate(Some(&read(vec![closed])), Some(&failed))),
            listed
        );
    }

    /// Decision 4 (L3): database names go through the connector's
    /// normalization; one matched by a classifier is `*`, and two that
    /// reach the console as one name are one entry with the stricter
    /// value.
    #[test]
    fn database_names_are_normalized_and_merged() {
        let m = evaluate(
            Some(&read(vec![
                row(5, "jane.doe@example.com", Some(CI_AS)),
                row(6, "FR7630006000011234567890189", Some(CS_AS)),
                row(7, "crm_cs ", Some(CS_AS)),
            ])),
            None,
        );
        let v = sent(&m);
        assert_eq!(
            v,
            serde_json::json!({
                "databases": "insensitive", "objects": "insensitive",
                "except": [
                    {"database": "*", "objects": "sensitive"},
                    {"database": "crm_cs", "objects": "sensitive"}
                ]
            })
        );
        assert!(!v.to_string().contains("jane"));
    }

    #[test]
    fn rows_are_parsed_by_position() {
        let r = vec![
            Value::Int(5),
            Value::Text("crm".to_owned()),
            Value::Int(1_700_000_000_000_000),
            Value::Int(CS_AS),
            Value::Int(0),
            Value::Int(1),
            Value::Int(0),
            Value::Null,
            Value::Int(CI_AS),
            Value::Int(1),
            Value::Text("mssql1".to_owned()),
        ];
        let read = parse(std::slice::from_ref(&r), true).unwrap();
        assert_eq!(read.server_style, Some(CI_AS));
        assert!(read.view_any_database);
        assert_eq!(read.server.as_deref(), Some("mssql1"));
        assert_eq!(
            read.rows,
            [DbRow {
                id: 5,
                name: "crm".to_owned(),
                created: 1_700_000_000_000_000,
                style: Some(CS_AS),
                contained: false,
                auto_close: true,
                state: Some(0),
                catalog: None,
            }]
        );
        assert!(parse(&[], true).is_none());
        assert!(parse(&[r[..10].to_vec()], true).is_none());
        let mut no_name = r;
        no_name[1] = Value::Null;
        assert!(parse(&[no_name], true).is_none());
    }
}
