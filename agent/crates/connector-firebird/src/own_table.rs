//! The own-statement table (ADR-0060 R8 item 4, R13 items 1 to 4, R20,
//! R23): per text of the closed set, which relations a record of the
//! agent's own execution may and must name in its per-table block, its
//! metadata-loading set and its static row bound. A record is taken as the
//! agent's own only when its block and `records fetched` match its text's
//! row here and its execution credit (the R22 / R35 bounds,
//! [`crate::own::within`]); the rows are the same on 4.0 and 5.0 (the 3d
//! measurements found no per-version difference for these texts).
//!
//! - **may-read**: every relation the text names (a test checks it against
//!   the statement analysis);
//! - **must-read**: relations every execution touches because the text
//!   forces it (`RDB$DATABASE` for a text that selects from it, R13 item
//!   1), possibly empty;
//! - **must-read with rows** (R23 item 2): relations in the block of an
//!   execution whose credit counted at least one row; with none counted,
//!   the block names them or is absent (a scan that matches nothing keeps
//!   its block, an empty relation writes none, R12);
//! - **metadata-loading** (R13 item 2, R23 item 1): `RDB$DATABASE` and
//!   `RDB$RELATIONS` for a text that reads a `MON$` or `SEC$` relation,
//!   `RDB$CHARACTER_SETS` and `RDB$COLLATIONS` for a read of `RDB$CONFIG`,
//!   allowed on any execution of the text; a test checks that each is on
//!   the never-sampled system list (decision 5);
//! - **the static row bound** (R13 item 3): 1 for own-row reads and the
//!   probes, and for a catalog read the connector's row limit for it plus
//!   one fetch round in flight (an early close at the limit, R22).
//!
//! Built texts (Discovery's sampling statements and the CAS store guard's
//! `ticket_type_counts`, R13 item 4) have no row: their block names
//! exactly the credit's table when the connector counted a row, and is
//! absent when it counted none.

use crate::catalog;
use crate::conn::FetchAccount;
use crate::sql;

/// One row of the table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Row {
    pub(crate) text: &'static str,
    pub(crate) may: &'static [&'static str],
    pub(crate) must: &'static [&'static str],
    pub(crate) must_with_rows: &'static [&'static str],
    pub(crate) loading: &'static [&'static str],
    pub(crate) bound: u64,
}

/// The `MON$` / `SEC$` metadata-loading set (R13 item 2).
const MON_LOADING: &[&str] = &["RDB$DATABASE", "RDB$RELATIONS"];
/// The `RDB$CONFIG` metadata-loading set (R23 item 1).
const CONFIG_LOADING: &[&str] = &["RDB$CHARACTER_SETS", "RDB$COLLATIONS"];
/// One fetch round in flight after an early close (decision 1, R22).
const ROUND: u64 = 64;

const fn limit(rows: usize) -> u64 {
    rows as u64 + ROUND
}

const DB: &[&str] = &["RDB$DATABASE"];
const NONE: &[&str] = &[];

const fn own_row(text: &'static str, may: &'static [&'static str]) -> Row {
    Row {
        text,
        may,
        must: DB,
        must_with_rows: NONE,
        loading: NONE,
        bound: 1,
    }
}

/// The constant texts of [`sql::STATEMENTS`].
const STATEMENT_ROWS: &[Row] = &[
    own_row(sql::VERSION, DB),
    own_row(sql::SESSION, DB),
    Row {
        text: sql::OWN_ATTACHMENT,
        may: &["MON$ATTACHMENTS"],
        must: NONE,
        must_with_rows: NONE,
        loading: MON_LOADING,
        bound: 1,
    },
    Row {
        text: sql::IDLE_TIMEOUT,
        may: NONE,
        must: NONE,
        must_with_rows: NONE,
        loading: NONE,
        bound: 0,
    },
    Row {
        text: sql::DATABASE_FILE,
        may: &["MON$DATABASE"],
        must: NONE,
        must_with_rows: NONE,
        loading: MON_LOADING,
        bound: 1,
    },
    own_row(sql::READ_BACK_PROBE, DB),
    Row {
        text: sql::IDENTITY,
        may: &["RDB$DATABASE", "MON$DATABASE", "SEC$USERS"],
        must: DB,
        must_with_rows: NONE,
        loading: MON_LOADING,
        bound: 1,
    },
    own_row(sql::SYSTEM_PRIVILEGES_4, DB),
    own_row(sql::SYSTEM_PRIVILEGES_5, DB),
    Row {
        text: sql::ROLE_MEMBERSHIPS,
        may: &["RDB$USER_PRIVILEGES"],
        must: NONE,
        must_with_rows: &["RDB$USER_PRIVILEGES"],
        loading: NONE,
        bound: limit(crate::check::MAX_CATALOG_ROWS),
    },
    Row {
        text: sql::ROLE_PRIVILEGES,
        may: &["RDB$ROLES"],
        must: NONE,
        must_with_rows: &["RDB$ROLES"],
        loading: NONE,
        bound: limit(crate::check::MAX_CATALOG_ROWS),
    },
    // R13: block-less on a database without a local mapping; nothing
    // must be read.
    Row {
        text: sql::AUTH_MAPPINGS,
        may: &["RDB$AUTH_MAPPING"],
        must: NONE,
        must_with_rows: &["RDB$AUTH_MAPPING"],
        loading: NONE,
        bound: limit(crate::check::MAX_CATALOG_ROWS),
    },
    Row {
        text: sql::GLOBAL_AUTH_MAPPINGS,
        may: &["SEC$GLOBAL_AUTH_MAPPING"],
        must: NONE,
        must_with_rows: NONE,
        loading: MON_LOADING,
        bound: limit(crate::check::MAX_CATALOG_ROWS),
    },
    // R13: 1 to 7 of the relations it names, never the `CASE` branches no
    // grant row reaches.
    Row {
        text: sql::OBJECT_GRANTS,
        may: &[
            "RDB$USER_PRIVILEGES",
            "RDB$RELATIONS",
            "RDB$PROCEDURES",
            "RDB$EXCEPTIONS",
            "RDB$FIELDS",
            "RDB$CHARACTER_SETS",
            "RDB$GENERATORS",
            "RDB$FUNCTIONS",
            "RDB$COLLATIONS",
            "RDB$PACKAGES",
        ],
        must: NONE,
        must_with_rows: &["RDB$USER_PRIVILEGES"],
        loading: NONE,
        bound: limit(crate::check::MAX_CATALOG_ROWS),
    },
    // R13: leaves out `RDB$EXCEPTIONS` when it is empty.
    own_row(
        sql::OWNED_OBJECTS,
        &[
            "RDB$DATABASE",
            "RDB$RELATIONS",
            "RDB$PROCEDURES",
            "RDB$FUNCTIONS",
            "RDB$PACKAGES",
            "RDB$GENERATORS",
            "RDB$EXCEPTIONS",
            "RDB$FIELDS",
            "RDB$ROLES",
        ],
    ),
    own_row(sql::DATABASE_TRIGGERS, &["RDB$DATABASE", "RDB$TRIGGERS"]),
    Row {
        text: sql::CREDENTIAL_RELATIONS,
        may: &["RDB$RELATIONS"],
        must: NONE,
        must_with_rows: &["RDB$RELATIONS"],
        loading: NONE,
        bound: limit(sql::PROBES.len() + 1),
    },
    // R13: leaves out `RDB$USER_PRIVILEGES` when the system privilege or
    // ownership already decides.
    Row {
        text: sql::RELATIONS,
        may: &["RDB$RELATIONS", "RDB$USER_PRIVILEGES"],
        must: NONE,
        must_with_rows: &["RDB$RELATIONS"],
        loading: NONE,
        bound: limit(catalog::MAX_RELATIONS),
    },
    Row {
        text: sql::COLUMNS,
        may: &["RDB$RELATION_FIELDS", "RDB$RELATIONS", "RDB$FIELDS"],
        must: NONE,
        must_with_rows: &["RDB$RELATION_FIELDS", "RDB$RELATIONS", "RDB$FIELDS"],
        loading: NONE,
        bound: limit(catalog::MAX_COLUMNS),
    },
    // R23 items 2 and 3.
    Row {
        text: sql::VIEW_RELATIONS,
        may: &["RDB$VIEW_RELATIONS"],
        must: NONE,
        must_with_rows: &["RDB$VIEW_RELATIONS"],
        loading: NONE,
        bound: limit(crate::views::MAX_ROWS),
    },
    Row {
        text: sql::DEPENDENCIES,
        may: &["RDB$DEPENDENCIES"],
        must: NONE,
        must_with_rows: &["RDB$DEPENDENCIES"],
        loading: NONE,
        bound: limit(crate::views::MAX_ROWS),
    },
    // R41: every column's source; a join of two persistent catalog
    // relations, both touched when a row is returned.
    Row {
        text: sql::FIELD_SOURCES,
        may: &["RDB$RELATION_FIELDS", "RDB$FIELDS"],
        must: NONE,
        must_with_rows: &["RDB$RELATION_FIELDS", "RDB$FIELDS"],
        loading: NONE,
        bound: limit(crate::views::MAX_ROWS),
    },
    // R41: a union of five catalog relations; any part may be empty.
    Row {
        text: sql::ROUTINES,
        may: &[
            "RDB$PROCEDURES",
            "RDB$FUNCTIONS",
            "RDB$PACKAGES",
            "RDB$TRIGGERS",
            "RDB$INDICES",
        ],
        must: NONE,
        must_with_rows: NONE,
        loading: NONE,
        bound: limit(crate::views::MAX_ROWS),
    },
    // R30 item 3: one row of `RDB$DATABASE`.
    own_row(sql::LINGER, DB),
    // R1 rule 5: one row of `MON$DATABASE`, block-less or the `MON$`
    // metadata-loading set (as `DATABASE_FILE`).
    Row {
        text: sql::RESTORE_STATE,
        may: &["MON$DATABASE"],
        must: NONE,
        must_with_rows: NONE,
        loading: MON_LOADING,
        bound: 1,
    },
];

/// The probe of `relation` (decision 4): `RDB$DATABASE` always, the probed
/// relation possibly, its metadata-loading set by kind.
const fn probe_row(
    text: &'static str,
    may: &'static [&'static str],
    loading: &'static [&'static str],
) -> Row {
    Row {
        text,
        may,
        must: DB,
        must_with_rows: NONE,
        loading,
        bound: 1,
    }
}

/// The one-bit probes of [`sql::PROBES`], in its order.
const PROBE_ROWS: &[Row] = &[
    probe_row(sql::PROBES[0].1, &["RDB$DATABASE", "PLG$SRP"], NONE),
    probe_row(sql::PROBES[1].1, &["RDB$DATABASE", "PLG$SRP_VIEW"], NONE),
    probe_row(sql::PROBES[2].1, &["RDB$DATABASE", "PLG$USERS"], NONE),
    probe_row(sql::PROBES[3].1, &["RDB$DATABASE", "PLG$VIEW_USERS"], NONE),
    probe_row(
        sql::PROBES[4].1,
        &["RDB$DATABASE", "SEC$USERS"],
        MON_LOADING,
    ),
    probe_row(
        sql::PROBES[5].1,
        &["RDB$DATABASE", "SEC$USER_ATTRIBUTES"],
        MON_LOADING,
    ),
    probe_row(
        sql::PROBES[6].1,
        &["RDB$DATABASE", "SEC$GLOBAL_AUTH_MAPPING"],
        MON_LOADING,
    ),
    probe_row(
        sql::PROBES[7].1,
        &["RDB$DATABASE", "RDB$CONFIG"],
        CONFIG_LOADING,
    ),
];

/// Every row of the table.
pub(crate) fn rows() -> impl Iterator<Item = &'static Row> {
    STATEMENT_ROWS.iter().chain(PROBE_ROWS)
}

/// The row of a constant text.
pub(crate) fn row(text: &str) -> Option<&'static Row> {
    rows().find(|r| r.text == text)
}

/// The longest text of the closed set, in bytes (R20: `max_sql_length` is
/// computed from the set, in UTF-8 bytes).
pub(crate) fn longest_text() -> usize {
    rows().map(|r| r.text.len()).max().unwrap_or(0)
}

/// Whether a record of the agent's attachment matches its credit's text:
/// `block` the relations of its per-table block (empty when block-less),
/// `fetched` its `records fetched`, `account` and `table` the credit's.
/// The R22 / R35 bounds are checked by the caller.
pub(crate) fn matches(
    text: &str,
    table: Option<&str>,
    block: &[&str],
    fetched: u64,
    account: &FetchAccount,
) -> bool {
    let rows_counted = account.counted > 0;
    match table {
        // A built text: exactly its table with rows, no block without.
        Some(t) => {
            if row(text).is_some() {
                return false;
            }
            if rows_counted {
                block == [t]
            } else {
                block.is_empty()
            }
        }
        None => {
            let Some(r) = row(text) else {
                return false;
            };
            fetched <= r.bound
                && block
                    .iter()
                    .all(|b| r.may.contains(b) || r.loading.contains(b))
                && r.must.iter().all(|m| block.contains(m))
                && (!rows_counted || r.must_with_rows.iter().all(|m| block.contains(m)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::FetchEnd;
    use databastion_classifiers::query::firebird::analyze_firebird;

    /// R20, R8 item 4: the table and the two lists of the closed set
    /// (`sql::STATEMENTS`, `sql::PROBES`) hold the same texts, once each;
    /// every row's may-read set is the relations its text names, its
    /// must-read sets lie within it, and its metadata-loading set is
    /// system relations of the never-sampled list (R23 item 1).
    #[test]
    fn every_text_of_the_closed_set_has_its_row() {
        let set: Vec<&str> = sql::STATEMENTS
            .iter()
            .map(|s| s.text)
            .chain(sql::PROBES.iter().map(|(_, t)| *t))
            .collect();
        let table: Vec<&str> = rows().map(|r| r.text).collect();
        assert_eq!(set.len(), table.len());
        for t in &set {
            assert_eq!(table.iter().filter(|x| *x == t).count(), 1, "{t}");
            assert!(sql::checked(t));
        }
        for r in rows() {
            let mut named = analyze_firebird(r.text).relations;
            named.sort();
            named.dedup();
            let mut may: Vec<String> = r.may.iter().map(|s| (*s).to_owned()).collect();
            may.sort();
            assert_eq!(named, may, "{}", r.text);
            for m in r.must.iter().chain(r.must_with_rows) {
                assert!(r.may.contains(m), "{m} in {}", r.text);
            }
            for l in r.loading {
                assert!(catalog::never_sampled(l), "{l}");
                assert!(l.starts_with("RDB$"), "{l}");
            }
            // A text that reads `MON$` or `SEC$` gets the R13 set; one that
            // reads `RDB$CONFIG` the R23 set; others none.
            let mon = r
                .may
                .iter()
                .any(|m| m.starts_with("MON$") || m.starts_with("SEC$"));
            let cfg = r.may.contains(&"RDB$CONFIG");
            let want: &[&str] = match (mon, cfg) {
                (true, _) => MON_LOADING,
                (false, true) => CONFIG_LOADING,
                _ => NONE,
            };
            assert_eq!(r.loading, want, "{}", r.text);
        }
        // The probes keep their order (the rows index `sql::PROBES`).
        for (r, (_, t)) in PROBE_ROWS.iter().zip(sql::PROBES) {
            assert_eq!(r.text, *t);
        }
        // R20: the longest text, in bytes.
        assert_eq!(longest_text(), sql::OBJECT_GRANTS.len());
    }

    fn acc(counted: u64) -> FetchAccount {
        FetchAccount {
            counted,
            requested: 64,
            last: 64,
            largest: 64,
            end: FetchEnd::End,
            ..FetchAccount::default()
        }
    }

    #[test]
    fn must_may_and_loading_sets() {
        // `RDB$DATABASE` must be read by the version text.
        assert!(matches(sql::VERSION, None, &["RDB$DATABASE"], 1, &acc(1)));
        assert!(!matches(sql::VERSION, None, &[], 1, &acc(1)));
        // Above the static bound.
        assert!(!matches(sql::VERSION, None, &["RDB$DATABASE"], 2, &acc(2)));
        // A `MON$` text: block-less, or the metadata-loading set.
        assert!(matches(sql::OWN_ATTACHMENT, None, &[], 1, &acc(1)));
        assert!(matches(
            sql::OWN_ATTACHMENT,
            None,
            &["RDB$DATABASE", "RDB$RELATIONS"],
            1,
            &acc(1)
        ));
        // Not another system relation, nor a user table.
        assert!(!matches(
            sql::OWN_ATTACHMENT,
            None,
            &["RDB$AUTH_MAPPING"],
            1,
            &acc(1)
        ));
        assert!(!matches(
            sql::VERSION,
            None,
            &["RDB$DATABASE", "CUSTOMERS"],
            1,
            &acc(1)
        ));
        // A text without a `MON$` read: no metadata-loading set.
        assert!(!matches(
            sql::ROLE_PRIVILEGES,
            None,
            &["RDB$ROLES", "RDB$RELATIONS"],
            3,
            &acc(3)
        ));
        // The `RDB$CONFIG` probe: its R23 set, not the `MON$` one.
        let cfg = sql::PROBES[7].1;
        assert!(matches(
            cfg,
            None,
            &["RDB$DATABASE", "RDB$CHARACTER_SETS", "RDB$COLLATIONS"],
            1,
            &acc(1)
        ));
        assert!(!matches(
            cfg,
            None,
            &["RDB$DATABASE", "RDB$RELATIONS"],
            1,
            &acc(1)
        ));
        // R23 item 2: with rows counted the relation is in the block;
        // without, named or absent.
        assert!(matches(
            sql::VIEW_RELATIONS,
            None,
            &["RDB$VIEW_RELATIONS"],
            2,
            &acc(2)
        ));
        assert!(!matches(sql::VIEW_RELATIONS, None, &[], 2, &acc(2)));
        assert!(matches(sql::VIEW_RELATIONS, None, &[], 0, &acc(0)));
        assert!(matches(
            sql::VIEW_RELATIONS,
            None,
            &["RDB$VIEW_RELATIONS"],
            0,
            &acc(0)
        ));
        // R13: AUTH_MAPPINGS is block-less without a local mapping.
        assert!(matches(sql::AUTH_MAPPINGS, None, &[], 0, &acc(0)));
        // A text outside the set has no row.
        assert!(!matches(
            "SELECT 1 FROM RDB$DATABASE",
            None,
            &["RDB$DATABASE"],
            1,
            &acc(1)
        ));
    }

    /// The forged-copy residual of R13 (L2) is no longer widened to every
    /// text (R39 (g)): a block-less copy of a text with a non-empty
    /// must-read set does not pass, so it cannot carry a read of a virtual
    /// relation (which writes no block) for that credit.
    #[test]
    fn a_block_less_copy_passes_only_texts_with_an_empty_must_read_set() {
        for r in rows() {
            let blockless = matches(r.text, None, &[], 0, &acc(0));
            assert_eq!(blockless, r.must.is_empty(), "{}", r.text);
        }
    }

    #[test]
    fn built_texts_name_exactly_their_table() {
        let b = sql::sample_statement("CUSTOMERS", &[("EMAIL", sql::Conv::Text)], 3).unwrap();
        assert_eq!(b.table(), "CUSTOMERS");
        let t = b.text();
        assert!(matches(t, Some("CUSTOMERS"), &["CUSTOMERS"], 3, &acc(3)));
        assert!(!matches(t, Some("CUSTOMERS"), &[], 3, &acc(3)));
        assert!(!matches(
            t,
            Some("CUSTOMERS"),
            &["CUSTOMERS", "RDB$RELATIONS"],
            3,
            &acc(3)
        ));
        assert!(!matches(t, Some("CUSTOMERS"), &["ORDERS"], 3, &acc(3)));
        // An empty table: no block.
        assert!(matches(t, Some("CUSTOMERS"), &[], 0, &acc(0)));
        assert!(!matches(t, Some("CUSTOMERS"), &["CUSTOMERS"], 0, &acc(0)));
        // A constant text never takes a table.
        assert!(!matches(
            sql::VERSION,
            Some("RDB$DATABASE"),
            &["RDB$DATABASE"],
            1,
            &acc(1)
        ));
        let g = sql::ticket_type_counts("CASTICKETS", "TYPE").unwrap();
        assert_eq!(g.table(), "CASTICKETS");
        assert!(matches(
            g.text(),
            Some("CASTICKETS"),
            &["CASTICKETS"],
            2,
            &acc(2)
        ));
    }
}
