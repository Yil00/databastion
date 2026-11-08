//! The authorizer's decision (ADR-0059 decision 5, security review L8),
//! independent of `rusqlite` so it can be property-tested: `db` converts
//! SQLite's callback into an [`Action`] and installs the result as
//! `SQLITE_DENY`, never `SQLITE_IGNORE` (which would silently read `NULL`).
//!
//! - The database-name argument must be `main` or absent, for every action.
//! - `SQLITE_SELECT` is allowed.
//! - `SQLITE_READ` only on the table the current statement template is
//!   for: its one table for the rowid-bounds and sampling templates,
//!   `sqlite_schema` (or `sqlite_master`) for the catalog (`type`, `name`,
//!   `rootpage`) and the schema-text statement (`type`, `name`, `sql`)
//!   only,
//!   `sqlite_stat1` for the statistics only.
//! - `SQLITE_FUNCTION` only for `typeof`, `octet_length`, `substr`, `min`,
//!   `max` under the sampling template, `min` and `max` under the
//!   rowid-bounds template, and, on the self-check's in-memory connection
//!   only, `sqlite_version` and `sqlite_source_id`; compared
//!   ASCII-case-insensitively.
//! - Under the sampling template only, also the closed list
//!   [`SCHEMA_EXPR_FUNCTIONS`] (ADR-0059 refinement of 2026-11-07): since
//!   SQLite 3.54, reading a column that has a `DEFAULT` or a `STORED`
//!   generated expression sends every function name of that expression to
//!   the authorizer while the statement is prepared
//!   (`sqlite3ColumnExprAuth`, called from `sqlite3ColumnDefault`). SQLite
//!   only authorizes those names there: the expression is turned into a
//!   value by `sqlite3ValueFromExpr` without a function context, so no
//!   function is run (a `STORED` value is read from the record, a
//!   `DEFAULT` one is used only for rows written before an `ALTER TABLE ...
//!   ADD COLUMN`, which allows only constant defaults). The callback cannot
//!   tell such a call from a call in the statement text (both are
//!   `SQLITE_FUNCTION` with no table, database or trigger / view name), but
//!   the statement texts are fixed and call only the five functions above,
//!   so any other name can only come from the file's schema.
//! - `SQLITE_PRAGMA` only for `table_xinfo` with an argument (the current
//!   table) and `journal_mode`, `schema_version`, `page_size`, `encoding`,
//!   `trusted_schema`, `compile_options` without one, compared
//!   ASCII-case-insensitively, and each only under its own template.
//! - Everything else is denied.

/// The statement template the next `prepare` is for (set before each).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Template {
    /// No statement is expected: everything is denied.
    #[default]
    None,
    /// The self-check (in-memory connection).
    SelfCheck,
    /// The catalog statement (`type`, `name`, `rootpage` of
    /// `sqlite_schema`; never `sql`).
    Catalog,
    /// One table's own schema text (`sql` of its `sqlite_schema` row, the
    /// row chosen by the statement's bound name): the ADR-0059 refinement
    /// of 2026-11-07's exception. The reader only checks that the text is
    /// valid UTF-8 and finds nothing else in it; the text is never stored,
    /// sent or logged.
    Schema,
    /// The statistics statement.
    Stats,
    /// `table_xinfo` of this table.
    Columns(String),
    /// Rowid bounds of this table (`min` / `max` of the rowid only: the
    /// rowid is read with `OP_Rowid`, so no column expression is
    /// authorized).
    Bounds(String),
    /// Sampling of this table.
    Read(String),
    /// One check pragma, by name.
    Pragma(&'static str),
}

/// What SQLite asks to authorize, reduced to what the rules look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    /// `SQLITE_SELECT`.
    Select,
    /// `SQLITE_READ` of `column` of `table`.
    Read {
        /// The table.
        table: &'a str,
        /// The column.
        column: &'a str,
    },
    /// `SQLITE_FUNCTION`.
    Function {
        /// The function name.
        name: &'a str,
    },
    /// `SQLITE_PRAGMA`.
    Pragma {
        /// The pragma name.
        name: &'a str,
        /// Its argument.
        arg: Option<&'a str>,
    },
    /// Any other action code (writes, DDL, `ATTACH`, transactions,
    /// `ANALYZE`, `RECURSIVE`…).
    Other,
}

/// The `sqlite_schema` columns the catalog statement reads.
const CATALOG_COLUMNS: [&str; 3] = ["type", "name", "rootpage"];
/// The `sqlite_schema` columns the schema-text statement reads.
const SCHEMA_COLUMNS: [&str; 3] = ["type", "name", "sql"];
/// Functions the sampling statements call.
const FUNCTIONS: [&str; 5] = ["typeof", "octet_length", "substr", "min", "max"];
/// Functions the rowid-bounds statement calls.
const BOUNDS_FUNCTIONS: [&str; 2] = ["min", "max"];
/// Built-in functions a column's `DEFAULT` or `STORED` generated expression
/// may name, authorized (never run) under the sampling template only
/// (ADR-0059 refinement of 2026-11-07). Each is registered by SQLite 3.54.1
/// without `SQLITE_FUNC_UNSAFE` or `SQLITE_DIRECTONLY` (innocuous: usable in
/// the schema under `TRUSTED_SCHEMA=0`), reads no file, environment or
/// memory beyond its arguments, and is not random. `->` and `->>` are the
/// names SQLite gives the JSON operators; `CURRENT_DATE`, `CURRENT_TIME`
/// and `CURRENT_TIMESTAMP` reach the authorizer as functions of those
/// names. `random`, `randomblob`, `load_extension`, `sqlite_*`,
/// `changes`-style connection functions and any name outside this list
/// stay refused: the statement fails with `auth` and the table is not
/// sampled.
pub const SCHEMA_EXPR_FUNCTIONS: [&str; 33] = [
    // Date and time.
    "current_date",
    "current_time",
    "current_timestamp",
    "date",
    "time",
    "datetime",
    "julianday",
    "unixepoch",
    "strftime",
    // Text.
    "lower",
    "upper",
    "trim",
    "ltrim",
    "rtrim",
    "substring",
    "replace",
    "instr",
    "length",
    "printf",
    "format",
    "hex",
    "concat",
    "concat_ws",
    // NULL handling and conditions.
    "coalesce",
    "ifnull",
    "nullif",
    "iif",
    "if",
    // Numbers.
    "abs",
    "round",
    // JSON.
    "json_extract",
    "->",
    "->>",
];
/// Functions of the self-check statement only.
const SELF_FUNCTIONS: [&str; 2] = ["sqlite_version", "sqlite_source_id"];
/// Pragmas read without an argument, with the template allowing each.
const PRAGMAS: [&str; 6] = [
    "journal_mode",
    "schema_version",
    "page_size",
    "encoding",
    "trusted_schema",
    "compile_options",
];

fn eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Whether `action` on `database` is allowed under `template`.
#[must_use]
pub fn allowed(template: &Template, action: Action<'_>, database: Option<&str>) -> bool {
    if database.is_some_and(|d| d != "main") {
        return false;
    }
    match action {
        Action::Select => !matches!(
            template,
            Template::None | Template::Columns(_) | Template::Pragma(_)
        ),
        Action::Read { table, column } => match template {
            Template::Catalog => {
                (eq(table, "sqlite_schema") || eq(table, "sqlite_master"))
                    && CATALOG_COLUMNS.iter().any(|c| eq(column, c))
            }
            Template::Schema => {
                (eq(table, "sqlite_schema") || eq(table, "sqlite_master"))
                    && SCHEMA_COLUMNS.iter().any(|c| eq(column, c))
            }
            Template::Stats => eq(table, "sqlite_stat1"),
            Template::Read(t) | Template::Bounds(t) => {
                eq(table, t) && !eq(table, "sqlite_schema") && !eq(table, "sqlite_master")
            }
            _ => false,
        },
        Action::Function { name } => match template {
            Template::Read(_) => {
                FUNCTIONS.iter().any(|f| eq(name, f))
                    || SCHEMA_EXPR_FUNCTIONS.iter().any(|f| eq(name, f))
            }
            Template::Bounds(_) => BOUNDS_FUNCTIONS.iter().any(|f| eq(name, f)),
            Template::SelfCheck => SELF_FUNCTIONS.iter().any(|f| eq(name, f)),
            _ => false,
        },
        Action::Pragma { name, arg } => match (template, arg) {
            (Template::Columns(t), Some(a)) => eq(name, "table_xinfo") && a == t,
            (Template::Pragma(p), None) => eq(name, p) && PRAGMAS.iter().any(|q| eq(name, q)),
            (Template::SelfCheck, None) => {
                eq(name, "trusted_schema") || eq(name, "compile_options")
            }
            _ => false,
        },
        Action::Other => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn the_listed_combinations_only() {
        let read = Template::Read("clients".into());
        assert!(allowed(&read, Action::Select, None));
        assert!(allowed(
            &read,
            Action::Read {
                table: "clients",
                column: "c"
            },
            Some("main")
        ));
        assert!(allowed(
            &read,
            Action::Read {
                table: "CLIENTS",
                column: "c"
            },
            Some("main")
        ));
        assert!(!allowed(
            &read,
            Action::Read {
                table: "other",
                column: "c"
            },
            Some("main")
        ));
        assert!(!allowed(
            &read,
            Action::Read {
                table: "clients",
                column: "c"
            },
            Some("temp")
        ));
        assert!(!allowed(
            &read,
            Action::Read {
                table: "clients",
                column: "c"
            },
            Some("aux")
        ));
        assert!(allowed(&read, Action::Function { name: "TypeOf" }, None));
        assert!(!allowed(
            &read,
            Action::Function {
                name: "load_extension"
            },
            None
        ));
        assert!(!allowed(
            &read,
            Action::Function {
                name: "sqlite_version"
            },
            None
        ));
        assert!(!allowed(&read, Action::Other, Some("main")));
        let cat = Template::Catalog;
        assert!(allowed(
            &cat,
            Action::Read {
                table: "sqlite_master",
                column: "name"
            },
            Some("main")
        ));
        assert!(!allowed(
            &cat,
            Action::Read {
                table: "clients",
                column: "c"
            },
            Some("main")
        ));
        assert!(!allowed(&cat, Action::Function { name: "min" }, None));
        assert!(!allowed(
            &Template::Read("sqlite_master".into()),
            Action::Read {
                table: "sqlite_master",
                column: "c"
            },
            Some("main")
        ));
        let cols = Template::Columns("t".into());
        assert!(allowed(
            &cols,
            Action::Pragma {
                name: "TABLE_XINFO",
                arg: Some("t")
            },
            Some("main")
        ));
        assert!(!allowed(
            &cols,
            Action::Pragma {
                name: "table_xinfo",
                arg: Some("u")
            },
            Some("main")
        ));
        assert!(!allowed(
            &cols,
            Action::Pragma {
                name: "table_info",
                arg: Some("t")
            },
            Some("main")
        ));
        assert!(!allowed(
            &cols,
            Action::Pragma {
                name: "table_xinfo",
                arg: None
            },
            Some("main")
        ));
        let jm = Template::Pragma("journal_mode");
        assert!(allowed(
            &jm,
            Action::Pragma {
                name: "journal_mode",
                arg: None
            },
            Some("main")
        ));
        assert!(!allowed(
            &jm,
            Action::Pragma {
                name: "journal_mode",
                arg: Some("delete")
            },
            Some("main")
        ));
        assert!(!allowed(
            &jm,
            Action::Pragma {
                name: "page_size",
                arg: None
            },
            Some("main")
        ));
        assert!(!allowed(
            &Template::Pragma("writable_schema"),
            Action::Pragma {
                name: "writable_schema",
                arg: None
            },
            Some("main")
        ));
        assert!(allowed(
            &Template::SelfCheck,
            Action::Function {
                name: "sqlite_source_id"
            },
            None
        ));
        assert!(!allowed(&Template::None, Action::Select, None));
    }

    /// ADR-0059 refinement of 2026-11-07: the schema-expression list is
    /// allowed under the sampling template only, in any ASCII case; names
    /// off the list (random, extension loading, SQLite's own state) stay
    /// refused there.
    #[test]
    fn schema_expression_functions_under_the_sampling_template_only() {
        let read = Template::Read("t".into());
        for f in SCHEMA_EXPR_FUNCTIONS {
            assert!(allowed(&read, Action::Function { name: f }, None), "{f}");
            let upper = f.to_ascii_uppercase();
            assert!(
                allowed(&read, Action::Function { name: &upper }, None),
                "{upper}"
            );
        }
        for f in [
            "random",
            "randomblob",
            "load_extension",
            "sqlite_version",
            "sqlite_source_id",
            "sqlite_compileoption_get",
            "sqlite_offset",
            "readfile",
            "writefile",
            "fts3_tokenizer",
            "changes",
            "last_insert_rowid",
            "zeroblob",
            "quote",
            "unknown",
            "lower ",
            "",
        ] {
            assert!(!allowed(&read, Action::Function { name: f }, None), "{f}");
        }
        // None of the listed names is a base function, a self-check
        // function or a name with characters SQLite's tokenizer would not
        // give a function (besides the JSON operators).
        for f in SCHEMA_EXPR_FUNCTIONS {
            assert!(
                !FUNCTIONS.contains(&f) && !SELF_FUNCTIONS.contains(&f),
                "{f}"
            );
            assert!(
                f == "->" || f == "->>" || f.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{f}"
            );
        }
    }

    /// The other templates are unchanged by the refinement: catalog,
    /// columns, statistics, check pragmas and the self-check allow no
    /// schema-expression function, and the rowid bounds only `min` and
    /// `max`.
    #[test]
    fn the_other_templates_are_unchanged() {
        let others = [
            Template::None,
            Template::SelfCheck,
            Template::Catalog,
            Template::Stats,
            Template::Columns("t".into()),
            Template::Schema,
            Template::Bounds("t".into()),
            Template::Pragma("journal_mode"),
        ];
        for t in &others {
            for f in SCHEMA_EXPR_FUNCTIONS {
                assert!(!allowed(t, Action::Function { name: f }, None), "{t:?} {f}");
            }
        }
        for t in &others[..5] {
            for f in FUNCTIONS {
                assert!(!allowed(t, Action::Function { name: f }, None), "{t:?} {f}");
            }
        }
        let bounds = Template::Bounds("t".into());
        assert!(allowed(&bounds, Action::Function { name: "MIN" }, None));
        assert!(allowed(&bounds, Action::Function { name: "max" }, None));
        for f in ["typeof", "octet_length", "substr", "sqlite_version"] {
            assert!(!allowed(&bounds, Action::Function { name: f }, None), "{f}");
        }
        assert!(allowed(&bounds, Action::Select, None));
        assert!(allowed(
            &bounds,
            Action::Read {
                table: "t",
                column: "c"
            },
            Some("main")
        ));
        assert!(!allowed(
            &bounds,
            Action::Read {
                table: "u",
                column: "c"
            },
            Some("main")
        ));
        assert!(!allowed(
            &Template::Bounds("sqlite_schema".into()),
            Action::Read {
                table: "sqlite_schema",
                column: "c"
            },
            Some("main")
        ));
        assert!(!allowed(&bounds, Action::Other, Some("main")));
    }

    /// ADR-0059 refinement of 2026-11-07: the schema-text statement reads
    /// `type`, `name` and `sql` of `sqlite_schema` only, and calls nothing;
    /// the catalog never reads `sql`.
    #[test]
    fn the_schema_text_template_reads_its_columns_only() {
        let sch = Template::Schema;
        assert!(allowed(&sch, Action::Select, None));
        for (table, column) in [
            ("sqlite_schema", "sql"),
            ("SQLITE_MASTER", "SQL"),
            ("sqlite_schema", "name"),
            ("sqlite_schema", "type"),
        ] {
            assert!(allowed(&sch, Action::Read { table, column }, Some("main")));
        }
        for (table, column) in [
            ("sqlite_schema", "rootpage"),
            ("sqlite_schema", "tbl_name"),
            ("t", "sql"),
            ("sqlite_stat1", "stat"),
        ] {
            assert!(!allowed(&sch, Action::Read { table, column }, Some("main")));
        }
        assert!(!allowed(
            &sch,
            Action::Read {
                table: "sqlite_schema",
                column: "sql"
            },
            Some("temp")
        ));
        for f in FUNCTIONS.iter().chain(SCHEMA_EXPR_FUNCTIONS.iter()) {
            assert!(!allowed(&sch, Action::Function { name: f }, None), "{f}");
        }
        assert!(!allowed(
            &sch,
            Action::Pragma {
                name: "table_xinfo",
                arg: Some("t")
            },
            Some("main")
        ));
        assert!(!allowed(&sch, Action::Other, Some("main")));
        let cat = Template::Catalog;
        for column in ["type", "name", "rootpage"] {
            assert!(allowed(
                &cat,
                Action::Read {
                    table: "sqlite_schema",
                    column
                },
                Some("main")
            ));
        }
        assert!(!allowed(
            &cat,
            Action::Read {
                table: "sqlite_schema",
                column: "sql"
            },
            Some("main")
        ));
    }

    fn template() -> impl Strategy<Value = Template> {
        prop_oneof![
            Just(Template::None),
            Just(Template::SelfCheck),
            Just(Template::Catalog),
            Just(Template::Schema),
            Just(Template::Stats),
            "[a-zA-Z_]{1,8}".prop_map(Template::Columns),
            "[a-zA-Z_]{1,8}".prop_map(Template::Bounds),
            "[a-zA-Z_]{1,8}".prop_map(Template::Read),
            prop::sample::select(PRAGMAS.to_vec()).prop_map(Template::Pragma),
        ]
    }

    fn mixed_case(s: &'static str) -> impl Strategy<Value = String> {
        proptest::collection::vec(any::<bool>(), s.len()).prop_map(move |up| {
            s.chars()
                .zip(up)
                .map(|(c, u)| if u { c.to_ascii_uppercase() } else { c })
                .collect()
        })
    }

    proptest! {
        /// Generated actions, names in mixed case and database names: only
        /// the listed combinations are allowed.
        #[test]
        fn only_listed_combinations_are_allowed(
            t in template(),
            kind in 0u8..5,
            name in prop_oneof![
                mixed_case("typeof"), mixed_case("substr"), mixed_case("load_extension"),
                mixed_case("lower"), mixed_case("current_timestamp"), mixed_case("randomblob"),
                Just("->>".to_owned()),
                mixed_case("sqlite_master"), mixed_case("sqlite_stat1"), mixed_case("table_xinfo"),
                mixed_case("journal_mode"), mixed_case("writable_schema"), "[a-zA-Z_]{1,8}",
            ],
            arg in proptest::option::of("[a-zA-Z_]{1,8}"),
            db in proptest::option::of(prop_oneof![Just("main".to_owned()), Just("temp".to_owned()), "[a-z]{1,5}"]),
        ) {
            let action = match kind {
                0 => Action::Select,
                1 => Action::Read { table: &name, column: "c" },
                2 => Action::Function { name: &name },
                3 => Action::Pragma { name: &name, arg: arg.as_deref() },
                _ => Action::Other,
            };
            let ok = allowed(&t, action, db.as_deref());
            if db.as_deref().is_some_and(|d| d != "main") || kind == 4 {
                prop_assert!(!ok);
            }
            if ok {
                let lower = name.to_ascii_lowercase();
                match action {
                    Action::Function { .. } => prop_assert!(
                        (matches!(t, Template::Read(_))
                            && (FUNCTIONS.contains(&lower.as_str())
                                || SCHEMA_EXPR_FUNCTIONS.contains(&lower.as_str())))
                            || (matches!(t, Template::Bounds(_))
                                && BOUNDS_FUNCTIONS.contains(&lower.as_str()))
                            || (t == Template::SelfCheck && SELF_FUNCTIONS.contains(&lower.as_str()))
                    ),
                    Action::Pragma { arg, .. } => {
                        prop_assert!(lower == "table_xinfo" || PRAGMAS.contains(&lower.as_str()));
                        prop_assert_eq!(lower == "table_xinfo", arg.is_some());
                    }
                    Action::Read { .. } => prop_assert!(matches!(t, Template::Read(_) | Template::Bounds(_) | Template::Catalog | Template::Schema | Template::Stats)),
                    _ => {}
                }
            }
        }
    }
}
