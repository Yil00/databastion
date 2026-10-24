//! The authorizer's decision (ADR-0059 decision 5, security review L8),
//! independent of `rusqlite` so it can be property-tested: `db` converts
//! SQLite's callback into an [`Action`] and installs the result as
//! `SQLITE_DENY`, never `SQLITE_IGNORE` (which would silently read `NULL`).
//!
//! - The database-name argument must be `main` or absent, for every action.
//! - `SQLITE_SELECT` is allowed.
//! - `SQLITE_READ` only on the table the current statement template is
//!   for: its one table for the rowid-bounds and sampling templates,
//!   `sqlite_schema` (or `sqlite_master`) for the catalog only,
//!   `sqlite_stat1` for the statistics only.
//! - `SQLITE_FUNCTION` only for `typeof`, `octet_length`, `substr`, `min`,
//!   `max` (and, on the self-check's in-memory connection only,
//!   `sqlite_version` and `sqlite_source_id`), compared
//!   ASCII-case-insensitively.
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
    /// The catalog statement.
    Catalog,
    /// The statistics statement.
    Stats,
    /// `table_xinfo` of this table.
    Columns(String),
    /// Rowid bounds or sampling of this table.
    Read(String),
    /// One check pragma, by name.
    Pragma(&'static str),
}

/// What SQLite asks to authorize, reduced to what the rules look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    /// `SQLITE_SELECT`.
    Select,
    /// `SQLITE_READ` of a column of `table`.
    Read {
        /// The table.
        table: &'a str,
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

/// Functions the reader's statements call.
const FUNCTIONS: [&str; 5] = ["typeof", "octet_length", "substr", "min", "max"];
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
        Action::Read { table } => match template {
            Template::Catalog => eq(table, "sqlite_schema") || eq(table, "sqlite_master"),
            Template::Stats => eq(table, "sqlite_stat1"),
            Template::Read(t) => {
                eq(table, t) && !eq(table, "sqlite_schema") && !eq(table, "sqlite_master")
            }
            _ => false,
        },
        Action::Function { name } => match template {
            Template::Read(_) => FUNCTIONS.iter().any(|f| eq(name, f)),
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
            Action::Read { table: "clients" },
            Some("main")
        ));
        assert!(allowed(
            &read,
            Action::Read { table: "CLIENTS" },
            Some("main")
        ));
        assert!(!allowed(
            &read,
            Action::Read { table: "other" },
            Some("main")
        ));
        assert!(!allowed(
            &read,
            Action::Read { table: "clients" },
            Some("temp")
        ));
        assert!(!allowed(
            &read,
            Action::Read { table: "clients" },
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
                table: "sqlite_master"
            },
            Some("main")
        ));
        assert!(!allowed(
            &cat,
            Action::Read { table: "clients" },
            Some("main")
        ));
        assert!(!allowed(&cat, Action::Function { name: "min" }, None));
        assert!(!allowed(
            &Template::Read("sqlite_master".into()),
            Action::Read {
                table: "sqlite_master"
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

    fn template() -> impl Strategy<Value = Template> {
        prop_oneof![
            Just(Template::None),
            Just(Template::SelfCheck),
            Just(Template::Catalog),
            Just(Template::Stats),
            "[a-zA-Z_]{1,8}".prop_map(Template::Columns),
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
                mixed_case("sqlite_master"), mixed_case("sqlite_stat1"), mixed_case("table_xinfo"),
                mixed_case("journal_mode"), mixed_case("writable_schema"), "[a-zA-Z_]{1,8}",
            ],
            arg in proptest::option::of("[a-zA-Z_]{1,8}"),
            db in proptest::option::of(prop_oneof![Just("main".to_owned()), Just("temp".to_owned()), "[a-z]{1,5}"]),
        ) {
            let action = match kind {
                0 => Action::Select,
                1 => Action::Read { table: &name },
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
                        FUNCTIONS.contains(&lower.as_str())
                            || (t == Template::SelfCheck && SELF_FUNCTIONS.contains(&lower.as_str()))
                    ),
                    Action::Pragma { arg, .. } => {
                        prop_assert!(lower == "table_xinfo" || PRAGMAS.contains(&lower.as_str()));
                        prop_assert_eq!(lower == "table_xinfo", arg.is_some());
                    }
                    Action::Read { .. } => prop_assert!(matches!(t, Template::Read(_) | Template::Catalog | Template::Stats)),
                    _ => {}
                }
            }
        }
    }
}
