//! SQL text of the connector (ADR-0012 obligations 1 to 3).
//!
//! - Every statement is sent with the extended query protocol, with bound
//!   parameters; no simple-query and no multi-statement string.
//! - Every catalog object and function is qualified with `pg_catalog`, and
//!   the session runs with `search_path = ''`: no user-defined function or
//!   operator can be resolved.
//! - Identifiers come from the catalogs and are quoted by [`quote_ident`],
//!   the connector's only quoting function. Job parameters never reach SQL
//!   text: filters are applied in Rust on catalog names.
//! - Sampling queries select columns by name, with no cast, function or
//!   operator applied to them: values arrive in their binary wire format and
//!   are decoded in Rust (`wire`).
//! - The catalog denylist of obligation 1 (`pg_authid`, `pg_shadow`,
//!   `pg_user_mapping`, `pg_subscription`, `pg_largeobject`,
//!   `pg_db_role_setting.setconfig`, `pg_foreign_server.srvoptions`,
//!   `pg_statistic*`, `pg_stats*`, `lo_*`) is checked by a unit test over
//!   every statement of this module.

/// Quotes an identifier read from the catalogs: wrapped in `"`, every `"`
/// doubled. `None` for a name PostgreSQL cannot hold (empty, NUL).
#[must_use]
pub(crate) fn quote_ident(name: &str) -> Option<String> {
    if name.is_empty() || name.contains('\0') {
        return None;
    }
    let mut out = String::with_capacity(name.len() + 2);
    out.push('"');
    for c in name.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    Some(out)
}

/// Session settings, once per connection (obligation 3):
/// `SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`,
/// `search_path = ''`, and session defaults of the timeouts (the
/// transactions set their own with `is_local = true`). `$1`: statement
/// timeout, `$2`: lock timeout, `$3`: idle-in-transaction timeout, in
/// milliseconds.
pub(crate) const SESSION_SETUP: &str = "SELECT \
    pg_catalog.set_config('search_path', '', false), \
    pg_catalog.set_config('default_transaction_read_only', 'on', false), \
    pg_catalog.set_config('statement_timeout', $1, false), \
    pg_catalog.set_config('lock_timeout', $2, false), \
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, false), \
    pg_catalog.current_setting('server_version_num')";

/// Every unit of work (never `REPEATABLE READ`: distinguishable from
/// `pg_dump`).
pub(crate) const BEGIN: &str = "BEGIN TRANSACTION READ ONLY";
pub(crate) const COMMIT: &str = "COMMIT";
pub(crate) const ROLLBACK: &str = "ROLLBACK";

/// `SET LOCAL` of the three timeouts (obligation 4); parameters as in
/// [`SESSION_SETUP`]. Also returns `transaction_read_only` as a guard.
pub(crate) const SET_LOCAL_TIMEOUTS: &str = "SELECT \
    pg_catalog.set_config('statement_timeout', $1, true), \
    pg_catalog.set_config('lock_timeout', $2, true), \
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, true), \
    pg_catalog.current_setting('transaction_read_only')";

/// Schemas never sampled nor reported (obligation 1), as a SQL predicate
/// on `n.nspname`.
macro_rules! user_schema {
    () => {
        "n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') \
         AND n.nspname NOT LIKE 'pg\\_temp\\_%' \
         AND n.nspname NOT LIKE 'pg\\_toast\\_temp\\_%'"
    };
}

/// Not an object of an extension (`pg_depend.deptype = 'e'`), as a SQL
/// predicate on `c.oid`.
macro_rules! not_extension_member {
    () => {
        "NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
           WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass \
             AND d.objid = c.oid AND d.deptype = 'e')"
    };
}

/// Introspection (obligations 1 and 2): tables, materialized views,
/// partitioned tables and foreign tables of the schemas the role has
/// `USAGE` on, outside the system schemas and extensions. `$1`: row limit.
///
/// Columns: oid, schema, name, relkind, relispartition, reltuples,
/// relrowsecurity, readable (`SELECT` on at least one column), whether an
/// ancestor (`pg_inherits`, followed recursively: partitions and
/// inheritance) has row-level security, the partition root, and whether a
/// policy of the relation depends on an object that is neither in
/// `pg_catalog` nor the relation itself (obligation 2: a function, operator
/// or type outside `pg_catalog`, or any other relation, e.g. a subquery on a
/// view).
pub(crate) const INTROSPECT: &str = concat!(
    "WITH RECURSIVE anc(rel, ancestor) AS ( \
       SELECT i.inhrelid, i.inhparent FROM pg_catalog.pg_inherits i \
       UNION \
       SELECT a.rel, i.inhparent FROM anc a \
         JOIN pg_catalog.pg_inherits i ON i.inhrelid = a.ancestor) \
     SELECT c.oid, n.nspname, c.relname, c.relkind, c.relispartition, c.reltuples, \
       c.relrowsecurity, \
       pg_catalog.has_any_column_privilege(c.oid, 'SELECT') AS readable, \
       EXISTS (SELECT 1 FROM anc a JOIN pg_catalog.pg_class ac ON ac.oid = a.ancestor \
               WHERE a.rel = c.oid AND ac.relrowsecurity) AS ancestor_rls, \
       CASE WHEN c.relispartition \
            THEN pg_catalog.pg_partition_root(c.oid)::pg_catalog.oid \
            ELSE c.oid END AS root, \
       (c.relrowsecurity AND EXISTS ( \
          SELECT 1 FROM pg_catalog.pg_policy p \
          JOIN pg_catalog.pg_depend d \
            ON d.classid = 'pg_catalog.pg_policy'::pg_catalog.regclass AND d.objid = p.oid \
          WHERE p.polrelid = c.oid \
            AND NOT (d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass \
                     AND d.refobjid = p.polrelid) \
            AND NOT ( \
              (d.refclassid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_proc x WHERE x.oid = d.refobjid \
                   AND x.pronamespace = 'pg_catalog'::pg_catalog.regnamespace)) \
              OR (d.refclassid = 'pg_catalog.pg_operator'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_operator x WHERE x.oid = d.refobjid \
                   AND x.oprnamespace = 'pg_catalog'::pg_catalog.regnamespace)) \
              OR (d.refclassid = 'pg_catalog.pg_type'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_type x WHERE x.oid = d.refobjid \
                   AND x.typnamespace = 'pg_catalog'::pg_catalog.regnamespace)) \
              OR (d.refclassid = 'pg_catalog.pg_collation'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_collation x WHERE x.oid = d.refobjid \
                   AND x.collnamespace = 'pg_catalog'::pg_catalog.regnamespace)) \
              OR (d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_class x WHERE x.oid = d.refobjid \
                   AND x.relnamespace = 'pg_catalog'::pg_catalog.regnamespace))))) \
       AS rls_blocked \
     FROM pg_catalog.pg_class c \
     JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     WHERE c.relkind IN ('r', 'm', 'p', 'f') AND c.relpersistence <> 't' AND ",
    user_schema!(),
    " AND ",
    not_extension_member!(),
    " AND pg_catalog.has_schema_privilege(n.oid, 'USAGE') \
     ORDER BY n.nspname, c.relname, c.oid \
     LIMIT $1"
);

/// Columns the role may read, for a set of relations (`$1`: `oid[]`).
/// Columns: relation, name, type oid, `typtype`, `typbasetype`, and whether
/// the type is `citext` from the `citext` extension.
pub(crate) const COLUMNS: &str = "SELECT a.attrelid, a.attname, t.oid, t.typtype, t.typbasetype, \
       (t.typname = 'citext' AND EXISTS ( \
          SELECT 1 FROM pg_catalog.pg_depend d \
          JOIN pg_catalog.pg_extension e ON e.oid = d.refobjid \
          WHERE d.classid = 'pg_catalog.pg_type'::pg_catalog.regclass AND d.objid = t.oid \
            AND d.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass \
            AND d.deptype = 'e' AND e.extname = 'citext')) AS is_citext \
     FROM pg_catalog.pg_attribute a \
     JOIN pg_catalog.pg_type t ON t.oid = a.atttypid \
     WHERE a.attrelid = ANY ($1) AND a.attnum > 0 AND NOT a.attisdropped \
       AND pg_catalog.has_column_privilege(a.attrelid, a.attnum, 'SELECT') \
     ORDER BY a.attrelid, a.attnum";

/// Expressions of the policies evaluated for `SELECT` (`polcmd` `r` or
/// `*`) of a set of relations (`$1`: `oid[]`), as `pg_node_tree` text. Read
/// only to extract oids (`policy`), never logged (H1).
pub(crate) const POLICY_TREES: &str = "SELECT p.polrelid, p.polqual::pg_catalog.text, \
       p.polwithcheck::pg_catalog.text \
     FROM pg_catalog.pg_policy p \
     WHERE p.polrelid = ANY ($1) AND p.polcmd IN ('r', '*')";

/// A function allowed in a policy expression evaluated by the agent's
/// session (H1): a `pg_catalog` function, aggregate or not, that is
/// immutable and outside the denylist, or one of a few stable built-ins
/// that only read the session state. The denylist holds the built-ins that
/// run SQL text or resolve object names at run time (`query_to_xml`,
/// `cursor_to_xml`, `table_to_xml`, `schema_to_xml`, `database_to_xml` and
/// their schema variants, `ts_stat`, `ts_rewrite`, `reg*in`, `to_reg*`),
/// and the ones with side effects or file access.
macro_rules! policy_function_ok {
    ($f:literal) => {
        concat!(
            "EXISTS (SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid = ",
            $f,
            " AND p.pronamespace = 'pg_catalog'::pg_catalog.regnamespace \
               AND p.prokind IN ('f', 'a') \
               AND ((p.provolatile = 'i' AND p.proname !~ \
                     '^(query_to_xml|query_to_xmlschema|query_to_xml_and_xmlschema\
|cursor_to_xml|cursor_to_xmlschema|table_to_xml|table_to_xmlschema\
|table_to_xml_and_xmlschema|schema_to_xml|schema_to_xmlschema\
|schema_to_xml_and_xmlschema|database_to_xml|database_to_xmlschema\
|database_to_xml_and_xmlschema|ts_stat|ts_rewrite|to_reg.*|reg[a-z]*(in|recv)\
|set_config|pg_sleep.*|pg_read_.*|pg_ls_.*|pg_stat_file|lo_.*|pg_.*advisory.*\
|pg_cancel_backend|pg_terminate_backend|pg_notify|pg_reload_conf|pg_rotate_logfile\
|dblink.*|nextval|setval|currval|lastval|txid_.*|pg_current_.*)$') \
                    OR p.oid IN ( \
                      'pg_catalog.current_setting(pg_catalog.text)'::pg_catalog.regprocedure, \
                      'pg_catalog.current_setting(pg_catalog.text, pg_catalog.bool)'\
                        ::pg_catalog.regprocedure, \
                      'pg_catalog.now()'::pg_catalog.regprocedure, \
                      'pg_catalog.current_database()'::pg_catalog.regprocedure, \
                      'pg_catalog.current_schema()'::pg_catalog.regprocedure)))"
        )
    };
}

/// Counts the policy references (`$1` functions, `$2` operators, `$3` I/O
/// coercion result types, `oid[]`) that are not allowed: functions per
/// `policy_function_ok`, operators and types in `pg_catalog` whose
/// function (`oprcode`, `typinput`) is allowed.
pub(crate) const POLICY_REFS_REJECTED: &str = concat!(
    "SELECT (SELECT pg_catalog.count(*) FROM pg_catalog.unnest($1::pg_catalog.oid[]) AS f(o) \
             WHERE NOT ",
    policy_function_ok!("f.o"),
    ") + (SELECT pg_catalog.count(*) FROM pg_catalog.unnest($2::pg_catalog.oid[]) AS x(o) \
             WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_operator op WHERE op.oid = x.o \
               AND op.oprnamespace = 'pg_catalog'::pg_catalog.regnamespace AND ",
    policy_function_ok!("op.oprcode"),
    ")) + (SELECT pg_catalog.count(*) FROM pg_catalog.unnest($3::pg_catalog.oid[]) AS t(o) \
             WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_type ty WHERE ty.oid = t.o \
               AND ty.typnamespace = 'pg_catalog'::pg_catalog.regnamespace AND ",
    policy_function_ok!("ty.typinput"),
    "))"
);

/// Builds the sampling statement of one relation: `FROM ONLY` (never an
/// inheritance child or partition through its parent, obligation 1), the
/// columns by name, no expression on them.
///
/// With `tablesample`: `$1` is the `SYSTEM` percentage (`float4`), `$2` the
/// row limit (`int8`); otherwise `$1` is the row limit.
#[must_use]
pub(crate) fn sample_statement(
    schema: &str,
    relation: &str,
    columns: &[&str],
    tablesample: bool,
) -> Option<String> {
    if columns.is_empty() {
        return None;
    }
    let mut list = Vec::with_capacity(columns.len());
    for c in columns {
        list.push(quote_ident(c)?);
    }
    let from = format!("{}.{}", quote_ident(schema)?, quote_ident(relation)?);
    Some(if tablesample {
        format!(
            "SELECT {} FROM ONLY {from} TABLESAMPLE SYSTEM ($1) LIMIT $2",
            list.join(", ")
        )
    } else {
        format!("SELECT {} FROM ONLY {from} LIMIT $1", list.join(", "))
    })
}

// ------------------------------------------------------------------ check()

/// Attributes of the current role. `pg_roles` is read for boolean columns
/// only (never `rolpassword`, never `rolconfig`, which comes from
/// `pg_db_role_setting`).
pub(crate) const ROLE_ATTRIBUTES: &str = "SELECT r.rolsuper, r.rolbypassrls, r.rolreplication, \
       r.rolcreaterole, r.rolcreatedb \
     FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER";

/// Roles the current role is a member of (directly or not), with whether
/// they are predefined (`oid < FirstNormalObjectId`).
pub(crate) const MEMBERSHIPS: &str = "SELECT r.rolname, r.oid < 16384 AS predefined \
     FROM pg_catalog.pg_roles r \
     WHERE r.rolname <> CURRENT_USER \
       AND pg_catalog.pg_has_role(CURRENT_USER, r.oid, 'MEMBER') \
     ORDER BY r.rolname \
     LIMIT 1000";

/// Relations of user schemas the role can write to (any write-type
/// privilege). `{maintain}` is `, MAINTAIN` on PostgreSQL 17+.
pub(crate) fn write_privileges(maintain: bool) -> String {
    format!(
        concat!(
            "SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE ",
            user_schema!(),
            " AND ((c.relkind IN ('r', 'p', 'm', 'f', 'v') \
                 AND (pg_catalog.has_table_privilege(c.oid, \
                        'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER{}') \
                      OR pg_catalog.has_any_column_privilege(c.oid, 'INSERT, UPDATE'))) \
               OR (CASE WHEN c.relkind = 'S' \
                        THEN pg_catalog.has_sequence_privilege(c.oid, 'UPDATE') \
                        ELSE false END))"
        ),
        if maintain { ", MAINTAIN" } else { "" }
    )
}

/// Objects owned by the current role.
pub(crate) const OWNERSHIP: &str = "WITH me AS (SELECT r.oid FROM pg_catalog.pg_roles r \
                                          WHERE r.rolname = CURRENT_USER) \
     SELECT (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c, me WHERE c.relowner = me.oid) \
          + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_namespace n, me \
               WHERE n.nspowner = me.oid) \
          + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p, me WHERE p.proowner = me.oid) \
          + (SELECT pg_catalog.count(*) FROM pg_catalog.pg_database d, me WHERE d.datdba = me.oid)";

/// Enabled `login` event triggers (PostgreSQL 17+).
pub(crate) const LOGIN_EVENT_TRIGGERS: &str = "SELECT pg_catalog.count(*) \
     FROM pg_catalog.pg_event_trigger e \
     WHERE e.evtevent = 'login' AND e.evtenabled <> 'D'";

/// User schemas without `USAGE` (not covered by Discovery), outside
/// extensions.
pub(crate) const SCHEMAS_WITHOUT_USAGE: &str = concat!(
    "SELECT n.nspname FROM pg_catalog.pg_namespace n WHERE ",
    user_schema!(),
    " AND NOT pg_catalog.has_schema_privilege(n.oid, 'USAGE') \
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
        WHERE d.classid = 'pg_catalog.pg_namespace'::pg_catalog.regclass \
          AND d.objid = n.oid AND d.deptype = 'e') \
     ORDER BY n.nspname LIMIT 1000"
);

/// Audit prerequisites visible without `pg_read_all_settings`: installed
/// extensions `pg_stat_statements` / `pgaudit` in this database; the schema
/// of `pg_stat_statements_info` if it is a member of `pg_stat_statements`
/// (obligation 3); membership of `pg_read_all_stats`; and the value of
/// `pgaudit.log` (`NULL` when pgaudit is not loaded).
pub(crate) const AUDIT_PREREQUISITES: &str = "SELECT \
       EXISTS (SELECT 1 FROM pg_catalog.pg_extension e WHERE e.extname = 'pg_stat_statements'), \
       EXISTS (SELECT 1 FROM pg_catalog.pg_extension e WHERE e.extname = 'pgaudit'), \
       (SELECT n.nspname FROM pg_catalog.pg_extension e \
          JOIN pg_catalog.pg_depend d \
            ON d.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass \
           AND d.refobjid = e.oid AND d.deptype = 'e' \
           AND d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass \
          JOIN pg_catalog.pg_class c ON c.oid = d.objid \
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
          WHERE e.extname = 'pg_stat_statements' AND c.relname = 'pg_stat_statements_info' \
            AND c.relnamespace = e.extnamespace), \
       pg_catalog.pg_has_role(CURRENT_USER, 'pg_read_all_stats', 'MEMBER'), \
       pg_catalog.current_setting('pgaudit.log', true)";

/// `pgaudit.log`, `NULL` when pgaudit is not loaded (a setting, not
/// data): shows whether pgaudit is loaded without `pg_read_all_settings`.
pub(crate) const PGAUDIT_LOG: &str = "SELECT pg_catalog.current_setting('pgaudit.log', true)";

/// Probes that `pg_stat_statements` is loaded (`shared_preload_libraries`
/// is not readable without `pg_read_all_settings`): the info view errors
/// otherwise. Reads no statement text.
#[must_use]
pub(crate) fn pss_probe(schema: &str) -> Option<String> {
    Some(format!(
        "SELECT 1 FROM {}.pg_stat_statements_info",
        quote_ident(schema)?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_quoted_and_quotes_doubled() {
        assert_eq!(quote_ident("customers").unwrap(), "\"customers\"");
        assert_eq!(quote_ident("a\"b").unwrap(), "\"a\"\"b\"");
        assert_eq!(
            quote_ident("x\"; DROP TABLE t; --").unwrap(),
            "\"x\"\"; DROP TABLE t; --\""
        );
        assert_eq!(quote_ident("Été").unwrap(), "\"Été\"");
        assert!(quote_ident("").is_none());
        assert!(quote_ident("a\0b").is_none());
    }

    #[test]
    fn sample_statement_reads_only_the_named_relation() {
        let s = sample_statement("crm", "customers", &["email", "a\"b"], true).unwrap();
        assert_eq!(
            s,
            "SELECT \"email\", \"a\"\"b\" FROM ONLY \"crm\".\"customers\" \
             TABLESAMPLE SYSTEM ($1) LIMIT $2"
        );
        let s = sample_statement("crm", "customers", &["email"], false).unwrap();
        assert_eq!(
            s,
            "SELECT \"email\" FROM ONLY \"crm\".\"customers\" LIMIT $1"
        );
        assert!(sample_statement("crm", "t", &[], false).is_none());
    }

    fn all_statements() -> Vec<String> {
        vec![
            SESSION_SETUP.to_owned(),
            BEGIN.to_owned(),
            COMMIT.to_owned(),
            ROLLBACK.to_owned(),
            SET_LOCAL_TIMEOUTS.to_owned(),
            INTROSPECT.to_owned(),
            POLICY_TREES.to_owned(),
            POLICY_REFS_REJECTED.to_owned(),
            COLUMNS.to_owned(),
            ROLE_ATTRIBUTES.to_owned(),
            MEMBERSHIPS.to_owned(),
            write_privileges(true),
            write_privileges(false),
            OWNERSHIP.to_owned(),
            LOGIN_EVENT_TRIGGERS.to_owned(),
            SCHEMAS_WITHOUT_USAGE.to_owned(),
            AUDIT_PREREQUISITES.to_owned(),
            PGAUDIT_LOG.to_owned(),
            pss_probe("public").unwrap(),
            sample_statement("s", "t", &["c"], true).unwrap(),
        ]
    }

    #[test]
    fn no_statement_touches_the_catalog_denylist() {
        // ADR-0012 obligation 1.
        let denied = [
            "pg_authid",
            "pg_shadow",
            "pg_user_mapping",
            "pg_subscription",
            "pg_largeobject",
            "setconfig",
            "pg_db_role_setting",
            "srvoptions",
            "pg_foreign_server",
            "pg_statistic",
            "pg_stats",
            "lo_",
            "rolpassword",
            "rolconfig",
            "pg_read_file",
            "pg_ls_",
            "dblink",
        ];
        for s in all_statements() {
            // The policy-function denylist regex names denied functions.
            let mut s = s;
            while let (Some(a), Some(b)) = (s.find("'^("), s.find(")$'")) {
                if a >= b {
                    break;
                }
                s = format!("{}{}", &s[..a], &s[b + 3..]);
            }
            let lower = s.to_lowercase();
            for d in denied {
                assert!(!lower.contains(d), "{d} in {s}");
            }
        }
    }

    #[test]
    fn statements_are_single_and_never_set_read_write() {
        for s in all_statements() {
            assert!(!s.contains(';'), "multi-statement: {s}");
            let upper = s.to_uppercase();
            assert!(!upper.contains("READ WRITE"), "{s}");
            assert!(!upper.contains("REPEATABLE READ"), "{s}");
            assert!(!upper.contains("SERIALIZABLE"), "{s}");
        }
    }

    #[test]
    fn functions_are_qualified() {
        // Every call is `pg_catalog.<function>(`; a bare call would be
        // resolved through the search path.
        let functions = [
            "set_config(",
            "current_setting(",
            "has_any_column_privilege(",
            "has_column_privilege(",
            "has_schema_privilege(",
            "has_table_privilege(",
            "has_sequence_privilege(",
            "pg_has_role(",
            "pg_partition_root(",
            "count(",
        ];
        for s in all_statements() {
            for f in functions {
                let bare = s.matches(f).count();
                let qualified = s.matches(&format!("pg_catalog.{f}")).count();
                assert_eq!(bare, qualified, "unqualified {f} in {s}");
            }
        }
    }
}
