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
        "n.nspname OPERATOR(pg_catalog.<>) ALL \
           ('{pg_catalog,information_schema,pg_toast}'::pg_catalog.name[]) \
         AND n.nspname OPERATOR(pg_catalog.!~~) 'pg\\_temp\\_%' \
         AND n.nspname OPERATOR(pg_catalog.!~~) 'pg\\_toast\\_temp\\_%'"
    };
}

/// Not an object of an extension (`pg_depend.deptype = 'e'`), as a SQL
/// predicate on `c.oid`.
macro_rules! not_extension_member {
    () => {
        "NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
           WHERE d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass \
             AND d.objid OPERATOR(pg_catalog.=) c.oid AND d.deptype OPERATOR(pg_catalog.=) 'e')"
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
         JOIN pg_catalog.pg_inherits i ON i.inhrelid OPERATOR(pg_catalog.=) a.ancestor) \
     SELECT c.oid, n.nspname, c.relname, c.relkind, c.relispartition, c.reltuples, \
       c.relrowsecurity, \
       pg_catalog.has_any_column_privilege(c.oid, 'SELECT') AS readable, \
       EXISTS (SELECT 1 FROM anc a JOIN pg_catalog.pg_class ac ON ac.oid OPERATOR(pg_catalog.=) a.ancestor \
               WHERE a.rel OPERATOR(pg_catalog.=) c.oid AND ac.relrowsecurity) AS ancestor_rls, \
       CASE WHEN c.relispartition \
            THEN pg_catalog.pg_partition_root(c.oid)::pg_catalog.oid \
            ELSE c.oid END AS root, \
       (c.relrowsecurity AND EXISTS ( \
          SELECT 1 FROM pg_catalog.pg_policy p \
          JOIN pg_catalog.pg_depend d \
            ON d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_policy'::pg_catalog.regclass AND d.objid OPERATOR(pg_catalog.=) p.oid \
          WHERE p.polrelid OPERATOR(pg_catalog.=) c.oid \
            AND NOT (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass \
                     AND d.refobjid OPERATOR(pg_catalog.=) p.polrelid) \
            AND NOT ( \
              (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_proc x WHERE x.oid OPERATOR(pg_catalog.=) d.refobjid \
                   AND x.pronamespace OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.regnamespace)) \
              OR (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_operator'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_operator x WHERE x.oid OPERATOR(pg_catalog.=) d.refobjid \
                   AND x.oprnamespace OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.regnamespace)) \
              OR (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_type'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_type x WHERE x.oid OPERATOR(pg_catalog.=) d.refobjid \
                   AND x.typnamespace OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.regnamespace)) \
              OR (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_collation'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_collation x WHERE x.oid OPERATOR(pg_catalog.=) d.refobjid \
                   AND x.collnamespace OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.regnamespace)) \
              OR (d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass AND EXISTS ( \
                 SELECT 1 FROM pg_catalog.pg_class x WHERE x.oid OPERATOR(pg_catalog.=) d.refobjid \
                   AND x.relnamespace OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.regnamespace))))) \
       AS rls_blocked \
     FROM pg_catalog.pg_class c \
     JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
     WHERE c.relkind OPERATOR(pg_catalog.=) \
       ANY ('{r,m,p,f}'::pg_catalog.\"char\"[]) AND c.relpersistence OPERATOR(pg_catalog.<>) 't' AND ",
    user_schema!(),
    " AND ",
    not_extension_member!(),
    " AND pg_catalog.has_schema_privilege(n.oid, 'USAGE') \
     ORDER BY n.nspname, c.relname, c.oid \
     LIMIT $1"
);

/// Columns the role may read, for a set of relations (`$1`: `oid[]`).
/// Virtual generated columns (PostgreSQL 18, `attgenerated = 'v'`) are
/// computed on read by an expression that may call functions: never
/// selected.
/// Columns: relation, name, type oid, `typtype`, `typbasetype`, and whether
/// the type is `citext` from the `citext` extension.
pub(crate) const COLUMNS: &str = "SELECT a.attrelid, a.attname, t.oid, t.typtype, t.typbasetype, \
       (t.typname OPERATOR(pg_catalog.=) 'citext' AND EXISTS ( \
          SELECT 1 FROM pg_catalog.pg_depend d \
          JOIN pg_catalog.pg_extension e ON e.oid OPERATOR(pg_catalog.=) d.refobjid \
          WHERE d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_type'::pg_catalog.regclass AND d.objid OPERATOR(pg_catalog.=) t.oid \
            AND d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_extension'::pg_catalog.regclass \
            AND d.deptype OPERATOR(pg_catalog.=) 'e' AND e.extname OPERATOR(pg_catalog.=) 'citext')) AS is_citext \
     FROM pg_catalog.pg_attribute a \
     JOIN pg_catalog.pg_type t ON t.oid OPERATOR(pg_catalog.=) a.atttypid \
     WHERE a.attrelid OPERATOR(pg_catalog.=) ANY ($1) AND a.attnum OPERATOR(pg_catalog.>) 0 AND NOT a.attisdropped \
       AND a.attgenerated OPERATOR(pg_catalog.<>) 'v' \
       AND pg_catalog.has_column_privilege(a.attrelid, a.attnum, 'SELECT') \
     ORDER BY a.attrelid, a.attnum";

/// Expressions of the policies evaluated for `SELECT` (`polcmd` `r` or
/// `*`) of a set of relations (`$1`: `oid[]`), as `pg_node_tree` text. Read
/// only to extract oids (`policy`), never logged (H1).
pub(crate) const POLICY_TREES: &str = "SELECT p.polrelid, p.polqual::pg_catalog.text, \
       p.polwithcheck::pg_catalog.text \
     FROM pg_catalog.pg_policy p \
     WHERE p.polrelid OPERATOR(pg_catalog.=) ANY ($1) AND p.polcmd OPERATOR(pg_catalog.=) \
       ANY ('{r,*}'::pg_catalog.\"char\"[])";

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
            "EXISTS (SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid OPERATOR(pg_catalog.=) ",
            $f,
            " AND p.pronamespace OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.regnamespace \
               AND p.prokind OPERATOR(pg_catalog.=) ANY ('{f,a}'::pg_catalog.\"char\"[]) \
               AND ((p.provolatile OPERATOR(pg_catalog.=) 'i' AND p.proname OPERATOR(pg_catalog.!~) \
                     '^(query_to_xml|query_to_xmlschema|query_to_xml_and_xmlschema\
|cursor_to_xml|cursor_to_xmlschema|table_to_xml|table_to_xmlschema\
|table_to_xml_and_xmlschema|schema_to_xml|schema_to_xmlschema\
|schema_to_xml_and_xmlschema|database_to_xml|database_to_xmlschema\
|database_to_xml_and_xmlschema|ts_stat|ts_rewrite|to_reg.*|reg[a-z]*(in|recv)\
|set_config|pg_sleep.*|pg_read_.*|pg_ls_.*|pg_stat_file|lo_.*|pg_.*advisory.*\
|pg_cancel_backend|pg_terminate_backend|pg_notify|pg_reload_conf|pg_rotate_logfile\
|dblink.*|nextval|setval|currval|lastval|txid_.*|pg_current_.*)$') \
                    OR p.oid OPERATOR(pg_catalog.=) ANY ('{\
                      \"pg_catalog.current_setting(pg_catalog.text)\",\
                      \"pg_catalog.current_setting(pg_catalog.text,pg_catalog.bool)\",\
                      \"pg_catalog.now()\",\
                      \"pg_catalog.current_database()\",\
                      \"pg_catalog.current_schema()\"}'\
                      ::pg_catalog.regprocedure[]::pg_catalog.oid[])))"
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
    ") OPERATOR(pg_catalog.+) (SELECT pg_catalog.count(*) FROM pg_catalog.unnest($2::pg_catalog.oid[]) AS x(o) \
             WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_operator op WHERE op.oid OPERATOR(pg_catalog.=) x.o \
               AND op.oprnamespace OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.regnamespace AND ",
    policy_function_ok!("op.oprcode"),
    ")) OPERATOR(pg_catalog.+) (SELECT pg_catalog.count(*) FROM pg_catalog.unnest($3::pg_catalog.oid[]) AS t(o) \
             WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_type ty WHERE ty.oid OPERATOR(pg_catalog.=) t.o \
               AND ty.typnamespace OPERATOR(pg_catalog.=) 'pg_catalog'::pg_catalog.regnamespace AND ",
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

// ------------------------------------------------------------ CAS guard

/// Every column name of one relation (`$1`: `oid`), readable or not (the
/// catalog is readable by every role), with whether the role can `SELECT`
/// it: the CAS store guard recognizes a ticket registry or an audit trail
/// by its column shape even when only its metadata columns are granted
/// (ADR-0041 decisions 5 and 6).
pub(crate) const ALL_COLUMNS: &str = "SELECT a.attname, \
       pg_catalog.has_column_privilege(a.attrelid, a.attnum, 'SELECT') \
     FROM pg_catalog.pg_attribute a \
     WHERE a.attrelid OPERATOR(pg_catalog.=) $1 AND a.attnum OPERATOR(pg_catalog.>) 0 AND NOT a.attisdropped \
     ORDER BY a.attnum LIMIT 1600";

/// The CAS store guard's only read of a ticket registry (ADR-0041
/// decision 5): the ticket count per `type`, nothing else. `FROM ONLY` one
/// relation; `$1`: row limit.
pub(crate) fn ticket_type_counts(schema: &str, relation: &str, column: &str) -> Option<String> {
    Some(format!(
        "SELECT {c}::pg_catalog.text, pg_catalog.count(*) FROM ONLY {}.{} GROUP BY 1 LIMIT $1",
        quote_ident(schema)?,
        quote_ident(relation)?,
        c = quote_ident(column)?,
    ))
}

/// Normalized name key of a catalog name in SQL, as
/// `databastion_core::cas_guard::name_key` (PR #141 review L7): the part
/// after the last `.`, every character but an ASCII letter or digit
/// removed (an explicit list: no collation or locale applies), then
/// lower-cased.
macro_rules! name_key {
    ($col:literal) => {
        concat!(
            "pg_catalog.lower(pg_catalog.regexp_replace(pg_catalog.regexp_replace(",
            $col,
            ", '^.*[.]', ''), \
             '[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789]', '', 'g'))"
        )
    };
}

/// Most candidate relations of [`CAS_GUARD_COLUMNS`]; one more is read to
/// tell a cut list (then reported as not evaluated).
pub(crate) const CAS_GUARD_MAX_RELATIONS: usize = 256;
/// Most rows of [`CAS_GUARD_COLUMNS`]; one more is read, as above.
pub(crate) const CAS_GUARD_MAX_ROWS: usize = 20_000;

/// `check()` of the CAS store guard, at every heartbeat (ADR-0041
/// decision 6): the columns of the relations that may be CAS stores (a
/// name key in `$1`, or a `body` / `json` / `AUD_RESOURCE` / `AUD_USER`
/// column), with whether the role can `SELECT` each one, directly, through
/// a role (membership with `INHERIT`), through `PUBLIC`, through a table
/// grant or through `pg_read_all_data` (`has_column_privilege` covers them
/// all). Relations matched by name come first (PR #141 review L2); at most
/// [`CAS_GUARD_MAX_RELATIONS`] + 1 relations and [`CAS_GUARD_MAX_ROWS`] + 1
/// rows, so a cut is seen. Columns: relation oid, relation name, column
/// name, readable.
pub(crate) const CAS_GUARD_COLUMNS: &str = concat!(
    "WITH cand AS ( \
       SELECT c.oid, (",
    name_key!("c.relname"),
    " OPERATOR(pg_catalog.=) ANY ($1)) AS named FROM pg_catalog.pg_class c \
       JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
       WHERE c.relkind OPERATOR(pg_catalog.=) \
         ANY ('{r,p,m,v,f}'::pg_catalog.\"char\"[]) AND ",
    user_schema!(),
    " AND ",
    not_extension_member!(),
    " AND (",
    name_key!("c.relname"),
    " OPERATOR(pg_catalog.=) ANY ($1) \
          OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute x \
             WHERE x.attrelid OPERATOR(pg_catalog.=) c.oid AND x.attnum OPERATOR(pg_catalog.>) 0 AND NOT x.attisdropped \
               AND ",
    name_key!("x.attname"),
    " OPERATOR(pg_catalog.=) \
               ANY ('{body,json,audresource,auduser}'::pg_catalog.text[]))) \
       ORDER BY named DESC, c.oid LIMIT 257) \
     SELECT c.oid, c.relname, a.attname, \
       pg_catalog.has_column_privilege(c.oid, a.attnum, 'SELECT') \
     FROM cand JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) cand.oid \
     JOIN pg_catalog.pg_attribute a ON a.attrelid OPERATOR(pg_catalog.=) c.oid AND a.attnum OPERATOR(pg_catalog.>) 0 \
       AND NOT a.attisdropped \
     ORDER BY cand.named DESC, c.oid, a.attnum LIMIT 20001"
);

// ------------------------------------------------------------------ check()

/// Attributes of the current role. `pg_roles` is read for boolean columns
/// only (never `rolpassword`, never `rolconfig`, which comes from
/// `pg_db_role_setting`).
pub(crate) const ROLE_ATTRIBUTES: &str = "SELECT r.rolsuper, r.rolbypassrls, r.rolreplication, \
       r.rolcreaterole, r.rolcreatedb \
     FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER";

/// Roles the current role is a member of (directly or not), with whether
/// they are predefined (`oid < FirstNormalObjectId`).
pub(crate) const MEMBERSHIPS: &str = "SELECT r.rolname, r.oid OPERATOR(pg_catalog.<) 16384 AS predefined \
     FROM pg_catalog.pg_roles r \
     WHERE r.rolname OPERATOR(pg_catalog.<>) CURRENT_USER \
       AND pg_catalog.pg_has_role(CURRENT_USER, r.oid, 'MEMBER') \
     ORDER BY r.rolname \
     LIMIT 1000";

/// Relations of user schemas the role can write to (any write-type
/// privilege), with `, MAINTAIN` on PostgreSQL 17+.
pub(crate) fn write_privileges(maintain: bool) -> String {
    // Not a format string: the text holds array literals (`'{…}'`).
    const HEAD: &str = concat!(
        "SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
         WHERE ",
        user_schema!(),
        " AND ((c.relkind OPERATOR(pg_catalog.=) \
                 ANY ('{r,p,m,f,v}'::pg_catalog.\"char\"[]) \
             AND (pg_catalog.has_table_privilege(c.oid, \
                    'INSERT, UPDATE, DELETE, TRUNCATE, TRIGGER"
    );
    const TAIL: &str = "') \
                  OR pg_catalog.has_any_column_privilege(c.oid, 'INSERT, UPDATE'))) \
           OR (CASE WHEN c.relkind OPERATOR(pg_catalog.=) 'S' \
                    THEN pg_catalog.has_sequence_privilege(c.oid, 'UPDATE') \
                    ELSE false END))";
    [HEAD, if maintain { ", MAINTAIN" } else { "" }, TAIL].concat()
}

/// Objects owned by the current role.
pub(crate) const OWNERSHIP: &str = "WITH me AS (SELECT r.oid FROM pg_catalog.pg_roles r \
                                          WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER) \
     SELECT (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c, me WHERE c.relowner OPERATOR(pg_catalog.=) me.oid) \
          OPERATOR(pg_catalog.+) (SELECT pg_catalog.count(*) FROM pg_catalog.pg_namespace n, me \
               WHERE n.nspowner OPERATOR(pg_catalog.=) me.oid) \
          OPERATOR(pg_catalog.+) (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p, me WHERE p.proowner OPERATOR(pg_catalog.=) me.oid) \
          OPERATOR(pg_catalog.+) (SELECT pg_catalog.count(*) FROM pg_catalog.pg_database d, me WHERE d.datdba OPERATOR(pg_catalog.=) me.oid)";

/// Enabled `login` event triggers (PostgreSQL 17+).
pub(crate) const LOGIN_EVENT_TRIGGERS: &str = "SELECT pg_catalog.count(*) \
     FROM pg_catalog.pg_event_trigger e \
     WHERE e.evtevent OPERATOR(pg_catalog.=) 'login' AND e.evtenabled OPERATOR(pg_catalog.<>) 'D'";

/// User schemas without `USAGE` (not covered by Discovery), outside
/// extensions.
pub(crate) const SCHEMAS_WITHOUT_USAGE: &str = concat!(
    "SELECT n.nspname FROM pg_catalog.pg_namespace n WHERE ",
    user_schema!(),
    " AND NOT pg_catalog.has_schema_privilege(n.oid, 'USAGE') \
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
        WHERE d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_namespace'::pg_catalog.regclass \
          AND d.objid OPERATOR(pg_catalog.=) n.oid AND d.deptype OPERATOR(pg_catalog.=) 'e') \
     ORDER BY n.nspname LIMIT 1000"
);

/// Audit prerequisites visible without `pg_read_all_settings`: installed
/// extensions `pg_stat_statements` / `pgaudit` in this database; the schema
/// of `pg_stat_statements_info` if it is a member of `pg_stat_statements`
/// (obligation 3); membership of `pg_read_all_stats`; and the value of
/// `pgaudit.log` (`NULL` when pgaudit is not loaded).
pub(crate) const AUDIT_PREREQUISITES: &str = "SELECT \
       EXISTS (SELECT 1 FROM pg_catalog.pg_extension e WHERE e.extname OPERATOR(pg_catalog.=) 'pg_stat_statements'), \
       EXISTS (SELECT 1 FROM pg_catalog.pg_extension e WHERE e.extname OPERATOR(pg_catalog.=) 'pgaudit'), \
       (SELECT n.nspname FROM pg_catalog.pg_extension e \
          JOIN pg_catalog.pg_depend d \
            ON d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_extension'::pg_catalog.regclass \
           AND d.refobjid OPERATOR(pg_catalog.=) e.oid AND d.deptype OPERATOR(pg_catalog.=) 'e' \
           AND d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_class'::pg_catalog.regclass \
          JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) d.objid \
          JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace \
          WHERE e.extname OPERATOR(pg_catalog.=) 'pg_stat_statements' AND c.relname OPERATOR(pg_catalog.=) 'pg_stat_statements_info' \
            AND c.relnamespace OPERATOR(pg_catalog.=) e.extnamespace), \
       pg_catalog.pg_has_role(CURRENT_USER, 'pg_read_all_stats', 'MEMBER'), \
       pg_catalog.current_setting('pgaudit.log', true)";

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

/// pgaudit settings of this session's database: `pgaudit.log`,
/// `pgaudit.log_rows`, `pgaudit.role`, `pgaudit.log_level` (`NULL` when
/// not set), whether the pgaudit library is loaded, and
/// `pgaudit.log_catalog`. Settings, not
/// data; readable without `pg_read_all_settings` (verified in P2-B).
///
/// A `pgaudit.*` value alone does not prove the library is loaded: set in
/// `postgresql.conf`, `ALTER DATABASE` or `ALTER ROLE` without the library
/// in `shared_preload_libraries`, it is a placeholder that
/// `current_setting` still returns. `shared_preload_libraries` itself is
/// not readable without `pg_read_all_settings`. `pg_settings` (readable by
/// every role) hides placeholders and shows a string type for them; the
/// library defines `pgaudit.log_catalog` as a boolean: that row is the
/// proof. `pgaudit.log_rows` needs the same proof on its own: pgaudit
/// before 1.6 (the PostgreSQL 13 builds) does not define it, so a value
/// set for it there is a placeholder and the records carry no row count.
/// `log_min_messages` and `log_min_error_statement` (readable by every
/// role, verified on PostgreSQL 16) decide whether a failed statement gets
/// an `ERROR` line, and whether that line holds the statement text
/// (ADR-0037, refinement of 2026-10-12, item 6).
pub(crate) const PGAUDIT_SETTINGS: &str = "SELECT \
       pg_catalog.current_setting('pgaudit.log', true), \
       pg_catalog.current_setting('pgaudit.log_rows', true), \
       pg_catalog.current_setting('pgaudit.role', true), \
       pg_catalog.current_setting('pgaudit.log_level', true), \
       EXISTS (SELECT 1 FROM pg_catalog.pg_settings s \
               WHERE s.name OPERATOR(pg_catalog.=) 'pgaudit.log_catalog' AND s.vartype OPERATOR(pg_catalog.=) 'bool'), \
       pg_catalog.current_setting('pgaudit.log_catalog', true), \
       EXISTS (SELECT 1 FROM pg_catalog.pg_settings s \
               WHERE s.name OPERATOR(pg_catalog.=) 'pgaudit.log_rows' AND s.vartype OPERATOR(pg_catalog.=) 'bool'), \
       pg_catalog.current_setting('log_min_messages', true), \
       pg_catalog.current_setting('log_min_error_statement', true)";

/// Client address the server sees for this session (`NULL` on a Unix
/// socket): tells the agent's own statements apart in the audit log.
pub(crate) const OWN_CLIENT_ADDR: &str = "SELECT pg_catalog.host(pg_catalog.inet_client_addr())";

/// The connector's statements that name no relation. They call
/// `pg_catalog` functions only, with bound parameters, and read no row of
/// any relation: `pg_catalog.set_config`, `pg_catalog.current_setting`,
/// `pg_catalog.inet_client_addr`, `pg_catalog.host`. The Audit stream
/// leaves them out for the agent's own account without charging its row
/// budget (`audit::events::PgOwn`), matched by exact text: as sent
/// (pgaudit), or as `pg_stat_statements` stores it, constants replaced
/// and these bound parameters in place (`audit::events::pss_form`). A
/// unit test checks that every other statement of this module names a
/// relation.
pub(crate) const OWN_TABLELESS: [&str; 3] = [SESSION_SETUP, SET_LOCAL_TIMEOUTS, OWN_CLIENT_ADDR];

/// Schema of the `pg_stat_statements(boolean)` function, if it is a member
/// of the `pg_stat_statements` extension in its own schema (obligation 3).
pub(crate) const PSS_FUNCTION_SCHEMA: &str = "SELECT n.nspname FROM pg_catalog.pg_extension e \
       JOIN pg_catalog.pg_depend d \
         ON d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_extension'::pg_catalog.regclass \
        AND d.refobjid OPERATOR(pg_catalog.=) e.oid AND d.deptype OPERATOR(pg_catalog.=) 'e' \
        AND d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass \
       JOIN pg_catalog.pg_proc p ON p.oid OPERATOR(pg_catalog.=) d.objid \
       JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) p.pronamespace \
       WHERE e.extname OPERATOR(pg_catalog.=) 'pg_stat_statements' AND p.proname OPERATOR(pg_catalog.=) 'pg_stat_statements' \
         AND p.pronamespace OPERATOR(pg_catalog.=) e.extnamespace AND p.pronargs OPERATOR(pg_catalog.=) 1 \
       LIMIT 1";

/// The namespace column `$col` is a user schema for the collision probe:
/// neither `pg_catalog` (its oid, 11) nor `information_schema` (the `ic`
/// CTE).
macro_rules! probe_user_ns {
    ($col:literal) => {
        concat!(
            $col,
            " OPERATOR(pg_catalog.<>) '11' AND ",
            $col,
            " OPERATOR(pg_catalog.<>) (TABLE ic)"
        )
    };
}

/// `$t` (a type oid) is reachable from a built-in value with no written
/// cast (the `reach` CTE of [`USER_CODE_PROBE`]).
macro_rules! probe_reached {
    ($t:literal) => {
        concat!($t, " OPERATOR(pg_catalog.=) ANY (TABLE reach)")
    };
}

/// At a position where a user overload's type `ut` is not reachable from
/// a built-in value (so only an untyped literal reaches it), the built-in
/// overload's type `bt` survives PostgreSQL's literal resolution whenever
/// the user type does (a `text`-like preferred string type, or the same
/// category with a type at least as preferred).
macro_rules! probe_co_candidate {
    () => {
        concat!(
            "(ut.oid OPERATOR(pg_catalog.=) bt.oid OR (NOT ",
            probe_reached!("ut.oid"),
            " AND ((bt.typcategory OPERATOR(pg_catalog.=) 'S' AND bt.typispreferred) \
               OR (bt.typcategory OPERATOR(pg_catalog.=) ut.typcategory \
                   AND (bt.typispreferred OR NOT ut.typispreferred)))))"
        )
    };
}

/// Whether the function `$p` (a `pg_proc` alias) runs only C or internal
/// code (an aggregate: every support function too; the `lang` and
/// `badagg` CTEs of [`USER_CODE_PROBE`]).
macro_rules! probe_native {
    ($p:literal) => {
        concat!(
            "(",
            $p,
            ".prolang OPERATOR(pg_catalog.=) ANY (TABLE lang) AND NOT ",
            $p,
            ".oid OPERATOR(pg_catalog.=) ANY (TABLE badagg))"
        )
    };
}

/// The collision probe of ADR-0049 decision 8 (`check()`, at every
/// heartbeat, in each declared database), from catalogs every role can
/// read. Rows of (kind, name), at most 20 000 + 1 (one more tells a cut):
///
/// - `f` / `o`: a function / operator name of `pg_catalog` with a user
///   overload (outside `pg_catalog` and `information_schema`) that a value
///   or literal of a catalog-only statement can reach: for some argument
///   count it accepts (defaults included; any `VARIADIC` overload), every
///   argument type is reachable from a built-in value (a `pg_catalog` type,
///   pseudo-types included; a domain over a reachable type; a composite
///   type, which `ROW(…)` reaches; an array of a reachable type; the target
///   of an implicit cast from a built-in type), or no built-in overload of
///   that name and argument count survives PostgreSQL's resolution of
///   untyped literals whenever it does (same types where the user type is
///   reachable; a preferred string type, or the same category with a type
///   at least as preferred, where it is not);
/// - `t`: a user type or domain whose name is a `pg_catalog` type name
///   (relation row types and their arrays excluded);
/// - `e` / `i`: the target type name of a user-function cast between two
///   built-in types, explicit / implicit or assignment;
/// - `F` / `O`: a function / operator name of `pg_catalog` with a user
///   overload, of any argument types, whose code is neither C nor internal
///   (a bound parameter typed by the client reaches it);
/// - `d`: a user domain has a constraint that depends on a function or
///   operator outside `pg_catalog` whose code is neither C nor internal (a
///   bound parameter of that domain runs it; security review of #211, M1).
///   A direct call of a `pg_catalog` function is not seen: PostgreSQL
///   records no dependency on the objects initdb creates.
///
/// Every operator is written `OPERATOR(pg_catalog.…)` and every function
/// and type is qualified, so that the probe itself never triggers decision
/// 8. `pg_catalog` is written as its oid, `'11'` (`PG_CATALOG_NAMESPACE`,
/// the same on every version; pinned by the facts test of
/// `it_user_code.rs`): a constant keeps the planner's estimates, which a
/// subquery does not, and the text short enough for the
/// `pg_stat_statements` read bound (a unit test). Argument positions and
/// counts come from constant series (a function
/// has at most 100 arguments), which keeps the planner's estimate below
/// PostgreSQL's default `jit_above_cost` on usual databases (JIT
/// compilation took the probe from about 15 ms to about 160 ms). Names only, kept in the agent's memory (`audit::user_code`), never
/// logged nor sent (I2).
pub(crate) const USER_CODE_PROBE: &str = concat!(
    "WITH RECURSIVE ic AS (SELECT 'information_schema'::pg_catalog.regnamespace::pg_catalog.oid), \
             lang AS (SELECT l.oid FROM pg_catalog.pg_language l \
               WHERE l.lanname OPERATOR(pg_catalog.=) ANY ('{c,internal}'::pg_catalog.name[])), \
             badagg AS (SELECT a.aggfnoid FROM pg_catalog.pg_aggregate a \
               , pg_catalog.unnest(ARRAY[a.aggtransfn, a.aggfinalfn, \
                 a.aggcombinefn, a.aggserialfn, a.aggdeserialfn, a.aggmtransfn, \
                 a.aggminvtransfn, a.aggmfinalfn]::pg_catalog.oid[]) AS s(f) \
               JOIN pg_catalog.pg_proc q ON q.oid OPERATOR(pg_catalog.=) s.f \
              WHERE NOT q.prolang OPERATOR(pg_catalog.=) ANY (TABLE lang)), \
             uf AS ( \
               SELECT p.oid, p.proname AS name, p.proargtypes AS args, \
                      p.pronargs::pg_catalog.int4 AS n, p.pronargdefaults::pg_catalog.int4 AS d, \
                      p.provariadic OPERATOR(pg_catalog.<>) '0' AS variadic \
                 FROM pg_catalog.pg_proc p \
                WHERE ",
    probe_user_ns!("p.pronamespace"),
    " AND p.proname OPERATOR(pg_catalog.=) ANY (SELECT b.proname FROM pg_catalog.pg_proc b \
                    WHERE b.pronamespace OPERATOR(pg_catalog.=) '11')), \
             uo AS ( \
               SELECT o.oid, o.oprname AS name, o.oprleft AS l, o.oprright AS r, o.oprcode \
                 FROM pg_catalog.pg_operator o \
                WHERE ",
    probe_user_ns!("o.oprnamespace"),
    " AND o.oprname OPERATOR(pg_catalog.=) ANY (SELECT b.oprname \
                    FROM pg_catalog.pg_operator b WHERE b.oprnamespace OPERATOR(pg_catalog.=) '11')), \
             argt AS ( \
               SELECT a.t FROM uf, \
                      pg_catalog.unnest(uf.args::pg_catalog.oid[]) AS a(t) \
               UNION SELECT uo.l FROM uo WHERE uo.l OPERATOR(pg_catalog.<>) '0' \
               UNION SELECT uo.r FROM uo), \
             chain(root, cur, depth) AS ( \
               SELECT argt.t, argt.t, 0 FROM argt \
               UNION ALL \
               SELECT c.root, \
                      CASE WHEN y.typtype OPERATOR(pg_catalog.=) 'd' THEN y.typbasetype \
                           ELSE y.typelem END, \
                      c.depth OPERATOR(pg_catalog.+) 1 \
                 FROM chain c JOIN pg_catalog.pg_type y ON y.oid OPERATOR(pg_catalog.=) c.cur \
                WHERE c.depth OPERATOR(pg_catalog.<) 8 \
                  AND y.typnamespace OPERATOR(pg_catalog.<>) '11' \
                  AND (y.typtype OPERATOR(pg_catalog.=) 'd' \
                       OR (y.typcategory OPERATOR(pg_catalog.=) 'A' \
                           AND y.typelem OPERATOR(pg_catalog.<>) '0'))), \
             reach AS ( \
               SELECT DISTINCT c.root AS t FROM chain c \
                 JOIN pg_catalog.pg_type y ON y.oid OPERATOR(pg_catalog.=) c.cur \
                WHERE y.typnamespace OPERATOR(pg_catalog.=) '11' \
                   OR y.typtype OPERATOR(pg_catalog.=) 'c' \
                   OR EXISTS (SELECT 1 FROM pg_catalog.pg_cast k \
                        JOIN pg_catalog.pg_type s ON s.oid OPERATOR(pg_catalog.=) k.castsource \
                       WHERE k.casttarget OPERATOR(pg_catalog.=) y.oid \
                         AND k.castcontext OPERATOR(pg_catalog.=) 'i' \
                         AND s.typnamespace OPERATOR(pg_catalog.=) '11')), \
             fk AS ( \
               SELECT uf.name, uf.args, uf.variadic, k.k \
                 FROM uf CROSS JOIN pg_catalog.generate_series(0, 100) AS k(k) \
                WHERE k.k OPERATOR(pg_catalog.>=) (uf.n OPERATOR(pg_catalog.-) uf.d) \
                  AND k.k OPERATOR(pg_catalog.<=) uf.n) \
             SELECT DISTINCT 'f'::pg_catalog.text, fk.name::pg_catalog.text FROM fk \
              WHERE fk.variadic OR NOT ( \
                EXISTS (SELECT 1 FROM pg_catalog.generate_series(0, 99) AS i(i) \
                         WHERE i.i OPERATOR(pg_catalog.<) fk.k AND NOT ",
    probe_reached!("fk.args[i.i]"),
    ") \
                AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc b \
                  WHERE b.pronamespace OPERATOR(pg_catalog.=) '11' \
                    AND b.proname OPERATOR(pg_catalog.=) fk.name \
                    AND b.provariadic OPERATOR(pg_catalog.=) '0' \
                    AND fk.k OPERATOR(pg_catalog.>=) \
                        (b.pronargs OPERATOR(pg_catalog.-) b.pronargdefaults) \
                    AND fk.k OPERATOR(pg_catalog.<=) b.pronargs \
                    AND NOT EXISTS ( \
                      SELECT 1 FROM pg_catalog.generate_series(0, 99) AS i(i) \
                        JOIN pg_catalog.pg_type ut ON i.i OPERATOR(pg_catalog.<) fk.k \
                         AND ut.oid OPERATOR(pg_catalog.=) fk.args[i.i] \
                        JOIN pg_catalog.pg_type bt \
                          ON bt.oid OPERATOR(pg_catalog.=) b.proargtypes[i.i] \
                       WHERE NOT ",
    probe_co_candidate!(),
    "))) \
             UNION ALL \
             SELECT DISTINCT 'o', uo.name::pg_catalog.text FROM uo \
              WHERE NOT ((uo.l OPERATOR(pg_catalog.<>) '0' AND NOT ",
    probe_reached!("uo.l"),
    ") OR NOT ",
    probe_reached!("uo.r"),
    ") \
                 OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_operator b \
                  WHERE b.oprnamespace OPERATOR(pg_catalog.=) '11' \
                    AND b.oprname OPERATOR(pg_catalog.=) uo.name \
                    AND (b.oprleft OPERATOR(pg_catalog.=) '0') \
                        OPERATOR(pg_catalog.=) (uo.l OPERATOR(pg_catalog.=) '0') \
                    AND NOT EXISTS ( \
                      SELECT 1 FROM (VALUES (uo.l, b.oprleft), (uo.r, b.oprright)) AS v(u, b) \
                        JOIN pg_catalog.pg_type ut ON ut.oid OPERATOR(pg_catalog.=) v.u \
                        JOIN pg_catalog.pg_type bt ON bt.oid OPERATOR(pg_catalog.=) v.b \
                       WHERE NOT ",
    probe_co_candidate!(),
    ")) \
             UNION ALL \
             SELECT DISTINCT 't', t.typname::pg_catalog.text FROM pg_catalog.pg_type t \
              WHERE ",
    probe_user_ns!("t.typnamespace"),
    " AND t.typrelid OPERATOR(pg_catalog.=) '0' \
                AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_type e \
                     WHERE e.oid OPERATOR(pg_catalog.=) t.typelem \
                       AND e.typrelid OPERATOR(pg_catalog.<>) '0') \
                AND t.typname OPERATOR(pg_catalog.=) ANY (SELECT b.typname \
                     FROM pg_catalog.pg_type b WHERE b.typnamespace OPERATOR(pg_catalog.=) '11') \
             UNION ALL \
             SELECT DISTINCT CASE WHEN k.castcontext OPERATOR(pg_catalog.=) 'e' \
                                  THEN 'e' ELSE 'i' END, tt.typname::pg_catalog.text \
               FROM pg_catalog.pg_cast k \
               JOIN pg_catalog.pg_proc f ON f.oid OPERATOR(pg_catalog.=) k.castfunc \
               JOIN pg_catalog.pg_type st ON st.oid OPERATOR(pg_catalog.=) k.castsource \
               JOIN pg_catalog.pg_type tt ON tt.oid OPERATOR(pg_catalog.=) k.casttarget \
              WHERE f.pronamespace OPERATOR(pg_catalog.<>) '11' \
                AND st.typnamespace OPERATOR(pg_catalog.=) '11' \
                AND tt.typnamespace OPERATOR(pg_catalog.=) '11' \
             UNION ALL \
             SELECT DISTINCT 'F', uf.name::pg_catalog.text FROM uf \
               JOIN pg_catalog.pg_proc p ON p.oid OPERATOR(pg_catalog.=) uf.oid \
              WHERE NOT ",
    probe_native!("p"),
    " \
             UNION ALL \
             SELECT DISTINCT 'O', uo.name::pg_catalog.text FROM uo \
               JOIN pg_catalog.pg_proc p ON p.oid OPERATOR(pg_catalog.=) uo.oprcode \
              WHERE NOT ",
    probe_native!("p"),
    " \
             UNION ALL \
             SELECT 'd', '' WHERE EXISTS ( \
               SELECT 1 FROM pg_catalog.pg_constraint c \
                 JOIN pg_catalog.pg_type t ON t.oid OPERATOR(pg_catalog.=) c.contypid \
                 JOIN pg_catalog.pg_depend dp \
                   ON dp.classid OPERATOR(pg_catalog.=) \
                      'pg_catalog.pg_constraint'::pg_catalog.regclass \
                  AND dp.objid OPERATOR(pg_catalog.=) c.oid \
                WHERE ",
    probe_user_ns!("t.typnamespace"),
    " AND ((dp.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass \
               AND EXISTS (SELECT 1 FROM pg_catalog.pg_proc dq \
                    WHERE dq.oid OPERATOR(pg_catalog.=) dp.refobjid \
                      AND (dq.pronamespace OPERATOR(pg_catalog.<>) '11' AND NOT ",
    probe_native!("dq"),
    "))) \
           OR (dp.refclassid OPERATOR(pg_catalog.=) \
               'pg_catalog.pg_operator'::pg_catalog.regclass \
               AND EXISTS (SELECT 1 FROM pg_catalog.pg_operator o \
                 JOIN pg_catalog.pg_proc dq ON dq.oid OPERATOR(pg_catalog.=) o.oprcode \
                    WHERE o.oid OPERATOR(pg_catalog.=) dp.refobjid \
                      AND o.oprnamespace OPERATOR(pg_catalog.<>) '11' AND NOT ",
    probe_native!("dq"),
    ")))) \
             LIMIT 20001"
);

/// The agent role's oid, the oids of the declared databases (`$1`,
/// `text[]`) and of this session's database: the `pg_stat_statements`
/// slots where the connector's own table-less statements may be
/// recognized (PR #90 review Low-1). Catalog reads only.
pub(crate) const OWN_OIDS: &str = "SELECT r.oid, \
       ARRAY(SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname OPERATOR(pg_catalog.=) ANY($1)), \
       (SELECT d.oid FROM pg_catalog.pg_database d \
         WHERE d.datname OPERATOR(pg_catalog.=) pg_catalog.current_database()) \
       FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) CURRENT_USER";

/// Most `pg_stat_statements` entries read per poll (`pg_stat_statements.max`
/// defaults to 5000).
pub(crate) const PSS_MAX_ENTRIES: u32 = 20_000;
/// Longest statement text read from `pg_stat_statements`, in characters.
pub(crate) const PSS_MAX_TEXT_CHARS: u32 = 8192;

/// `pg_stat_statements` counters, without statement text
/// (`showtext => false`: the text file is not read). `toplevel` exists
/// since PostgreSQL 14.
pub(crate) fn pss_counters(schema: &str, toplevel: bool) -> Option<String> {
    Some(format!(
        "SELECT s.userid, s.dbid, s.queryid, {}, s.calls, s.rows, \
                pg_catalog.pg_get_userbyid(s.userid), d.datname \
           FROM {}.pg_stat_statements(false) AS s \
           JOIN pg_catalog.pg_database d ON d.oid OPERATOR(pg_catalog.=) s.dbid \
          WHERE s.queryid IS NOT NULL \
          LIMIT {PSS_MAX_ENTRIES}",
        if toplevel { "s.toplevel" } else { "true" },
        quote_ident(schema)?
    ))
}

/// Statement texts of the given `queryid`s (`$1`, `int8[]`), cut at
/// [`PSS_MAX_TEXT_CHARS`] characters, with a flag when cut. The text goes
/// through the query normalizer only (obligation 5).
pub(crate) fn pss_texts(schema: &str, toplevel: bool) -> Option<String> {
    Some(format!(
        "SELECT s.userid, s.dbid, s.queryid, {}, \
                pg_catalog.left(s.query, {PSS_MAX_TEXT_CHARS}), \
                pg_catalog.char_length(s.query) OPERATOR(pg_catalog.>=) {PSS_MAX_TEXT_CHARS} \
           FROM {}.pg_stat_statements(true) AS s \
          WHERE s.queryid OPERATOR(pg_catalog.=) ANY($1) \
          LIMIT {PSS_MAX_ENTRIES}",
        if toplevel { "s.toplevel" } else { "true" },
        quote_ident(schema)?
    ))
}

/// The connector's fixed statements (not those built per schema or per
/// relation), as sent: what the Audit streams recognize as the
/// connector's own by exact text when a bound parameter meets a checked
/// user domain (ADR-0049 decision 8, security review of #211, M1).
pub(crate) fn connector_statements() -> Vec<String> {
    vec![
        SESSION_SETUP.to_owned(),
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
        PGAUDIT_SETTINGS.to_owned(),
        OWN_CLIENT_ADDR.to_owned(),
        PSS_FUNCTION_SCHEMA.to_owned(),
        OWN_OIDS.to_owned(),
        USER_CODE_PROBE.to_owned(),
        ALL_COLUMNS.to_owned(),
        CAS_GUARD_COLUMNS.to_owned(),
    ]
}

/// Every statement text of this module (tests).
#[cfg(test)]
pub(crate) fn all_statements() -> Vec<String> {
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
        pss_probe("public").unwrap(),
        PGAUDIT_SETTINGS.to_owned(),
        OWN_CLIENT_ADDR.to_owned(),
        PSS_FUNCTION_SCHEMA.to_owned(),
        OWN_OIDS.to_owned(),
        USER_CODE_PROBE.to_owned(),
        pss_counters("public", true).unwrap(),
        pss_counters("public", false).unwrap(),
        pss_texts("public", true).unwrap(),
        pss_texts("public", false).unwrap(),
        ALL_COLUMNS.to_owned(),
        ticket_type_counts("s", "t", "type").unwrap(),
        CAS_GUARD_COLUMNS.to_owned(),
        sample_statement("s", "t", &["c"], true).unwrap(),
        sample_statement("s", "t", &["c"], false).unwrap(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtual_generated_columns_are_never_selected() {
        assert!(COLUMNS.contains("a.attgenerated OPERATOR(pg_catalog.<>) 'v'"));
    }

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

    /// ADR-0048 decision 4: the connector names no statistics relation
    /// (a read of one is never its own), and none of its statements
    /// reaches the analyzer's relation bound (a text there adds `*` and is
    /// never its own either).
    #[test]
    fn no_statement_names_a_statistics_relation_or_reaches_the_bound() {
        for s in all_statements() {
            let lower = s.to_lowercase();
            for n in crate::audit::events::STATISTICS_RELATIONS {
                assert!(!lower.contains(n), "{n} in {s}");
            }
            let a = crate::audit::events::analyze_pss(&s, false);
            assert!(!a.parts().iter().any(|p| p.relations_full), "{s}");
        }
    }

    /// ADR-0048, refinement of 2026-10-12: no connector statement wraps a
    /// query (`EXPLAIN`, `DECLARE … CURSOR`, `PREPARE`): a read through one
    /// with the agent's identity is never its own. Discovery reads its
    /// sample through the extended protocol, never a cursor.
    #[test]
    fn no_statement_wraps_a_query() {
        for s in all_statements() {
            let a = crate::audit::events::analyze_pss(&s, false);
            assert!(a.parts().iter().all(|p| p.pg_wrapped.is_none()), "{s}");
            let lower = s.trim_start().to_lowercase();
            for w in ["explain", "declare", "prepare", "fetch", "move"] {
                assert!(!lower.starts_with(w), "{s}");
            }
        }
    }

    /// ADR-0049 decision 5: every connector statement names no entry of
    /// the statement-text lists, or reads one in the no-text shape
    /// (`pss_counters`), or is the text query (`pss_texts`); the names in
    /// the string literals of `AUDIT_PREREQUISITES` and
    /// `PSS_FUNCTION_SCHEMA` are not names; none calls a function of
    /// decision 7. In every database setting of the extension's schema.
    #[test]
    fn statements_and_the_statement_text_lists() {
        use crate::audit::events::{Catalogs, DbCatalog, analyze_pss, text_reads};
        for pss_schema in [Some("public"), None] {
            let mut catalogs = Catalogs::default();
            catalogs.insert(
                "shop",
                DbCatalog {
                    pss_schema: pss_schema.map(str::to_owned),
                    pgaudit_log_catalog: Some(false),
                },
            );
            let none = std::collections::HashSet::new();
            for unqualified_pg in [true, false] {
                let rule = catalogs.rule("shop", unqualified_pg, &none);
                for s in all_statements() {
                    let a = analyze_pss(&s, false);
                    let reads = text_reads(&s, &a, rule, false);
                    assert!(!reads.star, "{s}");
                    let texts = s == pss_texts("public", true).unwrap()
                        || s == pss_texts("public", false).unwrap();
                    if texts && pss_schema.is_some() {
                        assert_eq!(reads.objects.len(), 1, "{s}");
                        assert_eq!(reads.objects[0].name, "pg_stat_statements");
                    } else {
                        assert!(reads.objects.is_empty(), "{s}: {:?}", reads.objects);
                    }
                    let counters = s == pss_counters("public", true).unwrap()
                        || s == pss_counters("public", false).unwrap();
                    if counters && pss_schema.is_some() {
                        assert!(!reads.named.is_empty(), "the no-text shape: {s}");
                    }
                    if s == AUDIT_PREREQUISITES || s == PSS_FUNCTION_SCHEMA {
                        assert!(reads.named.is_empty(), "string literals: {s}");
                    }
                }
            }
        }
        // The decision 7 names appear only in the policy-function regular
        // expression literal.
        for s in all_statements() {
            for f in crate::audit::events::DATA_FUNCTIONS {
                let calls = s.matches(&format!("{f}(")).count();
                assert_eq!(calls, 0, "{f} called in {s}");
            }
        }
        // No connector statement reads `pg_stat_activity`.
        for s in all_statements() {
            assert!(!s.contains("pg_stat_activity"), "{s}");
            assert!(!s.contains("pg_stat_get_"), "{s}");
        }
    }

    /// ADR-0049 decisions 5 and 8: no connector statement runs user code
    /// next to catalogs, whatever the collision probe finds (every name a
    /// statement uses colliding, with every parameter route) and while
    /// the probe is not known (failed, cut, stale, not run, version not
    /// known): every function is qualified with `pg_catalog`, every
    /// operator is written `OPERATOR(pg_catalog.…)`, every type is
    /// qualified, and no keyword implies an operator (`IN`, `LIKE`,
    /// `BETWEEN`, a simple `CASE`, `USING (…)`). Casts to an explicit
    /// user-cast target and an implicit user cast between built-in types
    /// (superuser only, ADR-0049 R2 / F3) are left out: they report every
    /// such statement, the agent's included.
    #[test]
    fn statements_never_trigger_decision_8() {
        use crate::audit::builtins;
        use crate::audit::user_code::{ProbeNames, View, user_code};
        use databastion_classifiers::query::pg_scan;
        let excluded = |r: &databastion_classifiers::query::RelationName| {
            crate::audit::events::decided_elsewhere(r, Some("public"))
        };
        let mut catalogs = crate::audit::events::Catalogs::default();
        catalogs.insert(
            "shop",
            crate::audit::events::DbCatalog {
                pss_schema: Some("public".to_owned()),
                pgaudit_log_catalog: Some(true),
            },
        );
        let none = std::collections::HashSet::new();
        let rule = catalogs.rule("shop", true, &none);
        let mut applicable = 0;
        for major in builtins::OLDEST_MAJOR..=builtins::NEWEST_MAJOR {
            let lists = builtins::for_server(major * 10_000);
            for s in all_statements() {
                let a = crate::audit::events::analyze_pss(&s, false);
                let reads = crate::audit::events::text_reads(&s, &a, rule, false);
                // Decision 8 applies to catalog-only queries (the sampling
                // statements name application relations).
                let crate::audit::user_code::CodeUse::CatalogOnly { code, cut } = reads.code else {
                    continue;
                };
                applicable += 1;
                assert!(!cut, "{s}");
                let code = code.expect("scanned");
                assert_eq!(*code, pg_scan(&s).expect("lexes").code(), "{s}");
                let mut all = ProbeNames::default();
                for c in &code.calls {
                    all.functions.insert(c.name.name.clone());
                    all.param_functions.insert(c.name.name.clone());
                }
                for o in &code.operators {
                    all.operators.insert(o.symbol.clone());
                    all.param_operators.insert(o.symbol.clone());
                }
                for t in &code.types {
                    all.types.insert(t.name.name.clone());
                }
                // A checked user domain: a parameterized statement is
                // spared only by the exact-text exemption, which must know
                // it (security review of #211, M1).
                let mut domain = all.clone();
                domain.param_domain = true;
                let exempt: Vec<String> = connector_statements()
                    .into_iter()
                    .chain(pss_probe("public"))
                    .chain(
                        [true, false]
                            .into_iter()
                            .filter_map(|t| pss_counters("public", t)),
                    )
                    .chain(
                        [true, false]
                            .into_iter()
                            .filter_map(|t| pss_texts("public", t)),
                    )
                    .collect();
                match user_code(Some(&code), false, &View::Known(&domain, lists), &excluded) {
                    crate::audit::user_code::Verdict::BuiltIn => {}
                    crate::audit::user_code::Verdict::ParamDomain => {
                        assert!(exempt.contains(&s), "{major}: not exempt: {s}");
                    }
                    crate::audit::user_code::Verdict::UserCode => panic!("{major}: {s}"),
                }
                for view in [
                    View::Unknown(lists),
                    View::Unknown(None),
                    View::Known(&all, lists),
                ] {
                    assert!(
                        user_code(Some(&code), false, &view, &excluded)
                            == crate::audit::user_code::Verdict::BuiltIn,
                        "{major} {view:?}: {s}"
                    );
                }
            }
        }
        // Most of them are catalog-only.
        assert!(applicable >= 5 * 20, "{applicable}");
    }

    /// The statements of the exact-text exemption are statements of this
    /// module.
    #[test]
    fn connector_statements_are_listed() {
        let all = all_statements();
        for c in connector_statements() {
            assert!(all.contains(&c), "{c}");
        }
    }

    #[test]
    fn parentheses_balance() {
        for s in all_statements() {
            let mut depth = 0i32;
            let mut quote: Option<char> = None;
            for c in s.chars() {
                match (quote, c) {
                    (Some(q), c) if c == q => quote = None,
                    (Some(_), _) => {}
                    (None, '\'' | '"') => quote = Some(c),
                    (None, '(') => depth += 1,
                    (None, ')') => {
                        depth -= 1;
                        assert!(depth >= 0, "{s}");
                    }
                    _ => {}
                }
            }
            assert_eq!(depth, 0, "{s}");
            assert!(quote.is_none(), "{s}");
        }
    }

    /// Every statement fits the `pg_stat_statements` text bound: a cut
    /// text is a read of `*` (ADR-0049 decision 8), so a longer statement
    /// of the connector would be reported on that source.
    #[test]
    fn statements_fit_the_text_bound() {
        for s in all_statements() {
            assert!(
                s.chars().count() < PSS_MAX_TEXT_CHARS as usize,
                "{} characters: {s}",
                s.chars().count()
            );
        }
    }

    /// `pg_stat_statements` keeps an `ORDER BY` / `GROUP BY` position as
    /// written while `audit::events::pss_form` replaces every integer: the
    /// statements of the exact-text exemption use names there.
    #[test]
    fn connector_statements_order_by_name() {
        for s in connector_statements() {
            let upper = s.to_uppercase();
            for clause in ["ORDER BY ", "GROUP BY "] {
                for (i, _) in upper.match_indices(clause) {
                    let rest = &upper[i + clause.len()..];
                    assert!(
                        !rest.starts_with(|c: char| c.is_ascii_digit()),
                        "{clause}<position> in {s}"
                    );
                }
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
    fn only_the_own_tableless_statements_name_no_relation() {
        use databastion_classifiers::query::{AnalyzeOptions, StatementKind, analyze};
        for s in all_statements() {
            let a = analyze(&s, AnalyzeOptions::new());
            let named = a.parts().iter().any(|p| !p.relations.is_empty());
            let utility = a.kind() == StatementKind::Other;
            // The `pg_stat_statements` text query reads the extension's
            // function: registered by its stream (`audit::pss`).
            let own =
                OWN_TABLELESS.contains(&s.as_str()) || s.contains(".pg_stat_statements(true)");
            assert!(
                named || utility || own,
                "table-less statement not listed: {s}"
            );
            if OWN_TABLELESS.contains(&s.as_str()) {
                assert!(!named, "listed but names a relation: {s}");
                assert_eq!(a.kind(), StatementKind::Select, "{s}");
                assert_eq!(a.statements(), 1, "{s}");
                assert!(a.normalized().is_some(), "{s}");
            }
        }
        // Every call in them is a `pg_catalog` function.
        for s in OWN_TABLELESS {
            let b = s.as_bytes();
            for (i, _) in s.match_indices('(') {
                let mut j = i;
                while j > 0 && (b[j - 1].is_ascii_alphanumeric() || b[j - 1] == b'_') {
                    j -= 1;
                }
                if j < i {
                    assert!(s[..j].ends_with("pg_catalog."), "{}", &s[j..i]);
                }
            }
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
            "pg_get_userbyid(",
            "inet_client_addr(",
            "host(",
            "left(",
            "char_length(",
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
