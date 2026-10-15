//! The closed statement set (ADR-0051 decisions 4 and 5, refinement item
//! 7, M4): every text the connector sends is a constant of
//! [`STATEMENTS`] or one of its templates with placeholders replaced by
//! [`quote_ident`] identifiers, [`quote_literal`] catalog names or integer
//! literals built here. **Any change to this list is reviewed by the
//! `security-reviewer`** (the allow-list of M4); `tests` check the
//! deny-list of definition-bearing catalogs, functions and columns on
//! every entry, and `crates/agent/tests/architecture.rs` checks this file.
//!
//! Placeholders: `{db}` a bracketed database name, `{dbname}` the same
//! name as an `N'…'` literal, `{obj}` an object id, `{n}` a row count,
//! `{select}` / `{from}` / `{sample}` the sampling parts
//! ([`sample_statement`]).

/// The reviewed allow-list: (name, exact text or template).
pub(crate) const STATEMENTS: &[(&str, &str)] = &[
    ("session_settings", crate::conn::SESSION_SETTINGS),
    ("session_readback", crate::conn::SESSION_READBACK),
    ("version", VERSION),
    ("server_permissions", SERVER_PERMISSIONS),
    ("server_roles", SERVER_ROLES),
    ("server_grants", SERVER_GRANTS),
    ("password_hash_probe", PASSWORD_HASH_PROBE),
    ("logon_triggers", LOGON_TRIGGERS),
    ("accessible_databases", ACCESSIBLE_DATABASES),
    ("user_databases", USER_DATABASES),
    ("database_permissions", DATABASE_PERMISSIONS),
    ("database_roles", DATABASE_ROLES),
    ("database_grants", DATABASE_GRANTS),
    ("rls_view_definition", RLS_VIEW_DEFINITION),
    ("rls_denies", RLS_DENIES),
    ("rls_tables", RLS_TABLES),
    ("unsampled_objects", UNSAMPLED_OBJECTS),
    ("column_counts", COLUMN_COUNTS),
    ("tables", TABLES),
    ("columns", COLUMNS),
    ("cas_credential_columns", CAS_COLUMNS),
    ("ticket_type_counts", TICKET_TYPE_COUNTS),
    ("sample", SAMPLE),
];

/// Version and edition (decision 3).
pub(crate) const VERSION: &str = "SELECT CONVERT(int, SERVERPROPERTY('EngineEdition')), \
CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')), \
CONVERT(nvarchar(128), SERVERPROPERTY('ProductMajorVersion'))";

/// Effective server permissions (decision 4).
pub(crate) const SERVER_PERMISSIONS: &str = "SELECT TOP (513) \
CONVERT(nvarchar(128), permission_name) FROM sys.fn_my_permissions(NULL, 'SERVER')";

/// Server roles the login is a member of, directly or not (bounded at 64:
/// a 65th row means not evaluated).
pub(crate) const SERVER_ROLES: &str = "SELECT TOP (65) CONVERT(nvarchar(128), name) \
FROM sys.server_principals WHERE type = 'R' AND name <> N'public' AND IS_SRVROLEMEMBER(name) = 1";

/// Securable-level server grants to the login, its roles and `public`
/// (decision 4, M3): permission, state, class.
pub(crate) const SERVER_GRANTS: &str = "SELECT TOP (513) \
CONVERT(nvarchar(128), p.permission_name), CONVERT(nvarchar(1), p.state), CONVERT(int, p.class), \
CONVERT(int, CASE WHEN p.grantee_principal_id = 2 THEN 1 ELSE 0 END) \
FROM sys.server_permissions p WHERE p.state IN ('G', 'W') AND (p.grantee_principal_id = SUSER_ID() \
OR p.grantee_principal_id IN (SELECT r.principal_id FROM sys.server_principals r \
WHERE r.type = 'R' AND IS_SRVROLEMEMBER(r.name) = 1))";

/// The merged `password_hash` probe, exact text of the refinement (item 1,
/// security review L1): 1 refuse, 0 pass, 2 not evaluated.
pub(crate) const PASSWORD_HASH_PROBE: &str = "SELECT CASE
  WHEN EXISTS (SELECT 1 FROM sys.sql_logins WHERE sid <> SUSER_SID() AND password_hash IS NOT NULL) THEN 1
  WHEN EXISTS (SELECT 1 FROM sys.sql_logins WHERE sid <> SUSER_SID()) THEN 0
  ELSE 2
END";

/// Enabled server logon triggers (decision 7): a count only, evaluated
/// only when the catalog is visible to the account.
pub(crate) const LOGON_TRIGGERS: &str = "SELECT CONVERT(int, COUNT(*)) FROM sys.server_triggers \
WHERE is_disabled = 0 AND parent_class = 100";

/// Every database the login can enter (decision 4, M3: system databases
/// included).
pub(crate) const ACCESSIBLE_DATABASES: &str = "SELECT TOP (1025) CONVERT(nvarchar(128), name) \
FROM sys.databases WHERE HAS_DBACCESS(name) = 1 AND state = 0 AND source_database_id IS NULL \
ORDER BY name";

/// The user databases Discovery may read (decision 5).
pub(crate) const USER_DATABASES: &str = "SELECT TOP (1025) CONVERT(nvarchar(128), name) \
FROM sys.databases WHERE HAS_DBACCESS(name) = 1 AND state = 0 AND source_database_id IS NULL \
AND is_distributor = 0 AND name NOT IN (N'master', N'model', N'msdb', N'tempdb', N'distribution', \
N'SSISDB') AND name NOT LIKE N'ReportServer%' ORDER BY name";

/// Effective database permissions, through `HAS_PERMS_BY_NAME` over the
/// database's own permission list (decision 4): names held.
pub(crate) const DATABASE_PERMISSIONS: &str = "SELECT TOP (513) \
CONVERT(nvarchar(128), permission_name) FROM sys.fn_builtin_permissions(N'DATABASE') \
WHERE HAS_PERMS_BY_NAME({dbname}, N'DATABASE', permission_name) = 1";

/// Database roles of the login's user in `{db}`, followed recursively
/// (bounded at 64 levels; a 65th row means not evaluated). `dbo` (the
/// database owner) is reported as `db_owner`.
pub(crate) const DATABASE_ROLES: &str = "WITH me AS (SELECT principal_id, name FROM \
{db}.sys.database_principals WHERE sid = SUSER_SID()), roles (id, depth) AS (SELECT \
rm.role_principal_id, 1 FROM {db}.sys.database_role_members rm JOIN me ON \
rm.member_principal_id = me.principal_id UNION ALL SELECT rm.role_principal_id, r.depth + 1 FROM \
{db}.sys.database_role_members rm JOIN roles r ON rm.member_principal_id = r.id WHERE r.depth < 64) \
SELECT TOP (65) CONVERT(nvarchar(128), p.name) FROM {db}.sys.database_principals p WHERE \
p.principal_id IN (SELECT id FROM roles) UNION SELECT N'db_owner' FROM me WHERE me.name = N'dbo' \
OPTION (MAXRECURSION 64)";

/// Securable-level grants in `{db}` to the user, its roles and `public`
/// (decision 4, M3): permission, state, class, to `public`.
pub(crate) const DATABASE_GRANTS: &str = "WITH me AS (SELECT principal_id FROM \
{db}.sys.database_principals WHERE sid = SUSER_SID()), roles (id, depth) AS (SELECT \
rm.role_principal_id, 1 FROM {db}.sys.database_role_members rm JOIN me ON \
rm.member_principal_id = me.principal_id UNION ALL SELECT rm.role_principal_id, r.depth + 1 FROM \
{db}.sys.database_role_members rm JOIN roles r ON rm.member_principal_id = r.id WHERE r.depth < 64) \
SELECT TOP (1025) CONVERT(nvarchar(128), p.permission_name), CONVERT(nvarchar(1), p.state), \
CONVERT(int, p.class), CONVERT(int, CASE WHEN p.grantee_principal_id = 0 THEN 1 ELSE 0 END) \
FROM {db}.sys.database_permissions p WHERE p.state IN ('G', 'W') AND (p.grantee_principal_id = 0 \
OR p.grantee_principal_id IN (SELECT principal_id FROM me) OR p.grantee_principal_id IN \
(SELECT id FROM roles)) OPTION (MAXRECURSION 64)";

/// RLS tier (ii), first proof: database `VIEW DEFINITION` effective.
pub(crate) const RLS_VIEW_DEFINITION: &str =
    "SELECT CONVERT(int, HAS_PERMS_BY_NAME({dbname}, N'DATABASE', N'VIEW DEFINITION'))";

/// RLS tier (ii), second proof (refinement item 2, M1): `DENY` rows of
/// the definition-visibility permissions at any class, to the user, its
/// roles (at most 64) and `public`; with the number of roles. Counts only.
pub(crate) const RLS_DENIES: &str = "WITH me AS (SELECT principal_id FROM \
{db}.sys.database_principals WHERE sid = SUSER_SID()), roles (id, depth) AS (SELECT \
rm.role_principal_id, 1 FROM {db}.sys.database_role_members rm JOIN me ON \
rm.member_principal_id = me.principal_id UNION ALL SELECT rm.role_principal_id, r.depth + 1 FROM \
{db}.sys.database_role_members rm JOIN roles r ON rm.member_principal_id = r.id WHERE r.depth < 64) \
SELECT CONVERT(int, (SELECT COUNT(*) FROM {db}.sys.database_permissions p WHERE p.state = 'D' AND \
p.permission_name IN (N'VIEW DEFINITION', N'VIEW SECURITY DEFINITION', N'CONTROL') AND \
(p.grantee_principal_id = 0 OR p.grantee_principal_id IN (SELECT principal_id FROM me) OR \
p.grantee_principal_id IN (SELECT id FROM roles)))), CONVERT(int, (SELECT COUNT(DISTINCT id) FROM \
roles)), CONVERT(int, (SELECT COUNT(*) FROM me)) OPTION (MAXRECURSION 64)";

/// Tables with an enabled RLS predicate (never `predicate_definition`).
pub(crate) const RLS_TABLES: &str = "SELECT DISTINCT TOP (16385) \
CONVERT(int, sp.target_object_id) FROM {db}.sys.security_predicates sp JOIN \
{db}.sys.security_policies p ON p.object_id = sp.object_id WHERE p.is_enabled = 1";

/// Objects of `{db}` Discovery never samples, counted (decision 5): views,
/// synonyms, external tables.
pub(crate) const UNSAMPLED_OBJECTS: &str = "SELECT CONVERT(int, (SELECT COUNT(*) FROM \
{db}.sys.views WHERE is_ms_shipped = 0)), CONVERT(int, (SELECT COUNT(*) FROM {db}.sys.synonyms)), \
CONVERT(int, (SELECT COUNT(*) FROM {db}.sys.tables WHERE is_external = 1))";

/// Columns of `{db}`'s user tables that Discovery reports in notes
/// (decision 5): masked, Always Encrypted, computed; and the views.
pub(crate) const COLUMN_COUNTS: &str = "SELECT CONVERT(int, COUNT(CASE WHEN c.is_masked = 1 THEN 1 \
END)), CONVERT(int, COUNT(CASE WHEN c.encryption_type IS NOT NULL THEN 1 END)), CONVERT(int, \
COUNT(CASE WHEN c.is_computed = 1 THEN 1 END)), CONVERT(int, (SELECT COUNT(*) FROM {db}.sys.views \
WHERE is_ms_shipped = 0)) FROM {db}.sys.columns c JOIN {db}.sys.tables t ON t.object_id = \
c.object_id WHERE t.is_ms_shipped = 0 AND t.type = 'U'";

/// User tables of `{db}` (decision 5): id, schema, name, Stretch, memory
/// optimized, row estimate (metadata), `SELECT` on the table.
pub(crate) const TABLES: &str = "SELECT TOP ({n}) CONVERT(int, t.object_id), \
CONVERT(nvarchar(128), s.name), CONVERT(nvarchar(128), t.name), \
CONVERT(int, t.is_remote_data_archive_enabled), CONVERT(int, t.is_memory_optimized), \
CONVERT(bigint, (SELECT SUM(p.rows) FROM {db}.sys.partitions p WHERE p.object_id = t.object_id \
AND p.index_id IN (0, 1))), CONVERT(int, HAS_PERMS_BY_NAME(QUOTENAME({dbname}) + N'.' + \
QUOTENAME(s.name) + N'.' + QUOTENAME(t.name), N'OBJECT', N'SELECT')) FROM {db}.sys.tables t JOIN \
{db}.sys.schemas s ON s.schema_id = t.schema_id WHERE t.type = 'U' AND t.is_ms_shipped = 0 AND \
t.is_external = 0 AND t.is_filetable = 0 AND s.name NOT IN (N'sys', N'INFORMATION_SCHEMA', \
N'guest') AND s.name NOT LIKE N'db[_]%' ORDER BY t.object_id";

/// Columns of one table (decision 5, L3: types from `system_type_id`):
/// name, system type, computed, column set, Always Encrypted, masked,
/// graph, user type id, column `SELECT`.
pub(crate) const COLUMNS: &str = "SELECT TOP (4097) CONVERT(nvarchar(128), c.name), \
CONVERT(int, c.system_type_id), CONVERT(int, c.is_computed), CONVERT(int, c.is_column_set), \
CONVERT(int, CASE WHEN c.encryption_type IS NULL THEN 0 ELSE 1 END), CONVERT(int, c.is_masked), \
CONVERT(int, CASE WHEN c.graph_type IS NULL THEN 0 ELSE 1 END), CONVERT(int, c.user_type_id), \
CONVERT(int, HAS_PERMS_BY_NAME(QUOTENAME({dbname}) + N'.' + QUOTENAME(OBJECT_SCHEMA_NAME(c.object_id, \
DB_ID({dbname}))) + N'.' + QUOTENAME(OBJECT_NAME(c.object_id, DB_ID({dbname}))), N'OBJECT', \
N'SELECT', c.name, N'COLUMN')) FROM {db}.sys.columns c WHERE c.object_id = {obj} ORDER BY c.column_id";

/// The CAS store guard's `check()` read (ADR-0041 decision 6): table and
/// column names with the column `SELECT`, bounded.
pub(crate) const CAS_COLUMNS: &str = "SELECT TOP (20001) CONVERT(int, t.object_id), \
CONVERT(nvarchar(128), t.name), CONVERT(nvarchar(128), c.name), CONVERT(int, \
HAS_PERMS_BY_NAME(QUOTENAME({dbname}) + N'.' + QUOTENAME(s.name) + N'.' + QUOTENAME(t.name), \
N'OBJECT', N'SELECT', c.name, N'COLUMN')) FROM {db}.sys.tables t JOIN {db}.sys.schemas s ON \
s.schema_id = t.schema_id JOIN {db}.sys.columns c ON c.object_id = t.object_id WHERE t.type = 'U' \
AND t.is_ms_shipped = 0 ORDER BY t.object_id";

/// A CAS ticket registry's metadata (ADR-0041 decision 5): counts per
/// `type`, never a ticket.
pub(crate) const TICKET_TYPE_COUNTS: &str = "SELECT TOP (256) \
CONVERT(nvarchar(256), LEFT({col}, 256)), CONVERT(bigint, COUNT_BIG(*)) FROM {from} \
GROUP BY LEFT({col}, 256) OPTION (MAXDOP 1)";

/// The sampling statement (decision 5).
pub(crate) const SAMPLE: &str = "SELECT TOP ({n}) {select} FROM {from}{sample} OPTION (MAXDOP 1)";

/// Quotes an identifier from the catalog (`[` … `]`, `]` doubled). `None`
/// for an empty name, a name longer than `sysname`, or a control
/// character.
pub(crate) fn quote_ident(name: &str) -> Option<String> {
    if name.is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) {
        return None;
    }
    Some(format!("[{}]", name.replace(']', "]]")))
}

/// Quotes a catalog name as an `N'…'` literal (`'` doubled), for the
/// built-ins that take a name. Its output is only ever placed outside
/// brackets (a `]` in a string literal is plain text); the skeleton test
/// checks it on every template.
pub(crate) fn quote_literal(name: &str) -> Option<String> {
    if name.is_empty() || name.chars().count() > 128 || name.chars().any(char::is_control) {
        return None;
    }
    Some(format!("N'{}'", name.replace('\'', "''")))
}

/// Renders a template **in one pass** (security review C1): the template
/// is scanned for `{slot}` placeholders and each is replaced by its
/// already-quoted value; inserted text is never scanned again, so a name
/// holding `{from}` or `]` cannot reach another slot. `None` for an
/// unknown or unterminated placeholder.
pub(crate) fn render(template: &str, slots: &[(&str, &str)]) -> Option<String> {
    let mut out = String::with_capacity(template.len() + 64);
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(rest.get(..open)?);
        let after = rest.get(open + 1..)?;
        let close = after.find('}')?;
        let name = after.get(..close)?;
        let value = slots.iter().find(|(k, _)| *k == name)?.1;
        out.push_str(value);
        rest = after.get(close + 1..)?;
    }
    out.push_str(rest);
    Some(out)
}

/// A database statement: `{db}` and `{dbname}` filled.
pub(crate) fn in_database(template: &str, db: &str) -> Option<String> {
    let (q, l) = (quote_ident(db)?, quote_literal(db)?);
    render(template, &[("db", &q), ("dbname", &l)])
}

/// The table list of `{db}`, at most `limit` tables (one more read to
/// detect the cut).
pub(crate) fn tables(db: &str, limit: u32) -> Option<String> {
    let (q, l) = (quote_ident(db)?, quote_literal(db)?);
    let n = (u64::from(limit) + 1).to_string();
    render(TABLES, &[("db", &q), ("dbname", &l), ("n", &n)])
}

/// The columns of one table.
pub(crate) fn columns(db: &str, object_id: i64) -> Option<String> {
    let (q, l) = (quote_ident(db)?, quote_literal(db)?);
    let obj = object_id.to_string();
    render(COLUMNS, &[("db", &q), ("dbname", &l), ("obj", &obj)])
}

fn from(db: &str, schema: &str, table: &str) -> Option<String> {
    Some(format!(
        "{}.{}.{}",
        quote_ident(db)?,
        quote_ident(schema)?,
        quote_ident(table)?
    ))
}

/// A ticket registry's type counts.
pub(crate) fn ticket_type_counts(
    db: &str,
    schema: &str,
    table: &str,
    column: &str,
) -> Option<String> {
    let (col, from) = (quote_ident(column)?, from(db, schema, table)?);
    render(TICKET_TYPE_COUNTS, &[("col", &col), ("from", &from)])
}

/// How a column is sampled (decision 5, L3), by `system_type_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sampled {
    /// `char`, `varchar`, `nchar`, `nvarchar` (any collation): `LEFT`.
    Text,
    /// `text`, `ntext`: `SUBSTRING` (they do not accept `LEFT`).
    LargeText,
    /// `int`, `bigint`, `decimal`, `numeric`: digits.
    Number,
    /// `date`, `datetime`, `datetime2`, `smalldatetime`: style 23.
    Date,
}

/// The sampling kind of a `system_type_id`; `None`: not sampled (CLR,
/// `xml`, `sql_variant`, `timestamp`, `image`, binary, `uniqueidentifier`,
/// floats, money, `json`, `vector`, small integers, times…).
pub(crate) fn sampled_kind(system_type_id: i64) -> Option<Sampled> {
    match system_type_id {
        167 | 175 | 231 | 239 => Some(Sampled::Text),
        35 | 99 => Some(Sampled::LargeText),
        56 | 127 | 106 | 108 => Some(Sampled::Number),
        40 | 42 | 58 | 61 => Some(Sampled::Date),
        _ => None,
    }
}

/// The select-list expression of a sampled column: built-ins only.
pub(crate) fn sample_expr(column: &str, kind: Sampled) -> Option<String> {
    let c = quote_ident(column)?;
    Some(match kind {
        Sampled::Text => format!("CONVERT(nvarchar(4000), LEFT({c}, 4000))"),
        Sampled::LargeText => format!("CONVERT(nvarchar(4000), SUBSTRING({c}, 1, 4000))"),
        Sampled::Number => format!("CONVERT(nvarchar(64), {c})"),
        Sampled::Date => format!("CONVERT(nvarchar(10), {c}, 23)"),
    })
}

/// The `TABLESAMPLE` percentage targeting about 4 × `n` rows of
/// `estimate`, when the estimate is above 20 × `n` and 1 000 rows; `None`:
/// `TOP (n)` in storage order (decision 5).
pub(crate) fn tablesample_percent(n: u32, estimate: Option<u64>) -> Option<f64> {
    let est = estimate?;
    let n = u64::from(n);
    if est <= n.saturating_mul(20) || est <= 1000 {
        return None;
    }
    let p = (4.0 * n as f64 / est as f64 * 100.0).clamp(0.01, 100.0);
    Some(p)
}

/// The sampling statement of one table: no string literal, identifiers
/// quoted, integer and decimal literals built here.
pub(crate) fn sample_statement(
    db: &str,
    schema: &str,
    table: &str,
    columns: &[(&str, Sampled)],
    n: u32,
    percent: Option<f64>,
) -> Option<String> {
    if columns.is_empty() || n == 0 {
        return None;
    }
    let select: Vec<String> = columns
        .iter()
        .map(|(c, k)| sample_expr(c, *k))
        .collect::<Option<_>>()?;
    let sample = match percent {
        Some(p) => format!(" TABLESAMPLE SYSTEM ({p:.2} PERCENT)"),
        None => String::new(),
    };
    let (n, select, from) = (n.to_string(), select.join(", "), from(db, schema, table)?);
    render(
        SAMPLE,
        &[
            ("n", &n),
            ("select", &select),
            ("from", &from),
            ("sample", &sample),
        ],
    )
}

/// What no statement may read (refinement item 7, M4): module bodies and
/// definition-bearing catalogs, functions and columns, compared
/// case-insensitively on the text **outside** bracketed identifiers and
/// string literals ([`unquoted`]), so a user's table or column name never
/// trips it. Checked by the tests on every allow-listed text and, at run
/// time, on every text the session sends ([`checked`]).
pub(crate) const DENIED: &[&str] = &[
    "sql_modules",
    "syscomments",
    "numbered_procedures",
    "object_definition",
    "sp_helptext",
    "computed_columns",
    "check_constraints",
    "default_constraints",
    "partition_range_values",
    "predicate_definition",
    "filter_definition",
    "provider_string",
    "data_source",
    "server_audits",
    "definition",
    "sys.servers",
    "linked_logins",
    "credentials",
    "password_hash",
    "loginproperty",
    "certprivatekey",
    "pwdcompare",
];

/// The text without the content of bracketed identifiers and string
/// literals (each replaced by an empty pair), lower-cased.
pub(crate) fn unquoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let close = match c {
            '[' => ']',
            '\'' => '\'',
            _ => {
                out.extend(c.to_lowercase());
                continue;
            }
        };
        out.push(c);
        while let Some(d) = chars.next() {
            if d == close {
                if chars.peek() == Some(&close) {
                    chars.next();
                    continue;
                }
                break;
            }
        }
        out.push(close);
    }
    out
}

/// The denied token a text names outside quotes, if any.
pub(crate) fn denied_token(text: &str) -> Option<&'static str> {
    let bare = unquoted(text);
    DENIED.iter().copied().find(|d| bare.contains(d))
}

/// Whether the session may send `text`: the exact `password_hash` probe
/// (one bit, decision 4), or a text that names no denied token.
pub(crate) fn checked(text: &str) -> bool {
    text == PASSWORD_HASH_PROBE || denied_token(text).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_statement_passes_the_deny_list() {
        for (name, text) in STATEMENTS {
            assert!(checked(text), "{name}: {:?}", denied_token(text));
        }
        // A user's names never trip it.
        assert!(checked(
            "SELECT CONVERT(nvarchar(4000), LEFT([definition], 4000)) FROM [d].[credentials].[t]"
        ));
        assert!(checked(
            "SELECT HAS_PERMS_BY_NAME(N'db', N'DATABASE', N'VIEW DEFINITION')"
        ));
        assert!(!checked(
            "SELECT 1 FROM [x] JOIN sys.sql_modules m ON 1 = 1"
        ));
        assert!(!checked("SELECT password_hash FROM sys.sql_logins"));
        // The exempt probe is the refinement's exact constant.
        assert!(PASSWORD_HASH_PROBE.contains("sid <> SUSER_SID() AND password_hash IS NOT NULL"));
        // A raw predicate or a module body is refused.
        for bad in [
            "SELECT predicate FROM sys.server_audits",
            "SELECT definition FROM sys.sql_modules",
            "SELECT OBJECT_DEFINITION(1)",
            "SELECT provider_string FROM sys.servers",
            "SELECT filter_definition FROM sys.indexes",
            "EXEC sp_helptext N'x'",
        ] {
            assert!(denied_token(bad).is_some(), "{bad}");
        }
        let names: Vec<&str> = STATEMENTS.iter().map(|(n, _)| *n).collect();
        let mut dedup = names.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(names.len(), dedup.len());
    }

    #[test]
    fn identifiers_and_literals_are_quoted() {
        assert_eq!(quote_ident("a]b").unwrap(), "[a]]b]");
        assert_eq!(quote_literal("o'brien").unwrap(), "N'o''brien'");
        assert!(quote_ident("").is_none());
        assert!(quote_ident("a\nb").is_none());
        let s = sample_statement(
            "re]tail",
            "crm",
            "customers",
            &[("email", Sampled::Text), ("notes", Sampled::LargeText)],
            100,
            None,
        )
        .unwrap();
        assert_eq!(
            s,
            "SELECT TOP (100) CONVERT(nvarchar(4000), LEFT([email], 4000)), \
             CONVERT(nvarchar(4000), SUBSTRING([notes], 1, 4000)) FROM [re]]tail].[crm].[customers] \
             OPTION (MAXDOP 1)"
        );
        assert!(
            !s.contains('\''),
            "no string literal in a sampling statement"
        );
        let s = sample_statement("d", "s", "t", &[("c", Sampled::Date)], 10, Some(0.5)).unwrap();
        assert!(s.contains("[d].[s].[t] TABLESAMPLE SYSTEM (0.50 PERCENT) OPTION (MAXDOP 1)"));
    }

    #[test]
    fn tablesample_only_for_large_tables() {
        assert_eq!(tablesample_percent(100, Some(1500)), None);
        assert_eq!(tablesample_percent(10, Some(900)), None);
        assert_eq!(tablesample_percent(100, None), None);
        let p = tablesample_percent(100, Some(1_000_000)).unwrap();
        assert!((p - 0.04).abs() < 1e-9);
        assert_eq!(tablesample_percent(1, Some(u64::MAX)), Some(0.01));
    }

    #[test]
    fn types_come_from_system_type_id() {
        for (id, k) in [
            (167, Some(Sampled::Text)),
            (231, Some(Sampled::Text)),
            (35, Some(Sampled::LargeText)),
            (99, Some(Sampled::LargeText)),
            (56, Some(Sampled::Number)),
            (61, Some(Sampled::Date)),
            (240, None),
            (241, None),
            (98, None),
            (189, None),
            (34, None),
            (36, None),
            (165, None),
            (62, None),
            (60, None),
        ] {
            assert_eq!(sampled_kind(id), k, "{id}");
        }
    }
}
