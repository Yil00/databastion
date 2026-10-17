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
    ("rls_server_denies", RLS_SERVER_DENIES),
    ("rls_tables", RLS_TABLES),
    ("unsampled_objects", UNSAMPLED_OBJECTS),
    ("column_counts", COLUMN_COUNTS),
    ("tables", TABLES),
    ("columns", COLUMNS),
    ("cas_credential_columns", CAS_COLUMNS),
    ("ticket_type_counts", TICKET_TYPE_COUNTS),
    ("sample", SAMPLE),
    ("audit_file", AUDIT_FILE),
    ("audit_specifications", AUDIT_SPECIFICATIONS),
    ("audit_database_reads", AUDIT_DATABASE_READS),
    ("audit_poll_start", AUDIT_POLL_START),
    ("audit_poll_from", AUDIT_POLL_FROM),
    ("xe_session", XE_SESSION),
    ("xe_events", XE_EVENTS),
    ("xe_poll_start", XE_POLL_START),
    ("xe_poll_from", XE_POLL_FROM),
];

/// The Extended Events session named in `agent.yaml` (ADR-0051 decision 6,
/// proofs 1 and 4, "Position and gaps"), from `sys.dm_xe_sessions` (a
/// running session only): its `create_time` (a restart of the session
/// changes it), its drop counters, its retention mode
/// (`buffer_policy_desc`: `drop_event`, `drop_full_buffer` or
/// `do_not_drop_event`/`block`), whether it tracks causality, and the
/// current file of its `event_file` target, cut from the target's status
/// XML on the server (only that file name is read, never other target
/// data: a `ring_buffer` target holds events), and the session's
/// `MAX_DISPATCH_LATENCY` (ms, 0 for `INFINITE`, from
/// `sys.server_event_sessions`: the bound of the first start's floor,
/// re-review N1). Visible with `VIEW SERVER
/// STATE` (2019) or `VIEW SERVER PERFORMANCE STATE` (2022+). An exact own
/// text (refinement P9-A obligation L8).
pub(crate) const XE_SESSION: &str = "SELECT TOP (2) \
CONVERT(bigint, DATEDIFF_BIG(microsecond, '19700101', s.create_time)), \
CONVERT(bigint, s.dropped_event_count), CONVERT(bigint, s.dropped_buffer_count), \
CONVERT(nvarchar(60), s.buffer_policy_desc), \
CONVERT(int, CASE WHEN s.flag_desc LIKE N'%track_causality%' THEN 1 ELSE 0 END), \
CONVERT(nvarchar(260), (SELECT TOP (1) CONVERT(xml, t.target_data).value('(EventFileTarget/File/@name)[1]', \
'nvarchar(260)') FROM sys.dm_xe_session_targets t WHERE t.event_session_address = s.address AND \
t.target_name = N'event_file')), CONVERT(bigint, (SELECT TOP (1) d.max_dispatch_latency FROM \
sys.server_event_sessions d WHERE d.name = s.name)) FROM sys.dm_xe_sessions s WHERE s.name = {session}";

/// The events of the session (decision 6 proofs 2 and 3): each event's
/// name, **whether** it has a predicate (never the predicate, which can
/// hold literals), how many of the five required actions it carries, and
/// whether its statement collection is off (`collect_statement = 0`).
pub(crate) const XE_EVENTS: &str = "SELECT TOP (257) CONVERT(nvarchar(60), e.event_name), \
CONVERT(int, CASE WHEN e.event_predicate IS NULL THEN 1 ELSE 0 END), CONVERT(int, (SELECT COUNT(*) \
FROM sys.dm_xe_session_event_actions a WHERE a.event_session_address = e.event_session_address AND \
a.event_name = e.event_name AND a.action_name IN (N'server_principal_name', \
N'session_server_principal_name', N'client_app_name', N'database_name', N'session_id'))), \
CONVERT(int, (SELECT COUNT(*) FROM sys.dm_xe_session_object_columns c WHERE \
c.event_session_address = e.event_session_address AND c.object_name = e.event_name AND \
c.object_type = N'event' AND c.column_name = N'collect_statement' AND c.column_value = N'0')) \
FROM sys.dm_xe_session_events e JOIN sys.dm_xe_sessions s ON s.address = e.event_session_address \
WHERE s.name = {session}";

/// The largest event the Extended Events poll returns (UTF-16 bytes of
/// `event_data`): 64 Ki characters (decision 6: "bounded at 64 KiB per
/// event"). A larger event comes back without its XML, with its name,
/// position, time and size: a read of `*`, always reported.
pub(crate) const XE_EVENT_BYTES: usize = 131_072;

/// Slices of `event_data` per row: 17 of 8 000 bytes cover
/// [`XE_EVENT_BYTES`].
pub(crate) const XE_SLICES: usize = 17;

/// The columns of an Extended Events poll: the event's name, its XML (when
/// at most [`XE_EVENT_BYTES`]) as UTF-16LE bytes in [`XE_SLICES`]
/// `varbinary(8000)` slices, the position, the time (UTC, µs since 1970)
/// and the XML's size.
///
/// Measured on 2019: the session setting `SET TEXTSIZE 8000` (decision 5,
/// sent on every connection) cuts an `nvarchar(max)` value to 8 000 bytes,
/// so `event_data` itself would arrive cut, without a sign, for any event
/// above 4 000 characters. Slices of `varbinary(8000)` are not `max` values
/// (`TEXTSIZE` does not apply) and keep the client's closed type set
/// without a `max` column (decision 1). They are cut by byte, whatever the
/// collation (a supplementary-character collation counts characters, not
/// UTF-16 units, in `SUBSTRING` of `nvarchar`), and the client joins the
/// bytes before decoding them once (security review of lot 3, M2).
const XE_COLUMNS: &str = "CONVERT(nvarchar(60), f.object_name), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 1, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 8001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 16001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 24001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 32001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 40001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 48001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 56001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 64001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 72001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 80001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 88001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 96001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 104001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 112001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 120001, 8000)), \
CONVERT(varbinary(8000), SUBSTRING(x.b, 128001, 8000)), CONVERT(nvarchar(260), f.file_name), \
CONVERT(bigint, f.file_offset), CONVERT(bigint, DATEDIFF_BIG(microsecond, '19700101', f.timestamp_utc)), \
CONVERT(bigint, DATALENGTH(f.event_data))";

/// The first poll of an Extended Events session: from the start of its
/// file set. `{pattern}` is built from the session's current file
/// (`XE_SESSION`), a literal (decision 6, M1); `@p3` the row bound, `@p4`
/// the events skipped (as [`XE_POLL_FROM`]).
pub(crate) const XE_POLL_START: &str = "SELECT {columns} FROM \
sys.fn_xe_file_target_read_file({pattern}, NULL, NULL, NULL) f CROSS APPLY (SELECT CASE WHEN \
DATALENGTH(f.event_data) <= 131072 THEN CONVERT(varbinary(max), f.event_data) END) x(b) \
ORDER BY (SELECT NULL) OFFSET @p4 ROWS FETCH NEXT @p3 ROWS ONLY OPTION (MAXDOP 1)";

/// The following polls: after the buffer at `@p2` of the file `@p1`
/// (measured on 2019: the read starts after that buffer; an offset that is
/// not a buffer gives error 25722, a missing file 25717), the first `@p4`
/// events skipped on the server (those of the next buffer already
/// handled: a buffer holds hundreds of events, measured on 2025), at most
/// `@p3` returned, in file order.
pub(crate) const XE_POLL_FROM: &str = "SELECT {columns} FROM \
sys.fn_xe_file_target_read_file({pattern}, NULL, @p1, @p2) f CROSS APPLY (SELECT CASE WHEN \
DATALENGTH(f.event_data) <= 131072 THEN CONVERT(varbinary(max), f.event_data) END) x(b) \
ORDER BY (SELECT NULL) OFFSET @p4 ROWS FETCH NEXT @p3 ROWS ONLY OPTION (MAXDOP 1)";

/// The number of columns of an Extended Events poll.
pub(crate) const XE_POLL_COLUMNS: usize = 5 + XE_SLICES;

/// An Extended Events poll text for a quoted pattern ([`xe_pattern`]).
pub(crate) fn xe_poll(pattern: &str, from: bool) -> Option<String> {
    render(
        if from { XE_POLL_FROM } else { XE_POLL_START },
        &[("columns", XE_COLUMNS), ("pattern", pattern)],
    )
}

/// The file pattern of an Extended Events session, from its current file
/// as the server names it (`<folder>/<stem>_<n>_<timestamp>.xel`): the
/// same folder, stem and `<n>`, any timestamp, as an `N'…'` literal.
/// `None` for a name of another form, a folder or stem holding a control
/// character or a wildcard, or a path longer than 260 characters.
pub(crate) fn xe_pattern(current: &str) -> Option<String> {
    if current.chars().count() > 260
        || current
            .chars()
            .any(|c| c.is_control() || matches!(c, '*' | '?'))
    {
        return None;
    }
    let cut = current.rfind(['/', '\\']).map_or(0, |i| i + 1);
    let (folder, file) = current.split_at(cut);
    let stem = file.strip_suffix(".xel")?;
    let (rest, ts) = stem.rsplit_once('_')?;
    let (base, part) = rest.rsplit_once('_')?;
    let digits = |s: &str| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit());
    if folder.is_empty() || base.is_empty() || !digits(ts) || !digits(part) {
        return None;
    }
    let pattern = format!("{folder}{base}_{part}_*.xel");
    Some(format!("N'{}'", pattern.replace('\'', "''")))
}

/// The order key of an Extended Events file of one file set, (timestamp,
/// `<n>`), from `…_<n>_<timestamp>.xel`; `None` for another form. Files
/// are ordered by this key, never by their path string (lot 2 review H1).
pub(crate) fn xe_file_key(name: &str) -> Option<(i64, i64)> {
    let stem = name.strip_suffix(".xel")?;
    let (rest, ts) = stem.rsplit_once('_')?;
    let (_, part) = rest.rsplit_once('_')?;
    let num = |s: &str| {
        (!s.is_empty() && s.len() <= 18 && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<i64>().ok())
            .flatten()
    };
    Some((num(ts)?, num(part)?))
}

/// Own texts that read an always-reported object (decision 6): the agent's
/// own only by their exact text from one of its own sessions. The one-bit
/// `password_hash` probe (decision 4) and the Extended Events status read
/// (`sys.dm_xe_session_targets`, P9-A obligation L8).
pub(crate) fn own_listed_read(text: &str) -> bool {
    text == PASSWORD_HASH_PROBE || matches_template(XE_SESSION, text)
}

/// The Audit source's server audit (ADR-0051 decision 6, refinement item 1
/// (a'), M4), read from `sys.server_file_audits` (a `FILE` target only;
/// never `sys.server_audits`): enabled, **whether** it has a predicate
/// (never the predicate's text), `ON_FAILURE`, its GUID and folder (used
/// only to build the poll's file pattern), `QUEUE_DELAY` and its name as
/// the catalog writes it (the file names use it, whatever the case of the
/// name in `agent.yaml`; review L6). Visible with
/// `VIEW ANY SECURITY DEFINITION` (measured on 2022).
pub(crate) const AUDIT_FILE: &str = "SELECT TOP (2) CONVERT(int, is_state_enabled), \
CONVERT(int, CASE WHEN predicate IS NULL THEN 1 ELSE 0 END), CONVERT(int, on_failure), \
CONVERT(nvarchar(36), audit_guid), CONVERT(nvarchar(260), log_file_path), CONVERT(int, queue_delay), \
CONVERT(nvarchar(128), name) FROM sys.server_file_audits WHERE name = {audit}";

/// The action groups of the enabled server audit specifications of the
/// audit (decision 6 proofs 3 and 4): group names and audited results, a
/// closed vocabulary of the server, never an object or principal name.
pub(crate) const AUDIT_SPECIFICATIONS: &str = "SELECT TOP (513) \
CONVERT(nvarchar(64), d.audit_action_name), CONVERT(nvarchar(32), d.audited_result) \
FROM sys.server_audit_specifications s JOIN sys.server_audit_specification_details d ON \
d.server_specification_id = s.server_specification_id WHERE s.audit_guid = \
CONVERT(uniqueidentifier, {guid}) AND s.is_state_enabled = 1";

/// Read coverage of one monitored database by an enabled database audit
/// specification of the audit (decision 6 proof 3): `SCHEMA_OBJECT_ACCESS_GROUP`
/// or `SELECT` on the database by `public`, counted on the server (no
/// object or principal name is read; refinement item 1, I2).
pub(crate) const AUDIT_DATABASE_READS: &str = "SELECT CONVERT(int, COUNT(*)) FROM \
{db}.sys.database_audit_specifications s JOIN {db}.sys.database_audit_specification_details d \
ON d.database_specification_id = s.database_specification_id WHERE s.audit_guid = \
CONVERT(uniqueidentifier, {guid}) AND s.is_state_enabled = 1 AND d.audited_result LIKE N'SUCCESS%' \
AND (d.audit_action_name = N'SCHEMA_OBJECT_ACCESS_GROUP' OR (d.audit_action_name = N'SELECT' AND \
d.class = 0 AND d.audited_principal_id = 0))";

/// The columns of an Audit poll (decision 6, "What is kept"): times as
/// microseconds since 1970 (UTC), the closed fields, the statement (its
/// text never leaves the agent), the position, and for a failed login the
/// error number only, cut from `additional_information` on the server
/// (the rest of that XML is never read). Dropped: `host_name`,
/// `additional_information`, `data_sensitivity_information`,
/// `user_defined_information`, `permission_bitmask`, `affected_rows` and
/// `response_rows` (always 0 on boxed SQL Server, measured on 2022).
const AUDIT_COLUMNS: &str = "CONVERT(bigint, DATEDIFF_BIG(microsecond, '19700101', event_time)), \
CONVERT(nvarchar(4), action_id), CONVERT(int, succeeded), CONVERT(nvarchar(2), class_type), \
CONVERT(int, session_id), CONVERT(nvarchar(128), server_principal_name), \
CONVERT(nvarchar(128), session_server_principal_name), CONVERT(nvarchar(128), database_name), \
CONVERT(nvarchar(128), schema_name), CONVERT(nvarchar(128), object_name), statement, \
CONVERT(nvarchar(128), client_ip), CONVERT(nvarchar(128), application_name), \
CONVERT(int, sequence_number), CONVERT(bigint, transaction_id), CONVERT(nvarchar(260), file_name), \
CONVERT(bigint, audit_file_offset), CONVERT(nvarchar(34), sequence_group_id, 1), \
CONVERT(int, CASE WHEN action_id = 'LGIF' THEN CONVERT(int, TRY_CONVERT(varbinary(4), \
SUBSTRING(additional_information, CHARINDEX(N'<error>', additional_information) + 7, 10), 1)) END)";

/// The first poll of an audit: from the start of its file set. `{pattern}`
/// is the file pattern built from the catalog, a literal (decision 6,
/// M1: never a parameter); the first `@p4` records skipped on the server,
/// at most `@p3` returned, in file order (as [`AUDIT_POLL_FROM`]).
pub(crate) const AUDIT_POLL_START: &str = "SELECT {columns} FROM \
sys.fn_get_audit_file({pattern}, NULL, NULL) ORDER BY (SELECT NULL) OFFSET @p4 ROWS \
FETCH NEXT @p3 ROWS ONLY OPTION (MAXDOP 1)";

/// The following polls: after the buffer at `@p2` of the file `@p1`
/// (measured: the read starts after that buffer, in the next file when it
/// was its file's last; a file outside the pattern's set is refused with
/// error 33225), the first `@p4` records skipped on the server (those of
/// the next buffer already handled: a buffer holds about 500 KiB of
/// records, up to 1 047 measured on 2022, more than a read), at most `@p3`
/// returned, in file order.
pub(crate) const AUDIT_POLL_FROM: &str = "SELECT {columns} FROM \
sys.fn_get_audit_file({pattern}, @p1, @p2) ORDER BY (SELECT NULL) OFFSET @p4 ROWS \
FETCH NEXT @p3 ROWS ONLY OPTION (MAXDOP 1)";

/// The number of columns of an Audit poll.
pub(crate) const AUDIT_POLL_COLUMNS: usize = 19;

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
/// (decision 4, M3): permission, state, class, to `public`. `public`'s
/// rows are read at database and principal class only: its default
/// object grants in `master` and `msdb` run to thousands and hold no
/// right of the refusal list.
pub(crate) const DATABASE_GRANTS: &str = "WITH me AS (SELECT principal_id FROM \
{db}.sys.database_principals WHERE sid = SUSER_SID()), roles (id, depth) AS (SELECT \
rm.role_principal_id, 1 FROM {db}.sys.database_role_members rm JOIN me ON \
rm.member_principal_id = me.principal_id UNION ALL SELECT rm.role_principal_id, r.depth + 1 FROM \
{db}.sys.database_role_members rm JOIN roles r ON rm.member_principal_id = r.id WHERE r.depth < 64) \
SELECT TOP (1025) CONVERT(nvarchar(128), p.permission_name), CONVERT(nvarchar(1), p.state), \
CONVERT(int, p.class), CONVERT(int, CASE WHEN p.grantee_principal_id = 0 THEN 1 ELSE 0 END) \
FROM {db}.sys.database_permissions p WHERE p.state IN ('G', 'W') AND ((p.grantee_principal_id = 0 \
AND p.class IN (0, 4)) OR p.grantee_principal_id IN (SELECT principal_id FROM me) OR \
p.grantee_principal_id IN (SELECT id FROM roles)) OPTION (MAXRECURSION 64)";

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

/// RLS tier (ii), server-scope proof (security review M4): `DENY` rows
/// of the server definition-visibility permissions to the login, its
/// server roles and `public` (a member of every login). A count only.
pub(crate) const RLS_SERVER_DENIES: &str = "SELECT CONVERT(int, COUNT(*)) FROM \
sys.server_permissions p WHERE p.state = 'D' AND p.permission_name IN (N'VIEW ANY DEFINITION', \
N'VIEW ANY SECURITY DEFINITION', N'VIEW SERVER SECURITY STATE', N'CONTROL SERVER') AND \
(p.grantee_principal_id = SUSER_ID() OR p.grantee_principal_id IN (SELECT r.principal_id FROM \
sys.server_principals r WHERE r.type = 'R' AND IS_SRVROLEMEMBER(r.name) = 1))";

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

/// Quotes an audit file pattern as an `N'…'` literal: the folder read from
/// `sys.server_file_audits.log_file_path`, the audit's name and GUID
/// (`<folder><name>_<guid>_*.sqlaudit`). `None` for a folder longer than
/// 260 characters or holding a control character or a wildcard, a name
/// that is not a plain identifier of the catalog, or a GUID that is not
/// one.
pub(crate) fn audit_pattern(folder: &str, name: &str, guid: &str) -> Option<String> {
    let guid_ok = guid.len() == 36
        && guid.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        });
    let plain = |s: &str| !s.chars().any(|c| c.is_control() || matches!(c, '*' | '?'));
    if !guid_ok
        || folder.is_empty()
        || folder.chars().count() > 260
        || !plain(folder)
        || name.is_empty()
        || name.chars().count() > 128
        || !plain(name)
        || name.contains(['/', '\\'])
    {
        return None;
    }
    let sep = if folder.ends_with('/') || folder.ends_with('\\') {
        ""
    } else if folder.contains('\\') {
        "\\"
    } else {
        "/"
    };
    let pattern = format!("{folder}{sep}{name}_{guid}_*.sqlaudit");
    if pattern.chars().count() > 400 {
        return None;
    }
    Some(format!("N'{}'", pattern.replace('\'', "''")))
}

/// An Audit poll text for a quoted pattern ([`audit_pattern`]).
pub(crate) fn audit_poll(pattern: &str, from: bool) -> Option<String> {
    render(
        if from {
            AUDIT_POLL_FROM
        } else {
            AUDIT_POLL_START
        },
        &[("columns", AUDIT_COLUMNS), ("pattern", pattern)],
    )
}

/// A GUID as an `N'…'` literal, checked.
pub(crate) fn quote_guid(guid: &str) -> Option<String> {
    (guid.len() == 36 && guid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
        .then(|| format!("N'{guid}'"))
}

/// How an Audit record's statement text stands to the connector's own
/// statement set ([`own_text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnText {
    /// A constant of [`STATEMENTS`] or a catalog template filled with
    /// quoted names: matched by exact text, no credit needed.
    Exact,
    /// A sampling, ticket-count or Audit poll text: the agent's own only
    /// with an unexpired credit of the same session.
    NeedsCredit,
    /// Not one of the connector's statements.
    No,
}

/// Statements the server runs inside a built-in the agent calls, recorded
/// by SQL Server Audit with the caller's session and the built-in's own
/// text (measured on 2022: `sys.fn_my_permissions` checks
/// `sys.fn_builtin_permissions` with this statement). Exact texts of the
/// server's code, matched like the agent's own constants (from its own
/// sessions only); another build's text is reported, fail closed.
pub(crate) const SERVER_INTERNAL: &[&str] = &[
    "INSERT INTO @myperms\r\n\t    SELECT @entityname, '', fbp.permission_name\r\n\t    FROM \
     sys.fn_builtin_permissions(@class) AS fbp\r\n\t    WHERE has_perms_by_name(@entity, \
     @pseudoclass, fbp.permission_name) <> 0",
];

/// Templates matched only with a credit (security review L5; decision 6
/// "per-poll credit").
const CREDIT_ONLY: &[&str] = &[
    "sample",
    "ticket_type_counts",
    "audit_poll_start",
    "audit_poll_from",
    "xe_poll_start",
    "xe_poll_from",
];

/// The agent's catalog reads (`check()`, Discovery and the Audit proofs
/// that read catalog views): the statements whose compilation can make a
/// fresh server build statistics on the system base tables of ADR-0051's
/// refinement of 2026-10-15, case 2 (re-review: "exact catalog texts").
/// Never the session settings, the version, the samples and counts of
/// user tables, the polls, or the proof over DMVs only (`xe_events`).
/// Measured as build partners on 2022: `server_permissions`,
/// `server_roles`, `server_grants`, `accessible_databases`,
/// `database_grants`, `column_counts`, `tables`, `cas_credential_columns`,
/// `audit_file`, and `xe_session` (since it reads
/// `sys.server_event_sessions`, re-review N1).
const CATALOG_READS: &[&str] = &[
    "server_permissions",
    "server_roles",
    "server_grants",
    "password_hash_probe",
    "logon_triggers",
    "accessible_databases",
    "user_databases",
    "database_permissions",
    "database_roles",
    "database_grants",
    "rls_view_definition",
    "rls_denies",
    "rls_server_denies",
    "rls_tables",
    "unsampled_objects",
    "column_counts",
    "tables",
    "columns",
    "cas_credential_columns",
    "audit_file",
    "audit_specifications",
    "audit_database_reads",
    "xe_session",
];

/// Whether `text` is exactly one of the agent's catalog reads
/// ([`CATALOG_READS`]), as [`render`] produces it.
pub(crate) fn catalog_text(text: &str) -> bool {
    STATEMENTS.iter().any(|(name, template)| {
        CATALOG_READS.contains(name)
            && (*template == text || (template.contains('{') && matches_template(template, text)))
    })
}

/// Whether `text` is exactly one of the connector's statements: a
/// constant, or a template whose slots hold quoted values of the forms
/// [`render`] produces. Never by prefix or shape.
pub(crate) fn own_text(text: &str) -> OwnText {
    if SERVER_INTERNAL.contains(&text) {
        return OwnText::Exact;
    }
    for (name, template) in STATEMENTS {
        if CREDIT_ONLY.contains(name) {
            continue;
        }
        if *template == text || (template.contains('{') && matches_template(template, text)) {
            return OwnText::Exact;
        }
    }
    // Credit-only forms: decided by the credit (the exact text sent).
    if text.starts_with("SELECT TOP (")
        || text
            .strip_prefix("SELECT ")
            .is_some_and(|r| r.starts_with(XE_COLUMNS) || r.starts_with(AUDIT_COLUMNS))
    {
        return OwnText::NeedsCredit;
    }
    OwnText::No
}

/// Reads a bracketed identifier at the start of `s`: (unescaped, rest).
fn take_bracketed(s: &str) -> Option<(String, &str)> {
    let mut chars = s.strip_prefix('[')?.char_indices().peekable();
    let mut out = String::new();
    let body = s.get(1..)?;
    while let Some((i, c)) = chars.next() {
        if c == ']' {
            if chars.peek().map(|(_, d)| *d) == Some(']') {
                chars.next();
                out.push(']');
                continue;
            }
            return Some((out, body.get(i + 1..)?));
        }
        out.push(c);
    }
    None
}

/// Reads an `N'…'` literal at the start of `s`: (unescaped, rest).
fn take_literal(s: &str) -> Option<(String, &str)> {
    let body = s.strip_prefix("N'")?;
    let mut chars = body.char_indices().peekable();
    let mut out = String::new();
    while let Some((i, c)) = chars.next() {
        if c == '\'' {
            if chars.peek().map(|(_, d)| *d) == Some('\'') {
                chars.next();
                out.push('\'');
                continue;
            }
            return Some((out, body.get(i + 1..)?));
        }
        out.push(c);
    }
    None
}

/// Whether `text` is `template` with each slot filled the way [`render`]
/// and the quoting functions fill it: `{db}` a bracketed identifier,
/// `{dbname}`, `{audit}`, `{guid}` an `N'…'` literal (`{dbname}` equal to
/// `{db}`), `{n}` / `{obj}` an integer. Rendered again from the values
/// read and compared exactly, so nothing else can hide in a slot.
pub(crate) fn matches_template(template: &str, text: &str) -> bool {
    let mut rest_t = template;
    let mut rest = text;
    let mut slots: Vec<(String, String)> = Vec::new();
    while let Some(open) = rest_t.find('{') {
        let Some(lit) = rest_t.get(..open) else {
            return false;
        };
        let Some(r) = rest.strip_prefix(lit) else {
            return false;
        };
        rest = r;
        let Some(close) = rest_t.get(open..).and_then(|s| s.find('}')) else {
            return false;
        };
        let Some(name) = rest_t.get(open + 1..open + close) else {
            return false;
        };
        rest_t = rest_t.get(open + close + 1..).unwrap_or("");
        let value = match name {
            "db" => take_bracketed(rest).and_then(|(v, r)| quote_ident(&v).map(|q| (q, r))),
            "dbname" | "audit" | "session" => {
                take_literal(rest).and_then(|(v, r)| quote_literal(&v).map(|q| (q, r)))
            }
            "guid" => take_literal(rest).and_then(|(v, r)| quote_guid(&v).map(|q| (q, r))),
            "n" | "obj" => {
                let len = rest
                    .char_indices()
                    .take_while(|(i, c)| c.is_ascii_digit() || (*i == 0 && *c == '-'))
                    .count();
                (len > 0 && len <= 20).then(|| (rest[..len].to_owned(), &rest[len..]))
            }
            _ => None,
        };
        let Some((quoted, r)) = value else {
            return false;
        };
        rest = r;
        if let Some((_, prev)) = slots.iter().find(|(n, _)| n == name)
            && *prev != quoted
        {
            return false;
        }
        slots.push((name.to_owned(), quoted));
    }
    if rest != rest_t {
        return false;
    }
    // `{dbname}` names the same database as `{db}`.
    let get = |n: &str| slots.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    if let (Some(db), Some(name)) = (get("db"), get("dbname"))
        && take_bracketed(db).map(|(v, _)| v) != take_literal(name).map(|(v, _)| v)
    {
        return false;
    }
    let pairs: Vec<(&str, &str)> = slots
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    render(template, &pairs).as_deref() == Some(text)
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

/// Whether a text names `predicate` (an audit's `WHERE` filter) or
/// `event_predicate` (an Extended Events session's), which can hold
/// literals, other than as `… IS NULL` (M4).
pub(crate) fn raw_predicate(text: &str) -> bool {
    let bare = unquoted(text);
    let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '$');
    for name in ["predicate", "event_predicate"] {
        let mut from = 0;
        while let Some(i) = bare.get(from..).and_then(|r| r.find(name)) {
            let at = from + i;
            let end = at + name.len();
            let before = bare.get(..at).and_then(|b| b.chars().next_back());
            let after = bare.get(end..).unwrap_or_default();
            // A whole identifier (`sys.security_predicates` is another name).
            if !word(before) && !word(after.chars().next()) && !after.starts_with(" is null") {
                return true;
            }
            from = end;
        }
    }
    false
}

/// Whether the session may send `text`: the exact `password_hash` probe
/// (one bit, decision 4), or a text that names no denied token and no
/// raw audit predicate.
pub(crate) fn checked(text: &str) -> bool {
    text == PASSWORD_HASH_PROBE || (denied_token(text).is_none() && !raw_predicate(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog reads of case 2 (re-review): named statements, never a
    /// credit-only one, a sample, a poll or a session proof.
    #[test]
    fn catalog_reads_are_a_closed_list_of_statements() {
        for name in CATALOG_READS {
            assert!(STATEMENTS.iter().any(|(n, _)| n == name), "{name}");
            assert!(!CREDIT_ONLY.contains(name), "{name}");
        }
        for name in [
            "session_settings",
            "session_readback",
            "version",
            "sample",
            "ticket_type_counts",
            "xe_events",
            "audit_poll_start",
            "audit_poll_from",
            "xe_poll_start",
            "xe_poll_from",
        ] {
            assert!(!CATALOG_READS.contains(&name), "{name}");
        }
        assert!(catalog_text(SERVER_PERMISSIONS));
        assert!(catalog_text(&tables("retail", 16_384).unwrap()));
        assert!(!catalog_text(VERSION));
        assert!(!catalog_text(SERVER_INTERNAL[0]));
        assert!(!catalog_text("SELECT name FROM sys.objects"));
    }

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
        assert!(raw_predicate(
            "SELECT predicate FROM sys.server_file_audits"
        ));
        assert!(!raw_predicate(AUDIT_FILE));
        assert!(!raw_predicate(XE_EVENTS));
        assert!(raw_predicate(
            "SELECT e.event_predicate FROM sys.dm_xe_session_events e"
        ));
        assert!(!raw_predicate(RLS_TABLES));
        assert!(raw_predicate(
            "SELECT a.predicate FROM sys.server_file_audits a"
        ));
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
    fn own_texts_are_exact() {
        assert_eq!(own_text(VERSION), OwnText::Exact);
        assert_eq!(own_text(PASSWORD_HASH_PROBE), OwnText::Exact);
        assert_eq!(own_text(SERVER_INTERNAL[0]), OwnText::Exact);
        let db = in_database(DATABASE_GRANTS, "re]tail").unwrap();
        assert_eq!(own_text(&db), OwnText::Exact);
        // A slot holding anything else, a changed or longer text: not own.
        assert_ne!(
            own_text(&db.replace("TOP (1025)", "TOP (1026)")),
            OwnText::Exact
        );
        assert_ne!(own_text(&format!("{VERSION} ")), OwnText::Exact);
        assert_ne!(own_text(&format!("{VERSION}; SELECT 1")), OwnText::Exact);
        let other = in_database(DATABASE_PERMISSIONS, "a").unwrap().replace(
            "HAS_PERMS_BY_NAME(N'a'",
            "HAS_PERMS_BY_NAME(N'a' + (SELECT TOP 1 name FROM sys.sql_logins)",
        );
        assert_ne!(own_text(&other), OwnText::Exact);
        // `{dbname}` and `{db}` must name the same database.
        let t = tables("a", 10).unwrap().replacen("N'a'", "N'b'", 1);
        assert!(!matches_template(TABLES, &t));
        assert!(matches_template(TABLES, &tables("a]]b'c", 10).unwrap()));
        // Sampling texts need a credit.
        let sample = sample_statement("d", "s", "t", &[("c", Sampled::Text)], 5, None).unwrap();
        assert_eq!(own_text(&sample), OwnText::NeedsCredit);
        let p = audit_pattern(
            "/var/opt/mssql/audit/",
            "a'b",
            "B5BEF79B-88AC-4A47-91AE-0081BBD71D51",
        )
        .unwrap();
        assert_eq!(
            p,
            "N'/var/opt/mssql/audit/a''b_B5BEF79B-88AC-4A47-91AE-0081BBD71D51_*.sqlaudit'"
        );
        assert!(audit_pattern("/x/*", "a", "B5BEF79B-88AC-4A47-91AE-0081BBD71D51").is_none());
        assert!(audit_pattern("/x/", "a", "not-a-guid").is_none());
        for bad in ["../a", "a/b", "a\\b"] {
            assert!(audit_pattern("/x/", bad, "B5BEF79B-88AC-4A47-91AE-0081BBD71D51").is_none());
        }
        assert!(
            audit_pattern("C:\\Audit", "a", "B5BEF79B-88AC-4A47-91AE-0081BBD71D51")
                .unwrap()
                .starts_with("N'C:\\Audit\\a_")
        );
        let poll = audit_poll(&p, true).unwrap();
        assert!(checked(&poll));
        assert!(poll.contains("@p1, @p2) ORDER BY (SELECT NULL) OFFSET @p4 ROWS"));
        assert!(poll.contains("FETCH NEXT @p3 ROWS ONLY"));
        assert_eq!(own_text(&poll), OwnText::NeedsCredit);
        // Extended Events: the session reads are exact own texts, the
        // status read an exempt listed read; polls need a credit.
        let session = render(XE_SESSION, &[("session", &quote_literal("x'e").unwrap())]).unwrap();
        assert_eq!(own_text(&session), OwnText::Exact);
        assert!(own_listed_read(&session) && own_listed_read(PASSWORD_HASH_PROBE));
        assert!(!own_listed_read(&session.replace("TOP (2)", "TOP (3)")));
        let events = render(XE_EVENTS, &[("session", "N'x'")]).unwrap();
        assert_eq!(own_text(&events), OwnText::Exact);
        let p = xe_pattern("/var/opt/mssql/xe/databastion_xe_0_134365650237540000.xel").unwrap();
        assert_eq!(p, "N'/var/opt/mssql/xe/databastion_xe_0_*.xel'");
        let poll = xe_poll(&p, true).unwrap();
        assert!(checked(&poll) && poll.contains("NULL, @p1, @p2) f"));
        assert_eq!(poll.matches("SUBSTRING(x.b, ").count(), XE_SLICES);
        assert!(poll.contains(&format!(
            "SUBSTRING(x.b, {}, 8000)",
            (XE_SLICES - 1) * 8000 + 1
        )));
        assert!(poll.ends_with("OPTION (MAXDOP 1)"));
        const { assert!(XE_SLICES * 8000 >= XE_EVENT_BYTES) };
        assert_eq!(own_text(&poll), OwnText::NeedsCredit);
        assert_eq!(
            xe_pattern("C:\\XE\\o'x_0_1.xel").unwrap(),
            "N'C:\\XE\\o''x_0_*.xel'"
        );
        for bad in [
            "/x/a.xel",
            "/x/a_0_1.txt",
            "a_0_1.xel",
            "/x/*_0_1.xel",
            "/x/a_b_1.xel",
            "/x/_0_1.xel",
        ] {
            assert!(xe_pattern(bad).is_none(), "{bad}");
        }
        assert_eq!(
            xe_file_key("/x/databastion_xe_0_134365650237540000.xel"),
            Some((134_365_650_237_540_000, 0))
        );
        assert!(xe_file_key("/x/a.xel").is_none());
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
