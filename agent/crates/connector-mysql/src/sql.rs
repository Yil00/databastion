//! SQL text of the connector.
//!
//! - One statement per `COM_QUERY` (the connection never enables
//!   multi-statements); no user-defined function, procedure or view is
//!   ever called: catalog reads go to `information_schema` /
//!   `performance_schema`, sampling reads base tables by column name.
//! - Identifiers come from `information_schema` and are quoted by
//!   [`quote_ident`] (backticks, doubled); the few string literals (a
//!   schema and table name in the column query) by [`quote_str`], which
//!   relies on `NO_BACKSLASH_ESCAPES`, pinned and verified at connection
//!   (`conn`). Job parameters never reach SQL text: filters are applied in
//!   Rust on catalog names.
//! - The only functions applied to a sampled column are the built-in
//!   `LEFT()` (text bounded on the server) in sampling statements; a
//!   built-in name followed directly by `(` cannot resolve to a stored
//!   function (`IGNORE_SPACE` is not in the pinned `sql_mode`).
//! - System schemas (`mysql`, `sys`, `information_schema`,
//!   `performance_schema`) are never sampled; the `mysql` system tables
//!   (password hashes in `mysql.user`, `mysql.global_priv`) are never read
//!   by any statement (checked by a unit test).

use crate::conn::Flavor;

/// Quotes an identifier: wrapped in backticks, every backtick doubled.
/// `None` for a name MySQL cannot hold (empty, NUL).
#[must_use]
pub(crate) fn quote_ident(name: &str) -> Option<String> {
    if name.is_empty() || name.contains('\0') {
        return None;
    }
    let mut out = String::with_capacity(name.len() + 2);
    out.push('`');
    for c in name.chars() {
        if c == '`' {
            out.push('`');
        }
        out.push(c);
    }
    out.push('`');
    Some(out)
}

/// Quotes a string literal for a session with `NO_BACKSLASH_ESCAPES`
/// (verified at connection): wrapped in `'`, every `'` doubled. `None`
/// for a string with a NUL.
#[must_use]
pub(crate) fn quote_str(value: &str) -> Option<String> {
    if value.contains('\0') {
        return None;
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        if c == '\'' {
            out.push('\'');
        }
        out.push(c);
    }
    out.push('\'');
    Some(out)
}

/// The pinned `sql_mode`: strict, no engine substitution, and
/// `NO_BACKSLASH_ESCAPES` so that [`quote_str`] is complete. Never
/// `ANSI_QUOTES` (identifiers are backquoted) nor `IGNORE_SPACE`.
pub(crate) const SQL_MODE: &str = "STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,NO_BACKSLASH_ESCAPES";

/// Server-side idle and network timeouts of every session, in seconds:
/// `wait_timeout` (idle session closed by the server; the connector
/// reconnects after [`crate::conn::STALE_AFTER`]), `net_read_timeout` /
/// `net_write_timeout` (a client that stops reading a result, e.g.
/// paused, is dropped), `lock_wait_timeout` (metadata locks) and
/// `innodb_lock_wait_timeout`.
pub(crate) const WAIT_TIMEOUT_S: u32 = 60;
pub(crate) const NET_TIMEOUT_S: u32 = 30;
pub(crate) const LOCK_WAIT_TIMEOUT_S: u32 = 2;
/// MariaDB `idle_transaction_timeout` / `idle_readonly_transaction_timeout`:
/// a transaction left open is aborted by the server (the connector never
/// idles inside one).
pub(crate) const IDLE_TRANSACTION_TIMEOUT_S: u32 = 10;

/// Session settings, once per connection: `sql_mode`, character set,
/// autocommit, idle / network / lock timeouts and the statement timeout
/// (`max_execution_time` in ms on MySQL, `max_statement_time` in seconds on
/// MariaDB; never `0`).
#[must_use]
pub(crate) fn session_setup(flavor: Flavor, statement_ms: u32) -> String {
    let mut s = format!(
        "SET SESSION sql_mode = '{SQL_MODE}', \
         SESSION character_set_client = 'utf8mb4', \
         SESSION character_set_connection = 'utf8mb4', \
         SESSION character_set_results = 'utf8mb4', \
         SESSION collation_connection = 'utf8mb4_general_ci', \
         SESSION autocommit = 1, \
         SESSION wait_timeout = {WAIT_TIMEOUT_S}, \
         SESSION net_read_timeout = {NET_TIMEOUT_S}, \
         SESSION net_write_timeout = {NET_TIMEOUT_S}, \
         SESSION lock_wait_timeout = {LOCK_WAIT_TIMEOUT_S}, \
         SESSION innodb_lock_wait_timeout = {LOCK_WAIT_TIMEOUT_S}, "
    );
    match flavor {
        Flavor::Mysql => s.push_str(&set_statement_timeout_expr(flavor, statement_ms)),
        Flavor::Mariadb => {
            s.push_str(&set_statement_timeout_expr(flavor, statement_ms));
            s.push_str(&format!(
                ", SESSION idle_transaction_timeout = {IDLE_TRANSACTION_TIMEOUT_S}, \
                 SESSION idle_readonly_transaction_timeout = {IDLE_TRANSACTION_TIMEOUT_S}"
            ));
        }
    }
    s
}

/// `SESSION max_execution_time = <ms>` (MySQL) or `SESSION
/// max_statement_time = <s>` (MariaDB). `statement_ms` is at least 100.
fn set_statement_timeout_expr(flavor: Flavor, statement_ms: u32) -> String {
    let ms = statement_ms.max(100);
    match flavor {
        Flavor::Mysql => format!("SESSION max_execution_time = {ms}"),
        Flavor::Mariadb => format!(
            "SESSION max_statement_time = {}.{:03}",
            ms / 1000,
            ms % 1000
        ),
    }
}

/// Re-asserts the statement timeout of the session (at every transaction).
#[must_use]
pub(crate) fn set_statement_timeout(flavor: Flavor, statement_ms: u32) -> String {
    format!("SET {}", set_statement_timeout_expr(flavor, statement_ms))
}

/// Session default for every transaction and autocommit statement:
/// `READ ONLY`, `READ COMMITTED` (no long snapshot; distinguishable from
/// `mysqldump`'s consistent snapshot).
pub(crate) const SESSION_READ_ONLY: &str =
    "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY";

/// Reads back the session settings (guard). Columns: connection id,
/// statement timeout, read-only default, `sql_mode`, results character
/// set, `wait_timeout`, version.
#[must_use]
pub(crate) fn session_check(flavor: Flavor, tx_read_only_var: &str) -> String {
    let timeout = match flavor {
        Flavor::Mysql => "@@session.max_execution_time",
        Flavor::Mariadb => "@@session.max_statement_time",
    };
    format!(
        "SELECT CONNECTION_ID(), {timeout}, @@session.{tx_read_only_var}, @@session.sql_mode, \
         @@session.character_set_results, @@session.wait_timeout, @@version"
    )
}

/// Every unit of work.
pub(crate) const BEGIN: &str = "START TRANSACTION READ ONLY";
pub(crate) const COMMIT: &str = "COMMIT";
pub(crate) const ROLLBACK: &str = "ROLLBACK";

/// Kills the running statement of one of the agent's own sessions (any
/// account may kill its own threads).
#[must_use]
pub(crate) fn kill_query(connection_id: u32) -> String {
    format!("KILL QUERY {connection_id}")
}

/// System schemas, never sampled (compared case-insensitively).
pub(crate) const SYSTEM_SCHEMAS: [&str; 4] =
    ["mysql", "sys", "information_schema", "performance_schema"];

/// Most tables introspected per scan.
pub(crate) const MAX_TABLES: u32 = 100_000;
/// Most columns read per table.
pub(crate) const MAX_COLUMNS: u32 = 4096;

/// Tables, views and their engines outside the system schemas, as seen
/// by the account (`information_schema` lists only objects the account has
/// a privilege on). Columns: schema, name, type, engine.
///
/// No statistics column (`TABLE_ROWS`, `DATA_LENGTH`…): computing them
/// opens the table's handler, and a `FEDERATED` handler then connects to
/// its remote server (verified on MySQL 8.4, I5). Row estimates are read
/// per sampled table by [`table_rows`], once [`table_engine`] showed a local
/// engine.
pub(crate) const INTROSPECT: &str = "SELECT t.TABLE_SCHEMA, t.TABLE_NAME, t.TABLE_TYPE, t.ENGINE \
     FROM information_schema.TABLES t \
     WHERE LOWER(t.TABLE_SCHEMA) NOT IN \
       ('mysql', 'sys', 'information_schema', 'performance_schema') \
     ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME \
     LIMIT 100000";

/// Type and engine of one table (no statistics column: see
/// [`INTROSPECT`]). Columns: type, engine.
#[must_use]
pub(crate) fn table_engine(schema: &str, table: &str) -> Option<String> {
    Some(format!(
        "SELECT t.TABLE_TYPE, t.ENGINE FROM information_schema.TABLES t \
         WHERE t.TABLE_SCHEMA = {} AND t.TABLE_NAME = {}",
        quote_str(schema)?,
        quote_str(table)?
    ))
}

/// Estimated rows of one table. Computing `TABLE_ROWS` opens the table's
/// handler (MariaDB does so before applying any `ENGINE` filter): only
/// sent for a table whose engine [`table_engine`] showed to be local.
#[must_use]
pub(crate) fn table_rows(schema: &str, table: &str) -> Option<String> {
    Some(format!(
        "SELECT t.TABLE_ROWS FROM information_schema.TABLES t \
         WHERE t.TABLE_SCHEMA = {} AND t.TABLE_NAME = {}",
        quote_str(schema)?,
        quote_str(table)?
    ))
}

/// Columns of one table. Columns: name, data type, extra (generated
/// column kind), the account's privileges on the column.
#[must_use]
pub(crate) fn columns(schema: &str, table: &str) -> Option<String> {
    Some(format!(
        "SELECT c.COLUMN_NAME, c.DATA_TYPE, c.EXTRA, c.PRIVILEGES \
         FROM information_schema.COLUMNS c \
         WHERE c.TABLE_SCHEMA = {} AND c.TABLE_NAME = {} \
         ORDER BY c.ORDINAL_POSITION \
         LIMIT {MAX_COLUMNS}",
        quote_str(schema)?,
        quote_str(table)?
    ))
}

/// How a sampled column is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sampled {
    /// Text (`char`, `varchar`, `*text`, `json`): `LEFT(col, 4096)`, so the
    /// server never sends more than 4096 characters of a value.
    Text,
    /// Numbers and dates, sent as short text by the protocol.
    Plain,
}

/// Longest text sampled per value, in characters (server side); values
/// are then cut to 4096 bytes in Rust.
pub(crate) const MAX_VALUE_CHARS: u32 = 4096;

/// Builds the sampling statement of one table: columns by name, `LIMIT`,
/// and a per-statement timeout (MySQL optimizer hint
/// `MAX_EXECUTION_TIME`, MariaDB `SET STATEMENT max_statement_time`) on
/// top of the session value.
///
/// No `ORDER BY RAND()` (a full scan and sort of the table): the first
/// `limit` rows in the engine's order, bounded and cheap.
#[must_use]
pub(crate) fn sample_statement(
    flavor: Flavor,
    statement_ms: u32,
    schema: &str,
    table: &str,
    columns: &[(&str, Sampled)],
    limit: u32,
) -> Option<String> {
    if columns.is_empty() || limit == 0 {
        return None;
    }
    let mut list = Vec::with_capacity(columns.len());
    for (name, kind) in columns {
        let q = quote_ident(name)?;
        list.push(match kind {
            Sampled::Text => format!("LEFT({q}, {MAX_VALUE_CHARS})"),
            Sampled::Plain => q,
        });
    }
    let from = format!("{}.{}", quote_ident(schema)?, quote_ident(table)?);
    let ms = statement_ms.max(100);
    Some(match flavor {
        Flavor::Mysql => format!(
            "SELECT /*+ MAX_EXECUTION_TIME({ms}) */ {} FROM {from} LIMIT {limit}",
            list.join(", ")
        ),
        Flavor::Mariadb => format!(
            "SET STATEMENT max_statement_time = {}.{:03} FOR SELECT {} FROM {from} LIMIT {limit}",
            ms / 1000,
            ms % 1000,
            list.join(", ")
        ),
    })
}

// ------------------------------------------------------------ CAS guard

/// The CAS store guard's only read of a ticket registry (ADR-0041
/// decision 5): the ticket count per `type` (cut to 256 characters),
/// nothing else, under the per-statement timeout of [`sample_statement`].
#[must_use]
pub(crate) fn ticket_type_counts(
    flavor: Flavor,
    statement_ms: u32,
    schema: &str,
    table: &str,
    column: &str,
) -> Option<String> {
    let c = quote_ident(column)?;
    let from = format!("{}.{}", quote_ident(schema)?, quote_ident(table)?);
    let select =
        format!("SELECT LEFT(CAST({c} AS CHAR), 256), COUNT(*) FROM {from} GROUP BY 1 LIMIT 256");
    let ms = statement_ms.max(100);
    Some(match flavor {
        Flavor::Mysql => select.replacen(
            "SELECT",
            &format!("SELECT /*+ MAX_EXECUTION_TIME({ms}) */"),
            1,
        ),
        Flavor::Mariadb => format!(
            "SET STATEMENT max_statement_time = {}.{:03} FOR {select}",
            ms / 1000,
            ms % 1000
        ),
    })
}

/// `check()` of the CAS store guard, at every heartbeat (ADR-0041
/// decision 6): the columns the account can see (`information_schema`
/// lists those it holds a privilege on, directly, through its enabled
/// roles or `PUBLIC`) of the tables that may be CAS stores: a name key in
/// `keys` (letters and digits, lower-cased), or a `body` / `json` /
/// `AUD_RESOURCE` column. Columns: schema, table, column, privileges.
/// `None` when a key cannot be quoted.
#[must_use]
pub(crate) fn cas_guard_columns(keys: &[String]) -> Option<String> {
    let mut list = Vec::with_capacity(keys.len());
    for k in keys {
        list.push(quote_str(k)?);
    }
    if list.is_empty() {
        list.push("''".to_owned());
    }
    Some(format!(
        "SELECT c.TABLE_SCHEMA, c.TABLE_NAME, c.COLUMN_NAME, c.PRIVILEGES \
         FROM information_schema.COLUMNS c \
         WHERE LOWER(c.TABLE_SCHEMA) NOT IN \
           ('mysql', 'sys', 'information_schema', 'performance_schema') \
           AND (REGEXP_REPLACE(LOWER(c.TABLE_NAME), '[^a-z0-9]', '') IN ({}) \
             OR (c.TABLE_SCHEMA, c.TABLE_NAME) IN ( \
               SELECT x.TABLE_SCHEMA, x.TABLE_NAME FROM information_schema.COLUMNS x \
               WHERE LOWER(x.COLUMN_NAME) IN ('body', 'json', 'aud_resource', 'audresource'))) \
         ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION \
         LIMIT 20000",
        list.join(", ")
    ))
}

// ------------------------------------------------------------------ check()

/// The current account as it appears in the `GRANTEE` column of the
/// `information_schema` privilege tables (`'user'@'host'`), built from
/// `CURRENT_USER()` on the server (no literal from the agent).
macro_rules! grantee {
    () => {
        "(SELECT CONCAT('''', SUBSTRING(u.cu, 1, CHAR_LENGTH(u.cu) \
              - CHAR_LENGTH(SUBSTRING_INDEX(u.cu, '@', -1)) - 1), \
              '''@''', SUBSTRING_INDEX(u.cu, '@', -1), '''') \
          FROM (SELECT CURRENT_USER() AS cu) u)"
    };
}

/// `CURRENT_USER()` (to detect names the grantee expression cannot
/// match, e.g. with a quote).
pub(crate) const CURRENT_USER: &str = "SELECT CURRENT_USER()";

/// Global privileges of the account. Columns: privilege, grantable.
pub(crate) const USER_PRIVILEGES: &str = concat!(
    "SELECT p.PRIVILEGE_TYPE, p.IS_GRANTABLE FROM information_schema.USER_PRIVILEGES p \
     WHERE p.GRANTEE = ",
    grantee!(),
    " LIMIT 1000"
);

/// Database-level privileges. Columns: schema, privilege, grantable.
pub(crate) const SCHEMA_PRIVILEGES: &str = concat!(
    "SELECT p.TABLE_SCHEMA, p.PRIVILEGE_TYPE, p.IS_GRANTABLE \
     FROM information_schema.SCHEMA_PRIVILEGES p WHERE p.GRANTEE = ",
    grantee!(),
    " LIMIT 10000"
);

/// Table-level privileges. Columns: schema, privilege, grantable.
pub(crate) const TABLE_PRIVILEGES: &str = concat!(
    "SELECT p.TABLE_SCHEMA, p.PRIVILEGE_TYPE, p.IS_GRANTABLE \
     FROM information_schema.TABLE_PRIVILEGES p WHERE p.GRANTEE = ",
    grantee!(),
    " LIMIT 100000"
);

/// Column-level privileges. Columns: schema, privilege, grantable.
pub(crate) const COLUMN_PRIVILEGES: &str = concat!(
    "SELECT p.TABLE_SCHEMA, p.PRIVILEGE_TYPE, p.IS_GRANTABLE \
     FROM information_schema.COLUMN_PRIVILEGES p WHERE p.GRANTEE = ",
    grantee!(),
    " LIMIT 100000"
);

/// Roles applicable to the account, MySQL 8.0.19+ (granted directly,
/// through another role, or mandatory). Columns: role name, role host,
/// grantable (`WITH ADMIN OPTION`), mandatory, granted to the account
/// itself (`1`) rather than to one of its roles.
pub(crate) const APPLICABLE_ROLES_MYSQL: &str = "SELECT r.ROLE_NAME, r.ROLE_HOST, r.IS_GRANTABLE, \
     r.IS_MANDATORY, r.GRANTEE = r.USER AND r.GRANTEE_HOST = r.HOST \
     FROM information_schema.APPLICABLE_ROLES r LIMIT 1001";

/// Roles applicable to the account, MariaDB (granted directly or through
/// another role, the default role included). Columns: role name,
/// grantable (`WITH ADMIN OPTION`).
pub(crate) const APPLICABLE_ROLES_MARIADB: &str =
    "SELECT r.ROLE_NAME, r.IS_GRANTABLE FROM information_schema.APPLICABLE_ROLES r LIMIT 1001";

/// Rows of `APPLICABLE_ROLES_*` read at most: the statements ask for one
/// more, and more rows than this means the list is cut (every role is
/// then reported as not evaluated).
pub(crate) const MAX_ROLE_ROWS: usize = 1000;

/// Whether a role name or host from `APPLICABLE_ROLES` may be written into
/// a statement: a short allow-listed charset, on top of the quoting, so a
/// name chosen by whoever administers the server cannot shape the SQL text.
fn role_part_ok(part: &str, may_be_empty: bool) -> bool {
    (may_be_empty || !part.is_empty())
        && part.len() <= 255
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_$.%-:/".contains(&b))
}

/// MySQL: the privileges of the account and of `roles` (`(name, host)`,
/// the roles granted to it directly or mandatory; the server expands the
/// roles they grant). `SHOW GRANTS` about the current user needs no
/// privilege. `None` for an empty list or a name outside the allow-list.
pub(crate) fn show_grants_using(roles: &[(String, String)]) -> Option<String> {
    if roles.is_empty() {
        return None;
    }
    let mut out = String::from("SHOW GRANTS FOR CURRENT_USER() USING ");
    for (i, (name, host)) in roles.iter().enumerate() {
        if !role_part_ok(name, false) || !role_part_ok(host, true) {
            return None;
        }
        if i > 0 {
            out.push_str(", ");
        }
        // `'name'@'host'`: the account-name form of the MySQL manual
        // ("Specifying Account Names"); an empty host is `''` (a quoted
        // identifier cannot be empty).
        out.push_str(&quote_str(name)?);
        out.push('@');
        out.push_str(&quote_str(host)?);
    }
    Some(out)
}

/// MariaDB: the role enabled in the session (the default role at login),
/// or NULL.
pub(crate) const CURRENT_ROLE: &str = "SELECT CURRENT_ROLE()";

/// The account's own grants, role grant lines included (both servers),
/// read when `APPLICABLE_ROLES` cannot be (MySQL before 8.0.19, or an
/// error): the roles are counted, their privileges not evaluated.
pub(crate) const SHOW_GRANTS_OWN: &str = "SHOW GRANTS FOR CURRENT_USER()";

/// MySQL: the roles every account holds (`mandatory_roles`, 8.0.2 and
/// later; no privilege needed). Only whether it is empty and how many
/// roles it names are used.
pub(crate) const MANDATORY_ROLES: &str = "SELECT @@GLOBAL.mandatory_roles";

/// MariaDB: the privileges of the role enabled in the session. MariaDB
/// shows a role's grants without `SELECT` on the `mysql` database only for
/// the session's current role (`SHOW GRANTS FOR <other role>` is refused),
/// and `SET ROLE` is not used (it would enable the role's privileges, write
/// privileges included, on the agent's session).
pub(crate) const SHOW_GRANTS_CURRENT_ROLE: &str = "SHOW GRANTS FOR CURRENT_ROLE";

/// MariaDB 10.11 and later: the privileges granted to `PUBLIC`, which every
/// account holds and `APPLICABLE_ROLES` does not list. MariaDB shows them
/// without `SELECT` on the `mysql` database.
pub(crate) const SHOW_GRANTS_PUBLIC: &str = "SHOW GRANTS FOR PUBLIC";

/// Whether `init_connect` is set (SQL run at every login of an account
/// without `SUPER` / `CONNECTION_ADMIN`: user code at connection). The text
/// itself is not read.
pub(crate) const INIT_CONNECT: &str = "SELECT CHAR_LENGTH(@@GLOBAL.init_connect) > 0";

/// Audit plugins. Columns: name, status.
pub(crate) const AUDIT_PLUGINS: &str = "SELECT p.PLUGIN_NAME, p.PLUGIN_STATUS \
     FROM information_schema.PLUGINS p \
     WHERE p.PLUGIN_NAME IN ('SERVER_AUDIT', 'audit_log', 'audit_log_filter')";

/// MariaDB `server_audit` settings (only when the plugin is active: the
/// variables do not exist otherwise). The log path is not read.
pub(crate) const SERVER_AUDIT_SETTINGS: &str = "SELECT @@GLOBAL.server_audit_logging, \
     @@GLOBAL.server_audit_output_type, @@GLOBAL.server_audit_events";

/// Percona `audit_log` plugin settings (only when it is active). The log
/// path is not read.
pub(crate) const AUDIT_LOG_SETTINGS: &str =
    "SELECT @@GLOBAL.audit_log_format, @@GLOBAL.audit_log_policy";

/// Format of the `audit_log_filter` component (an error when it is not
/// installed: the variable does not exist).
pub(crate) const AUDIT_LOG_FILTER_FORMAT: &str = "SELECT @@GLOBAL.audit_log_filter.format";

/// MariaDB `server_audit_query_log_limit`: statement texts are cut there.
pub(crate) const SERVER_AUDIT_QUERY_LIMIT: &str = "SELECT @@GLOBAL.server_audit_query_log_limit";

/// Seconds the server's system time zone is ahead of UTC now
/// (`server_audit` writes local times).
pub(crate) const SYSTEM_UTC_OFFSET: &str = "SELECT TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), \
     CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', 'SYSTEM'))";

/// The account and the client host as the server sees this session
/// (`user@host`; no privilege needed).
pub(crate) const SESSION_USER: &str = "SELECT USER()";

/// `performance_schema` enabled, and the general log (noted only).
pub(crate) const PS_ENABLED: &str =
    "SELECT @@GLOBAL.performance_schema, @@GLOBAL.general_log, @@GLOBAL.log_output";

/// Statement consumers. Columns: name, enabled.
pub(crate) const PS_CONSUMERS: &str = "SELECT c.NAME, c.ENABLED \
     FROM performance_schema.setup_consumers c \
     WHERE c.NAME IN ('events_statements_history_long', 'events_statements_history', \
                      'events_statements_current', 'global_instrumentation', \
                      'thread_instrumentation')";

/// Readability of the statement history (a count: no statement text).
pub(crate) const PS_HISTORY_LONG: &str =
    "SELECT COUNT(*) FROM performance_schema.events_statements_history_long";
pub(crate) const PS_HISTORY: &str =
    "SELECT COUNT(*) FROM performance_schema.events_statements_history";
pub(crate) const PS_CURRENT: &str =
    "SELECT COUNT(*) FROM performance_schema.events_statements_current";

/// Thread id of this session in `performance_schema` (Audit).
pub(crate) const PS_OWN_THREAD: &str = "SELECT t.THREAD_ID FROM performance_schema.threads t \
     WHERE t.PROCESSLIST_ID = CONNECTION_ID()";

/// Seconds since the server started (`SHOW GLOBAL STATUS` needs no
/// privilege). With the agent's clock it gives the server's start time,
/// which tells a persisted `performance_schema` cursor (timers count from
/// the server start) from one of an earlier server run.
pub(crate) const SERVER_UPTIME: &str = "SHOW GLOBAL STATUS LIKE 'Uptime'";

/// Text limits of `performance_schema` (statement text, digest text).
pub(crate) const PS_TEXT_LIMIT: &str = "SELECT @@GLOBAL.performance_schema_max_sql_text_length";
pub(crate) const PS_DIGEST_LIMIT: &str = "SELECT @@GLOBAL.performance_schema_max_digest_length";

/// Timers of an Audit poll: this session's current statement start (the
/// timer's "now") and the oldest and newest end in the polled table. No
/// text. `table` is one of the three statement tables (`PsTable`).
#[must_use]
pub(crate) fn ps_stats(table: &str, own_thread: u64) -> String {
    format!(
        "SELECT (SELECT c.TIMER_START FROM performance_schema.events_statements_current c \
                 WHERE c.THREAD_ID = {own_thread} ORDER BY c.EVENT_ID DESC LIMIT 1), \
                MIN(h.TIMER_END), MAX(h.TIMER_END) FROM performance_schema.{table} h"
    )
}

/// The Audit poll of `performance_schema` statements (the only statement
/// that reads statement text, ADR-0018): `DIGEST_TEXT`, and `SQL_TEXT` only
/// for a statement without a digest; with the session's account, host,
/// type and `program_name` while it is connected. Rows are ordered by end
/// timer from `from`, this session's own thread excluded, at most `limit`.
/// `table` is one of the three statement tables (`PsTable`).
#[must_use]
pub(crate) fn ps_statements(
    table: &str,
    own_thread: u64,
    from: u64,
    limit: usize,
    with_program: bool,
) -> String {
    let program = if with_program {
        "(SELECT a.ATTR_VALUE FROM performance_schema.session_connect_attrs a \
          WHERE a.PROCESSLIST_ID = t.PROCESSLIST_ID AND a.ATTR_NAME = 'program_name' LIMIT 1)"
    } else {
        "NULL"
    };
    format!(
        "SELECT h.THREAD_ID, h.EVENT_ID, h.TIMER_END, h.CURRENT_SCHEMA, h.DIGEST_TEXT, \
         CASE WHEN h.DIGEST_TEXT IS NULL THEN h.SQL_TEXT END, h.ROWS_SENT, h.ROWS_AFFECTED, \
         h.MYSQL_ERRNO, t.PROCESSLIST_USER, t.PROCESSLIST_HOST, t.TYPE, {program} \
         FROM performance_schema.{table} h \
         LEFT JOIN performance_schema.threads t ON t.THREAD_ID = h.THREAD_ID \
         WHERE h.TIMER_END >= {from} AND h.END_EVENT_ID IS NOT NULL \
           AND h.THREAD_ID <> {own_thread} \
         ORDER BY h.TIMER_END, h.THREAD_ID, h.EVENT_ID LIMIT {limit}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_backquoted_and_backquotes_doubled() {
        assert_eq!(quote_ident("customers").unwrap(), "`customers`");
        assert_eq!(quote_ident("a`b").unwrap(), "`a``b`");
        assert_eq!(
            quote_ident("x`; DROP TABLE t; --").unwrap(),
            "`x``; DROP TABLE t; --`"
        );
        assert_eq!(quote_ident("Été 2024").unwrap(), "`Été 2024`");
        assert_eq!(quote_ident("a\"b'c").unwrap(), "`a\"b'c`");
        assert!(quote_ident("").is_none());
        assert!(quote_ident("a\0b").is_none());
    }

    #[test]
    fn string_literals_double_quotes() {
        assert_eq!(quote_str("hr").unwrap(), "'hr'");
        assert_eq!(quote_str("o'neil").unwrap(), "'o''neil'");
        // Backslashes are literal under NO_BACKSLASH_ESCAPES.
        assert_eq!(quote_str("a\\'b").unwrap(), "'a\\''b'");
        assert!(quote_str("a\0").is_none());
        assert!(SQL_MODE.contains("NO_BACKSLASH_ESCAPES"));
        assert!(!SQL_MODE.contains("ANSI_QUOTES") && !SQL_MODE.contains("IGNORE_SPACE"));
    }

    #[test]
    fn sample_statement_reads_only_the_named_table() {
        let s = sample_statement(
            Flavor::Mysql,
            30_000,
            "hr",
            "employees",
            &[("email", Sampled::Text), ("a`b", Sampled::Plain)],
            200,
        )
        .unwrap();
        assert_eq!(
            s,
            "SELECT /*+ MAX_EXECUTION_TIME(30000) */ LEFT(`email`, 4096), `a``b` \
             FROM `hr`.`employees` LIMIT 200"
        );
        let s = sample_statement(
            Flavor::Mariadb,
            1500,
            "support",
            "t",
            &[("c", Sampled::Plain)],
            5,
        )
        .unwrap();
        assert_eq!(
            s,
            "SET STATEMENT max_statement_time = 1.500 FOR SELECT `c` FROM `support`.`t` LIMIT 5"
        );
        assert!(sample_statement(Flavor::Mysql, 1, "s", "t", &[], 5).is_none());
        assert!(
            sample_statement(Flavor::Mysql, 1, "s", "t", &[("c", Sampled::Plain)], 0).is_none()
        );
        // The statement timeout is never 0.
        let s = sample_statement(Flavor::Mysql, 0, "s", "t", &[("c", Sampled::Plain)], 1).unwrap();
        assert!(s.contains("MAX_EXECUTION_TIME(100)"), "{s}");
    }

    #[test]
    fn introspection_reads_no_statistics() {
        // Statistics open the handler: a FEDERATED table connects out.
        for column in [
            "TABLE_ROWS",
            "DATA_LENGTH",
            "AVG_ROW_LENGTH",
            "UPDATE_TIME",
            "CHECKSUM",
        ] {
            assert!(!INTROSPECT.contains(column), "{column}");
        }
        assert!(!table_engine("hr", "t").unwrap().contains("TABLE_ROWS"));
    }

    #[test]
    fn statement_timeouts_are_never_zero() {
        assert!(session_setup(Flavor::Mysql, 0).contains("max_execution_time = 100"));
        assert!(session_setup(Flavor::Mariadb, 0).contains("max_statement_time = 0.100"));
        assert!(session_setup(Flavor::Mariadb, 30_000).contains("max_statement_time = 30.000"));
        assert!(session_setup(Flavor::Mariadb, 1).contains("idle_readonly_transaction_timeout"));
        assert_eq!(
            set_statement_timeout(Flavor::Mysql, 2500),
            "SET SESSION max_execution_time = 2500"
        );
    }

    fn all_statements() -> Vec<String> {
        let mut v = vec![
            session_setup(Flavor::Mysql, 1000),
            session_setup(Flavor::Mariadb, 1000),
            SESSION_READ_ONLY.to_owned(),
            session_check(Flavor::Mysql, "transaction_read_only"),
            session_check(Flavor::Mariadb, "tx_read_only"),
            BEGIN.to_owned(),
            COMMIT.to_owned(),
            ROLLBACK.to_owned(),
            kill_query(42),
            INTROSPECT.to_owned(),
            columns("hr", "employees").unwrap(),
            table_engine("hr", "employees").unwrap(),
            table_rows("hr", "employees").unwrap(),
            CURRENT_USER.to_owned(),
            USER_PRIVILEGES.to_owned(),
            SCHEMA_PRIVILEGES.to_owned(),
            TABLE_PRIVILEGES.to_owned(),
            COLUMN_PRIVILEGES.to_owned(),
            APPLICABLE_ROLES_MYSQL.to_owned(),
            APPLICABLE_ROLES_MARIADB.to_owned(),
            show_grants_using(&[("app_read".to_owned(), "%".to_owned())]).unwrap(),
            CURRENT_ROLE.to_owned(),
            SHOW_GRANTS_CURRENT_ROLE.to_owned(),
            SHOW_GRANTS_PUBLIC.to_owned(),
            SHOW_GRANTS_OWN.to_owned(),
            MANDATORY_ROLES.to_owned(),
            INIT_CONNECT.to_owned(),
            AUDIT_PLUGINS.to_owned(),
            SERVER_AUDIT_SETTINGS.to_owned(),
            PS_ENABLED.to_owned(),
            PS_CONSUMERS.to_owned(),
            PS_HISTORY_LONG.to_owned(),
            PS_HISTORY.to_owned(),
            PS_CURRENT.to_owned(),
            AUDIT_LOG_SETTINGS.to_owned(),
            AUDIT_LOG_FILTER_FORMAT.to_owned(),
            SERVER_AUDIT_QUERY_LIMIT.to_owned(),
            SYSTEM_UTC_OFFSET.to_owned(),
            SESSION_USER.to_owned(),
            PS_TEXT_LIMIT.to_owned(),
            PS_DIGEST_LIMIT.to_owned(),
            SERVER_UPTIME.to_owned(),
            ps_stats("events_statements_history_long", 7),
            cas_guard_columns(&["castickets".to_owned(), "comaudittrail".to_owned()]).unwrap(),
        ];
        for flavor in [Flavor::Mysql, Flavor::Mariadb] {
            v.push(set_statement_timeout(flavor, 1000));
            v.push(sample_statement(flavor, 1000, "s", "t", &[("c", Sampled::Text)], 10).unwrap());
            v.push(ticket_type_counts(flavor, 1000, "s", "t", "type").unwrap());
        }
        v
    }

    #[test]
    fn no_statement_reads_system_tables_or_runs_user_code() {
        let denied = [
            "mysql.",
            "`mysql`",
            "global_priv",
            "authentication_string",
            "password",
            "general_log",
            "slow_log",
            "into outfile",
            "into dumpfile",
            "load_file",
            "load data",
            "call ",
            "handler ",
            "events_statements_history_long.sql_text",
            "sql_text",
            "digest_text",
            "processlist",
            "session_connect_attrs",
        ];
        for s in all_statements() {
            let lower = s.to_lowercase();
            for d in denied {
                // `@@GLOBAL.general_log` (a boolean setting) is allowed.
                if d == "general_log" && lower.contains("@@global.general_log") {
                    continue;
                }
                // A length setting, not the statement text.
                if d == "sql_text"
                    && lower == "select @@global.performance_schema_max_sql_text_length"
                {
                    continue;
                }
                assert!(!lower.contains(d), "{d} in {s}");
            }
        }
    }

    #[test]
    fn the_audit_poll_reads_text_only_through_the_digest() {
        for with_program in [true, false] {
            let s = ps_statements("events_statements_history_long", 7, 0, 10, with_program);
            let lower = s.to_lowercase();
            // SQL_TEXT only when there is no digest; never the text of a
            // running statement of another session (PROCESSLIST_INFO), the
            // processlist, or another attribute than program_name.
            assert_eq!(lower.matches("sql_text").count(), 1, "{s}");
            assert!(
                lower.contains("case when h.digest_text is null then h.sql_text end"),
                "{s}"
            );
            for d in [
                "processlist_info",
                "information_schema.processlist",
                "mysql.",
                "into outfile",
                "call ",
                ";",
            ] {
                assert!(!lower.contains(d), "{d} in {s}");
            }
            assert_eq!(
                lower.matches("session_connect_attrs").count(),
                usize::from(with_program)
            );
            if with_program {
                assert!(lower.contains("a.attr_name = 'program_name'"));
            }
            assert!(lower.contains("h.thread_id <> 7"), "{s}");
        }
    }

    #[test]
    fn statements_are_single_and_never_read_write() {
        for s in all_statements() {
            assert!(!s.contains(';'), "multi-statement: {s}");
            let upper = s.to_uppercase();
            assert!(!upper.contains("READ WRITE"), "{s}");
            assert!(!upper.contains("CONSISTENT SNAPSHOT"), "{s}");
            assert!(!upper.contains("ORDER BY RAND"), "{s}");
            for w in [
                "INSERT ", "UPDATE ", "DELETE ", "REPLACE ", "CREATE ", "DROP ", "GRANT ",
            ] {
                assert!(!upper.contains(w), "{w} in {s}");
            }
        }
    }

    #[test]
    fn role_statements_quote_allow_listed_names_only() {
        assert_eq!(
            show_grants_using(&[
                ("app_read".to_owned(), "%".to_owned()),
                ("ops".to_owned(), "10.0.0.0/255.0.0.0".to_owned()),
                ("r".to_owned(), String::new()),
            ])
            .as_deref(),
            Some(
                "SHOW GRANTS FOR CURRENT_USER() USING 'app_read'@'%', \
                 'ops'@'10.0.0.0/255.0.0.0', 'r'@''"
            )
        );
        assert_eq!(show_grants_using(&[]), None);
        for bad in [
            "",
            "a`b",
            "a'b",
            "a b",
            "a;b",
            "r\\",
            "caf\u{e9}",
            &"x".repeat(256),
        ] {
            assert_eq!(
                show_grants_using(&[(bad.to_owned(), "%".to_owned())]),
                None,
                "{bad}"
            );
            if !bad.is_empty() {
                assert_eq!(
                    show_grants_using(&[("r".to_owned(), bad.to_owned())]),
                    None,
                    "{bad}"
                );
            }
        }
    }
}
