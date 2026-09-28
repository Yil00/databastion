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
/// per sampled table by [`table_rows`], filtered on local engines.
pub(crate) const INTROSPECT: &str = "SELECT t.TABLE_SCHEMA, t.TABLE_NAME, t.TABLE_TYPE, t.ENGINE \
     FROM information_schema.TABLES t \
     WHERE LOWER(t.TABLE_SCHEMA) NOT IN \
       ('mysql', 'sys', 'information_schema', 'performance_schema') \
     ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME \
     LIMIT 100000";

/// Engine and estimated rows of one table, only if its engine is still a
/// local one (checked again in the sampling transaction). Columns: engine,
/// estimated rows.
#[must_use]
pub(crate) fn table_rows(schema: &str, table: &str) -> Option<String> {
    let engines: Vec<String> = crate::catalog::LOCAL_ENGINES
        .iter()
        .map(|e| format!("'{e}'"))
        .collect();
    Some(format!(
        "SELECT t.ENGINE, t.TABLE_ROWS FROM information_schema.TABLES t \
         WHERE t.TABLE_SCHEMA = {} AND t.TABLE_NAME = {} \
           AND t.TABLE_TYPE IN ('BASE TABLE', 'SYSTEM VERSIONED') AND t.ENGINE IN ({})",
        quote_str(schema)?,
        quote_str(table)?,
        engines.join(", ")
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

/// Roles granted to the account (their privileges are not listed in the
/// tables above).
pub(crate) const ROLES: &str = "SELECT COUNT(*) FROM information_schema.APPLICABLE_ROLES";

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
pub(crate) const SERVER_AUDIT_SETTINGS: &str =
    "SELECT @@GLOBAL.server_audit_logging, @@GLOBAL.server_audit_output_type";

/// `performance_schema` enabled, and the general log (noted only).
pub(crate) const PS_ENABLED: &str =
    "SELECT @@GLOBAL.performance_schema, @@GLOBAL.general_log, @@GLOBAL.log_output";

/// Statement consumers. Columns: name, enabled.
pub(crate) const PS_CONSUMERS: &str = "SELECT c.NAME, c.ENABLED \
     FROM performance_schema.setup_consumers c \
     WHERE c.NAME IN ('events_statements_history_long', 'events_statements_history', \
                      'events_statements_current')";

/// Readability of the statement history (a count: no statement text).
pub(crate) const PS_HISTORY_LONG: &str =
    "SELECT COUNT(*) FROM performance_schema.events_statements_history_long";
pub(crate) const PS_CURRENT: &str =
    "SELECT COUNT(*) FROM performance_schema.events_statements_current";

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
        let rows = table_rows("hr", "t").unwrap();
        assert!(
            rows.contains("t.ENGINE IN ('InnoDB', 'MyISAM', 'Aria'"),
            "{rows}"
        );
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
            table_rows("hr", "employees").unwrap(),
            CURRENT_USER.to_owned(),
            USER_PRIVILEGES.to_owned(),
            SCHEMA_PRIVILEGES.to_owned(),
            TABLE_PRIVILEGES.to_owned(),
            COLUMN_PRIVILEGES.to_owned(),
            ROLES.to_owned(),
            INIT_CONNECT.to_owned(),
            AUDIT_PLUGINS.to_owned(),
            SERVER_AUDIT_SETTINGS.to_owned(),
            PS_ENABLED.to_owned(),
            PS_CONSUMERS.to_owned(),
            PS_HISTORY_LONG.to_owned(),
            PS_CURRENT.to_owned(),
        ];
        for flavor in [Flavor::Mysql, Flavor::Mariadb] {
            v.push(set_statement_timeout(flavor, 1000));
            v.push(sample_statement(flavor, 1000, "s", "t", &[("c", Sampled::Text)], 10).unwrap());
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
        ];
        for s in all_statements() {
            let lower = s.to_lowercase();
            for d in denied {
                // `@@GLOBAL.general_log` (a boolean setting) is allowed.
                if d == "general_log" && lower.contains("@@global.general_log") {
                    continue;
                }
                assert!(!lower.contains(d), "{d} in {s}");
            }
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
}
