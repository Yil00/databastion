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
        list.push(sample_item(name, *kind)?);
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

/// The sampling statements of one table ([`sample_statement`]): `columns`
/// split, in order, into consecutive batches of at most `max_columns`, each
/// as long as its statement stays within [`MAX_OWN_STATEMENT`] (so that it
/// is never cut in the audit logs, where a cut text is reported as a read
/// of `*`), counting [`SAMPLE_DIGEST_MARGIN`] more bytes per column for its
/// `performance_schema` digest text. A batch has at least one column: one
/// column always fits (three names of at most 64 characters). Each item:
/// the batch's range in `columns` and its statement.
#[must_use]
pub(crate) fn sample_statements(
    flavor: Flavor,
    statement_ms: u32,
    schema: &str,
    table: &str,
    columns: &[(&str, Sampled)],
    limit: u32,
    max_columns: usize,
) -> Option<Vec<(std::ops::Range<usize>, String)>> {
    let first = sample_statement(
        flavor,
        statement_ms,
        schema,
        table,
        columns.get(..1)?,
        limit,
    )?;
    // Per column: its length as `server_audit` logs it (escaped) and as
    // `performance_schema` may have stored it ([`stored_len`]: 4 bytes per
    // non-ASCII character, security review of cea63c5, S1); a statement
    // is bounded by the larger of the two.
    let items: Vec<(usize, usize)> = columns
        .iter()
        .map(|(n, k)| {
            sample_item(n, *k).map(|i| (server_audit_escaped_len(&i), stored_len(i.as_bytes())))
        })
        .collect::<Option<_>>()?;
    // The statement without its column list (`, ` is ASCII, unescaped).
    let base = (
        server_audit_escaped_len(&first) - items[0].0,
        stored_len(first.as_bytes()) - items[0].1,
    );
    let mut out = Vec::new();
    let mut start = 0;
    while start < columns.len() {
        let mut len = (base.0 + items[start].0, base.1 + items[start].1);
        let mut end = start + 1;
        while end < columns.len()
            && end - start < max_columns.max(1)
            && (len.0 + 2 + items[end].0).max(len.1 + 2 + items[end].1)
                + SAMPLE_DIGEST_MARGIN * (end - start + 1)
                <= MAX_OWN_STATEMENT
        {
            len = (len.0 + 2 + items[end].0, len.1 + 2 + items[end].1);
            end += 1;
        }
        let s = sample_statement(
            flavor,
            statement_ms,
            schema,
            table,
            &columns[start..end],
            limit,
        )?;
        debug_assert_eq!(
            (server_audit_escaped_len(&s), stored_len(s.as_bytes())),
            len
        );
        out.push((start..end, s));
        start = end;
    }
    Some(out)
}

/// Bytes counted per sampled column on top of its text by
/// [`sample_statements`]: a `performance_schema` digest text spaces its
/// tokens (`LEFT ( `c` , ? ) , ` for `LEFT(`c`, 4096), `), at most 3 bytes
/// more per column, and is reported cut from 4 bytes under
/// `performance_schema_max_digest_length` (`audit::pfs`). Measured on MySQL
/// 8.4 and MariaDB 11.4: see the `sample_statements_stay_short` test.
pub(crate) const SAMPLE_DIGEST_MARGIN: usize = 4;

/// One selected column of [`sample_statement`].
fn sample_item(name: &str, kind: Sampled) -> Option<String> {
    let q = quote_ident(name)?;
    Some(match kind {
        Sampled::Text => format!("LEFT({q}, {MAX_VALUE_CHARS})"),
        Sampled::Plain => q,
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

/// Normalized name key of a catalog name in SQL, as
/// `databastion_core::cas_guard::name_key` (PR #141 review L7): the part
/// after the last `.`, every character but an ASCII letter or digit
/// removed (binary collation and an explicit list: no case folding beyond
/// ASCII), then lower-cased.
macro_rules! name_key {
    ($col:literal) => {
        concat!(
            "LOWER(REGEXP_REPLACE(SUBSTRING_INDEX(CONVERT(",
            $col,
            " USING utf8mb4) COLLATE utf8mb4_bin, '.', -1), \
             '[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789]', ''))"
        )
    };
}

/// Most rows of the CAS store guard statements together; one more is read
/// to tell a cut list (then reported as not evaluated, PR #141 review L2).
pub(crate) const CAS_GUARD_MAX_ROWS: usize = 20_000;

/// Longest statement the agent sends, in bytes as `server_audit` logs it
/// (escaped): well under the 1024-byte defaults of
/// `server_audit_query_log_limit` and `performance_schema_max_sql_text_length`,
/// so that the agent's statements are never cut at the default limits. The
/// Audit stream reports a cut text with no table record as a read of `*`,
/// always, whoever sent it (security review of #181, H1). Held by every
/// fixed statement and the CAS store guard statements, and by the sampling
/// statements, split into column batches ([`sample_statements`]), and by
/// `SHOW GRANTS … USING`, whose role list is split over several statements
/// ([`show_grants_using`]).
pub(crate) const MAX_OWN_STATEMENT: usize = 900;

/// Longest CAS store guard statement ([`MAX_OWN_STATEMENT`]): its exact
/// text must be recognized by the Audit stream.
pub(crate) const CAS_GUARD_MAX_STATEMENT: usize = MAX_OWN_STATEMENT;

/// Upper estimate of the bytes `t` takes on the server in the client's
/// character set (security review of 09e93da, R1): every allowed client
/// character set is ASCII-compatible with at most 4 bytes per character,
/// so an ASCII byte counts 1 and any other character 4 (any other byte 4
/// when `t` is not UTF-8). `performance_schema` limits apply to these
/// bytes (`audit::pfs::text_cut`). Never more than twice the length.
#[must_use]
pub(crate) fn stored_len(t: &[u8]) -> usize {
    let ascii = t.iter().filter(|b| b.is_ascii()).count();
    let other = match std::str::from_utf8(t) {
        Ok(s) => s.chars().filter(|c| !c.is_ascii()).count(),
        Err(_) => t.len() - ascii,
    };
    ascii + 4 * other
}

/// Length of `s` once escaped by MariaDB's `server_audit` (`'`, `\`,
/// newline, carriage return, tab, backspace and form feed gain a `\`).
#[must_use]
pub(crate) fn server_audit_escaped_len(s: &str) -> usize {
    s.len()
        + s.bytes()
            .filter(|b| matches!(b, b'\'' | b'\\' | b'\n' | b'\r' | b'\t' | 0x08 | 0x0c))
            .count()
}

/// The schemas the guard never looks at.
const CAS_GUARD_SCHEMAS: &str =
    "LOWER(TABLE_SCHEMA) NOT IN ('mysql', 'sys', 'information_schema', 'performance_schema')";

/// The CAS store guard's table list (ADR-0041 decision 6): the schema and
/// name of every table and view outside the system schemas, nothing else.
/// Selecting only these columns lets the server answer from the catalog
/// without opening any table definition (measured: no
/// `Opened_table_definitions` on MariaDB, a data dictionary index read on
/// MySQL). `check()` streams it, computes each name key in Rust
/// (`databastion_core::cas_guard::name_key`, the key of [`name_key!`]) and
/// keeps only the keys it knows; no name is kept. At most
/// [`CAS_GUARD_MAX_TABLES`] + 1 rows: one more tells a cut list (the guard
/// is then not evaluated).
pub(crate) const CAS_GUARD_TABLES: &str = "SELECT TABLE_SCHEMA, TABLE_NAME \
     FROM information_schema.TABLES WHERE LOWER(TABLE_SCHEMA) NOT IN \
     ('mysql', 'sys', 'information_schema', 'performance_schema') LIMIT 1000001";

/// Most rows of [`CAS_GUARD_TABLES`] read; it asks for one more.
pub(crate) const CAS_GUARD_MAX_TABLES: usize = 1_000_000;

/// The CAS store guard statements of `check()` (ADR-0041 decision 6),
/// every text known from the configuration alone (the Audit stream
/// recognizes them by their exact text; none depends on the catalog).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CasGuardStatements {
    /// [`CAS_GUARD_TABLES`].
    pub(crate) tables: &'static str,
    /// Per name key, in key order: the columns, with the account's
    /// privileges, of the tables whose name key is that key. Sent only for
    /// the keys found in the table list.
    pub(crate) by_key: Vec<(String, String)>,
    /// The columns of the tables with a `body` / `json` / `AUD_RESOURCE` /
    /// `AUD_USER` column (recognition by shape), sent last.
    pub(crate) shape: String,
}

impl CasGuardStatements {
    /// Every text, for the Audit stream: the name statements, the shape
    /// statement, then the table list.
    #[must_use]
    pub(crate) fn texts(&self) -> Vec<String> {
        self.by_key
            .iter()
            .map(|(_, s)| s.clone())
            .chain([self.shape.clone(), self.tables.to_owned()])
            .collect()
    }
}

/// The CAS store guard statements for the name keys `keys` (the built-in
/// names and `cas_stores`; see [`CasGuardStatements`]). Columns of the
/// column statements: schema, table, column, privileges; each ordered by
/// schema, table and column position, at most [`CAS_GUARD_MAX_ROWS`] + 1
/// rows; each within [`CAS_GUARD_MAX_STATEMENT`].
///
/// One column statement per key (PR #165 follow-up, measured cost): a
/// filter on the name key cannot use the catalog's name lookup, so each
/// statement walks the whole table list (without opening a table
/// definition); `check()` sends only those of the keys the table list
/// holds, usually none, instead of one per chunk of every key.
///
/// `None` when a key cannot be quoted or does not fit one statement.
#[must_use]
pub(crate) fn cas_guard_statements(keys: &[String]) -> Option<CasGuardStatements> {
    let head = format!(
        "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGES \
         FROM information_schema.COLUMNS WHERE {CAS_GUARD_SCHEMAS} AND {} IN (",
        name_key!("TABLE_NAME"),
    );
    let tail = ") ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION LIMIT 20001";
    let mut by_key = Vec::with_capacity(keys.len());
    for k in keys {
        let s = format!("{head}{}{tail}", quote_str(k)?);
        if server_audit_escaped_len(&s) > CAS_GUARD_MAX_STATEMENT {
            return None;
        }
        by_key.push((k.clone(), s));
    }
    by_key.sort();
    by_key.dedup();
    let shape = format!(
        "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGES \
         FROM information_schema.COLUMNS WHERE {CAS_GUARD_SCHEMAS} \
         AND (TABLE_SCHEMA, TABLE_NAME) IN (SELECT x.TABLE_SCHEMA, x.TABLE_NAME \
         FROM information_schema.COLUMNS x WHERE {} IN ('body', 'json', 'audresource', 'auduser')) \
         ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION LIMIT 20001",
        name_key!("x.COLUMN_NAME"),
    );
    let out = CasGuardStatements {
        tables: CAS_GUARD_TABLES,
        by_key,
        shape,
    };
    debug_assert!(
        out.texts()
            .iter()
            .all(|s| server_audit_escaped_len(s) <= CAS_GUARD_MAX_STATEMENT)
    );
    Some(out)
}

/// The CAS store guard statements of a target: [`cas_guard_statements`]
/// of the built-in and `cas_stores` name keys. One builder for `check()`
/// and for the Audit stream, which recognizes them by their exact text.
#[must_use]
pub(crate) fn cas_guard_statements_of(
    stores: Option<&databastion_core::cas_guard::CasStores>,
) -> Option<CasGuardStatements> {
    cas_guard_statements(&databastion_core::cas_guard::known_name_keys(stores))
}

/// Every CAS store guard text of a target ([`CasGuardStatements::texts`]).
#[must_use]
pub(crate) fn cas_guard_statement_texts(
    stores: Option<&databastion_core::cas_guard::CasStores>,
) -> Option<Vec<String>> {
    cas_guard_statements_of(stores).map(|g| g.texts())
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

/// Head of the [`show_grants_using`] statements.
const SHOW_GRANTS_USING: &str = "SHOW GRANTS FOR CURRENT_USER() USING ";

/// MySQL: the privileges of the account and of `roles` (`(name, host)`,
/// the roles granted to it directly or mandatory; the server expands the
/// roles they grant). `SHOW GRANTS` about the current user needs no
/// privilege. `None` for an empty list or a name outside the allow-list.
///
/// The role list is split over several statements, in order, each within
/// [`MAX_OWN_STATEMENT`] bytes as `server_audit` logs it (its quotes
/// escaped) and as `performance_schema` may store it ([`stored_len`]), so
/// that no statement is cut at the default log limits (a cut text with no
/// table record is a read of `*`, always, even from the agent's account).
/// One role always fits: an allow-listed name and host take at most 519
/// bytes escaped. The caller takes the union of the privileges the
/// statements show (MySQL combines the privileges of the account and of
/// its active roles as a union, partial revokes included: a restriction
/// of one source is lifted by a grant of another), and the parser ignores
/// `REVOKE` lines (`grants`), so the split changes no result.
pub(crate) fn show_grants_using(roles: &[(String, String)]) -> Option<Vec<String>> {
    if roles.is_empty() {
        return None;
    }
    let fits = |t: &str| {
        server_audit_escaped_len(t) <= MAX_OWN_STATEMENT
            && stored_len(t.as_bytes()) <= MAX_OWN_STATEMENT
    };
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::from(SHOW_GRANTS_USING);
    for (name, host) in roles {
        if !role_part_ok(name, false) || !role_part_ok(host, true) {
            return None;
        }
        // `'name'@'host'`: the account-name form of the MySQL manual
        // ("Specifying Account Names"); an empty host is `''` (a quoted
        // identifier cannot be empty).
        let role = format!("{}@{}", quote_str(name)?, quote_str(host)?);
        let first = cur.len() == SHOW_GRANTS_USING.len();
        let next = if first {
            format!("{cur}{role}")
        } else {
            format!("{cur}, {role}")
        };
        if fits(&next) {
            cur = next;
        } else if first {
            // Unreachable with allow-listed parts; fail closed.
            return None;
        } else {
            out.push(std::mem::replace(
                &mut cur,
                format!("{SHOW_GRANTS_USING}{role}"),
            ));
            if !fits(&cur) {
                return None;
            }
        }
    }
    out.push(cur);
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
                      'thread_instrumentation', 'statements_digest')";

/// Readability of the statement history: `EXPLAIN` needs the `SELECT`
/// privilege on the table (error 1142 without it, 1146 for a table that
/// does not exist; verified on MySQL 8.4 and MariaDB 11.4) and reads no
/// row. Not a read of a statement-text table (ADR-0045): `check()` sends
/// these on a short heartbeat session that has ended when a
/// `performance_schema` poll sees them (no account, a digest only), so a
/// `SELECT` there could not be recognized as the agent's own. Each is the
/// literal probe shape of ADR-0047 decision 5 (`EXPLAIN SELECT 1 FROM t`:
/// no condition, so no `const` table, and a literal select list), quiet
/// for every account on every source, digests included; any other
/// `EXPLAIN` is a read of what it names, never the agent's own.
pub(crate) const PS_HISTORY_LONG: &str =
    "EXPLAIN SELECT 1 FROM performance_schema.events_statements_history_long";
pub(crate) const PS_HISTORY: &str =
    "EXPLAIN SELECT 1 FROM performance_schema.events_statements_history";
pub(crate) const PS_CURRENT: &str =
    "EXPLAIN SELECT 1 FROM performance_schema.events_statements_current";

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
/// The parser's digest storage (`max_digest_length`, set at startup): a
/// digest is cut at the smaller of the two limits.
pub(crate) const MAX_DIGEST_LIMIT: &str = "SELECT @@GLOBAL.max_digest_length";

/// The statement tables an Audit poll reads (`audit::pfs::PsTable`).
pub(crate) const PS_POLL_TABLES: [&str; 3] = [
    "events_statements_history_long",
    "events_statements_history",
    "events_statements_current",
];

/// Rows read per poll query at most (the constant `LIMIT` of
/// [`ps_statements`]).
pub(crate) const PS_BATCH: usize = 2000;

/// This session's `performance_schema` thread id, computed by the server
/// inside the stats texts (security review of #186, H1: a session variable
/// set by the client could be set to another value by anyone replaying
/// the constant text with the agent's credential). The poll texts leave
/// their own thread out on the `threads` row they join instead
/// ([`ps_statements`]).
pub(crate) const PS_OWN_THREAD_EXPR: &str = "(SELECT o.THREAD_ID FROM performance_schema.threads o \
     WHERE o.PROCESSLIST_ID = CONNECTION_ID())";

/// The digest length from which the poll also reads `SQL_TEXT`
/// (`audit::pfs::sql_text_from` of the smaller digest limit), computed by
/// the server from its own settings inside the poll text (security review
/// of #186, H1). Both settings are global only (`@@` reads the global
/// value) and at most 1 MiB (`audit::pfs::MAX_TEXT_BYTES`); `GREATEST`
/// before the subtraction keeps the unsigned value from going below zero.
/// Pinned to the Rust function by a unit test and, on each server, by an
/// integration test.
#[must_use]
pub(crate) fn ps_sql_text_from_expr() -> String {
    let sub = crate::audit::pfs::MAX_DIGEST_TOKEN + 3;
    format!(
        "(GREATEST(LEAST(@@performance_schema_max_digest_length, @@max_digest_length), \
         {sub}) - {sub}) DIV 3"
    )
}

/// The session user variable of the poll texts (ADR-0045 decision 4),
/// sent on the poll session right before each [`ps_statements`]: the end
/// timer to read from (the agent's cursor). A session `SET` of a user
/// variable produces no event (`audit::events::is_quiet`), and keeps the
/// poll texts constant, so that the Audit stream recognizes them by their
/// exact text. The thread id and the `SQL_TEXT` threshold are computed by
/// the server ([`PS_OWN_THREAD_EXPR`], [`ps_sql_text_from_expr`]): whoever
/// replays a poll text with the agent's credential chooses only where to
/// read from, and reads what the poll reads.
#[must_use]
pub(crate) fn ps_poll_variables(from: u64) -> String {
    format!("SET @databastion_from = {from}")
}

/// Timers of an Audit poll: this session's current statement start (the
/// timer's "now") and the oldest and newest end in the polled table. No
/// text. `table` is one of [`PS_POLL_TABLES`]. A constant text per table,
/// with no variable.
#[must_use]
pub(crate) fn ps_stats(table: &str) -> String {
    format!(
        "SELECT (SELECT c.TIMER_START FROM performance_schema.events_statements_current c \
                 WHERE c.THREAD_ID = {PS_OWN_THREAD_EXPR} ORDER BY c.EVENT_ID DESC LIMIT 1), \
                MIN(h.TIMER_END), MAX(h.TIMER_END) FROM performance_schema.{table} h"
    )
}

/// The Audit poll of `performance_schema` statements (the only statement
/// that reads statement text, ADR-0018): `DIGEST_TEXT`, and `SQL_TEXT` only
/// for a statement without a digest, with a digest of
/// [`ps_sql_text_from_expr`] bytes or more (it may have been cut at its
/// token storage: `pfs::digest_cut`), or of the agent's own sessions (the
/// poll session's login user and client host, from `USER()`: its
/// Discovery statements are recognized by their exact text); with the
/// session's account, host, type and `program_name` while it is
/// connected. Rows are ordered by end timer from `@databastion_from`, this
/// session's own thread excluded (its `threads` row has this connection's
/// id; `<=>` keeps the rows of ended threads, which have none), at most
/// [`PS_BATCH`]. `table` is one of [`PS_POLL_TABLES`]. A constant text per
/// table and `with_program` (the cursor is set by [`ps_poll_variables`]).
#[must_use]
pub(crate) fn ps_statements(table: &str, with_program: bool) -> String {
    let program = if with_program {
        "(SELECT a.ATTR_VALUE FROM performance_schema.session_connect_attrs a \
          WHERE a.PROCESSLIST_ID = t.PROCESSLIST_ID AND a.ATTR_NAME = 'program_name' LIMIT 1)"
    } else {
        "NULL"
    };
    let text_from = ps_sql_text_from_expr();
    format!(
        "SELECT h.THREAD_ID, h.EVENT_ID, h.TIMER_END, h.CURRENT_SCHEMA, h.DIGEST_TEXT, \
         CASE WHEN h.DIGEST_TEXT IS NULL OR LENGTH(h.DIGEST_TEXT) >= {text_from} \
           OR CONCAT(t.PROCESSLIST_USER, '@', t.PROCESSLIST_HOST) = USER() \
         THEN h.SQL_TEXT END, h.ROWS_SENT, h.ROWS_AFFECTED, \
         h.MYSQL_ERRNO, t.PROCESSLIST_USER, t.PROCESSLIST_HOST, t.TYPE, {program} \
         FROM performance_schema.{table} h \
         LEFT JOIN performance_schema.threads t ON t.THREAD_ID = h.THREAD_ID \
         WHERE h.TIMER_END >= @databastion_from AND h.END_EVENT_ID IS NOT NULL \
           AND NOT t.PROCESSLIST_ID <=> CONNECTION_ID() \
         ORDER BY h.TIMER_END, h.THREAD_ID, h.EVENT_ID LIMIT {PS_BATCH}"
    )
}

/// The connector's own statements that read `performance_schema` tables
/// (ADR-0045 decision 4): each exact text, with the tables it reads. The
/// Audit stream leaves such a statement of the agent's identity out,
/// without a charge, only when its whole uncut text is one of these and
/// its table records (if any) read only these tables; any other read of a
/// statement-text table by the agent's identity is reported. Every text
/// is constant: the probes of `check()` and of the Audit re-probe (the
/// readability probes have the literal probe shape of ADR-0047, quiet in
/// any case, listed for completeness), the own-thread probe sent once per
/// Audit session, and
/// the poll and stats texts of each statement table.
#[must_use]
pub(crate) fn own_performance_schema_reads() -> Vec<(String, Vec<&'static str>)> {
    let mut v: Vec<(String, Vec<&'static str>)> = vec![
        (PS_CONSUMERS.to_owned(), vec!["setup_consumers"]),
        (
            PS_HISTORY_LONG.to_owned(),
            vec!["events_statements_history_long"],
        ),
        (PS_HISTORY.to_owned(), vec!["events_statements_history"]),
        (PS_CURRENT.to_owned(), vec!["events_statements_current"]),
        (PS_OWN_THREAD.to_owned(), vec!["threads"]),
    ];
    for table in PS_POLL_TABLES {
        v.push((
            ps_stats(table),
            vec!["events_statements_current", "threads", table],
        ));
        v.push((ps_statements(table, false), vec![table, "threads"]));
        v.push((
            ps_statements(table, true),
            vec![table, "threads", "session_connect_attrs"],
        ));
    }
    v
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

    /// Role lists for `SHOW GRANTS … USING`: 40 roles of 20 characters,
    /// 64 of the longest allow-listed name and host (255 each), and names
    /// with every allow-listed punctuation character.
    fn role_lists() -> Vec<Vec<(String, String)>> {
        vec![
            (0..40)
                .map(|i| (format!("databastion_role_{i:03}"), "%".to_owned()))
                .collect(),
            (0..64)
                .map(|i| (format!("{i:02}{}", "r".repeat(253)), "h".repeat(255)))
                .collect(),
            (0..64)
                .map(|i| (format!("r_$.%-:/{i}"), "10.0.0.0/255.0.0.0".to_owned()))
                .collect(),
            vec![("r".to_owned(), String::new())],
        ]
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
            show_grants_using(&[("app_read".to_owned(), "%".to_owned())])
                .unwrap()
                .remove(0),
            SHOW_GRANTS_OWN.to_owned(),
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
            MAX_DIGEST_LIMIT.to_owned(),
            SERVER_UPTIME.to_owned(),
            ps_stats("events_statements_history_long"),
            ps_poll_variables(8),
        ];
        for roles in role_lists() {
            v.extend(show_grants_using(&roles).unwrap());
        }
        v.extend(
            cas_guard_statements(&["castickets".to_owned(), "comaudittrail".to_owned()])
                .unwrap()
                .texts(),
        );
        for flavor in [Flavor::Mysql, Flavor::Mariadb] {
            v.push(set_statement_timeout(flavor, 1000));
            v.push(sample_statement(flavor, 1000, "s", "t", &[("c", Sampled::Text)], 10).unwrap());
            v.push(ticket_type_counts(flavor, 1000, "s", "t", "type").unwrap());
        }
        v
    }

    /// The guard statements never reach the default 1024-byte log limits
    /// (security review of f9bab99): one column statement per name key,
    /// the shape statement, and the table list, which reads names only.
    #[test]
    fn cas_guard_statements_stay_short_and_cover_every_key() {
        let names = |p: char| -> Vec<String> {
            (0..64)
                .map(|i| format!("{i:02}{}", p.to_string().repeat(126)))
                .collect()
        };
        let full = databastion_core::cas_guard::CasStores {
            ticket_registry: names('t'),
            service_registry: names('s'),
            audit_trail: names('a'),
        };
        for stores in [None, Some(&full)] {
            let keys = databastion_core::cas_guard::known_name_keys(stores);
            let guard = cas_guard_statements_of(stores).unwrap();
            let all = guard.texts();
            assert_eq!(cas_guard_statement_texts(stores).unwrap(), all);
            for s in &all {
                assert!(
                    server_audit_escaped_len(s) <= CAS_GUARD_MAX_STATEMENT,
                    "{}",
                    s.len()
                );
            }
            assert_eq!(all.last().map(String::as_str), Some(CAS_GUARD_TABLES));
            assert!(guard.shape.contains("'audresource'"));
            assert!(guard.shape.ends_with("LIMIT 20001"));
            // One column statement per key, with that key only.
            assert_eq!(
                guard.by_key.iter().map(|(k, _)| k).collect::<Vec<_>>(),
                keys.iter().collect::<Vec<_>>()
            );
            for (k, s) in &guard.by_key {
                assert!(
                    s.ends_with(&format!(
                        "IN ('{k}') ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION LIMIT 20001"
                    )),
                    "{s}"
                );
                assert_eq!(s.matches('\'').count(), 2 * 8, "{s}");
            }
            // Built-in names: 27 keys; 64 names of 128 characters per list
            // more: 219.
            assert_eq!(guard.by_key.len(), if stores.is_none() { 27 } else { 219 });
        }
        // A key that cannot fit one statement: no statement at all.
        assert!(cas_guard_statements(&["k".repeat(800)]).is_none());
    }

    /// The agent's statements stay within `MAX_OWN_STATEMENT`, so that
    /// the audit logs never cut them at their default limits (a cut text
    /// with no table record is reported as a read of `*`: security review
    /// of #181, H1). Sampling statements are split into column batches;
    /// their digest texts measured at most 850 bytes on MySQL 8.4 and
    /// MariaDB 11.4 for these shapes (`SAMPLE_DIGEST_MARGIN`).
    #[test]
    fn sample_statements_stay_short() {
        let name = |i: usize, n: usize| -> String {
            let s = format!("{i:x}{}", "c".repeat(n));
            s.chars().take(n.max(1)).collect::<String>() + &format!("{i}")
        };
        // Non-ASCII names (security review of cea63c5, S1): `中` (3 bytes
        // in UTF-8), `é` (2), `😀` (4), each 4 bytes as stored.
        let wide = |i: usize, n: usize, c: &str| -> String { format!("{}{i}", c.repeat(n)) };
        let mut shapes: Vec<(Vec<String>, Sampled)> = [
            (1, Sampled::Plain),
            (1, Sampled::Text),
            (20, Sampled::Text),
            (60, Sampled::Plain),
        ]
        .into_iter()
        .map(|(n, kind)| ((0..4096).map(|i| name(i, n)).collect(), kind))
        .collect();
        for c in ["中", "é", "\u{1F600}"] {
            for (n, kind) in [
                (30, Sampled::Text),
                (60, Sampled::Plain),
                (1, Sampled::Text),
            ] {
                shapes.push(((0..200).map(|i| wide(i, n, c)).collect(), kind));
            }
        }
        for (cols, kind) in shapes {
            let sel: Vec<(&str, Sampled)> = cols.iter().map(|c| (c.as_str(), kind)).collect();
            for flavor in [Flavor::Mysql, Flavor::Mariadb] {
                for max in [1024, 3] {
                    let all = sample_statements(
                        flavor,
                        4_294_967_295,
                        "s'chema",
                        "t\\able",
                        &sel,
                        u32::MAX,
                        max,
                    )
                    .unwrap();
                    let mut next = 0;
                    for (range, s) in &all {
                        assert_eq!(range.start, next);
                        assert!(!range.is_empty() && range.len() <= max);
                        next = range.end;
                        let len = server_audit_escaped_len(s).max(stored_len(s.as_bytes()));
                        assert!(
                            len + SAMPLE_DIGEST_MARGIN * range.len() <= MAX_OWN_STATEMENT,
                            "{len}"
                        );
                        assert!(stored_len(s.as_bytes()) + 4 < 1024);
                        assert_eq!(
                            *s,
                            sample_statement(
                                flavor,
                                4_294_967_295,
                                "s'chema",
                                "t\\able",
                                &sel[range.clone()],
                                u32::MAX
                            )
                            .unwrap()
                        );
                    }
                    assert_eq!(next, cols.len());
                }
            }
        }
        // The longest names (64 characters of 4 bytes, or of characters
        // `server_audit` escapes): one column always fits.
        for c in ["\u{1F600}", "中", "é", "'", "`"] {
            let long = c.repeat(64);
            for flavor in [Flavor::Mysql, Flavor::Mariadb] {
                let all = sample_statements(
                    flavor,
                    4_294_967_295,
                    &long,
                    &long,
                    &[
                        (long.as_str(), Sampled::Text),
                        (long.as_str(), Sampled::Plain),
                    ],
                    u32::MAX,
                    1024,
                )
                .unwrap();
                assert_eq!(all.iter().map(|(r, _)| r.len()).sum::<usize>(), 2, "{c}");
                for (_, s) in &all {
                    assert!(server_audit_escaped_len(s) <= MAX_OWN_STATEMENT, "{c}");
                    // Never taken as cut by `performance_schema` (a single
                    // column of 64 four-byte names still fits).
                    assert!(stored_len(s.as_bytes()) + 4 < 1024, "{c}");
                }
            }
        }
        assert!(sample_statements(Flavor::Mysql, 1, "s", "t", &[], 1, 1).is_none());
    }

    /// Every fixed statement, and the per-table catalog statements with the
    /// longest names, stay within `MAX_OWN_STATEMENT`.
    #[test]
    fn own_statements_stay_short() {
        let long = [
            "\u{1F600}".repeat(64),
            "中".repeat(64),
            "é".repeat(64),
            "'".repeat(64),
            "`".repeat(64),
        ];
        let mut all: Vec<String> = [
            INTROSPECT,
            SESSION_READ_ONLY,
            BEGIN,
            CURRENT_USER,
            USER_PRIVILEGES,
            SCHEMA_PRIVILEGES,
            TABLE_PRIVILEGES,
            COLUMN_PRIVILEGES,
            APPLICABLE_ROLES_MYSQL,
            APPLICABLE_ROLES_MARIADB,
            CURRENT_ROLE,
            SHOW_GRANTS_OWN,
            MANDATORY_ROLES,
            SHOW_GRANTS_CURRENT_ROLE,
            SHOW_GRANTS_PUBLIC,
            INIT_CONNECT,
            AUDIT_PLUGINS,
            SERVER_AUDIT_SETTINGS,
            AUDIT_LOG_SETTINGS,
            AUDIT_LOG_FILTER_FORMAT,
            SERVER_AUDIT_QUERY_LIMIT,
            SYSTEM_UTC_OFFSET,
            SESSION_USER,
            PS_ENABLED,
            PS_CONSUMERS,
            PS_HISTORY_LONG,
            PS_HISTORY,
            PS_CURRENT,
            PS_OWN_THREAD,
            SERVER_UPTIME,
            PS_TEXT_LIMIT,
            PS_DIGEST_LIMIT,
            MAX_DIGEST_LIMIT,
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        for flavor in [Flavor::Mysql, Flavor::Mariadb] {
            all.push(session_setup(flavor, u32::MAX));
            all.push(set_statement_timeout(flavor, u32::MAX));
            all.push(session_check(flavor, "transaction_read_only"));
            for n in &long {
                all.push(ticket_type_counts(flavor, u32::MAX, n, n, n).unwrap());
            }
        }
        for n in &long {
            all.push(table_engine(n, n).unwrap());
            all.push(table_rows(n, n).unwrap());
            all.push(columns(n, n).unwrap());
        }
        all.extend(own_performance_schema_reads().into_iter().map(|(t, _)| t));
        all.push(ps_poll_variables(u64::MAX));
        all.push(kill_query(u32::MAX));
        all.extend(cas_guard_statement_texts(None).unwrap());
        for roles in role_lists() {
            all.extend(show_grants_using(&roles).unwrap());
        }
        for s in &all {
            assert!(server_audit_escaped_len(s) <= MAX_OWN_STATEMENT, "{s}");
            // Not taken as cut by `performance_schema` either (S1).
            assert!(stored_len(s.as_bytes()) + 4 < 1024, "{s}");
        }
    }

    /// The table list reads the schema and name only, outside the same
    /// system schemas as the column statements.
    #[test]
    fn the_cas_guard_table_list_reads_names_only() {
        assert!(CAS_GUARD_TABLES.contains(CAS_GUARD_SCHEMAS));
        assert!(
            CAS_GUARD_TABLES.starts_with(
                "SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.TABLES WHERE "
            )
        );
        assert!(!CAS_GUARD_TABLES.contains("COLUMNS"));
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
            // The statistics tables that hold column values (ADR-0048
            // decision 4: never the agent's own, so it sends none).
            "column_stat",
            "table_stats",
            "index_stats",
        ];
        for s in all_statements() {
            let lower = s.to_lowercase();
            for d in denied {
                // `@@GLOBAL.general_log` (a boolean setting) is allowed.
                if d == "general_log" && lower.contains("@@global.general_log") {
                    continue;
                }
                // The poll stats text finds its own thread by its
                // connection id (`PS_OWN_THREAD_EXPR`), not the processlist.
                if d == "processlist"
                    && lower
                        .replace(&PS_OWN_THREAD_EXPR.to_lowercase(), "")
                        .find("processlist")
                        .is_none()
                {
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

    /// ADR-0048 decision 4: no statement of the agent, its
    /// `performance_schema` polls and probes included, names a statistics
    /// table (`COLUMN_STATISTICS`, `mysql.column_stats`).
    #[test]
    fn no_statement_names_a_statistics_table() {
        let mut all = all_statements();
        all.extend(own_performance_schema_reads().into_iter().map(|(t, _)| t));
        for with_program in [true, false] {
            all.push(ps_statements(
                "events_statements_history_long",
                with_program,
            ));
        }
        for s in &all {
            let lower = s.to_lowercase();
            for (db, t) in crate::audit::events::STATISTICS_TABLES {
                assert!(!lower.contains(&t.to_lowercase()), "{db}.{t} in {s}");
            }
        }
    }

    #[test]
    fn the_audit_poll_reads_text_only_through_the_digest() {
        for with_program in [true, false] {
            let s = ps_statements("events_statements_history_long", with_program);
            let lower = s.to_lowercase();
            // SQL_TEXT only when there is no digest, a long digest or
            // the agent's own account; never the text of a running
            // statement of another session (PROCESSLIST_INFO), the
            // processlist, or another attribute than program_name.
            assert_eq!(lower.matches("sql_text").count(), 1, "{s}");
            assert!(
                lower.contains(
                    "case when h.digest_text is null or length(h.digest_text) >= \
                     (greatest(least(@@performance_schema_max_digest_length, \
                     @@max_digest_length), 263) - 263) div 3 \
                     or concat(t.processlist_user, '@', t.processlist_host) = user() \
                     then h.sql_text end"
                ),
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
            assert!(
                lower.contains("and not t.processlist_id <=> connection_id() order by"),
                "{s}"
            );
            assert!(!lower.contains("@databastion_thread") && !lower.contains("@databastion_text"));
            assert!(lower.contains("h.timer_end >= @databastion_from"), "{s}");
            assert!(lower.ends_with(" limit 2000"), "{s}");
        }
    }

    /// ADR-0045 decision 4: the poll and stats texts are constant (no
    /// digit outside the fixed `LIMIT`s and the quoted names), distinct,
    /// and each lists the `performance_schema` tables it names; the
    /// session `SET` before them is quiet and names no table.
    #[test]
    fn the_poll_texts_are_constant_and_their_tables_listed() {
        use databastion_classifiers::query::{AnalyzeOptions, analyze};
        let own = own_performance_schema_reads();
        assert_eq!(own.len(), 5 + 3 * 3);
        let texts: std::collections::HashSet<&str> = own.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(texts.len(), own.len(), "texts are distinct");
        for (text, tables) in &own {
            let a = analyze(text, AnalyzeOptions::mysql());
            assert!(a.lexed(), "{text}");
            let mut named: Vec<String> = Vec::new();
            for p in a.parts() {
                for r in &p.relations {
                    assert_eq!(r.schema.as_deref(), Some("performance_schema"), "{text}");
                    named.push(r.name.to_ascii_lowercase());
                }
            }
            named.sort();
            named.dedup();
            let mut listed: Vec<String> = tables.iter().map(|t| t.to_ascii_lowercase()).collect();
            listed.sort();
            listed.dedup();
            assert_eq!(named, listed, "{text}");
            // Constant: no number but the fixed limits and the threshold
            // formula's constants (security review of #186, H1).
            let stripped = text
                .replace(&ps_sql_text_from_expr(), "")
                .replace("LIMIT 2000", "")
                .replace("LIMIT 1", "")
                .replace("'@', -1", "")
                .replace("'@', 1", "")
                .replace("SELECT 1 FROM", "");
            assert!(!stripped.bytes().any(|b| b.is_ascii_digit()), "{text}");
            assert!(
                server_audit_escaped_len(text) <= MAX_OWN_STATEMENT,
                "{text}"
            );
            assert!(stored_len(text.as_bytes()) <= MAX_OWN_STATEMENT, "{text}");
        }
        for from in [0, u64::MAX] {
            let set = ps_poll_variables(from);
            assert_eq!(set, format!("SET @databastion_from = {from}"));
            let a = analyze(&set, AnalyzeOptions::mysql());
            assert!(a.lexed(), "{set}");
            for p in a.parts() {
                assert!(p.relations.is_empty(), "{set}");
                assert!(crate::audit::events::is_quiet(p), "{set}");
            }
            assert!(server_audit_escaped_len(&set) <= MAX_OWN_STATEMENT);
        }
        assert_eq!(
            PS_POLL_TABLES.map(|t| t.to_owned()),
            [
                crate::audit::pfs::PsTable::HistoryLong,
                crate::audit::pfs::PsTable::History,
                crate::audit::pfs::PsTable::Current
            ]
            .map(|t| t.name().to_owned())
        );
    }

    /// The server-side `SQL_TEXT` threshold of the poll text is the Rust
    /// one (`pfs::sql_text_from` of the smaller digest limit, each capped
    /// at `pfs::MAX_TEXT_BYTES`; security review of #186, H1).
    #[test]
    fn the_server_side_threshold_is_the_rust_one() {
        use crate::audit::pfs::{MAX_DIGEST_TOKEN, MAX_TEXT_BYTES, sql_text_from};
        let expr = ps_sql_text_from_expr();
        assert_eq!(
            expr,
            "(GREATEST(LEAST(@@performance_schema_max_digest_length, @@max_digest_length), \
             263) - 263) DIV 3"
        );
        // The SQL formula, evaluated as the server does (unsigned values
        // that never go below zero, `DIV` truncating). The servers cap
        // both settings at 1 MiB (`MAX_TEXT_BYTES`).
        let sql = |ps: u64, parser: u64| -> u64 {
            let sub = u64::try_from(MAX_DIGEST_TOKEN + 3).unwrap();
            (ps.min(parser).max(sub) - sub) / 3
        };
        let values = [
            0, 1, 100, 262, 263, 264, 265, 266, 500, 1023, 1024, 1025, 4096, 65_536, 1_048_575,
            1_048_576,
        ];
        for ps in values {
            for parser in values {
                let limit = |v: u64| usize::try_from(v).unwrap().min(MAX_TEXT_BYTES);
                let rust = sql_text_from(limit(ps).min(limit(parser)));
                assert_eq!(
                    usize::try_from(sql(ps, parser)).unwrap(),
                    rust,
                    "{ps} {parser}"
                );
            }
        }
    }

    /// Every statement the agent sends is a recognized read or on the
    /// Audit stream's allow-list of statements of no known kind: the
    /// fail-closed `Other` path never reports the agent's own traffic.
    ///
    /// ADR-0045 decision 9: no statement the agent sends calls a name that
    /// is not built in, on any list (an unknown call is never the agent's
    /// own), nor on the names built in on every listed server.
    #[test]
    fn own_statements_are_reads_or_allow_listed() {
        use databastion_classifiers::query::{AnalyzeOptions, StatementKind, analyze};
        let lists = crate::builtins::lists()
            .iter()
            .chain(std::iter::once(crate::builtins::any_server()));
        let mut statements = all_statements();
        statements.extend(own_performance_schema_reads().into_iter().map(|(t, _)| t));
        for flavor in [Flavor::Mysql, Flavor::Mariadb] {
            statements.push(
                sample_statement(
                    flavor,
                    1000,
                    "s",
                    "t",
                    &[("a", Sampled::Text), ("b", Sampled::Plain)],
                    10,
                )
                .unwrap(),
            );
        }
        let mut checked = 0;
        for list in lists {
            for s in statements.clone() {
                let a = analyze(&s, AnalyzeOptions::mysql().builtins(list));
                assert!(a.lexed(), "{s}");
                assert!(
                    !a.unknown_call(),
                    "{:?} {:?}: {s}",
                    list.flavor,
                    list.series
                );
                for p in a.parts() {
                    let read = matches!(p.kind, StatementKind::Select | StatementKind::Table);
                    let quiet = p.kind == StatementKind::Other && crate::audit::events::is_quiet(p);
                    assert!(read || quiet, "{s}");
                    // ADR-0047 decision 6: the agent sends no explain of a
                    // statement but the literal probe shape.
                    assert!(!p.explain_statement || p.explain_probe, "{s}");
                    assert!(!p.routine_call && !p.compound && !p.analyze_wrapped, "{s}");
                    // No read into variables (#195 review M2) and no
                    // `CREATE … AS SELECT` (#186 review L4): never the
                    // agent's own.
                    assert!(!p.into_var && !p.var_assign && !p.create_query, "{s}");
                }
                checked += 1;
            }
        }
        assert!(checked > 7 * 50, "{checked}");
    }

    #[test]
    fn statements_are_single_and_never_read_write() {
        for s in all_statements() {
            assert!(!s.contains(';'), "multi-statement: {s}");
            // The Audit stream's double-quote backstop relies on it.
            assert!(!s.contains('"'), "double quote: {s}");
            let upper = s.to_uppercase();
            assert!(!upper.contains("READ WRITE"), "{s}");
            assert!(!upper.contains("CONSISTENT SNAPSHOT"), "{s}");
            assert!(!upper.contains("ORDER BY RAND"), "{s}");
            for w in [
                "INSERT ", "UPDATE ", "DELETE ", "REPLACE ", "CREATE ", "DROP ", "GRANT ",
            ] {
                assert!(!upper.contains(w), "{w} in {s}");
            }
            // No server configuration change either (I4): the Audit
            // stream reports these from any account, the agent's included.
            for w in [
                "TRUNCATE",
                "CALL ",
                "PREPARE",
                "EXECUTE",
                "DO ",
                "HANDLER",
                "FLUSH",
                "RESET",
                "KILL",
                "SET GLOBAL",
                "SET PERSIST",
                "SET @@",
                ", GLOBAL ",
                ", PERSIST",
                "INSTALL",
                "ALTER ",
                "RENAME ",
                "LOAD ",
            ] {
                // The one exception: the server-side cancel of the
                // agent's own statement on its other connection
                // (`KILL QUERY <id>`, nothing else).
                if w == "KILL"
                    && upper
                        .strip_prefix("KILL QUERY ")
                        .is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
                {
                    continue;
                }
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
                &["SHOW GRANTS FOR CURRENT_USER() USING 'app_read'@'%', \
                 'ops'@'10.0.0.0/255.0.0.0', 'r'@''"
                    .to_owned()][..]
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
        // A bad name anywhere in a long list: no statement at all.
        let mut roles = role_lists().remove(0);
        roles.push(("a'b".to_owned(), "%".to_owned()));
        assert_eq!(show_grants_using(&roles), None);
    }

    /// Security review of 914c9d2 (Low): the role list is split over
    /// statements of at most `MAX_OWN_STATEMENT` bytes by both measures,
    /// each role named once, in order, and a statement is closed only when
    /// the next role does not fit.
    #[test]
    fn role_lists_are_split_within_the_own_statement_bound() {
        for roles in role_lists() {
            let statements = show_grants_using(&roles).unwrap();
            let mut named = Vec::new();
            for (i, s) in statements.iter().enumerate() {
                assert!(server_audit_escaped_len(s) <= MAX_OWN_STATEMENT, "{s}");
                assert!(stored_len(s.as_bytes()) <= MAX_OWN_STATEMENT, "{s}");
                let list = s.strip_prefix(SHOW_GRANTS_USING).unwrap();
                let here: Vec<&str> = list.split(", ").collect();
                assert!(
                    !here.is_empty() && here.iter().all(|r| !r.is_empty()),
                    "{s}"
                );
                if let Some(next) = statements.get(i + 1) {
                    let first = next
                        .strip_prefix(SHOW_GRANTS_USING)
                        .unwrap()
                        .split(", ")
                        .next()
                        .unwrap();
                    let joined = format!("{s}, {first}");
                    assert!(
                        server_audit_escaped_len(&joined) > MAX_OWN_STATEMENT
                            || stored_len(joined.as_bytes()) > MAX_OWN_STATEMENT,
                        "{s}"
                    );
                }
                named.extend(here.into_iter().map(str::to_owned));
            }
            let want: Vec<String> = roles.iter().map(|(n, h)| format!("'{n}'@'{h}'")).collect();
            assert_eq!(named, want);
        }
        // 40 roles of 20 characters: more than one statement, where one
        // statement was cut before (1 315 bytes escaped).
        assert!(show_grants_using(&role_lists()[0]).unwrap().len() > 1);
        // The longest role alone, with the most escaping.
        let one = show_grants_using(&[("r".repeat(255), "h".repeat(255))]).unwrap();
        assert_eq!(one.len(), 1);
        assert!(server_audit_escaped_len(&one[0]) <= MAX_OWN_STATEMENT);
    }
}
