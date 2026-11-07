//! Every `rusqlite` call of the crate (ADR-0059 decisions 1, 3 and 5, and
//! security review L1): this module's functions return the crate's own
//! [`Failure`]; no `rusqlite::Error` leaves it. [`map_error`] is the one
//! exhaustive mapping of every `rusqlite::Error` variant to closed codes;
//! it keeps nothing else (the message of `SqliteFailure`, the path of
//! `InvalidPath`, the column name of `InvalidColumnName`, the text inside
//! `FromSqlConversionFailure` and `SqlInputError` are dropped there). No
//! `rusqlite::Error` is ever formatted (`Display` or `Debug`): the
//! architecture test `sqlite_errors_are_never_formatted` and this crate's
//! `clippy.toml` check it. `SQLITE_CONFIG_LOG` is never installed.
//!
//! Runs only in the reader process (and in this crate's in-process tests).

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rusqlite::config::DbConfig;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::limits::Limit;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use zeroize::Zeroizing;

use crate::auth::{self, Action, Template};
use crate::ipc::{
    CELL_OVERHEAD, CatalogRow, Code, ColumnExpr, ColumnRow, Failure, MAX_CATALOG, MAX_COLUMNS,
    MAX_NAME, MAX_RESPONSE, MAX_STATS, MAX_TABLE_COLUMNS, MAX_VALUE, PragmaInfo, RowidAlias,
    SampleRange, SampleRequest, Sampled,
};
use crate::sql;

/// Compile options `PRAGMA compile_options` must list (decision 1,
/// positive checks first).
pub const REQUIRED_OPTIONS: [&str; 5] = [
    "OMIT_LOAD_EXTENSION",
    "MAX_MMAP_SIZE=0",
    "THREADSAFE=1",
    "DEFAULT_CACHE_SIZE=-2048",
    "TEMP_STORE=3",
];
/// Compile options it must not list.
pub const FORBIDDEN_OPTIONS: [&str; 8] = [
    "ENABLE_LOAD_EXTENSION",
    "ENABLE_FTS3",
    "ENABLE_FTS5",
    "ENABLE_RTREE",
    "ENABLE_DBSTAT_VTAB",
    "ENABLE_DBPAGE_VTAB",
    "ENABLE_BYTECODE_VTAB",
    "ENABLE_CARRAY",
];

/// Busy timeout (decision 3).
pub const BUSY_TIMEOUT: Duration = Duration::from_millis(100);
/// Heap limit per reader process (decision 5).
pub const HARD_HEAP_LIMIT: i64 = 64 * 1024 * 1024;
/// Response bytes a sampling statement may fill before it stops (the
/// response bound, with room for the frame's own fields).
const SAMPLE_RESPONSE_BUDGET: usize = MAX_RESPONSE - 64 * 1024;

/// What the self-check expects: the library compiled into
/// `libsqlite3-sys`, and the compile options.
#[derive(Debug, Clone)]
pub struct Expected {
    /// `SQLITE_VERSION`.
    pub version: String,
    /// `SQLITE_SOURCE_ID`.
    pub source_id: String,
    /// Options that must be listed.
    pub required: Vec<String>,
    /// Options that must not be listed.
    pub forbidden: Vec<String>,
}

/// The expectations of this build: the version constants compiled into
/// `libsqlite3-sys` (the only use of `rusqlite::ffi` in the crate).
#[must_use]
pub fn expected() -> Expected {
    Expected {
        version: rusqlite::ffi::SQLITE_VERSION
            .to_str()
            .unwrap_or_default()
            .to_owned(),
        source_id: rusqlite::ffi::SQLITE_SOURCE_ID
            .to_str()
            .unwrap_or_default()
            .to_owned(),
        required: REQUIRED_OPTIONS.iter().map(|s| (*s).to_owned()).collect(),
        forbidden: FORBIDDEN_OPTIONS.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// Why the self-check failed (a closed kind, for the tests and the log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfCheckFailure {
    /// `sqlite_version()` or `sqlite_source_id()` differ from the
    /// compiled-in values (a system library linked by mistake).
    Version,
    /// A required option is missing.
    MissingOption,
    /// A forbidden option is listed.
    ForbiddenOption,
    /// `trusted_schema` does not read 0 by default.
    TrustedSchema,
    /// `SQLITE_DBCONFIG_DEFENSIVE` is not on by default.
    Defensive,
    /// A statement of the check failed.
    Statement,
}

/// The self-check of decision 1 on a fresh in-memory connection.
///
/// # Errors
/// [`Code::SelfCheckFailed`].
pub fn self_check() -> Result<(), Failure> {
    let mut conn = Connection::open_in_memory_with_flags(
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE,
    )
    .map_err(|_| Failure::new(Code::SelfCheckFailed))?;
    self_check_on(&mut conn, &expected()).map_err(|_| Failure::new(Code::SelfCheckFailed))
}

/// The self-check against `expected` on `conn` (the negative-control test
/// runs it against wrong expectations and a connection already changed).
///
/// # Errors
/// The first check that failed.
pub fn self_check_on(conn: &mut Connection, expected: &Expected) -> Result<(), SelfCheckFailure> {
    // Read before anything sets them: the compile-time defaults.
    let defensive = conn
        .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
        .map_err(|_| SelfCheckFailure::Statement)?;
    let template = Arc::new(Mutex::new(Template::SelfCheck));
    install_authorizer(conn, &template).map_err(|_| SelfCheckFailure::Statement)?;
    let trusted: i64 = conn
        .query_row(sql::SELF_TRUSTED_SCHEMA, [], |r| r.get(0))
        .map_err(|_| SelfCheckFailure::Statement)?;
    let (version, source): (String, String) = conn
        .query_row(sql::SELF_VERSION, [], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|_| SelfCheckFailure::Statement)?;
    let mut options = Vec::new();
    {
        let mut stmt = conn
            .prepare(sql::SELF_COMPILE_OPTIONS)
            .map_err(|_| SelfCheckFailure::Statement)?;
        let mut rows = stmt.query([]).map_err(|_| SelfCheckFailure::Statement)?;
        while let Some(row) = rows.next().map_err(|_| SelfCheckFailure::Statement)? {
            let o: String = row.get(0).map_err(|_| SelfCheckFailure::Statement)?;
            options.push(o);
            if options.len() > 512 {
                return Err(SelfCheckFailure::Statement);
            }
        }
    }
    if version != expected.version || source != expected.source_id {
        return Err(SelfCheckFailure::Version);
    }
    if !expected.required.iter().all(|r| options.contains(r)) {
        return Err(SelfCheckFailure::MissingOption);
    }
    // An option is listed as `NAME` or `NAME=value`.
    if options.iter().any(|o| {
        let name = o.split('=').next().unwrap_or(o);
        expected.forbidden.iter().any(|f| f == name)
    }) {
        return Err(SelfCheckFailure::ForbiddenOption);
    }
    if trusted != 0 {
        return Err(SelfCheckFailure::TrustedSchema);
    }
    if !defensive {
        return Err(SelfCheckFailure::Defensive);
    }
    Ok(())
}

/// The SQLite primary result codes the mapping looks at.
mod rc {
    pub(super) const ERROR: i32 = 1;
    pub(super) const BUSY: i32 = 5;
    pub(super) const LOCKED: i32 = 6;
    pub(super) const NOMEM: i32 = 7;
    pub(super) const READONLY: i32 = 8;
    pub(super) const INTERRUPT: i32 = 9;
    pub(super) const CORRUPT: i32 = 11;
    pub(super) const CANTOPEN: i32 = 14;
    pub(super) const TOOBIG: i32 = 18;
    pub(super) const AUTH: i32 = 23;
    pub(super) const NOTADB: i32 = 26;
    pub(super) const READONLY_RECOVERY: i32 = READONLY | (1 << 8);
    pub(super) const READONLY_ROLLBACK: i32 = READONLY | (3 << 8);
    pub(super) const READONLY_CANTINIT: i32 = READONLY | (5 << 8);
    pub(super) const READONLY_DIRECTORY: i32 = READONLY | (6 << 8);
    pub(super) const CANTOPEN_SYMLINK: i32 = CANTOPEN | (6 << 8);
}

/// The code of an SQLite failure, from its extended result code, and for
/// `SQLITE_ERROR` from fixed prefixes of its message (which is then
/// dropped, never kept).
fn sqlite_code(extended: i32, message: Option<&str>) -> Code {
    match extended & 0xff {
        rc::BUSY | rc::LOCKED => Code::Busy,
        rc::INTERRUPT => Code::Interrupted,
        rc::NOMEM => Code::NoMemory,
        rc::TOOBIG => Code::TooBig,
        rc::CORRUPT => Code::Corrupt,
        rc::NOTADB => Code::UnrecognizedFormat,
        rc::AUTH => Code::Auth,
        rc::READONLY => match extended {
            rc::READONLY_ROLLBACK => Code::HotJournal,
            rc::READONLY_RECOVERY | rc::READONLY_CANTINIT | rc::READONLY_DIRECTORY => {
                Code::WalNotReadable
            }
            _ => Code::Internal,
        },
        rc::CANTOPEN => {
            if extended == rc::CANTOPEN_SYMLINK {
                Code::PathRefused
            } else {
                Code::WalNotReadable
            }
        }
        rc::ERROR => match message {
            Some(m) if m.starts_with("access to view") => Code::ViewProhibited,
            Some(m) if m.starts_with("no such table") => Code::NoSuchTable,
            Some(m) if m.starts_with("no such column") => Code::NoRowid,
            Some(m) if m.starts_with("malformed database schema") => Code::UnrecognizedFormat,
            // A function of a column's DEFAULT or STORED expression denied
            // by the authorizer (`sqlite3FuncAuth`, SQLite 3.54+: plain
            // SQLITE_ERROR, not SQLITE_AUTH; ADR-0059 refinement of
            // 2026-11-07). The statement texts call only functions the
            // authorizer allows, so the name comes from the file's schema.
            Some(m) if m.starts_with("not authorized to use function") => {
                Code::SchemaFunctionRefused
            }
            // An authorizer answer other than OK, DENY or IGNORE
            // (`sqliteAuthBadReturnCode`). `rusqlite` 0.41.1 answers a
            // caught panic of its hook with SQLITE_ERROR, which is the same
            // value as SQLITE_DENY (1), so SQLite reads it as a denial
            // today; a version answering another code would land here
            // (security review L1 of #425): a denial all the same.
            Some(m) if m.starts_with("authorizer malfunction") => Code::Auth,
            _ => Code::Internal,
        },
        _ => Code::Internal,
    }
}

/// The one mapping of every `rusqlite::Error` variant (decision 5,
/// security review L1). Exhaustive over the variants of the version and
/// features used; the last arm is for a `#[non_exhaustive]` future one.
/// Only codes survive.
#[must_use]
pub fn map_error(e: rusqlite::Error) -> Failure {
    use rusqlite::Error as E;
    match e {
        E::SqliteFailure(f, message) => Failure {
            code: sqlite_code(f.extended_code, message.as_deref()),
            engine_code: Some(f.extended_code),
            rule: None,
        },
        E::SqlInputError { error, msg, .. } => Failure {
            code: sqlite_code(error.extended_code, Some(msg.as_str())),
            engine_code: Some(error.extended_code),
            rule: None,
        },
        E::SqliteSingleThreadedMode
        | E::FromSqlConversionFailure(..)
        | E::IntegralValueOutOfRange(..)
        | E::Utf8Error(..)
        | E::NulError(..)
        | E::InvalidParameterName(..)
        | E::InvalidPath(..)
        | E::ExecuteReturnedResults
        | E::QueryReturnedNoRows
        | E::QueryReturnedMoreThanOneRow
        | E::InvalidColumnIndex(..)
        | E::InvalidColumnName(..)
        | E::InvalidColumnType(..)
        | E::StatementChangedRows(..)
        | E::ToSqlConversionFailure(..)
        | E::InvalidQuery
        | E::UnwindingPanic
        | E::MultipleStatement
        | E::InvalidParameterCount(..)
        | E::InvalidDatabaseIndex(..) => Failure::new(Code::Internal),
        _ => Failure::new(Code::Internal),
    }
}

fn install_authorizer(
    conn: &mut Connection,
    template: &Arc<Mutex<Template>>,
) -> Result<(), Failure> {
    let state = Arc::clone(template);
    conn.authorizer(Some(move |ctx: AuthContext<'_>| {
        let current = state.lock().map(|t| t.clone()).unwrap_or(Template::None);
        let action = match ctx.action {
            AuthAction::Select => Action::Select,
            AuthAction::Read {
                table_name,
                column_name,
            } => Action::Read {
                table: table_name,
                column: column_name,
            },
            AuthAction::Function { function_name } => Action::Function {
                name: function_name,
            },
            AuthAction::Pragma {
                pragma_name,
                pragma_value,
            } => Action::Pragma {
                name: pragma_name,
                arg: pragma_value,
            },
            _ => Action::Other,
        };
        if auth::allowed(&current, action, ctx.database_name) {
            Authorization::Allow
        } else {
            Authorization::Deny
        }
    }))
    .map_err(map_error)
}

/// The schema texts `Db::schema_texts_are_utf8` checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Utf8Texts<'a> {
    /// Every column name (a statement naming the rowid).
    names: bool,
    /// The columns a sampling statement reads: when one of them has a
    /// `DEFAULT` or a generated expression, the table's own schema text.
    columns: &'a [Zeroizing<Vec<u8>>],
}

impl Utf8Texts<'static> {
    /// The rowid-bounds statement: names only (it reads no column, so no
    /// column expression is authorized).
    const ROWID: Self = Self {
        names: true,
        columns: &[],
    };
}

/// The longest schema text the reader copies to check (SQLite's own
/// `SQLITE_LIMIT_SQL_LENGTH` bound for a statement it parsed).
const MAX_SCHEMA_SQL: usize = 1_000_000;
/// The `table` rows of one name `SCHEMA_SQL` may return (one in a file
/// SQLite loads; more are checked all the same).
const MAX_SCHEMA_ROWS: usize = 4;

/// One `table_xinfo` row as the checks see it.
struct XinfoRow {
    /// The row as sent (its `expr` still [`ColumnExpr::None`]).
    row: ColumnRow,
    /// Whether the stored name is valid UTF-8.
    name_utf8: bool,
    /// Whether reading the column authorizes an expression's functions.
    expr: bool,
}

/// An open, set-up connection to one declared file.
pub struct Db {
    conn: Connection,
    template: Arc<Mutex<Template>>,
    deadline: Arc<AtomicU64>,
    epoch: Instant,
    max_statement: Duration,
    /// How many times the deadline was set (tests: one per request).
    #[cfg(test)]
    deadlines_set: std::sync::atomic::AtomicU32,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db").finish_non_exhaustive()
    }
}

/// Decision 2 step 5 to decision 5's setup: `sqlite3_open_v2` with
/// decision 3's flags and URI, `bind` (step 6, before any pragma or
/// statement), `Connection::path()` against the declared path, then the
/// connection setup.
///
/// # Errors
/// The mapped failure; the connection is closed.
pub fn open(
    path: &Path,
    max_statement_ms: u32,
    bind: impl FnOnce() -> Result<(), Failure>,
) -> Result<Db, Failure> {
    let bytes = crate::files::path_bytes(path);
    let uri = sql::uri(&bytes);
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_EXRESCODE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE;
    let conn = Connection::open_with_flags(&uri, flags).map_err(map_error)?;
    bind()?;
    if conn.path().map(str::as_bytes) != Some(bytes.as_slice()) {
        return Err(Failure::rule(
            Code::PathRefused,
            crate::ipc::Rule::DescriptorBinding,
        ));
    }
    let mut db = Db {
        conn,
        template: Arc::new(Mutex::new(Template::None)),
        deadline: Arc::new(AtomicU64::new(0)),
        epoch: Instant::now(),
        max_statement: Duration::from_millis(u64::from(max_statement_ms)),
        #[cfg(test)]
        deadlines_set: std::sync::atomic::AtomicU32::new(0),
    };
    db.setup()?;
    Ok(db)
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl Db {
    /// Decision 5's connection setup, in its order.
    fn setup(&mut self) -> Result<(), Failure> {
        let c = &mut self.conn;
        for (limit, value) in [
            (Limit::SQLITE_LIMIT_ATTACHED, 0),
            (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 8),
            (Limit::SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 50),
            (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 1),
            (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
            (Limit::SQLITE_LIMIT_VDBE_OP, 250_000),
            (Limit::SQLITE_LIMIT_LENGTH, 1_048_576),
            (Limit::SQLITE_LIMIT_SQL_LENGTH, 1_000_000),
        ] {
            c.set_limit(limit, value).map_err(map_error)?;
        }
        for (option, on) in [
            (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true),
            (DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE, false),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE, false),
            (DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true),
            (DbConfig::SQLITE_DBCONFIG_DQS_DML, false),
            (DbConfig::SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER, false),
            (DbConfig::SQLITE_DBCONFIG_WRITABLE_SCHEMA, false),
            (DbConfig::SQLITE_DBCONFIG_REVERSE_SCANORDER, false),
        ] {
            if c.set_db_config(option, on).map_err(map_error)? != on {
                return Err(Failure::new(Code::Internal));
            }
        }
        // Pragmas that do not read the schema.
        c.execute_batch(
            "PRAGMA query_only = ON; PRAGMA cell_size_check = ON; \
             PRAGMA automatic_index = OFF; PRAGMA trusted_schema = OFF",
        )
        .map_err(map_error)?;
        let heap: i64 = c
            .query_row("PRAGMA hard_heap_limit = 67108864", [], |r| r.get(0))
            .map_err(map_error)?;
        if heap != HARD_HEAP_LIMIT {
            return Err(Failure::new(Code::Internal));
        }
        c.busy_timeout(BUSY_TIMEOUT).map_err(map_error)?;
        let deadline = Arc::clone(&self.deadline);
        let epoch = self.epoch;
        c.progress_handler(
            1_000,
            Some(move || ms(epoch.elapsed()) > deadline.load(Ordering::Relaxed)),
        )
        .map_err(map_error)?;
        // Last: the setup statements above are the only assignments ever
        // made on this connection.
        install_authorizer(c, &self.template)
    }

    /// Arms the statement deadline and sets the template of the next
    /// statement.
    fn arm(&self, template: Template) {
        self.arm_deadline();
        self.set_template(template);
    }

    /// Arms the statement deadline: once per request, so that the
    /// statements of one request share it (decision 3: one statement
    /// deadline bounds one unit's lock time; the agent kills the reader at
    /// that deadline plus 2 s).
    fn arm_deadline(&self) {
        #[cfg(test)]
        self.deadlines_set.fetch_add(1, Ordering::Relaxed);
        self.deadline.store(
            ms(self.epoch.elapsed() + self.max_statement),
            Ordering::Relaxed,
        );
    }

    /// Sets the template of the next statement, under the deadline already
    /// armed.
    fn set_template(&self, template: Template) {
        if let Ok(mut t) = self.template.lock() {
            *t = template;
        }
    }

    fn disarm(&self) {
        if let Ok(mut t) = self.template.lock() {
            *t = Template::None;
        }
    }

    /// The catalog statement: `table` and `view` rows; `true` when cut (the
    /// object bound or the response bound).
    ///
    /// # Errors
    /// The mapped failure.
    pub fn catalog(&self) -> Result<(Vec<CatalogRow>, bool), Failure> {
        self.arm(Template::Catalog);
        let out = (|| {
            let mut stmt = self.conn.prepare(sql::CATALOG).map_err(map_error)?;
            let mut rows = stmt.query([]).map_err(map_error)?;
            let mut out = Vec::new();
            let mut bytes = 0usize;
            while let Some(row) = rows.next().map_err(map_error)? {
                let kind = match row.get_ref(0).map_err(map_error)? {
                    ValueRef::Text(t) => t,
                    _ => continue,
                };
                let view = kind == b"view";
                let name = match row.get_ref(1).map_err(map_error)? {
                    ValueRef::Text(t) if t.len() <= MAX_NAME => Zeroizing::new(t.to_vec()),
                    // A name that cannot travel: its object is not sampled.
                    _ => Zeroizing::new(Vec::new()),
                };
                let rootpage = match row.get_ref(2).map_err(map_error)? {
                    ValueRef::Integer(i) => i,
                    _ => 0,
                };
                bytes += 13 + name.len();
                if out.len() + 1 >= MAX_CATALOG || bytes > SAMPLE_RESPONSE_BUDGET {
                    return Ok((out, true));
                }
                out.push(CatalogRow {
                    view,
                    name,
                    rootpage,
                });
            }
            Ok((out, false))
        })();
        self.disarm();
        out
    }

    /// Before the statistics statement (ADR-0059 refinement of
    /// 2026-11-07, security review M1 of #425): `sqlite_stat1`'s schema
    /// text must be valid UTF-8 ([`Code::NameNotUtf8`]), and the table must
    /// have exactly the shape SQLite writes, `tbl`, `idx` and `stat`, plain
    /// columns without a `DEFAULT` or a generated expression
    /// ([`Code::StatsUnusable`]). A crafted `sqlite_stat1` could otherwise
    /// make the statement authorize an expression's functions: refused when
    /// off the list (the estimates silently lost), or a name that is not
    /// UTF-8 handed to `rusqlite`'s conversion.
    fn stat1_is_plain(&self) -> Result<(), Failure> {
        const STAT1: &str = "sqlite_stat1";
        self.schema_sql_is_utf8(STAT1)?;
        let cols = self.xinfo(STAT1.as_bytes(), STAT1)?;
        let expected: [&[u8]; 3] = [b"tbl", b"idx", b"stat"];
        let plain = cols.len() == expected.len()
            && cols.iter().zip(expected).all(|(c, e)| {
                c.row.name.as_slice().eq_ignore_ascii_case(e) && c.row.hidden == 0 && !c.expr
            });
        if plain {
            Ok(())
        } else {
            Err(Failure::new(Code::StatsUnusable))
        }
    }

    /// `sqlite_stat1` row counts, the first integer of `stat`, one per
    /// table (see [`StatsFold`]), once `sqlite_stat1` passes
    /// `stat1_is_plain`.
    ///
    /// # Errors
    /// The mapped failure; [`Code::StatsUnusable`] and
    /// [`Code::NameNotUtf8`] from `stat1_is_plain`.
    pub fn stats(&self) -> Result<Vec<crate::ipc::StatRow>, Failure> {
        self.arm_deadline();
        self.stat1_is_plain()?;
        self.set_template(Template::Stats);
        let out = (|| {
            let mut stmt = self.conn.prepare(sql::STATS).map_err(map_error)?;
            let mut rows = stmt.query([]).map_err(map_error)?;
            let mut fold = StatsFold::default();
            let mut read = 0usize;
            while let Some(row) = rows.next().map_err(map_error)? {
                read += 1;
                if read > MAX_STAT_ROWS_READ {
                    break;
                }
                let ValueRef::Text(tbl) = row.get_ref(0).map_err(map_error)? else {
                    continue;
                };
                let idx = match row.get_ref(1).map_err(map_error)? {
                    ValueRef::Null => None,
                    ValueRef::Text(i) => Some(i),
                    _ => continue,
                };
                let ValueRef::Text(stat) = row.get_ref(2).map_err(map_error)? else {
                    continue;
                };
                fold.add(tbl, idx, stat);
            }
            Ok(fold.finish())
        })();
        self.disarm();
        out
    }

    /// `PRAGMA main.table_xinfo(<table>)`: `name`, `pk` and `hidden`, and
    /// for each column the authorizer's verdict on its `DEFAULT` or
    /// `STORED` generated expression ([`ColumnExpr`], ADR-0059 refinement
    /// of 2026-11-07).
    ///
    /// The verdict is what SQLite itself does, observed without running
    /// anything: when an expression column can be sampled at all (a name
    /// it can quote), the table's own schema text must be valid UTF-8
    /// ([`Db::schema_sql_is_utf8`]; otherwise every expression column is
    /// [`ColumnExpr::NotUtf8`]); then the plain sampling statement for the
    /// expression columns, in groups of at most 64, is prepared and never
    /// stepped. SQLite authorizes each expression's functions while it
    /// prepares it; a group denied with "not authorized to use function"
    /// ([`Code::SchemaFunctionRefused`]) is prepared again column by
    /// column, and each denied column is [`ColumnExpr::Refused`]. So at
    /// most one prepare per expression column and one per group: bounded
    /// by [`MAX_TABLE_COLUMNS`], all under one statement deadline. Any
    /// other failure fails the request (fail closed); a denial that the
    /// schema text, checked again, explains is [`ColumnExpr::NotUtf8`].
    ///
    /// # Errors
    /// The mapped failure; [`Code::Internal`] for a name that cannot be
    /// quoted.
    pub fn columns(&self, table: &[u8]) -> Result<Vec<ColumnRow>, Failure> {
        let name = std::str::from_utf8(table).map_err(|_| Failure::new(Code::Internal))?;
        self.arm_deadline();
        let rows = self.xinfo(table, name)?;
        let candidate: Vec<bool> = rows
            .iter()
            .map(|r| r.expr && sql::quote(&r.row.name).is_some())
            .collect();
        let mut out: Vec<ColumnRow> = rows.into_iter().map(|r| r.row).collect();
        let names: Vec<&[u8]> = out
            .iter()
            .zip(&candidate)
            .filter(|(_, k)| **k)
            .map(|(c, _)| c.name.as_slice())
            .collect();
        if names.is_empty() {
            return Ok(out);
        }
        let verdicts = match self.schema_sql_is_utf8(name) {
            Ok(()) => self.probe_all(table, name, &names),
            Err(f) if f.code == Code::NameNotUtf8 => Ok(vec![ColumnExpr::NotUtf8; names.len()]),
            Err(f) => Err(f),
        }?;
        let mut verdicts = verdicts.into_iter();
        for (c, k) in out.iter_mut().zip(&candidate) {
            if *k {
                c.expr = verdicts.next().unwrap_or(ColumnExpr::Refused);
            }
        }
        Ok(out)
    }

    /// The verdicts of [`Db::columns`] for the expression columns `names`,
    /// in order.
    fn probe_all(
        &self,
        table: &[u8],
        name: &str,
        names: &[&[u8]],
    ) -> Result<Vec<ColumnExpr>, Failure> {
        let mut out = Vec::with_capacity(names.len());
        for group in names.chunks(MAX_COLUMNS) {
            match self.probe(table, name, group) {
                Ok(()) => out.extend(group.iter().map(|_| ColumnExpr::Listed)),
                Err(f) if f.code == Code::SchemaFunctionRefused => {
                    for col in group {
                        out.push(match self.probe(table, name, &[col]) {
                            Ok(()) => ColumnExpr::Listed,
                            Err(g) if g.code == Code::SchemaFunctionRefused => ColumnExpr::Refused,
                            Err(g) => return self.probe_failed(g, name, names.len()),
                        });
                    }
                }
                Err(f) => return self.probe_failed(f, name, names.len()),
            }
        }
        Ok(out)
    }

    /// A probe failed otherwise than by an unlisted function: a denial
    /// that the schema text, checked again, explains (the application
    /// changed it since) makes every expression column
    /// [`ColumnExpr::NotUtf8`]; anything else fails the request.
    fn probe_failed(&self, f: Failure, name: &str, n: usize) -> Result<Vec<ColumnExpr>, Failure> {
        if f.code == Code::Auth
            && matches!(self.schema_sql_is_utf8(name), Err(g) if g.code == Code::NameNotUtf8)
        {
            return Ok(vec![ColumnExpr::NotUtf8; n]);
        }
        Err(f)
    }

    /// Before a statement that reads `table`: the schema texts of the table
    /// that SQLite can hand to the authorizer must be valid UTF-8, or
    /// [`Code::NameNotUtf8`]. Every column name (`table_xinfo`, hidden
    /// columns included) when `texts.names` (a statement naming the rowid);
    /// the table's own schema text ([`Db::schema_sql_is_utf8`]) when one of
    /// `texts.columns` has a `DEFAULT` or a `STORED` generated expression.
    ///
    /// `rusqlite`'s authorizer hook converts each string argument with a
    /// panic on invalid UTF-8 (0.40.2 and 0.41.1; no bytes variant). That
    /// panic is caught by `rusqlite`, which answers SQLite `SQLITE_ERROR`,
    /// the same value as `SQLITE_DENY` (1): SQLite reads it as a denial, so
    /// the statement is refused, never allowed (were the answer another
    /// code, SQLite would report "authorizer malfunction", mapped to
    /// [`Code::Auth`] too). But the panic would abort a process whose panic
    /// hook aborts (a fuzz target) and report a hostile file as an
    /// authorizer bug. Two kinds of text from the file reach the authorizer:
    ///
    /// - When a statement names the rowid of a table that has an `INTEGER
    ///   PRIMARY KEY` column, SQLite hands that column's name, as stored in
    ///   the file's schema, to the authorizer (`sqlite3AuthRead`). The
    ///   columns the reader's statements name are always valid UTF-8
    ///   ([`sql::quote`]), and SQLite matches them only to a stored name
    ///   equal but for ASCII case, so the rowid alias is the only name from
    ///   the file the authorizer can receive there; every column is checked,
    ///   not only the primary key's, so the rule does not depend on which
    ///   column SQLite takes as the alias.
    /// - Since SQLite 3.54, reading a column with a `DEFAULT` or a `STORED`
    ///   generated expression hands every function name of that expression,
    ///   as written in the schema, to the authorizer (`sqlite3ColumnExprAuth`,
    ///   ADR-0059 refinement of 2026-11-07). Neither kind of expression
    ///   needs to name a known function: a `DEFAULT` is not resolved when
    ///   the schema is read, and while the schema is parsed SQLite does not
    ///   report an unknown function in a generated expression either (so
    ///   `g\xe4(a)` in a `STORED` expression loads). `table_xinfo` gives no
    ///   text for a generated column, so the table's own `sql` is checked,
    ///   whole: every expression's text is a part of it.
    ///
    /// It runs under the deadline its caller armed for the whole request
    /// (`arm_deadline`), never one of its own.
    ///
    /// Residual race (fail closed): the application can change the schema
    /// to such a text between this check and the prepare of the statement.
    /// The panic is then caught as above and the statement is denied
    /// (`SQLITE_AUTH`); `after_read_statement` checks the texts once more
    /// and reports [`Code::NameNotUtf8`] rather than [`Code::Auth`] when it
    /// finds such a text.
    fn schema_texts_are_utf8(
        &self,
        table: &[u8],
        name: &str,
        texts: Utf8Texts<'_>,
    ) -> Result<(), Failure> {
        if !texts.names && texts.columns.is_empty() {
            return Ok(());
        }
        let cols = self.xinfo(table, name)?;
        if texts.names && cols.iter().any(|c| !c.name_utf8) {
            return Err(Failure::new(Code::NameNotUtf8));
        }
        // A requested column is matched as SQLite matches it (equal but for
        // ASCII case), so more columns match, never fewer.
        let reads_expr = cols.iter().any(|c| {
            c.expr
                && texts
                    .columns
                    .iter()
                    .any(|r| r.as_slice().eq_ignore_ascii_case(&c.row.name))
        });
        if reads_expr {
            self.schema_sql_is_utf8(name)?;
        }
        Ok(())
    }

    /// `PRAGMA main.table_xinfo(<table>)` under the deadline already armed:
    /// each column, whether its name is valid UTF-8, and whether reading it
    /// makes SQLite authorize an expression's functions (a `DEFAULT` on a
    /// plain column, or a `STORED` generated column). The `DEFAULT` text is
    /// only tested for presence, never kept.
    fn xinfo(&self, table: &[u8], name: &str) -> Result<Vec<XinfoRow>, Failure> {
        let text = sql::columns(table).ok_or_else(|| Failure::new(Code::Internal))?;
        self.set_template(Template::Columns(name.to_owned()));
        let out = (|| {
            let mut stmt = self.conn.prepare(&text).map_err(map_error)?;
            let mut rows = stmt.query([]).map_err(map_error)?;
            let mut out = Vec::new();
            while let Some(row) = rows.next().map_err(map_error)? {
                let (name, name_utf8) = match row.get_ref(1).map_err(map_error)? {
                    ValueRef::Text(t) => (
                        if t.len() <= MAX_NAME {
                            Zeroizing::new(t.to_vec())
                        } else {
                            Zeroizing::new(Vec::new())
                        },
                        std::str::from_utf8(t).is_ok(),
                    ),
                    _ => (Zeroizing::new(Vec::new()), false),
                };
                let int = |i: usize| match row.get_ref(i) {
                    Ok(ValueRef::Integer(v)) => v,
                    _ => 0,
                };
                let hidden = int(6);
                let default = !matches!(row.get_ref(4).map_err(map_error)?, ValueRef::Null);
                out.push(XinfoRow {
                    row: ColumnRow {
                        name,
                        pk: int(5),
                        hidden,
                        expr: ColumnExpr::None,
                    },
                    name_utf8,
                    // Hidden 1 (a virtual table's) and 2 (VIRTUAL generated)
                    // are never sampled; any other value with a DEFAULT,
                    // and 3 (STORED), is an expression column.
                    expr: hidden == 3 || (default && hidden != 1 && hidden != 2),
                });
                if out.len() > MAX_TABLE_COLUMNS {
                    return Err(Failure::new(Code::TooBig));
                }
            }
            Ok(out)
        })();
        self.disarm();
        out
    }

    /// The ADR-0059 refinement of 2026-11-07's exception: the `sql` of the
    /// `table` rows named `name` (ASCII case folded, as SQLite resolves
    /// it), under the deadline already armed, must be valid UTF-8, or
    /// [`Code::NameNotUtf8`]. The text is copied into a zeroizing buffer,
    /// checked, and dropped: the only result is the verdict. A row whose
    /// `sql` is not text, or longer than [`MAX_SCHEMA_SQL`], fails the
    /// check; no row is [`Code::NoSuchTable`].
    fn schema_sql_is_utf8(&self, name: &str) -> Result<(), Failure> {
        self.set_template(Template::Schema);
        let out = (|| {
            let mut stmt = self.conn.prepare(sql::SCHEMA_SQL).map_err(map_error)?;
            let mut rows = stmt.query([name]).map_err(map_error)?;
            let mut n = 0usize;
            while let Some(row) = rows.next().map_err(map_error)? {
                n += 1;
                if n > MAX_SCHEMA_ROWS {
                    return Err(Failure::new(Code::NameNotUtf8));
                }
                let ValueRef::Text(t) = row.get_ref(0).map_err(map_error)? else {
                    return Err(Failure::new(Code::NameNotUtf8));
                };
                if t.len() > MAX_SCHEMA_SQL {
                    return Err(Failure::new(Code::NameNotUtf8));
                }
                let text: Zeroizing<Vec<u8>> = Zeroizing::new(t.to_vec());
                if std::str::from_utf8(&text).is_err() {
                    return Err(Failure::new(Code::NameNotUtf8));
                }
            }
            if n == 0 {
                return Err(Failure::new(Code::NoSuchTable));
            }
            Ok(())
        })();
        self.disarm();
        out
    }

    /// Prepares, never steps, the plain sampling statement for `columns` of
    /// `table` under the sampling template, under the deadline already
    /// armed: SQLite authorizes the functions of their expressions while it
    /// prepares it ([`Db::columns`]).
    fn probe(&self, table: &[u8], name: &str, columns: &[&[u8]]) -> Result<(), Failure> {
        let text = sql::sample(table, None, columns, SampleRange::Plain { reverse: false })
            .ok_or_else(|| Failure::new(Code::Internal))?;
        self.set_template(Template::Read(name.to_owned()));
        let out = self.conn.prepare(&text).map(drop).map_err(map_error);
        self.disarm();
        out
    }

    /// `min` / `max` of the rowid; [`Code::NoRowid`] for a `WITHOUT ROWID`
    /// table, [`Code::NameNotUtf8`] for a table with a column name that is
    /// not UTF-8 (`schema_texts_are_utf8`).
    ///
    /// # Errors
    /// The mapped failure.
    pub fn bounds(&self, table: &[u8], alias: RowidAlias) -> Result<Option<(i64, i64)>, Failure> {
        let text = sql::bounds(table, alias).ok_or_else(|| Failure::new(Code::Internal))?;
        let name = std::str::from_utf8(table).map_err(|_| Failure::new(Code::Internal))?;
        self.arm_deadline();
        self.schema_texts_are_utf8(table, name, Utf8Texts::ROWID)?;
        self.set_template(Template::Bounds(name.to_owned()));
        let out = self
            .conn
            .query_row(&text, [], |r| {
                Ok(match (r.get_ref(0)?, r.get_ref(1)?) {
                    (ValueRef::Integer(lo), ValueRef::Integer(hi)) => Some((lo, hi)),
                    _ => None,
                })
            })
            .map_err(map_error);
        self.disarm();
        self.after_read_statement(out, table, name, Utf8Texts::ROWID)
    }

    /// After a statement whose texts passed `schema_texts_are_utf8`: a
    /// denial (`Code::Auth`) is checked once more, under the same deadline,
    /// and reported as [`Code::NameNotUtf8`] when a checked text is no
    /// longer valid UTF-8 (the application changed the schema in between).
    fn after_read_statement<T>(
        &self,
        out: Result<T, Failure>,
        table: &[u8],
        name: &str,
        texts: Utf8Texts<'_>,
    ) -> Result<T, Failure> {
        match out {
            Err(f) if f.code == Code::Auth => {
                match self.schema_texts_are_utf8(table, name, texts) {
                    Err(g) if g.code == Code::NameNotUtf8 => Err(g),
                    _ => Err(f),
                }
            }
            other => other,
        }
    }

    /// One sampling statement of decision 5's closed list; one by the
    /// rowid is refused with [`Code::NameNotUtf8`] as [`Db::bounds`] is,
    /// and one reading a column with a `DEFAULT` or a `STORED` expression
    /// when the table's schema text is not valid UTF-8
    /// (`schema_texts_are_utf8`).
    ///
    /// # Errors
    /// The mapped failure.
    pub fn sample(&self, req: &SampleRequest) -> Result<Sampled, Failure> {
        let text = sql::sample(&req.table, req.alias, &req.columns, req.range)
            .ok_or_else(|| Failure::new(Code::Internal))?;
        let name = std::str::from_utf8(&req.table).map_err(|_| Failure::new(Code::Internal))?;
        self.arm_deadline();
        let texts = Utf8Texts {
            names: req.alias.is_some(),
            columns: &req.columns,
        };
        self.schema_texts_are_utf8(&req.table, name, texts)?;
        let reverse = matches!(req.range, SampleRange::Plain { reverse: true });
        self.conn
            .set_db_config(DbConfig::SQLITE_DBCONFIG_REVERSE_SCANORDER, reverse)
            .map_err(map_error)?;
        self.set_template(Template::Read(name.to_owned()));
        let out = (|| {
            let mut stmt = self.conn.prepare(&text).map_err(map_error)?;
            let limit = i64::from(req.limit);
            let mut rows = match req.range {
                SampleRange::From(a) | SampleRange::Below(a) => {
                    stmt.query(rusqlite::params![a, limit])
                }
                SampleRange::Between(a, b) => stmt.query(rusqlite::params![a, b, limit]),
                SampleRange::Plain { .. } => stmt.query(rusqlite::params![limit]),
            }
            .map_err(map_error)?;
            let first = usize::from(req.alias.is_some());
            let mut out = Sampled {
                values: req.columns.iter().map(|_| Vec::new()).collect(),
                ..Sampled::default()
            };
            let mut bytes = 0usize;
            let mut cells: Vec<Option<Zeroizing<Vec<u8>>>> = Vec::with_capacity(out.values.len());
            while let Some(row) = rows.next().map_err(map_error)? {
                let rowid = match req.alias {
                    Some(_) => match row.get_ref(0).map_err(map_error)? {
                        ValueRef::Integer(id) => Some(id),
                        _ => None,
                    },
                    None => None,
                };
                cells.clear();
                let mut row_bytes = 0usize;
                for i in 0..out.values.len() {
                    let cell = match row.get_ref(first + i).map_err(map_error)? {
                        ValueRef::Text(t) => Some(cut(t)),
                        ValueRef::Integer(v) => Some(Zeroizing::new(sql::decimal(v).into_bytes())),
                        _ => None,
                    };
                    row_bytes += CELL_OVERHEAD + cell.as_ref().map_or(0, |c| c.len());
                    cells.push(cell);
                }
                // Review N2: the budget is checked before the row is added.
                // A row that would pass it is left for the continuation
                // (from the last rowid kept); the first row of a response
                // is always kept (at most 64 values of 4 096 bytes, far
                // below the budget).
                if out.rows > 0 && bytes + row_bytes > SAMPLE_RESPONSE_BUDGET {
                    out.truncated = true;
                    break;
                }
                bytes += row_bytes;
                if rowid.is_some() {
                    out.last_rowid = rowid;
                }
                for (col, cell) in out.values.iter_mut().zip(cells.drain(..)) {
                    col.push(cell);
                }
                out.rows += 1;
            }
            Ok(out)
        })();
        self.disarm();
        let _ = self
            .conn
            .set_db_config(DbConfig::SQLITE_DBCONFIG_REVERSE_SCANORDER, false);
        self.after_read_statement(out, &req.table, name, texts)
    }

    /// The check pragmas.
    ///
    /// # Errors
    /// The mapped failure.
    pub fn pragmas(&self) -> Result<PragmaInfo, Failure> {
        let text = |stmt: &'static str, name: &'static str| -> Result<Vec<u8>, Failure> {
            self.arm(Template::Pragma(name));
            let out = self
                .conn
                .query_row(stmt, [], |r| {
                    Ok(match r.get_ref(0)? {
                        ValueRef::Text(t) => t.to_vec(),
                        ValueRef::Integer(i) => sql::decimal(i).into_bytes(),
                        _ => Vec::new(),
                    })
                })
                .map_err(map_error);
            self.disarm();
            out
        };
        let int = |v: Vec<u8>| -> i64 {
            std::str::from_utf8(&v)
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        };
        let journal = text(sql::PRAGMA_JOURNAL_MODE, "journal_mode")?;
        let schema_version = int(text(sql::PRAGMA_SCHEMA_VERSION, "schema_version")?);
        let page_size = int(text(sql::PRAGMA_PAGE_SIZE, "page_size")?);
        let encoding = match text(sql::PRAGMA_ENCODING, "encoding")?.as_slice() {
            b"UTF-8" => 1,
            b"UTF-16le" => 2,
            b"UTF-16be" => 3,
            _ => 0,
        };
        Ok(PragmaInfo {
            wal: journal.eq_ignore_ascii_case(b"wal"),
            schema_version,
            page_size,
            encoding,
        })
    }
}

/// A value cut to [`MAX_VALUE`] bytes on a character boundary (invalid
/// UTF-8 is kept as it is, cut at the bound: the agent classifies it with
/// its invalid sequences replaced, review L3).
fn cut(t: &[u8]) -> Zeroizing<Vec<u8>> {
    if t.len() <= MAX_VALUE {
        return Zeroizing::new(t.to_vec());
    }
    let mut end = MAX_VALUE;
    // Back to the start of a UTF-8 sequence.
    while end > 0 && t.get(end).is_some_and(|b| b & 0xC0 == 0x80) {
        end -= 1;
    }
    Zeroizing::new(t.get(..end).unwrap_or_default().to_vec())
}

/// Most `sqlite_stat1` rows the statistics statement reads (one per index
/// and per table without a full index, so several per table).
const MAX_STAT_ROWS_READ: usize = 10 * MAX_STATS;

/// Folds `sqlite_stat1` rows into one row count per table.
///
/// `ANALYZE` writes, per table, one row per index (`idx` the index name,
/// the first integer of `stat` its entries) and, only when the table has
/// no index without a `WHERE` clause, one row with a NULL `idx` (the
/// table's rows). A `WITHOUT ROWID` table's primary key row has `idx`
/// equal to `tbl`. So the table's own row (NULL `idx`, or `idx = tbl`)
/// is its count when present; otherwise the table has a full index,
/// whose entries are the table's rows, and a partial index has fewer:
/// the largest index count is the table's. A table with no row (never
/// analyzed, or empty when analyzed) gets no estimate.
#[derive(Default)]
pub(crate) struct StatsFold {
    out: Vec<crate::ipc::StatRow>,
    /// Per table in `out`: whether its count is its own row's.
    own: Vec<bool>,
    /// Indexes into `out` by a hash of the name (the names stay in `out`
    /// only, zeroized there).
    at: std::collections::HashMap<u64, Vec<usize>>,
    hasher: std::collections::hash_map::RandomState,
    bytes: usize,
}

impl StatsFold {
    /// Adds one row: `false` when it is not kept (unparseable, or a new
    /// table once the response bounds are reached; the tables already
    /// kept are still updated, so the order of the rows cannot hide an
    /// index row of theirs).
    pub(crate) fn add(&mut self, tbl: &[u8], idx: Option<&[u8]>, stat: &[u8]) -> bool {
        let Some(n) = first_integer(stat) else {
            return false;
        };
        if tbl.is_empty() || tbl.len() > MAX_NAME {
            return false;
        }
        let own = idx.is_none_or(|i| i == tbl);
        let key = {
            use std::hash::{BuildHasher, Hasher};
            let mut h = self.hasher.build_hasher();
            h.write(tbl);
            h.finish()
        };
        let found = self.at.get(&key).and_then(|c| {
            c.iter()
                .copied()
                .find(|&i| self.out.get(i).is_some_and(|r| r.name.as_slice() == tbl))
        });
        if let Some(i) = found {
            let (Some(row), Some(was_own)) = (self.out.get_mut(i), self.own.get_mut(i)) else {
                return false;
            };
            if own && !*was_own {
                row.rows = n;
                *was_own = true;
            } else if own == *was_own {
                row.rows = row.rows.max(n);
            }
            return true;
        }
        let bytes = self.bytes + 12 + tbl.len();
        if self.out.len() >= MAX_STATS || bytes > SAMPLE_RESPONSE_BUDGET {
            return false;
        }
        self.bytes = bytes;
        self.at.entry(key).or_default().push(self.out.len());
        self.out.push(crate::ipc::StatRow {
            name: Zeroizing::new(tbl.to_vec()),
            rows: n,
        });
        self.own.push(own);
        true
    }

    /// The row counts, in the order their tables were first read.
    pub(crate) fn finish(self) -> Vec<crate::ipc::StatRow> {
        self.out
    }
}

/// The first decimal integer of a `sqlite_stat1.stat` text, at most 19
/// digits.
fn first_integer(stat: &[u8]) -> Option<u64> {
    let digits: Vec<u8> = stat
        .iter()
        .copied()
        .take_while(u8::is_ascii_digit)
        .take(20)
        .collect();
    if digits.is_empty() || digits.len() > 19 {
        return None;
    }
    std::str::from_utf8(&digits).ok()?.parse().ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// ADR-0059 refinement of 2026-11-07: SQLite 3.54 reports a function of
    /// a column's `DEFAULT` or `STORED` expression denied by the authorizer
    /// as `SQLITE_ERROR` with this message; it is mapped to
    /// `schema_function_refused` (security review L3 of #425), other errors
    /// are not.
    #[test]
    fn a_denied_schema_expression_function_is_auth() {
        assert_eq!(
            sqlite_code(
                rc::ERROR,
                Some("not authorized to use function: randomblob(16)")
            ),
            Code::SchemaFunctionRefused
        );
        // Security review L1 of #425: an authorizer answer SQLite does not
        // know (a caught panic answered with another code) is a denial.
        assert_eq!(
            sqlite_code(rc::ERROR, Some("authorizer malfunction")),
            Code::Auth
        );
        assert_eq!(sqlite_code(rc::AUTH, Some("not authorized")), Code::Auth);
        assert_eq!(
            sqlite_code(rc::ERROR, Some("near \"x\": syntax error")),
            Code::Internal
        );
        assert_eq!(sqlite_code(rc::ERROR, None), Code::Internal);
    }

    /// Review L1 of #423: the names check and the rowid statement of one
    /// request share one deadline (armed once), in bounds and in a rowid
    /// sample; review L2: a denial after a passed check is reported as
    /// `name_not_utf8` when the names are now bad, and stays `auth`
    /// otherwise.
    #[test]
    fn a_rowid_request_arms_one_deadline_and_rechecks_a_denial() {
        let d = crate::it::Dir::new("db-rowid-deadline");
        let good = d.path("good.db");
        crate::it::non_utf8_schema(
            &good,
            "CREATE TABLE t (i INTEGER PRIMARY KEY, a TEXT, b TEXT)",
            b"CREATE TABLE t (i INTEGER PRIMARY KEY, a TEXT, b TEXT)",
        );
        let db = open(&good, 60_000, || Ok(())).unwrap();
        let sets = || db.deadlines_set.load(Ordering::Relaxed);
        let before = sets();
        let deadline = |db: &Db| db.deadline.load(Ordering::Relaxed);
        assert_eq!(db.bounds(b"t", RowidAlias::Rowid), Ok(Some((1, 2))));
        assert_eq!(sets(), before + 1);
        let armed = deadline(&db);
        let req = SampleRequest {
            table: Zeroizing::new(b"t".to_vec()),
            alias: Some(RowidAlias::Rowid),
            columns: vec![Zeroizing::new(b"a".to_vec())],
            range: SampleRange::From(1),
            limit: 5,
        };
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(db.sample(&req).unwrap().rows, 2);
        assert_eq!(sets(), before + 2);
        assert!(deadline(&db) > armed);
        // A denial with valid names stays `auth`; other results pass.
        let auth = || Err::<(), _>(Failure::new(Code::Auth));
        assert_eq!(
            db.after_read_statement(auth(), b"t", "t", Utf8Texts::ROWID)
                .unwrap_err()
                .code,
            Code::Auth
        );
        assert_eq!(
            db.after_read_statement(Ok(3), b"t", "t", Utf8Texts::ROWID),
            Ok(3)
        );
        assert_eq!(sets(), before + 2);
        let bad = d.path("bad.db");
        crate::it::non_utf8_schema(
            &bad,
            "CREATE TABLE t (i INTEGER PRIMARY KEY, a TEXT, b TEXT)",
            b"CREATE TABLE t (i\xff INTEGER PRIMARY KEY, a TEXT, b TEXT)",
        );
        let db = open(&bad, 60_000, || Ok(())).unwrap();
        assert_eq!(
            db.after_read_statement(auth(), b"t", "t", Utf8Texts::ROWID)
                .unwrap_err()
                .code,
            Code::NameNotUtf8
        );
        // The re-check arms no deadline of its own.
        assert_eq!(db.deadlines_set.load(Ordering::Relaxed), 0);
    }

    fn memory() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn the_self_check_passes_on_this_build() {
        self_check().unwrap();
        let e = expected();
        assert_eq!(e.version, "3.54.1");
        assert!(!e.source_id.is_empty());
    }

    /// Decision 1's negative control: the same check fails against wrong
    /// expectations and against a connection whose `trusted_schema` was
    /// set, so it cannot pass everything.
    #[test]
    fn the_self_check_fails_closed() {
        let mut wrong = expected();
        wrong.version = "3.40.1".to_owned();
        assert_eq!(
            self_check_on(&mut memory(), &wrong),
            Err(SelfCheckFailure::Version)
        );
        let mut wrong = expected();
        wrong.source_id.push('x');
        assert_eq!(
            self_check_on(&mut memory(), &wrong),
            Err(SelfCheckFailure::Version)
        );
        let mut wrong = expected();
        wrong.required.push("ENABLE_SOMETHING_ABSENT".to_owned());
        assert_eq!(
            self_check_on(&mut memory(), &wrong),
            Err(SelfCheckFailure::MissingOption)
        );
        let mut wrong = expected();
        wrong.forbidden.push("THREADSAFE".to_owned());
        assert_eq!(
            self_check_on(&mut memory(), &wrong),
            Err(SelfCheckFailure::ForbiddenOption)
        );
        let mut changed = memory();
        changed.execute_batch("PRAGMA trusted_schema = 1").unwrap();
        assert_eq!(
            self_check_on(&mut changed, &expected()),
            Err(SelfCheckFailure::TrustedSchema)
        );
        let mut changed = memory();
        changed
            .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, false)
            .unwrap();
        assert_eq!(
            self_check_on(&mut changed, &expected()),
            Err(SelfCheckFailure::Defensive)
        );
    }

    #[test]
    fn values_are_cut_on_a_character_boundary() {
        let s = "é".repeat(3000);
        let c = cut(s.as_bytes());
        assert!(c.len() <= MAX_VALUE);
        assert!(std::str::from_utf8(&c).is_ok());
        assert_eq!(cut(b"abc").as_slice(), b"abc");
    }

    /// One `sqlite_stat1` row: `tbl`, `idx`, `stat`.
    type StatInput<'a> = (&'a [u8], Option<&'a [u8]>, &'a [u8]);

    fn stats_fold(rows: &[StatInput<'_>]) -> Vec<(Vec<u8>, u64)> {
        let mut f = StatsFold::default();
        for (t, i, s) in rows {
            f.add(t, *i, s);
        }
        f.finish()
            .into_iter()
            .map(|r| (r.name.to_vec(), r.rows))
            .collect()
    }

    /// The rows `ANALYZE` writes (SQLite 3.53.2, checked by
    /// `it::row_estimates_cover_tables_with_an_index`), folded to one
    /// count per table.
    #[test]
    fn stat_rows_fold_to_the_table_count() {
        let got = stats_fold(&[
            // No index: the table's own row.
            (b"plain", None, b"10"),
            // A full and a partial index, no own row: the largest count.
            (b"indexed", Some(b"partial_i"), b"4 1"),
            (b"indexed", Some(b"full_i"), b"10 1"),
            // Only a partial index: its own row is written and wins.
            (b"part_only", Some(b"p_i"), b"6 1"),
            (b"part_only", None, b"10"),
            // WITHOUT ROWID: the primary key's row has idx = tbl and wins
            // over a larger, hostile index row.
            (b"wr", Some(b"wr_v"), b"99 1"),
            (b"wr", Some(b"wr"), b"10 1"),
            // An unparseable stat, a too-long name: ignored.
            (b"bad", Some(b"bad_i"), b"x 1"),
            (&[b'n'; MAX_NAME + 1], None, b"5"),
            (b"", None, b"5"),
        ]);
        assert_eq!(
            got,
            [
                (b"plain".to_vec(), 10),
                (b"indexed".to_vec(), 10),
                (b"part_only".to_vec(), 10),
                (b"wr".to_vec(), 10),
            ]
        );
    }

    #[test]
    fn stat_rows_are_bounded_by_table() {
        let mut f = StatsFold::default();
        for i in 0..MAX_STATS {
            let t = format!("t{i}");
            assert!(f.add(t.as_bytes(), Some(b"i"), b"1"));
            // A second row of the same table costs no entry.
            assert!(f.add(t.as_bytes(), Some(b"j"), b"2"));
        }
        // Full: a new table is refused, ...
        assert!(!f.add(b"new", None, b"9"));
        // ... but the tables kept are still updated, by their own row and
        // by a larger index count.
        assert!(f.add(b"t0", None, b"7"));
        assert!(f.add(b"t1", Some(b"k"), b"5"));
        let out = f.finish();
        assert_eq!(out.len(), MAX_STATS);
        assert!(!out.iter().any(|r| r.name.as_slice() == b"new"));
        assert_eq!(out.first().map(|r| r.rows), Some(7));
        assert_eq!(out.get(1).map(|r| r.rows), Some(5));
        assert_eq!(out.get(2).map(|r| r.rows), Some(2));
    }

    #[test]
    fn stat_counts() {
        assert_eq!(first_integer(b"1200 3 1"), Some(1200));
        assert_eq!(first_integer(b"x"), None);
        assert_eq!(first_integer(b"99999999999999999999"), None);
        assert_eq!(
            first_integer(b"1234567890123456789"),
            Some(1_234_567_890_123_456_789)
        );
        // A long run of digits is cut at 20 and refused, never collected.
        assert_eq!(first_integer(&[b'1'; 100_000]), None);
    }

    /// No message survives the mapping (security review L1).
    #[test]
    fn errors_keep_codes_only() {
        let c = memory();
        let secret = "jean.richard@example.com";
        let e = c
            .execute_batch(&format!("SELECT * FROM \"{secret}\""))
            .unwrap_err();
        let f = map_error(e);
        assert_eq!(f.code, Code::NoSuchTable);
        assert_eq!(f.engine_code, Some(1));
        let e = c
            .query_row("SELECT 1", [], |r| r.get::<_, String>(5))
            .unwrap_err();
        assert_eq!(map_error(e).code, Code::Internal);
        for (ext, code) in [
            (5, Code::Busy),
            (6, Code::Busy),
            (9, Code::Interrupted),
            (7, Code::NoMemory),
            (18, Code::TooBig),
            (11, Code::Corrupt),
            (267, Code::Corrupt),
            (26, Code::UnrecognizedFormat),
            (776, Code::HotJournal),
            (264, Code::WalNotReadable),
            (1288, Code::WalNotReadable),
            (1544, Code::WalNotReadable),
            (14, Code::WalNotReadable),
            (1550, Code::PathRefused),
            (23, Code::Auth),
            (2, Code::Internal),
        ] {
            assert_eq!(sqlite_code(ext, Some("anything")), code, "{ext}");
        }
    }
}
