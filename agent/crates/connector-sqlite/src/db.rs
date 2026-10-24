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
    CELL_OVERHEAD, CatalogRow, Code, ColumnRow, Failure, MAX_CATALOG, MAX_NAME, MAX_RESPONSE,
    MAX_STATS, MAX_TABLE_COLUMNS, MAX_VALUE, PragmaInfo, RowidAlias, SampleRange, SampleRequest,
    Sampled,
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
    let conn = Connection::open_in_memory_with_flags(
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE,
    )
    .map_err(|_| Failure::new(Code::SelfCheckFailed))?;
    self_check_on(&conn, &expected()).map_err(|_| Failure::new(Code::SelfCheckFailed))
}

/// The self-check against `expected` on `conn` (the negative-control test
/// runs it against wrong expectations and a connection already changed).
///
/// # Errors
/// The first check that failed.
pub fn self_check_on(conn: &Connection, expected: &Expected) -> Result<(), SelfCheckFailure> {
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

fn install_authorizer(conn: &Connection, template: &Arc<Mutex<Template>>) -> Result<(), Failure> {
    let state = Arc::clone(template);
    conn.authorizer(Some(move |ctx: AuthContext<'_>| {
        let current = state.lock().map(|t| t.clone()).unwrap_or(Template::None);
        let action = match ctx.action {
            AuthAction::Select => Action::Select,
            AuthAction::Read { table_name, .. } => Action::Read { table: table_name },
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

/// An open, set-up connection to one declared file.
pub struct Db {
    conn: Connection,
    template: Arc<Mutex<Template>>,
    deadline: Arc<AtomicU64>,
    epoch: Instant,
    max_statement: Duration,
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
    let db = Db {
        conn,
        template: Arc::new(Mutex::new(Template::None)),
        deadline: Arc::new(AtomicU64::new(0)),
        epoch: Instant::now(),
        max_statement: Duration::from_millis(u64::from(max_statement_ms)),
    };
    db.setup()?;
    Ok(db)
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

impl Db {
    /// Decision 5's connection setup, in its order.
    fn setup(&self) -> Result<(), Failure> {
        let c = &self.conn;
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
        self.deadline.store(
            ms(self.epoch.elapsed() + self.max_statement),
            Ordering::Relaxed,
        );
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

    /// `sqlite_stat1` row counts, the first integer of `stat`.
    ///
    /// # Errors
    /// The mapped failure.
    pub fn stats(&self) -> Result<Vec<crate::ipc::StatRow>, Failure> {
        self.arm(Template::Stats);
        let out = (|| {
            let mut stmt = self.conn.prepare(sql::STATS).map_err(map_error)?;
            let mut rows = stmt.query([]).map_err(map_error)?;
            let mut out = Vec::new();
            let mut bytes = 0usize;
            while let Some(row) = rows.next().map_err(map_error)? {
                let (ValueRef::Text(tbl), ValueRef::Text(stat)) = (
                    row.get_ref(0).map_err(map_error)?,
                    row.get_ref(1).map_err(map_error)?,
                ) else {
                    continue;
                };
                let Some(n) = first_integer(stat) else {
                    continue;
                };
                if tbl.len() > MAX_NAME {
                    continue;
                }
                bytes += 12 + tbl.len();
                if out.len() >= MAX_STATS || bytes > SAMPLE_RESPONSE_BUDGET {
                    break;
                }
                out.push(crate::ipc::StatRow {
                    name: Zeroizing::new(tbl.to_vec()),
                    rows: n,
                });
            }
            Ok(out)
        })();
        self.disarm();
        out
    }

    /// `PRAGMA main.table_xinfo(<table>)`: `name`, `pk` and `hidden` only.
    ///
    /// # Errors
    /// The mapped failure; [`Code::Internal`] for a name that cannot be
    /// quoted.
    pub fn columns(&self, table: &[u8]) -> Result<Vec<ColumnRow>, Failure> {
        let text = sql::columns(table).ok_or_else(|| Failure::new(Code::Internal))?;
        let name = std::str::from_utf8(table).map_err(|_| Failure::new(Code::Internal))?;
        self.arm(Template::Columns(name.to_owned()));
        let out = (|| {
            let mut stmt = self.conn.prepare(&text).map_err(map_error)?;
            let mut rows = stmt.query([]).map_err(map_error)?;
            let mut out = Vec::new();
            while let Some(row) = rows.next().map_err(map_error)? {
                let name = match row.get_ref(1).map_err(map_error)? {
                    ValueRef::Text(t) if t.len() <= MAX_NAME => Zeroizing::new(t.to_vec()),
                    _ => Zeroizing::new(Vec::new()),
                };
                let int = |i: usize| match row.get_ref(i) {
                    Ok(ValueRef::Integer(v)) => v,
                    _ => 0,
                };
                out.push(ColumnRow {
                    name,
                    pk: int(5),
                    hidden: int(6),
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

    /// `min` / `max` of the rowid; [`Code::NoRowid`] for a `WITHOUT ROWID`
    /// table.
    ///
    /// # Errors
    /// The mapped failure.
    pub fn bounds(&self, table: &[u8], alias: RowidAlias) -> Result<Option<(i64, i64)>, Failure> {
        let text = sql::bounds(table, alias).ok_or_else(|| Failure::new(Code::Internal))?;
        let name = std::str::from_utf8(table).map_err(|_| Failure::new(Code::Internal))?;
        self.arm(Template::Read(name.to_owned()));
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
        out
    }

    /// One sampling statement of decision 5's closed list.
    ///
    /// # Errors
    /// The mapped failure.
    pub fn sample(&self, req: &SampleRequest) -> Result<Sampled, Failure> {
        let text = sql::sample(&req.table, req.alias, &req.columns, req.range)
            .ok_or_else(|| Failure::new(Code::Internal))?;
        let name = std::str::from_utf8(&req.table).map_err(|_| Failure::new(Code::Internal))?;
        let reverse = matches!(req.range, SampleRange::Plain { reverse: true });
        self.conn
            .set_db_config(DbConfig::SQLITE_DBCONFIG_REVERSE_SCANORDER, reverse)
            .map_err(map_error)?;
        self.arm(Template::Read(name.to_owned()));
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
            while let Some(row) = rows.next().map_err(map_error)? {
                if req.alias.is_some()
                    && let ValueRef::Integer(id) = row.get_ref(0).map_err(map_error)?
                {
                    out.last_rowid = Some(id);
                }
                for (i, col) in out.values.iter_mut().enumerate() {
                    let cell = match row.get_ref(first + i).map_err(map_error)? {
                        ValueRef::Text(t) => Some(cut(t)),
                        ValueRef::Integer(v) => Some(Zeroizing::new(sql::decimal(v).into_bytes())),
                        _ => None,
                    };
                    bytes += CELL_OVERHEAD + cell.as_ref().map_or(0, |c| c.len());
                    col.push(cell);
                }
                out.rows += 1;
                if bytes > SAMPLE_RESPONSE_BUDGET && out.rows < req.limit {
                    out.truncated = true;
                    break;
                }
            }
            Ok(out)
        })();
        self.disarm();
        let _ = self
            .conn
            .set_db_config(DbConfig::SQLITE_DBCONFIG_REVERSE_SCANORDER, false);
        out
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
/// UTF-8 is kept as it is, cut at the bound: the agent drops it).
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

/// The first decimal integer of a `sqlite_stat1.stat` text, at most 19
/// digits.
fn first_integer(stat: &[u8]) -> Option<u64> {
    let digits: Vec<u8> = stat
        .iter()
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect();
    if digits.is_empty() || digits.len() > 19 {
        return None;
    }
    std::str::from_utf8(&digits).ok()?.parse().ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn memory() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn the_self_check_passes_on_this_build() {
        self_check().unwrap();
        let e = expected();
        assert_eq!(e.version, "3.53.2");
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
            self_check_on(&memory(), &wrong),
            Err(SelfCheckFailure::Version)
        );
        let mut wrong = expected();
        wrong.source_id.push('x');
        assert_eq!(
            self_check_on(&memory(), &wrong),
            Err(SelfCheckFailure::Version)
        );
        let mut wrong = expected();
        wrong.required.push("ENABLE_SOMETHING_ABSENT".to_owned());
        assert_eq!(
            self_check_on(&memory(), &wrong),
            Err(SelfCheckFailure::MissingOption)
        );
        let mut wrong = expected();
        wrong.forbidden.push("THREADSAFE".to_owned());
        assert_eq!(
            self_check_on(&memory(), &wrong),
            Err(SelfCheckFailure::ForbiddenOption)
        );
        let changed = memory();
        changed.execute_batch("PRAGMA trusted_schema = 1").unwrap();
        assert_eq!(
            self_check_on(&changed, &expected()),
            Err(SelfCheckFailure::TrustedSchema)
        );
        let changed = memory();
        changed
            .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, false)
            .unwrap();
        assert_eq!(
            self_check_on(&changed, &expected()),
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

    #[test]
    fn stat_counts() {
        assert_eq!(first_integer(b"1200 3 1"), Some(1200));
        assert_eq!(first_integer(b"x"), None);
        assert_eq!(first_integer(b"99999999999999999999"), None);
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
