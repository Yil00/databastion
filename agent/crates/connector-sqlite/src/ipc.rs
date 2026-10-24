//! The IPC protocol between the agent and its SQLite reader process
//! (ADR-0059 decision 4): length-prefixed frames (a 4-byte big-endian
//! length) over the `UnixStream::pair()` passed as the reader's standard
//! input, at most [`MAX_REQUEST`] bytes per request and [`MAX_RESPONSE`]
//! per response, decoded by this module's own bounded decoder (no `serde`
//! format), with a closed set of messages.
//!
//! Raw names (at most [`MAX_NAME`] bytes) and raw values (at most
//! [`MAX_VALUE`] bytes) cross this channel in zeroizing buffers; the agent
//! normalizes the names and classifies and masks the values (I2). A frame
//! over its bound, an unknown message or a malformed field is a protocol
//! violation: the agent kills the reader, the reader exits.
//!
//! The socket itself is created only here, on the agent side
//! ([`socket_pair`]): the architecture test allows `UnixStream` in this
//! module only, as `UnixStream::pair`.

use zeroize::Zeroizing;

/// Largest request frame (decision 4).
pub const MAX_REQUEST: usize = 64 * 1024;
/// Largest response frame (decision 4).
pub const MAX_RESPONSE: usize = 1024 * 1024;
/// Longest raw name (decision 4).
pub const MAX_NAME: usize = 1_024;
/// Longest raw value (decision 4).
pub const MAX_VALUE: usize = 4_096;
/// Most columns per sampling statement (decision 6).
pub const MAX_COLUMNS: usize = 64;
/// Most rows a sampling response may carry (`limits.max_sample_rows`).
pub const MAX_ROWS: u32 = 10_000;
/// Most catalog rows read per scan (decision 6), plus one to tell a cut.
pub const MAX_CATALOG: usize = 10_001;
/// Most `sqlite_stat1` rows read.
pub const MAX_STATS: usize = 10_000;
/// Most columns `table_xinfo` may list (SQLite's own `SQLITE_MAX_COLUMN`).
pub const MAX_TABLE_COLUMNS: usize = 2_000;

/// A protocol violation (a closed kind, never the bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    /// A frame or field longer than its bound.
    #[error("frame or field over its bound")]
    TooLarge,
    /// An unknown message tag or value.
    #[error("unknown message")]
    Unknown,
    /// A truncated or malformed field, or bytes after the message.
    #[error("malformed message")]
    Malformed,
}

/// How the rowid is addressed (decision 6): the first of `rowid`,
/// `_rowid_`, `oid` that is not a declared column name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowidAlias {
    /// `rowid`.
    Rowid,
    /// `_rowid_`.
    UnderscoreRowid,
    /// `oid`.
    Oid,
}

impl RowidAlias {
    /// The alias as written in a statement.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rowid => "rowid",
            Self::UnderscoreRowid => "_rowid_",
            Self::Oid => "oid",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Rowid => 1,
            Self::UnderscoreRowid => 2,
            Self::Oid => 3,
        }
    }

    fn from_tag(t: u8) -> Result<Self, Violation> {
        match t {
            1 => Ok(Self::Rowid),
            2 => Ok(Self::UnderscoreRowid),
            3 => Ok(Self::Oid),
            _ => Err(Violation::Unknown),
        }
    }
}

/// The rows a sampling statement reads (decision 6): rowid ranges of the
/// table's own b-tree, or the plain `LIMIT` read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleRange {
    /// `rowid >= from`.
    From(i64),
    /// `rowid < below` (the wrap-around).
    Below(i64),
    /// `from <= rowid < below` (the wrap-around, continued).
    Between(i64, i64),
    /// No rowid: the plain `LIMIT` read, the scan order reversed or not
    /// (`SQLITE_DBCONFIG_REVERSE_SCANORDER`, `WITHOUT ROWID` tables).
    Plain {
        /// Reverse scan order.
        reverse: bool,
    },
}

/// The open request: what the reader opens, with its limits.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenRequest {
    /// The declared database file (never logged).
    pub path: Zeroizing<Vec<u8>>,
    /// `sqlite.max_statement_ms`.
    pub max_statement_ms: u32,
    /// `sqlite.rollback_mode: read`.
    pub rollback_read: bool,
}

impl std::fmt::Debug for OpenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenRequest")
            .field("max_statement_ms", &self.max_statement_ms)
            .field("rollback_read", &self.rollback_read)
            .finish_non_exhaustive()
    }
}

/// A sampling request: one statement (decision 5's closed list).
#[derive(Clone, PartialEq, Eq)]
pub struct SampleRequest {
    /// The table (raw name).
    pub table: Zeroizing<Vec<u8>>,
    /// The rowid alias (`None` with [`SampleRange::Plain`]).
    pub alias: Option<RowidAlias>,
    /// The columns (raw names), 1 to [`MAX_COLUMNS`].
    pub columns: Vec<Zeroizing<Vec<u8>>>,
    /// The rows read.
    pub range: SampleRange,
    /// Most rows returned.
    pub limit: u32,
}

impl std::fmt::Debug for SampleRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SampleRequest")
            .field("columns", &self.columns.len())
            .field("range", &self.range)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

/// Agent -> reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The self-check, the open procedure and the connection setup.
    Open(OpenRequest),
    /// The catalog statement (the first statement: the schema is read).
    Catalog,
    /// The statistics statement (`sqlite_stat1`).
    Stats,
    /// `PRAGMA main.table_xinfo(<table>)`.
    Columns(Zeroizing<Vec<u8>>),
    /// `min` / `max` of the rowid.
    Bounds(Zeroizing<Vec<u8>>, RowidAlias),
    /// One sampling statement.
    Sample(SampleRequest),
    /// The check pragmas.
    Pragmas,
    /// The light check on the held check descriptor.
    LightCheck,
    /// Close the connection and exit.
    Close,
}

/// A closed failure code of the reader (decision 7's table, by cause).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    /// The path or a component is missing (`ENOENT`).
    NotFound,
    /// Not readable by the agent (`EACCES`).
    NotReadable,
    /// A path rule or a descriptor binding failed (`coverage.file_path_refused`).
    PathRefused,
    /// The file, a side file or an ancestor is writable by the agent.
    Writable,
    /// The file system is not mounted read-only for the agent.
    NotReadOnlyFs,
    /// A network or FUSE file system.
    NetworkFs,
    /// No Landlock, or a sandbox step failed.
    SandboxUnavailable,
    /// The compile-option self-check failed (decision 1).
    SelfCheckFailed,
    /// Not a SQLite 3 file the reader accepts, or a schema it cannot load.
    UnrecognizedFormat,
    /// The WAL side files are missing, unreadable or too large.
    WalNotReadable,
    /// The `-wal` grew past the 128 MiB cap.
    WalTooLarge,
    /// A hot rollback journal.
    HotJournal,
    /// A rollback-journal mode file under `rollback_mode: skip`.
    RollbackNotRead,
    /// `SQLITE_BUSY` / `SQLITE_LOCKED` past the busy timeout.
    Busy,
    /// The statement deadline (`SQLITE_INTERRUPT`).
    Interrupted,
    /// `SQLITE_NOMEM` (heap limit).
    NoMemory,
    /// `SQLITE_TOOBIG`.
    TooBig,
    /// `SQLITE_CORRUPT*` while reading a table.
    Corrupt,
    /// The table has no rowid (`WITHOUT ROWID`).
    NoRowid,
    /// The table is gone since the catalog read.
    NoSuchTable,
    /// A view posing as a table ("access to view prohibited").
    ViewProhibited,
    /// `SQLITE_AUTH`: the authorizer refused one of the reader's own
    /// statements (a bug).
    Auth,
    /// The file is no longer the one opened.
    FileChanged,
    /// A malformed or out-of-order request.
    Protocol,
    /// Anything else.
    Internal,
}

const CODES: [Code; 25] = [
    Code::NotFound,
    Code::NotReadable,
    Code::PathRefused,
    Code::Writable,
    Code::NotReadOnlyFs,
    Code::NetworkFs,
    Code::SandboxUnavailable,
    Code::SelfCheckFailed,
    Code::UnrecognizedFormat,
    Code::WalNotReadable,
    Code::WalTooLarge,
    Code::HotJournal,
    Code::RollbackNotRead,
    Code::Busy,
    Code::Interrupted,
    Code::NoMemory,
    Code::TooBig,
    Code::Corrupt,
    Code::NoRowid,
    Code::NoSuchTable,
    Code::ViewProhibited,
    Code::Auth,
    Code::FileChanged,
    Code::Protocol,
    Code::Internal,
];

impl Code {
    /// Every code.
    pub const ALL: &'static [Self] = &CODES;

    fn tag(self) -> u8 {
        let i = CODES
            .iter()
            .position(|c| *c == self)
            .unwrap_or(CODES.len() - 1);
        u8::try_from(i).unwrap_or(u8::MAX)
    }

    fn from_tag(t: u8) -> Result<Self, Violation> {
        CODES.get(usize::from(t)).copied().ok_or(Violation::Unknown)
    }

    /// Stable name, for the agent's logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotReadable => "not_readable",
            Self::PathRefused => "path_refused",
            Self::Writable => "writable",
            Self::NotReadOnlyFs => "filesystem_not_read_only",
            Self::NetworkFs => "network_filesystem",
            Self::SandboxUnavailable => "sandbox_unavailable",
            Self::SelfCheckFailed => "self_check_failed",
            Self::UnrecognizedFormat => "unrecognized_file_format",
            Self::WalNotReadable => "wal_files_not_readable",
            Self::WalTooLarge => "wal_too_large",
            Self::HotJournal => "hot_journal",
            Self::RollbackNotRead => "rollback_mode_not_read",
            Self::Busy => "busy",
            Self::Interrupted => "interrupted",
            Self::NoMemory => "no_memory",
            Self::TooBig => "too_big",
            Self::Corrupt => "corrupt",
            Self::NoRowid => "no_rowid",
            Self::NoSuchTable => "no_such_table",
            Self::ViewProhibited => "view_prohibited",
            Self::Auth => "auth",
            Self::FileChanged => "file_changed",
            Self::Protocol => "protocol",
            Self::Internal => "internal",
        }
    }
}

/// A failure: a closed code, the SQLite extended result code when SQLite
/// gave one, and, for a path rule, the rule's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// The cause.
    pub code: Code,
    /// SQLite's extended result code (`EngineCode`, decimal).
    pub engine_code: Option<i32>,
    /// The path rule broken (a closed name), for the agent's log.
    pub rule: Option<Rule>,
}

impl Failure {
    /// A failure without an engine code.
    #[must_use]
    pub const fn new(code: Code) -> Self {
        Self {
            code,
            engine_code: None,
            rule: None,
        }
    }

    /// A path-rule refusal naming its rule.
    #[must_use]
    pub const fn rule(code: Code, rule: Rule) -> Self {
        Self {
            code,
            engine_code: None,
            rule: Some(rule),
        }
    }
}

/// The path and file rules of decision 2, by name (logged with the target
/// id, never the path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Not an absolute canonical path.
    NotCanonical,
    /// A component is a symbolic link.
    SymlinkComponent,
    /// A component is not a directory.
    NotDirectory,
    /// A directory writable by every local user without the sticky bit.
    WorldWritableDirectory,
    /// Not a regular file.
    NotRegularFile,
    /// More than one hard link.
    HardLink,
    /// Under a refused location.
    RefusedLocation,
    /// The same file as another target's.
    DuplicateFile,
    /// A side file of another owner, or on another file system.
    SideFileForeign,
    /// A descriptor binding failed (decision 2, steps 6 and 8).
    DescriptorBinding,
    /// A descriptor on the file opened for writing.
    DescriptorWritable,
}

const RULES: [Rule; 11] = [
    Rule::NotCanonical,
    Rule::SymlinkComponent,
    Rule::NotDirectory,
    Rule::WorldWritableDirectory,
    Rule::NotRegularFile,
    Rule::HardLink,
    Rule::RefusedLocation,
    Rule::DuplicateFile,
    Rule::SideFileForeign,
    Rule::DescriptorBinding,
    Rule::DescriptorWritable,
];

impl Rule {
    /// Stable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotCanonical => "not_canonical",
            Self::SymlinkComponent => "symlink_component",
            Self::NotDirectory => "not_directory",
            Self::WorldWritableDirectory => "world_writable_directory",
            Self::NotRegularFile => "not_regular_file",
            Self::HardLink => "hard_link",
            Self::RefusedLocation => "refused_location",
            Self::DuplicateFile => "duplicate_file",
            Self::SideFileForeign => "side_file_foreign",
            Self::DescriptorBinding => "descriptor_binding",
            Self::DescriptorWritable => "descriptor_writable",
        }
    }

    fn tag(self) -> u8 {
        let i = RULES.iter().position(|r| *r == self).unwrap_or(0);
        u8::try_from(i + 1).unwrap_or(u8::MAX)
    }

    fn from_tag(t: u8) -> Result<Option<Self>, Violation> {
        if t == 0 {
            return Ok(None);
        }
        RULES
            .get(usize::from(t) - 1)
            .copied()
            .map(Some)
            .ok_or(Violation::Unknown)
    }
}

/// What the open procedure found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenInfo {
    /// The file's `st_dev`.
    pub dev: u64,
    /// The file's `st_ino`.
    pub ino: u64,
    /// The file is read in WAL mode.
    pub wal: bool,
    /// Readable by every local user (`security.file_world_readable`).
    pub world_readable: bool,
    /// The SQLite version number that last wrote the file (header offset
    /// 96), for the agent's log only.
    pub writer_version: u32,
}

/// A row of the catalog (`sqlite_schema`): `table` or `view`.
#[derive(Clone, PartialEq, Eq)]
pub struct CatalogRow {
    /// `true` for a `view` row.
    pub view: bool,
    /// The raw name.
    pub name: Zeroizing<Vec<u8>>,
    /// `rootpage` (0 for a virtual table).
    pub rootpage: i64,
}

impl std::fmt::Debug for CatalogRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CatalogRow")
            .field("view", &self.view)
            .field("rootpage", &self.rootpage)
            .finish_non_exhaustive()
    }
}

/// A column of `table_xinfo`.
#[derive(Clone, PartialEq, Eq)]
pub struct ColumnRow {
    /// The raw name.
    pub name: Zeroizing<Vec<u8>>,
    /// `pk`.
    pub pk: i64,
    /// `hidden` (2: `VIRTUAL` generated, 3: `STORED` generated).
    pub hidden: i64,
}

impl std::fmt::Debug for ColumnRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColumnRow")
            .field("pk", &self.pk)
            .field("hidden", &self.hidden)
            .finish_non_exhaustive()
    }
}

/// The rows of one sampling statement, column by column.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Sampled {
    /// Rows read.
    pub rows: u32,
    /// The last rowid read (rowid ranges only), to continue from.
    pub last_rowid: Option<i64>,
    /// The response bound stopped the statement before its `LIMIT`.
    pub truncated: bool,
    /// Per column, its sampled values (`None`: not `TEXT` / `INTEGER`, or
    /// over the size bound).
    pub values: Vec<Vec<Option<Zeroizing<Vec<u8>>>>>,
}

impl std::fmt::Debug for Sampled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sampled")
            .field("rows", &self.rows)
            .field("truncated", &self.truncated)
            .field("columns", &self.values.len())
            .finish_non_exhaustive()
    }
}

/// The check pragmas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PragmaInfo {
    /// `journal_mode` is `wal`.
    pub wal: bool,
    /// `schema_version`.
    pub schema_version: i64,
    /// `page_size`.
    pub page_size: i64,
    /// `encoding`: 1 UTF-8, 2 UTF-16le, 3 UTF-16be, 0 other.
    pub encoding: u8,
}

/// A `sqlite_stat1` row count: the raw table name and its rows.
pub type StatRow = (Zeroizing<Vec<u8>>, u64);

/// Reader -> agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The request failed.
    Failed(Failure),
    /// The file is open and the connection set up.
    Opened(OpenInfo),
    /// The catalog rows (at most [`MAX_CATALOG`]); `true` when the response
    /// bound cut the list.
    Catalog(Vec<CatalogRow>, bool),
    /// `sqlite_stat1` row counts per table.
    Stats(Vec<StatRow>),
    /// The table's columns.
    Columns(Vec<ColumnRow>),
    /// `min` and `max` of the rowid (`None`: an empty table).
    Bounds(Option<(i64, i64)>),
    /// One sampling statement's rows.
    Sample(Sampled),
    /// The check pragmas.
    Pragmas(PragmaInfo),
    /// The light check passed.
    LightOk,
    /// Closed.
    Closed,
}

/// A frame body being built (zeroized on drop: it may hold raw values).
struct Writer(Zeroizing<Vec<u8>>);

impl Writer {
    fn new(tag: u8) -> Self {
        let mut v = Zeroizing::new(Vec::with_capacity(64));
        v.push(tag);
        Self(v)
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(u32::try_from(b.len()).unwrap_or(u32::MAX));
        self.0.extend_from_slice(b);
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// A bounded decoder over one frame body.
struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Violation> {
        if n > self.buf.len() {
            return Err(Violation::Malformed);
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, Violation> {
        Ok(*self.take(1)?.first().ok_or(Violation::Malformed)?)
    }
    fn bool(&mut self) -> Result<bool, Violation> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Violation::Malformed),
        }
    }
    fn u32(&mut self) -> Result<u32, Violation> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| Violation::Malformed)?;
        Ok(u32::from_be_bytes(b))
    }
    fn u64(&mut self) -> Result<u64, Violation> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| Violation::Malformed)?;
        Ok(u64::from_be_bytes(b))
    }
    fn i64(&mut self) -> Result<i64, Violation> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| Violation::Malformed)?;
        Ok(i64::from_be_bytes(b))
    }
    /// A length-prefixed byte string of at most `max` bytes, copied into a
    /// zeroizing buffer.
    fn bytes(&mut self, max: usize) -> Result<Zeroizing<Vec<u8>>, Violation> {
        let n = usize::try_from(self.u32()?).map_err(|_| Violation::TooLarge)?;
        if n > max {
            return Err(Violation::TooLarge);
        }
        Ok(Zeroizing::new(self.take(n)?.to_vec()))
    }
    /// A count of at most `max` items, never more than the bytes left
    /// could hold at `min_item` bytes each (no allocation past the frame).
    fn count(&mut self, max: usize, min_item: usize) -> Result<usize, Violation> {
        let n = usize::try_from(self.u32()?).map_err(|_| Violation::TooLarge)?;
        if n > max {
            return Err(Violation::TooLarge);
        }
        if n.saturating_mul(min_item) > self.buf.len() {
            return Err(Violation::Malformed);
        }
        Ok(n)
    }
    fn end(&self) -> Result<(), Violation> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Violation::Malformed)
        }
    }
}

const fn opt_tag(b: bool) -> u8 {
    if b { 1 } else { 0 }
}

impl Request {
    /// The frame (length prefix included).
    ///
    /// # Errors
    /// [`Violation::TooLarge`] when it would exceed [`MAX_REQUEST`] or a
    /// field its bound.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Violation> {
        let too_long = |b: &[u8]| b.len() > MAX_NAME;
        let w = match self {
            Self::Open(o) => {
                if too_long(&o.path) {
                    return Err(Violation::TooLarge);
                }
                let mut w = Writer::new(1);
                w.bytes(&o.path);
                w.u32(o.max_statement_ms);
                w.u8(opt_tag(o.rollback_read));
                w
            }
            Self::Catalog => Writer::new(2),
            Self::Stats => Writer::new(3),
            Self::Columns(t) => {
                if too_long(t) {
                    return Err(Violation::TooLarge);
                }
                let mut w = Writer::new(4);
                w.bytes(t);
                w
            }
            Self::Bounds(t, a) => {
                if too_long(t) {
                    return Err(Violation::TooLarge);
                }
                let mut w = Writer::new(5);
                w.bytes(t);
                w.u8(a.tag());
                w
            }
            Self::Sample(s) => {
                if too_long(&s.table)
                    || s.columns.is_empty()
                    || s.columns.len() > MAX_COLUMNS
                    || s.columns.iter().any(|c| too_long(c))
                    || s.limit > MAX_ROWS
                {
                    return Err(Violation::TooLarge);
                }
                let mut w = Writer::new(6);
                w.bytes(&s.table);
                w.u8(s.alias.map_or(0, RowidAlias::tag));
                w.u32(u32::try_from(s.columns.len()).unwrap_or(u32::MAX));
                for c in &s.columns {
                    w.bytes(c);
                }
                match s.range {
                    SampleRange::From(a) => {
                        w.u8(1);
                        w.i64(a);
                    }
                    SampleRange::Below(b) => {
                        w.u8(2);
                        w.i64(b);
                    }
                    SampleRange::Between(a, b) => {
                        w.u8(3);
                        w.i64(a);
                        w.i64(b);
                    }
                    SampleRange::Plain { reverse } => {
                        w.u8(4);
                        w.u8(opt_tag(reverse));
                    }
                }
                w.u32(s.limit);
                w
            }
            Self::Pragmas => Writer::new(7),
            Self::LightCheck => Writer::new(8),
            Self::Close => Writer::new(9),
        };
        frame(&w, MAX_REQUEST)
    }

    /// Decodes a frame body (without its length prefix).
    ///
    /// # Errors
    /// A [`Violation`].
    pub fn decode(body: &[u8]) -> Result<Self, Violation> {
        if body.len() > MAX_REQUEST {
            return Err(Violation::TooLarge);
        }
        let mut r = Reader { buf: body };
        let req = match r.u8()? {
            1 => {
                let path = r.bytes(MAX_NAME)?;
                let max_statement_ms = r.u32()?;
                let rollback_read = r.bool()?;
                Self::Open(OpenRequest {
                    path,
                    max_statement_ms,
                    rollback_read,
                })
            }
            2 => Self::Catalog,
            3 => Self::Stats,
            4 => Self::Columns(r.bytes(MAX_NAME)?),
            5 => {
                let t = r.bytes(MAX_NAME)?;
                Self::Bounds(t, RowidAlias::from_tag(r.u8()?)?)
            }
            6 => {
                let table = r.bytes(MAX_NAME)?;
                let alias = match r.u8()? {
                    0 => None,
                    t => Some(RowidAlias::from_tag(t)?),
                };
                let n = r.count(MAX_COLUMNS, 4)?;
                if n == 0 {
                    return Err(Violation::Malformed);
                }
                let mut columns = Vec::with_capacity(n);
                for _ in 0..n {
                    columns.push(r.bytes(MAX_NAME)?);
                }
                let range = match r.u8()? {
                    1 => SampleRange::From(r.i64()?),
                    2 => SampleRange::Below(r.i64()?),
                    3 => {
                        let a = r.i64()?;
                        SampleRange::Between(a, r.i64()?)
                    }
                    4 => SampleRange::Plain { reverse: r.bool()? },
                    _ => return Err(Violation::Unknown),
                };
                let limit = r.u32()?;
                if limit > MAX_ROWS {
                    return Err(Violation::TooLarge);
                }
                if alias.is_none() != matches!(range, SampleRange::Plain { .. }) {
                    return Err(Violation::Malformed);
                }
                Self::Sample(SampleRequest {
                    table,
                    alias,
                    columns,
                    range,
                    limit,
                })
            }
            7 => Self::Pragmas,
            8 => Self::LightCheck,
            9 => Self::Close,
            _ => return Err(Violation::Unknown),
        };
        r.end()?;
        Ok(req)
    }
}

/// Bytes a sampled cell costs in a response at most (its tag and length).
pub const CELL_OVERHEAD: usize = 5;

impl Response {
    /// The frame (length prefix included).
    ///
    /// # Errors
    /// [`Violation::TooLarge`] when it would exceed [`MAX_RESPONSE`] or a
    /// field its bound.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Violation> {
        let w = match self {
            Self::Failed(f) => {
                let mut w = Writer::new(0x80);
                w.u8(f.code.tag());
                match f.engine_code {
                    Some(c) => {
                        w.u8(1);
                        w.u32(c.cast_unsigned());
                    }
                    None => w.u8(0),
                }
                w.u8(f.rule.map_or(0, Rule::tag));
                w
            }
            Self::Opened(o) => {
                let mut w = Writer::new(0x81);
                w.u64(o.dev);
                w.u64(o.ino);
                w.u8(opt_tag(o.wal));
                w.u8(opt_tag(o.world_readable));
                w.u32(o.writer_version);
                w
            }
            Self::Catalog(rows, cut) => {
                if rows.len() > MAX_CATALOG {
                    return Err(Violation::TooLarge);
                }
                let mut w = Writer::new(0x82);
                w.u8(opt_tag(*cut));
                w.u32(u32::try_from(rows.len()).unwrap_or(u32::MAX));
                for row in rows {
                    if row.name.len() > MAX_NAME {
                        return Err(Violation::TooLarge);
                    }
                    w.u8(opt_tag(row.view));
                    w.bytes(&row.name);
                    w.i64(row.rootpage);
                }
                w
            }
            Self::Stats(rows) => {
                if rows.len() > MAX_STATS {
                    return Err(Violation::TooLarge);
                }
                let mut w = Writer::new(0x83);
                w.u32(u32::try_from(rows.len()).unwrap_or(u32::MAX));
                for (name, n) in rows {
                    if name.len() > MAX_NAME {
                        return Err(Violation::TooLarge);
                    }
                    w.bytes(name);
                    w.u64(*n);
                }
                w
            }
            Self::Columns(cols) => {
                if cols.len() > MAX_TABLE_COLUMNS {
                    return Err(Violation::TooLarge);
                }
                let mut w = Writer::new(0x84);
                w.u32(u32::try_from(cols.len()).unwrap_or(u32::MAX));
                for c in cols {
                    if c.name.len() > MAX_NAME {
                        return Err(Violation::TooLarge);
                    }
                    w.bytes(&c.name);
                    w.i64(c.pk);
                    w.i64(c.hidden);
                }
                w
            }
            Self::Bounds(b) => {
                let mut w = Writer::new(0x85);
                match b {
                    Some((lo, hi)) => {
                        w.u8(1);
                        w.i64(*lo);
                        w.i64(*hi);
                    }
                    None => w.u8(0),
                }
                w
            }
            Self::Sample(s) => {
                if s.values.len() > MAX_COLUMNS || s.rows > MAX_ROWS {
                    return Err(Violation::TooLarge);
                }
                let mut w = Writer::new(0x86);
                w.u32(s.rows);
                match s.last_rowid {
                    Some(r) => {
                        w.u8(1);
                        w.i64(r);
                    }
                    None => w.u8(0),
                }
                w.u8(opt_tag(s.truncated));
                w.u32(u32::try_from(s.values.len()).unwrap_or(u32::MAX));
                for col in &s.values {
                    if col.len() != s.rows as usize {
                        return Err(Violation::Malformed);
                    }
                    for cell in col {
                        match cell {
                            Some(v) => {
                                if v.len() > MAX_VALUE {
                                    return Err(Violation::TooLarge);
                                }
                                w.u8(1);
                                w.bytes(v);
                            }
                            None => w.u8(0),
                        }
                    }
                    if w.len() > MAX_RESPONSE {
                        return Err(Violation::TooLarge);
                    }
                }
                w
            }
            Self::Pragmas(p) => {
                let mut w = Writer::new(0x87);
                w.u8(opt_tag(p.wal));
                w.i64(p.schema_version);
                w.i64(p.page_size);
                w.u8(p.encoding);
                w
            }
            Self::LightOk => Writer::new(0x88),
            Self::Closed => Writer::new(0x89),
        };
        frame(&w, MAX_RESPONSE)
    }

    /// Decodes a frame body (without its length prefix).
    ///
    /// # Errors
    /// A [`Violation`].
    pub fn decode(body: &[u8]) -> Result<Self, Violation> {
        if body.len() > MAX_RESPONSE {
            return Err(Violation::TooLarge);
        }
        let mut r = Reader { buf: body };
        let resp = match r.u8()? {
            0x80 => {
                let code = Code::from_tag(r.u8()?)?;
                let engine_code = match r.u8()? {
                    0 => None,
                    1 => Some(r.u32()?.cast_signed()),
                    _ => return Err(Violation::Malformed),
                };
                let rule = Rule::from_tag(r.u8()?)?;
                Self::Failed(Failure {
                    code,
                    engine_code,
                    rule,
                })
            }
            0x81 => Self::Opened(OpenInfo {
                dev: r.u64()?,
                ino: r.u64()?,
                wal: r.bool()?,
                world_readable: r.bool()?,
                writer_version: r.u32()?,
            }),
            0x82 => {
                let cut = r.bool()?;
                let n = r.count(MAX_CATALOG, 13)?;
                let mut rows = Vec::with_capacity(n);
                for _ in 0..n {
                    let view = r.bool()?;
                    let name = r.bytes(MAX_NAME)?;
                    let rootpage = r.i64()?;
                    rows.push(CatalogRow {
                        view,
                        name,
                        rootpage,
                    });
                }
                Self::Catalog(rows, cut)
            }
            0x83 => {
                let n = r.count(MAX_STATS, 12)?;
                let mut rows = Vec::with_capacity(n);
                for _ in 0..n {
                    let name = r.bytes(MAX_NAME)?;
                    rows.push((name, r.u64()?));
                }
                Self::Stats(rows)
            }
            0x84 => {
                let n = r.count(MAX_TABLE_COLUMNS, 20)?;
                let mut cols = Vec::with_capacity(n);
                for _ in 0..n {
                    let name = r.bytes(MAX_NAME)?;
                    let pk = r.i64()?;
                    let hidden = r.i64()?;
                    cols.push(ColumnRow { name, pk, hidden });
                }
                Self::Columns(cols)
            }
            0x85 => match r.u8()? {
                0 => Self::Bounds(None),
                1 => {
                    let lo = r.i64()?;
                    Self::Bounds(Some((lo, r.i64()?)))
                }
                _ => return Err(Violation::Malformed),
            },
            0x86 => {
                let rows = r.u32()?;
                if rows > MAX_ROWS {
                    return Err(Violation::TooLarge);
                }
                let last_rowid = match r.u8()? {
                    0 => None,
                    1 => Some(r.i64()?),
                    _ => return Err(Violation::Malformed),
                };
                let truncated = r.bool()?;
                let ncols = r.count(MAX_COLUMNS, 0)?;
                let rows_n = rows as usize;
                // Each cell is at least one byte.
                if ncols.saturating_mul(rows_n) > r.buf.len() {
                    return Err(Violation::Malformed);
                }
                let mut values = Vec::with_capacity(ncols);
                for _ in 0..ncols {
                    let mut col = Vec::with_capacity(rows_n);
                    for _ in 0..rows_n {
                        col.push(match r.u8()? {
                            0 => None,
                            1 => Some(r.bytes(MAX_VALUE)?),
                            _ => return Err(Violation::Malformed),
                        });
                    }
                    values.push(col);
                }
                Self::Sample(Sampled {
                    rows,
                    last_rowid,
                    truncated,
                    values,
                })
            }
            0x87 => Self::Pragmas(PragmaInfo {
                wal: r.bool()?,
                schema_version: r.i64()?,
                page_size: r.i64()?,
                encoding: r.u8()?,
            }),
            0x88 => Self::LightOk,
            0x89 => Self::Closed,
            _ => return Err(Violation::Unknown),
        };
        r.end()?;
        Ok(resp)
    }
}

fn frame(w: &Writer, max: usize) -> Result<Zeroizing<Vec<u8>>, Violation> {
    let body = &w.0;
    if body.len() > max {
        return Err(Violation::TooLarge);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(body.len() + 4));
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// A frame assembler for a byte stream, for both sides: bytes arrive in
/// any split, frames come out whole; a length over `max` is a violation
/// before any allocation.
pub struct FrameBuffer {
    buf: Zeroizing<Vec<u8>>,
    max: usize,
}

impl FrameBuffer {
    /// A buffer for frames of at most `max` bytes.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
            max,
        }
    }

    /// The length the next frame needs, once its prefix is known.
    fn needed(&self) -> Result<Option<usize>, Violation> {
        let Some(prefix) = self.buf.get(..4) else {
            return Ok(None);
        };
        let n = u32::from_be_bytes(prefix.try_into().map_err(|_| Violation::Malformed)?);
        let n = usize::try_from(n).map_err(|_| Violation::TooLarge)?;
        if n > self.max {
            return Err(Violation::TooLarge);
        }
        Ok(Some(n))
    }

    /// Appends `bytes`; never grows past one frame and its prefix.
    ///
    /// # Errors
    /// [`Violation::TooLarge`] for a declared length over the bound, or
    /// bytes past the end of the frame (a peer sends one frame per turn).
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Violation> {
        self.buf.extend_from_slice(bytes);
        if let Some(n) = self.needed()?
            && self.buf.len() > n + 4
        {
            return Err(Violation::Malformed);
        }
        if self.buf.len() > self.max + 4 {
            return Err(Violation::TooLarge);
        }
        Ok(())
    }

    /// How many bytes to read next: the rest of the prefix, then the rest
    /// of the body (`0`: a whole frame is buffered).
    ///
    /// # Errors
    /// [`Violation::TooLarge`].
    pub fn want(&self) -> Result<usize, Violation> {
        Ok(match self.needed()? {
            None => 4 - self.buf.len(),
            Some(n) => (n + 4).saturating_sub(self.buf.len()),
        })
    }

    /// The whole frame's body, if buffered; the buffer is then empty.
    ///
    /// # Errors
    /// [`Violation::TooLarge`].
    pub fn take(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>, Violation> {
        match self.needed()? {
            Some(n) if self.buf.len() == n + 4 => {
                let body = Zeroizing::new(self.buf.get(4..).unwrap_or_default().to_vec());
                self.buf.clear();
                Ok(Some(body))
            }
            _ => Ok(None),
        }
    }
}

/// Why an exchange failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// The deadline passed.
    Deadline,
    /// The peer closed the channel or an I/O error.
    Closed,
    /// A protocol violation.
    Protocol,
}

/// The agent's end of the channel. The connector's only socket (I1,
/// decision 4): created here by `UnixStream::pair`, never connected
/// anywhere.
pub struct Channel(std::os::unix::net::UnixStream);

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel").finish_non_exhaustive()
    }
}

impl Channel {
    /// A fresh pair (both ends `O_CLOEXEC`): the agent's end, and the
    /// reader's end as the descriptor that becomes its standard input.
    ///
    /// # Errors
    /// The `socketpair` error.
    pub fn pair() -> std::io::Result<(Self, std::os::fd::OwnedFd)> {
        let (agent, reader) = std::os::unix::net::UnixStream::pair()?;
        Ok((Self(agent), std::os::fd::OwnedFd::from(reader)))
    }

    /// Blocking: one request frame out, one response frame in, both under
    /// `deadline` (socket timeouts). Returns the channel for the next call.
    pub fn exchange(
        mut self,
        frame: &[u8],
        deadline: std::time::Duration,
    ) -> (Self, Result<Response, ChannelError>) {
        use std::io::{Read, Write};
        let end = std::time::Instant::now() + deadline;
        let remaining = || {
            end.checked_duration_since(std::time::Instant::now())
                .filter(|d| !d.is_zero())
        };
        let io = |e: &std::io::Error| match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => ChannelError::Deadline,
            _ => ChannelError::Closed,
        };
        let sock = &mut self.0;
        let r = (|| {
            let Some(left) = remaining() else {
                return Err(ChannelError::Deadline);
            };
            sock.set_write_timeout(Some(left))
                .map_err(|_| ChannelError::Deadline)?;
            sock.write_all(frame).map_err(|e| io(&e))?;
            let mut fb = FrameBuffer::new(MAX_RESPONSE);
            let mut chunk = Zeroizing::new(vec![0u8; 64 * 1024]);
            loop {
                let want = fb.want().map_err(|_| ChannelError::Protocol)?;
                if want == 0 {
                    break;
                }
                let Some(left) = remaining() else {
                    return Err(ChannelError::Deadline);
                };
                sock.set_read_timeout(Some(left))
                    .map_err(|_| ChannelError::Deadline)?;
                let n = want.min(chunk.len());
                let buf = chunk.get_mut(..n).ok_or(ChannelError::Protocol)?;
                match sock.read(buf) {
                    Ok(0) => return Err(ChannelError::Closed),
                    Ok(got) => fb
                        .push(buf.get(..got).ok_or(ChannelError::Protocol)?)
                        .map_err(|_| ChannelError::Protocol)?,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(io(&e)),
                }
            }
            let body = fb
                .take()
                .map_err(|_| ChannelError::Protocol)?
                .ok_or(ChannelError::Protocol)?;
            Response::decode(&body).map_err(|_| ChannelError::Protocol)
        })();
        (self, r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn z(b: &[u8]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(b.to_vec())
    }

    fn body(frame: &[u8]) -> &[u8] {
        frame.get(4..).unwrap()
    }

    fn requests() -> Vec<Request> {
        vec![
            Request::Open(OpenRequest {
                path: z(b"/srv/crm/crm.db"),
                max_statement_ms: 500,
                rollback_read: true,
            }),
            Request::Catalog,
            Request::Stats,
            Request::Columns(z("clients é".as_bytes())),
            Request::Bounds(z(b"t"), RowidAlias::Oid),
            Request::Sample(SampleRequest {
                table: z(b"t"),
                alias: Some(RowidAlias::Rowid),
                columns: vec![z(b"a"), z(b"b")],
                range: SampleRange::Between(-5, i64::MAX),
                limit: 1000,
            }),
            Request::Sample(SampleRequest {
                table: z(b"t"),
                alias: None,
                columns: vec![z(b"a")],
                range: SampleRange::Plain { reverse: true },
                limit: 1,
            }),
            Request::Pragmas,
            Request::LightCheck,
            Request::Close,
        ]
    }

    fn responses() -> Vec<Response> {
        vec![
            Response::Failed(Failure {
                code: Code::Corrupt,
                engine_code: Some(267),
                rule: None,
            }),
            Response::Failed(Failure::rule(Code::PathRefused, Rule::HardLink)),
            Response::Opened(OpenInfo {
                dev: 1,
                ino: u64::MAX,
                wal: true,
                world_readable: false,
                writer_version: 3_053_002,
            }),
            Response::Catalog(
                vec![CatalogRow {
                    view: true,
                    name: z(b"v"),
                    rootpage: 0,
                }],
                true,
            ),
            Response::Stats(vec![(z(b"t"), 42)]),
            Response::Columns(vec![ColumnRow {
                name: z(b"c"),
                pk: 1,
                hidden: 3,
            }]),
            Response::Bounds(Some((i64::MIN, i64::MAX))),
            Response::Bounds(None),
            Response::Sample(Sampled {
                rows: 2,
                last_rowid: Some(9),
                truncated: false,
                values: vec![vec![Some(z(b"x@y.z")), None], vec![None, Some(z(b""))]],
            }),
            Response::Pragmas(PragmaInfo {
                wal: false,
                schema_version: 3,
                page_size: 4096,
                encoding: 1,
            }),
            Response::LightOk,
            Response::Closed,
        ]
    }

    #[test]
    fn every_message_round_trips() {
        for req in requests() {
            let f = req.encode().unwrap();
            assert_eq!(Request::decode(body(&f)).unwrap(), req);
        }
        for resp in responses() {
            let f = resp.encode().unwrap();
            assert_eq!(Response::decode(body(&f)).unwrap(), resp);
        }
        for c in Code::ALL {
            let f = Response::Failed(Failure::new(*c)).encode().unwrap();
            assert_eq!(
                Response::decode(body(&f)).unwrap(),
                Response::Failed(Failure::new(*c))
            );
        }
    }

    #[test]
    fn bounds_are_enforced_on_both_sides() {
        let long = Request::Columns(z(&[b'a'; MAX_NAME + 1]));
        assert_eq!(long.encode(), Err(Violation::TooLarge));
        let mut w = Writer::new(4);
        w.bytes(&[b'a'; MAX_NAME + 1]);
        assert_eq!(Request::decode(&w.0), Err(Violation::TooLarge));
        // A count larger than the bytes left: refused before allocating.
        let mut w = Writer::new(0x82);
        w.u8(0);
        w.u32(10_000);
        assert_eq!(Response::decode(&w.0), Err(Violation::Malformed));
        // Trailing bytes, unknown tags.
        let mut f = Request::Catalog.encode().unwrap().to_vec();
        f.push(0);
        assert_eq!(Request::decode(body(&f)), Err(Violation::Malformed));
        assert_eq!(Request::decode(&[0x7f]), Err(Violation::Unknown));
        assert_eq!(Response::decode(&[0x01]), Err(Violation::Unknown));
        // A frame prefix over the bound.
        let mut fb = FrameBuffer::new(MAX_REQUEST);
        assert_eq!(
            fb.push(&u32::try_from(MAX_REQUEST + 1).unwrap().to_be_bytes()),
            Err(Violation::TooLarge)
        );
        // A plain range needs no alias, a rowid range one.
        let bad = SampleRequest {
            table: z(b"t"),
            alias: None,
            columns: vec![z(b"a")],
            range: SampleRange::From(1),
            limit: 1,
        };
        let f = Request::Sample(bad).encode().unwrap();
        assert_eq!(Request::decode(body(&f)), Err(Violation::Malformed));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Arbitrary bytes never panic and never allocate past the bounds.
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = Request::decode(&bytes);
            let _ = Response::decode(&bytes);
            let mut fb = FrameBuffer::new(MAX_RESPONSE);
            if fb.push(&bytes).is_ok() {
                let _ = fb.want();
                let _ = fb.take();
            }
        }

        /// Every split of a stream gives the same frame.
        #[test]
        fn every_split_of_a_stream_gives_the_frame(i in 0usize..12, cut in any::<prop::sample::Index>()) {
            let all = responses();
            let resp = &all[i % all.len()];
            let f = resp.encode().unwrap();
            let at = cut.index(f.len() + 1);
            let mut fb = FrameBuffer::new(MAX_RESPONSE);
            let (a, b) = f.split_at(at);
            fb.push(a).unwrap();
            if at < f.len() {
                prop_assert!(fb.take().unwrap().is_none());
                prop_assert!(fb.want().unwrap() > 0);
            }
            fb.push(b).unwrap();
            prop_assert_eq!(fb.want().unwrap(), 0);
            let got = fb.take().unwrap().unwrap();
            prop_assert_eq!(&Response::decode(&got).unwrap(), resp);
        }

        /// Round trips of generated sampling responses.
        #[test]
        fn sampling_responses_round_trip(
            cells in proptest::collection::vec(proptest::option::of(proptest::collection::vec(any::<u8>(), 0..64)), 0..40),
            ncols in 1usize..4,
            last in proptest::option::of(any::<i64>()),
        ) {
            let rows = cells.len() / ncols;
            let values: Vec<Vec<Option<Zeroizing<Vec<u8>>>>> = (0..ncols)
                .map(|c| (0..rows).map(|r| cells[c * rows + r].clone().map(Zeroizing::new)).collect())
                .collect();
            let s = Response::Sample(Sampled { rows: u32::try_from(rows).unwrap(), last_rowid: last, truncated: rows % 2 == 0, values });
            let f = s.encode().unwrap();
            prop_assert_eq!(Response::decode(body(&f)).unwrap(), s);
        }
    }
}
