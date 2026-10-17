//! The token stream decoder (ADR-0051 decision 1, obligation L1): a
//! closed token set and a closed row type set, decoded incrementally, value
//! by value, from the message payload bytes as they arrive.
//!
//! - Tokens: `LOGINACK`, `ENVCHANGE`, `ERROR`, `INFO`, `COLMETADATA`,
//!   `ROW`, `NBCROW`, `DONE` / `DONEPROC` / `DONEINPROC`, `RETURNSTATUS`,
//!   `RETURNVALUE` (skipped, bounded), `ORDER` (skipped). Any other byte
//!   ends the connection: tokens have no common length prefix, so an
//!   unknown one cannot be skipped safely.
//! - Every type info of MS-TDS is parsed to find column boundaries, but a
//!   `COLMETADATA` whose column types fall outside the row set (`INTN` and
//!   the fixed integers, `BITN` / `BIT`, `NVARCHAR` / `NCHAR`,
//!   `BIGVARBIN` / `BIGBINARY`, `DATETIME2N`; `max` lengths only when the
//!   statement allows PLP) is refused, before any row.
//! - Lengths are checked against the token, the declared column length and
//!   the statement's limits before bytes are buffered; PLP values chunk by
//!   chunk against their cap.
//! - `ERROR` and `INFO` keep the number, state and class only: the message,
//!   server and procedure names are skipped by length, never decoded.

#![deny(clippy::indexing_slicing, clippy::string_slice)]

/// Token bytes.
pub(crate) mod tok {
    pub(crate) const COLMETADATA: u8 = 0x81;
    pub(crate) const RETURNSTATUS: u8 = 0x79;
    pub(crate) const ORDER: u8 = 0xA9;
    pub(crate) const ERROR: u8 = 0xAA;
    pub(crate) const INFO: u8 = 0xAB;
    pub(crate) const RETURNVALUE: u8 = 0xAC;
    pub(crate) const LOGINACK: u8 = 0xAD;
    pub(crate) const ROW: u8 = 0xD1;
    pub(crate) const NBCROW: u8 = 0xD2;
    pub(crate) const ENVCHANGE: u8 = 0xE3;
    pub(crate) const DONE: u8 = 0xFD;
    pub(crate) const DONEPROC: u8 = 0xFE;
    pub(crate) const DONEINPROC: u8 = 0xFF;
}

/// `DONE` status bits.
pub(crate) mod done {
    #[cfg(test)]
    pub(crate) const ERROR: u16 = 0x0002;
    #[cfg(test)]
    pub(crate) const COUNT: u16 = 0x0010;
    pub(crate) const ATTN: u16 = 0x0020;
}

/// Most columns of one `COLMETADATA` (the server's `SELECT` list limit).
pub(crate) const MAX_COLUMNS: usize = 4096;
/// Largest non-PLP value (`nvarchar(4000)`, `varbinary(8000)`).
pub(crate) const MAX_SHORT_VALUE: usize = 8000;
/// Bound of a skipped `RETURNVALUE` value.
pub(crate) const MAX_RETURN_VALUE: usize = 64 * 1024;
/// Most bytes a single incomplete token may hold in the buffer.
pub(crate) const MAX_PENDING: usize = 2 * 1024 * 1024;

/// A decode error: the stream cannot be trusted further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenError {
    /// A token byte outside the closed set.
    UnknownToken,
    /// A type outside MS-TDS, or outside the statement's row type set.
    UnsupportedType,
    /// Inconsistent lengths, a row without metadata, bad UTF-16 framing.
    Malformed,
    /// More columns, or a longer value, than the statement accepts.
    Limit,
}

/// Length class of a type, how its values are framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Framing {
    /// A fixed number of bytes.
    Fixed(usize),
    /// A one-byte length (0 = NULL for the nullable types).
    Byte,
    /// A two-byte length (0xFFFF = NULL).
    Short,
    /// PLP: the `max` types, `xml`, UDT, JSON.
    Plp,
    /// `text` / `ntext` / `image`: text pointer then a four-byte length.
    Long,
    /// `sql_variant`: a four-byte length.
    Variant,
}

/// What a row value of a column decodes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Int,
    Bit,
    Text,
    Binary,
    DateTime2,
    /// Not a row type: refused in `COLMETADATA`.
    Other,
}

/// The parsed type info of a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TypeInfo {
    pub(crate) id: u8,
    pub(crate) framing: Framing,
    /// Declared maximum length in bytes (0 for fixed / PLP).
    pub(crate) max_len: usize,
    pub(crate) kind: Kind,
}

/// A row value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Null,
    Int(i64),
    Bit(bool),
    /// UTF-16 decoded lossily (lone surrogates and an odd byte become
    /// U+FFFD).
    Text(String),
    Binary(Vec<u8>),
    /// `datetime2` raw bytes (time then date), never interpreted here.
    DateTime2(Vec<u8>),
}

impl Value {
    /// Bytes the value took on the wire (budget accounting).
    pub(crate) fn wire_len(&self) -> usize {
        match self {
            Self::Null | Self::Bit(_) => 1,
            Self::Int(_) => 8,
            Self::Text(s) => s.len(),
            Self::Binary(b) | Self::DateTime2(b) => b.len(),
        }
    }

    pub(crate) fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Bit(b) => Some(i64::from(*b)),
            _ => None,
        }
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        match self {
            Self::Text(s) => zeroize::Zeroize::zeroize(s),
            Self::Binary(b) | Self::DateTime2(b) => zeroize::Zeroize::zeroize(b),
            _ => {}
        }
    }
}

/// A decoded event.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Event {
    ColMetadata(usize),
    RowStart,
    Value(usize, Value),
    RowEnd,
    Done {
        token: u8,
        status: u16,
        rows: u64,
    },
    Error {
        number: i32,
        state: u8,
        class: u8,
    },
    Info {
        number: i32,
    },
    LoginAck {
        tds_version: u32,
        major: u8,
        minor: u8,
        build: u16,
    },
    PacketSize(usize),
    Database,
    /// A transaction `ENVCHANGE` (begin, commit, rollback, enlist, defect,
    /// promote, manager address, ended): the connection ends.
    Transaction,
    /// A routing `ENVCHANGE` (type 20): the connection ends (I5).
    Routing,
    ReturnStatus(i32),
    /// Skipped tokens (`ORDER`, `RETURNVALUE`, ignored `ENVCHANGE` types).
    Skipped,
}

/// Limits of one statement.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// Most columns accepted in `COLMETADATA`.
    pub(crate) max_columns: usize,
    /// Cap of one PLP value; 0: no `max` column accepted.
    pub(crate) plp_cap: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_columns: MAX_COLUMNS,
            plp_cap: 0,
        }
    }
}

#[derive(Debug)]
enum State {
    Token,
    Row {
        col: usize,
        nulls: Option<Vec<u8>>,
    },
    Plp {
        col: usize,
        nulls: Option<Vec<u8>>,
        total: Option<u64>,
        acc: Vec<u8>,
        chunk_left: usize,
    },
}

/// The incremental decoder of one connection.
#[derive(Debug)]
pub(crate) struct Decoder {
    state: State,
    columns: Vec<TypeInfo>,
    pub(crate) limits: Limits,
    /// After an `ATTENTION`: values are parsed and dropped, PLP values not
    /// buffered (the cap no longer applies).
    pub(crate) discard: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

/// A little-endian reader over a slice; `None` when out of bytes.
struct Cur<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).and_then(|s| s.first().copied())
    }
    fn u16(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_le_bytes(s.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        let s = self.take(4)?;
        Some(u32::from_le_bytes(s.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        let s = self.take(8)?;
        Some(u64::from_le_bytes(s.try_into().ok()?))
    }
    /// `B_VARCHAR`: a one-byte character count, skipped.
    fn skip_b_varchar(&mut self) -> Option<()> {
        let n = usize::from(self.u8()?);
        self.take(n * 2).map(|_| ())
    }
    /// `US_VARCHAR`: a two-byte character count, skipped.
    fn skip_us_varchar(&mut self) -> Option<()> {
        let n = usize::from(self.u16()?);
        self.take(n * 2).map(|_| ())
    }
}

/// Outcome of parsing a whole-token structure from the buffer: incomplete
/// (`Ok(None)`) or a protocol error.
type Parsed<T> = Result<Option<T>, TokenError>;

/// Parses a `TYPE_INFO`. `Ok(None)`: more bytes needed.
fn type_info(c: &mut Cur<'_>) -> Parsed<TypeInfo> {
    let Some(id) = c.u8() else { return Ok(None) };
    let fixed = |n, kind| {
        Ok(Some(TypeInfo {
            id,
            framing: Framing::Fixed(n),
            max_len: 0,
            kind,
        }))
    };
    let byte_len = |c: &mut Cur<'_>, kind: Kind| -> Parsed<TypeInfo> {
        let Some(len) = c.u8() else { return Ok(None) };
        Ok(Some(TypeInfo {
            id,
            framing: Framing::Byte,
            max_len: usize::from(len),
            kind,
        }))
    };
    match id {
        0x1F => fixed(0, Kind::Other),               // NULLTYPE
        0x30 => fixed(1, Kind::Int),                 // INT1
        0x32 => fixed(1, Kind::Bit),                 // BIT
        0x34 => fixed(2, Kind::Int),                 // INT2
        0x38 => fixed(4, Kind::Int),                 // INT4
        0x7F => fixed(8, Kind::Int),                 // INT8
        0x3A | 0x3B | 0x7A => fixed(4, Kind::Other), // DATETIM4, FLT4, MONEY4
        0x3C..=0x3E => fixed(8, Kind::Other),        // MONEY, DATETIME, FLT8
        0x26 => {
            let t = byte_len(c, Kind::Int)?;
            match t {
                Some(t) if ![1, 2, 4, 8].contains(&t.max_len) => Err(TokenError::Malformed),
                t => Ok(t),
            }
        }
        0x68 => {
            let t = byte_len(c, Kind::Bit)?;
            match t {
                Some(t) if t.max_len != 1 => Err(TokenError::Malformed),
                t => Ok(t),
            }
        }
        // GUID, FLTN, MONEYN, DATETIMN, legacy byte-length types.
        0x24 | 0x6D | 0x6E | 0x6F | 0x2F | 0x27 | 0x2D | 0x25 => byte_len(c, Kind::Other),
        // DECIMAL / NUMERIC (legacy and N): length, precision, scale.
        0x37 | 0x3F | 0x6A | 0x6C => {
            let Some(t) = byte_len(c, Kind::Other)? else {
                return Ok(None);
            };
            if c.take(2).is_none() {
                return Ok(None);
            }
            Ok(Some(t))
        }
        // DATEN: no length in the type info, a byte length in the value.
        0x28 => Ok(Some(TypeInfo {
            id,
            framing: Framing::Byte,
            max_len: 3,
            kind: Kind::Other,
        })),
        // TIMEN, DATETIME2N, DATETIMEOFFSETN: a scale byte.
        0x29..=0x2B => {
            let Some(scale) = c.u8() else { return Ok(None) };
            if scale > 7 {
                return Err(TokenError::Malformed);
            }
            let time = match scale {
                0..=2 => 3,
                3 | 4 => 4,
                _ => 5,
            };
            let (len, kind) = match id {
                0x29 => (time, Kind::Other),
                0x2A => (time + 3, Kind::DateTime2),
                _ => (time + 5, Kind::Other),
            };
            Ok(Some(TypeInfo {
                id,
                framing: Framing::Byte,
                max_len: len,
                kind,
            }))
        }
        // Two-byte length types; 0xFFFF is `max` (PLP).
        0xA5 | 0xAD | 0xA7 | 0xAF | 0xE7 | 0xEF => {
            let Some(len) = c.u16() else { return Ok(None) };
            let collated = matches!(id, 0xA7 | 0xAF | 0xE7 | 0xEF);
            if collated && c.take(5).is_none() {
                return Ok(None);
            }
            let kind = match id {
                0xE7 | 0xEF => Kind::Text,
                0xA5 | 0xAD => Kind::Binary,
                _ => Kind::Other,
            };
            if len == 0xFFFF {
                return Ok(Some(TypeInfo {
                    id,
                    framing: Framing::Plp,
                    max_len: 0,
                    kind,
                }));
            }
            let len = usize::from(len);
            if len > MAX_SHORT_VALUE {
                return Err(TokenError::Malformed);
            }
            Ok(Some(TypeInfo {
                id,
                framing: Framing::Short,
                max_len: len,
                kind,
            }))
        }
        // TEXT, NTEXT, IMAGE: a four-byte length, a collation for the
        // character types (the table name follows in COLMETADATA only).
        0x23 | 0x63 | 0x22 => {
            if c.u32().is_none() {
                return Ok(None);
            }
            if id != 0x22 && c.take(5).is_none() {
                return Ok(None);
            }
            Ok(Some(TypeInfo {
                id,
                framing: Framing::Long,
                max_len: 0,
                kind: Kind::Other,
            }))
        }
        // SSVARIANT: a four-byte maximum length.
        0x62 => {
            if c.u32().is_none() {
                return Ok(None);
            }
            Ok(Some(TypeInfo {
                id,
                framing: Framing::Variant,
                max_len: 0,
                kind: Kind::Other,
            }))
        }
        // XML: schema present, then three names.
        0xF1 => {
            let Some(present) = c.u8() else {
                return Ok(None);
            };
            if present == 1
                && (c.skip_b_varchar().is_none()
                    || c.skip_b_varchar().is_none()
                    || c.skip_us_varchar().is_none())
            {
                return Ok(None);
            }
            Ok(Some(TypeInfo {
                id,
                framing: Framing::Plp,
                max_len: 0,
                kind: Kind::Other,
            }))
        }
        // UDT (CLR types): max length, three names, assembly name.
        0xF0 => {
            if c.u16().is_none()
                || c.skip_b_varchar().is_none()
                || c.skip_b_varchar().is_none()
                || c.skip_b_varchar().is_none()
                || c.skip_us_varchar().is_none()
            {
                return Ok(None);
            }
            Ok(Some(TypeInfo {
                id,
                framing: Framing::Plp,
                max_len: 0,
                kind: Kind::Other,
            }))
        }
        // JSON (SQL Server 2025): PLP, no type parameters.
        0xF4 => Ok(Some(TypeInfo {
            id,
            framing: Framing::Plp,
            max_len: 0,
            kind: Kind::Other,
        })),
        _ => Err(TokenError::UnsupportedType),
    }
}

/// Decodes UTF-16LE lossily: lone surrogates and a trailing odd byte
/// become U+FFFD; never panics, never drops a value.
pub(crate) fn utf16_lossy(bytes: &[u8]) -> String {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p));
    let mut s: String = char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect();
    if bytes.len() % 2 == 1 {
        s.push(char::REPLACEMENT_CHARACTER);
    }
    s
}

fn le_int(b: &[u8]) -> Option<i64> {
    Some(match b.len() {
        1 => i64::from(*b.first()?),
        2 => i64::from(i16::from_le_bytes(b.try_into().ok()?)),
        4 => i64::from(i32::from_le_bytes(b.try_into().ok()?)),
        8 => i64::from_le_bytes(b.try_into().ok()?),
        _ => return None,
    })
}

fn value_of(t: &TypeInfo, raw: &[u8]) -> Result<Value, TokenError> {
    Ok(match t.kind {
        Kind::Int => Value::Int(le_int(raw).ok_or(TokenError::Malformed)?),
        Kind::Bit => Value::Bit(raw.first().copied().ok_or(TokenError::Malformed)? != 0),
        Kind::Text => Value::Text(utf16_lossy(raw)),
        Kind::Binary => Value::Binary(raw.to_vec()),
        Kind::DateTime2 => Value::DateTime2(raw.to_vec()),
        Kind::Other => return Err(TokenError::UnsupportedType),
    })
}

/// Bytes a whole non-PLP value takes at the start of `c` (length prefix
/// included), for skipping a `RETURNVALUE`. `Ok(None)`: incomplete.
fn skip_value(t: &TypeInfo, c: &mut Cur<'_>) -> Parsed<()> {
    let n = match t.framing {
        Framing::Fixed(n) => n,
        Framing::Byte => match c.u8() {
            Some(n) => usize::from(n),
            None => return Ok(None),
        },
        Framing::Short => match c.u16() {
            Some(0xFFFF) => 0,
            Some(n) => usize::from(n),
            None => return Ok(None),
        },
        Framing::Variant => match c.u32() {
            Some(n) => n as usize,
            None => return Ok(None),
        },
        Framing::Long => {
            let Some(ptr) = c.u8() else { return Ok(None) };
            if ptr == 0 {
                0
            } else {
                if c.take(usize::from(ptr) + 8).is_none() {
                    return Ok(None);
                }
                match c.u32() {
                    Some(n) => n as usize,
                    None => return Ok(None),
                }
            }
        }
        Framing::Plp => {
            let Some(total) = c.u64() else {
                return Ok(None);
            };
            if total == u64::MAX {
                return Ok(Some(()));
            }
            let mut seen = 0usize;
            loop {
                let Some(chunk) = c.u32() else {
                    return Ok(None);
                };
                if chunk == 0 {
                    return Ok(Some(()));
                }
                seen = seen.saturating_add(chunk as usize);
                if seen > MAX_RETURN_VALUE {
                    return Err(TokenError::Limit);
                }
                if c.take(chunk as usize).is_none() {
                    return Ok(None);
                }
            }
        }
    };
    if n > MAX_RETURN_VALUE {
        return Err(TokenError::Limit);
    }
    Ok(c.take(n).map(|_| ()))
}

/// The `PacketSize` value of an `ENVCHANGE`, `B_VARCHAR` digits.
fn packet_size(data: &[u8]) -> Option<usize> {
    let mut c = Cur::new(data);
    let n = usize::from(c.u8()?);
    let s = utf16_lossy(c.take(n * 2)?);
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl Decoder {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            state: State::Token,
            columns: Vec::new(),
            limits,
            discard: false,
        }
    }

    /// Whether the decoder is between tokens (a message may end here).
    pub(crate) fn at_token(&self) -> bool {
        matches!(self.state, State::Token)
    }

    /// Decodes the next step from `buf`: `Ok(None)` when more bytes are
    /// needed, otherwise the event (if any) and the bytes consumed. Every
    /// `Some` makes progress: an event, or at least one byte consumed.
    pub(crate) fn next(
        &mut self,
        buf: &[u8],
    ) -> Result<Option<(Option<Event>, usize)>, TokenError> {
        let row_done = matches!(&self.state, State::Row { col, .. } if *col >= self.columns.len());
        if buf.is_empty() && !row_done {
            return Ok(None);
        }
        let state = std::mem::replace(&mut self.state, State::Token);
        let (state, out) = match state {
            State::Token => (State::Token, self.token(buf)),
            State::Row { col, nulls } => self.row(buf, col, nulls),
            State::Plp {
                col,
                nulls,
                total,
                acc,
                chunk_left,
            } => self.plp(buf, col, nulls, total, acc, chunk_left),
        };
        // `token` may have entered a row: it sets `self.state` itself.
        if !matches!(state, State::Token) {
            self.state = state;
        }
        out
    }

    fn token(&mut self, buf: &[u8]) -> Result<Option<(Option<Event>, usize)>, TokenError> {
        let mut c = Cur::new(buf);
        let Some(t) = c.u8() else { return Ok(None) };
        let whole = |c: &mut Cur<'_>| -> Option<usize> {
            let len = usize::from(c.u16()?);
            Some(len)
        };
        match t {
            tok::COLMETADATA => {
                let Some(count) = c.u16() else {
                    return Ok(None);
                };
                if count == 0xFFFF {
                    self.columns.clear();
                    return Ok(Some((Some(Event::ColMetadata(0)), c.pos)));
                }
                let count = usize::from(count);
                if count > self.limits.max_columns || count > MAX_COLUMNS {
                    return Err(TokenError::Limit);
                }
                let mut cols = Vec::with_capacity(count);
                for _ in 0..count {
                    // UserType, Flags.
                    if c.take(6).is_none() {
                        return Ok(None);
                    }
                    let Some(ti) = type_info(&mut c)? else {
                        return Ok(None);
                    };
                    if ti.framing == Framing::Long {
                        let Some(parts) = c.u8() else { return Ok(None) };
                        for _ in 0..parts {
                            if c.skip_us_varchar().is_none() {
                                return Ok(None);
                            }
                        }
                    }
                    if c.skip_b_varchar().is_none() {
                        return Ok(None);
                    }
                    // Fail closed on what the statement did not ask for.
                    if ti.kind == Kind::Other
                        || (ti.framing == Framing::Plp
                            && (self.limits.plp_cap == 0 || ti.kind != Kind::Text))
                    {
                        return Err(TokenError::UnsupportedType);
                    }
                    cols.push(ti);
                }
                self.columns = cols;
                Ok(Some((Some(Event::ColMetadata(count)), c.pos)))
            }
            tok::ROW | tok::NBCROW => {
                if self.columns.is_empty() {
                    return Err(TokenError::Malformed);
                }
                let nulls = if t == tok::NBCROW {
                    let n = self.columns.len().div_ceil(8);
                    let Some(b) = c.take(n) else { return Ok(None) };
                    Some(b.to_vec())
                } else {
                    None
                };
                self.state = State::Row { col: 0, nulls };
                Ok(Some((Some(Event::RowStart), c.pos)))
            }
            tok::DONE | tok::DONEPROC | tok::DONEINPROC => {
                let (Some(status), Some(_cmd), Some(rows)) = (c.u16(), c.u16(), c.u64()) else {
                    return Ok(None);
                };
                Ok(Some((
                    Some(Event::Done {
                        token: t,
                        status,
                        rows,
                    }),
                    c.pos,
                )))
            }
            tok::RETURNSTATUS => {
                let Some(v) = c.u32() else { return Ok(None) };
                Ok(Some((Some(Event::ReturnStatus(v as i32)), c.pos)))
            }
            tok::ERROR | tok::INFO | tok::LOGINACK | tok::ENVCHANGE | tok::ORDER => {
                let Some(len) = whole(&mut c) else {
                    return Ok(None);
                };
                let Some(body) = c.take(len) else {
                    return Ok(None);
                };
                let ev = Self::sized(t, body)?;
                Ok(Some((Some(ev), c.pos)))
            }
            tok::RETURNVALUE => {
                // Ordinal, name, status, user type, flags, type info, value.
                if c.take(2).is_none() || c.skip_b_varchar().is_none() || c.take(7).is_none() {
                    return Ok(None);
                }
                let Some(ti) = type_info(&mut c)? else {
                    return Ok(None);
                };
                if skip_value(&ti, &mut c)?.is_none() {
                    return Ok(None);
                }
                Ok(Some((Some(Event::Skipped), c.pos)))
            }
            _ => Err(TokenError::UnknownToken),
        }
    }

    /// The tokens with a two-byte length.
    fn sized(t: u8, body: &[u8]) -> Result<Event, TokenError> {
        let mut c = Cur::new(body);
        let bad = TokenError::Malformed;
        Ok(match t {
            tok::ERROR | tok::INFO => {
                let number = c.u32().ok_or(bad)? as i32;
                let state = c.u8().ok_or(bad)?;
                let class = c.u8().ok_or(bad)?;
                // Message text, server and procedure names: never read.
                if t == tok::ERROR {
                    Event::Error {
                        number,
                        state,
                        class,
                    }
                } else {
                    Event::Info { number }
                }
            }
            tok::LOGINACK => {
                let _interface = c.u8().ok_or(bad)?;
                let v = c.take(4).ok_or(bad)?;
                let tds_version = u32::from_be_bytes(v.try_into().map_err(|_| bad)?);
                c.skip_b_varchar().ok_or(bad)?;
                let p = c.take(4).ok_or(bad)?;
                let [major, minor, hi, lo]: [u8; 4] = p.try_into().map_err(|_| bad)?;
                Event::LoginAck {
                    tds_version,
                    major,
                    minor,
                    build: u16::from_be_bytes([hi, lo]),
                }
            }
            tok::ENVCHANGE => {
                let kind = c.u8().ok_or(bad)?;
                let rest = body.get(1..).unwrap_or_default();
                match kind {
                    1 => Event::Database,
                    4 => Event::PacketSize(packet_size(rest).ok_or(bad)?),
                    8..=12 | 15..=17 => Event::Transaction,
                    20 => Event::Routing,
                    // Language, collation, mirroring partner (13: ignored,
                    // never connected to), reset ack, user instance…
                    _ => Event::Skipped,
                }
            }
            _ => Event::Skipped,
        })
    }

    #[allow(clippy::type_complexity)]
    fn row(
        &mut self,
        buf: &[u8],
        col: usize,
        nulls: Option<Vec<u8>>,
    ) -> (State, Result<Option<(Option<Event>, usize)>, TokenError>) {
        let Some(t) = self.columns.get(col).copied() else {
            return (State::Token, Ok(Some((Some(Event::RowEnd), 0))));
        };
        // After the row's last value, the next call emits `RowEnd`.
        let next = |col: usize, nulls: Option<Vec<u8>>| State::Row {
            col: col + 1,
            nulls,
        };
        let is_null = nulls
            .as_ref()
            .and_then(|n| n.get(col / 8))
            .is_some_and(|b| b & (1 << (col % 8)) != 0);
        if is_null {
            return (
                next(col, nulls),
                Ok(Some((Some(Event::Value(col, Value::Null)), 0))),
            );
        }
        let mut c = Cur::new(buf);
        let raw: Option<&[u8]> = match t.framing {
            Framing::Fixed(n) => match c.take(n) {
                Some(r) => Some(r),
                None => return (State::Row { col, nulls }, Ok(None)),
            },
            Framing::Byte => {
                let Some(n) = c.u8() else {
                    return (State::Row { col, nulls }, Ok(None));
                };
                let n = usize::from(n);
                if n == 0 {
                    None
                } else if n > t.max_len || (t.kind == Kind::Int && ![1, 2, 4, 8].contains(&n)) {
                    return (State::Token, Err(TokenError::Malformed));
                } else {
                    match c.take(n) {
                        Some(r) => Some(r),
                        None => return (State::Row { col, nulls }, Ok(None)),
                    }
                }
            }
            Framing::Short => {
                let Some(n) = c.u16() else {
                    return (State::Row { col, nulls }, Ok(None));
                };
                if n == 0xFFFF {
                    None
                } else if usize::from(n) > t.max_len {
                    return (State::Token, Err(TokenError::Malformed));
                } else {
                    match c.take(usize::from(n)) {
                        Some(r) => Some(r),
                        None => return (State::Row { col, nulls }, Ok(None)),
                    }
                }
            }
            Framing::Plp => {
                let Some(total) = c.u64() else {
                    return (State::Row { col, nulls }, Ok(None));
                };
                if total == u64::MAX {
                    None
                } else {
                    let known = (total != u64::MAX - 1).then_some(total);
                    if !self.discard && known.is_some_and(|n| n > self.limits.plp_cap as u64) {
                        return (State::Token, Err(TokenError::Limit));
                    }
                    return (
                        State::Plp {
                            col,
                            nulls,
                            total: known,
                            acc: Vec::new(),
                            chunk_left: 0,
                        },
                        Ok(Some((None, c.pos))),
                    );
                }
            }
            Framing::Long | Framing::Variant => {
                return (State::Token, Err(TokenError::UnsupportedType));
            }
        };
        let value = match raw {
            None => Value::Null,
            Some(r) => match value_of(&t, r) {
                Ok(v) => v,
                Err(e) => return (State::Token, Err(e)),
            },
        };
        let pos = c.pos;
        (
            next(col, nulls),
            Ok(Some((Some(Event::Value(col, value)), pos))),
        )
    }

    #[allow(clippy::type_complexity)]
    fn plp(
        &mut self,
        buf: &[u8],
        col: usize,
        nulls: Option<Vec<u8>>,
        total: Option<u64>,
        mut acc: Vec<u8>,
        chunk_left: usize,
    ) -> (State, Result<Option<(Option<Event>, usize)>, TokenError>) {
        let mut c = Cur::new(buf);
        if chunk_left > 0 {
            let n = chunk_left.min(buf.len());
            let Some(bytes) = c.take(n) else {
                return (State::Token, Err(TokenError::Malformed));
            };
            if !self.discard {
                acc.extend_from_slice(bytes);
            }
            return (
                State::Plp {
                    col,
                    nulls,
                    total,
                    acc,
                    chunk_left: chunk_left - n,
                },
                Ok(Some((None, n))),
            );
        }
        let Some(chunk) = c.u32() else {
            return (
                State::Plp {
                    col,
                    nulls,
                    total,
                    acc,
                    chunk_left,
                },
                Ok(None),
            );
        };
        let chunk = chunk as usize;
        if chunk == 0 {
            if !self.discard && total.is_some_and(|t| t != acc.len() as u64) {
                return (State::Token, Err(TokenError::Malformed));
            }
            let value = if self.discard {
                Value::Null
            } else {
                Value::Text(utf16_lossy(&acc))
            };
            zeroize::Zeroize::zeroize(&mut acc);
            return (
                State::Row {
                    col: col + 1,
                    nulls,
                },
                Ok(Some((Some(Event::Value(col, value)), c.pos))),
            );
        }
        // Checked before the chunk is buffered (L1).
        if !self.discard && acc.len().saturating_add(chunk) > self.limits.plp_cap {
            return (State::Token, Err(TokenError::Limit));
        }
        (
            State::Plp {
                col,
                nulls,
                total,
                acc,
                chunk_left: chunk,
            },
            Ok(Some((None, c.pos))),
        )
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
pub(crate) mod tests {
    use super::*;

    /// Test builders of server token streams.
    pub(crate) mod build {
        use super::super::tok;

        pub(crate) fn b_varchar(s: &str) -> Vec<u8> {
            let u = crate::tds::utf16(s);
            let mut v = vec![(u.len() / 2) as u8];
            v.extend(u);
            v
        }

        /// COLMETADATA with `nvarchar(n)` columns (`n` characters).
        pub(crate) fn colmeta_nvarchar(cols: &[(&str, u16)]) -> Vec<u8> {
            let mut v = vec![tok::COLMETADATA];
            v.extend((cols.len() as u16).to_le_bytes());
            for (name, n) in cols {
                v.extend([0, 0, 0, 0, 1, 0]);
                v.push(0xE7);
                v.extend((n * 2).to_le_bytes());
                v.extend([0x09, 0x04, 0xD0, 0x00, 0x34]);
                v.extend(b_varchar(name));
            }
            v
        }

        pub(crate) fn colmeta_int(names: &[&str]) -> Vec<u8> {
            let mut v = vec![tok::COLMETADATA];
            v.extend((names.len() as u16).to_le_bytes());
            for name in names {
                v.extend([0, 0, 0, 0, 1, 0, 0x26, 4]);
                v.extend(b_varchar(name));
            }
            v
        }

        pub(crate) fn row_text(values: &[Option<&str>]) -> Vec<u8> {
            let mut v = vec![tok::ROW];
            for value in values {
                match value {
                    None => v.extend(0xFFFFu16.to_le_bytes()),
                    Some(s) => {
                        let u = crate::tds::utf16(s);
                        v.extend((u.len() as u16).to_le_bytes());
                        v.extend(u);
                    }
                }
            }
            v
        }

        pub(crate) fn row_int(values: &[Option<i32>]) -> Vec<u8> {
            let mut v = vec![tok::ROW];
            for value in values {
                match value {
                    None => v.push(0),
                    Some(i) => {
                        v.push(4);
                        v.extend(i.to_le_bytes());
                    }
                }
            }
            v
        }

        pub(crate) fn done(token: u8, status: u16, rows: u64) -> Vec<u8> {
            let mut v = vec![token];
            v.extend(status.to_le_bytes());
            v.extend(0xC1u16.to_le_bytes());
            v.extend(rows.to_le_bytes());
            v
        }

        pub(crate) fn error(number: i32, class: u8, message: &str) -> Vec<u8> {
            let mut body = Vec::new();
            body.extend(number.to_le_bytes());
            body.push(1);
            body.push(class);
            let m = crate::tds::utf16(message);
            body.extend(((m.len() / 2) as u16).to_le_bytes());
            body.extend(m);
            body.extend(b_varchar("srv"));
            body.extend(b_varchar(""));
            body.extend(1i32.to_le_bytes());
            let mut v = vec![tok::ERROR];
            v.extend((body.len() as u16).to_le_bytes());
            v.extend(body);
            v
        }

        pub(crate) fn envchange(kind: u8, data: &[u8]) -> Vec<u8> {
            let mut v = vec![tok::ENVCHANGE];
            v.extend(((data.len() + 1) as u16).to_le_bytes());
            v.push(kind);
            v.extend(data);
            v
        }

        pub(crate) fn loginack(major: u8, minor: u8, build: u16) -> Vec<u8> {
            let mut body = vec![1];
            body.extend(0x7400_0004u32.to_be_bytes());
            body.extend(b_varchar("Microsoft SQL Server"));
            body.push(major);
            body.push(minor);
            body.extend(build.to_be_bytes());
            let mut v = vec![tok::LOGINACK];
            v.extend((body.len() as u16).to_le_bytes());
            v.extend(body);
            v
        }
    }

    /// Decodes a whole stream, feeding it `step` bytes at a time.
    pub(crate) fn decode_all(
        dec: &mut Decoder,
        stream: &[u8],
        step: usize,
    ) -> Result<Vec<Event>, TokenError> {
        let mut buf: Vec<u8> = Vec::new();
        let mut events = Vec::new();
        let mut fed = 0;
        loop {
            match dec.next(&buf)? {
                Some((ev, n)) => {
                    buf.drain(..n);
                    events.extend(ev);
                }
                None => {
                    if fed >= stream.len() {
                        return Ok(events);
                    }
                    let end = (fed + step).min(stream.len());
                    buf.extend_from_slice(&stream[fed..end]);
                    fed = end;
                }
            }
        }
    }

    #[test]
    fn rows_of_text_and_ints_in_any_split() {
        let mut s = build::colmeta_nvarchar(&[("a", 4000), ("b", 10)]);
        s.extend(build::row_text(&[Some("héllo"), None]));
        s.extend(build::row_text(&[Some(""), Some("x")]));
        s.extend(build::done(tok::DONE, done::COUNT, 2));
        for step in [1, 3, 7, 64, 10_000] {
            let mut d = Decoder::default();
            let ev = decode_all(&mut d, &s, step).unwrap();
            assert_eq!(
                ev,
                vec![
                    Event::ColMetadata(2),
                    Event::RowStart,
                    Event::Value(0, Value::Text("héllo".into())),
                    Event::Value(1, Value::Null),
                    Event::RowEnd,
                    Event::RowStart,
                    Event::Value(0, Value::Text(String::new())),
                    Event::Value(1, Value::Text("x".into())),
                    Event::RowEnd,
                    Event::Done {
                        token: tok::DONE,
                        status: done::COUNT,
                        rows: 2
                    },
                ],
                "step {step}"
            );
            assert!(d.at_token());
        }
    }

    #[test]
    fn error_text_is_never_kept() {
        let s = build::error(
            245,
            16,
            "Conversion failed when converting the nvarchar value 'SECRET-MARKER'",
        );
        let mut d = Decoder::default();
        let ev = decode_all(&mut d, &s, 5).unwrap();
        assert_eq!(
            ev,
            vec![Event::Error {
                number: 245,
                state: 1,
                class: 16
            }]
        );
        assert!(!format!("{ev:?}").contains("SECRET"));
    }

    #[test]
    fn closed_sets_fail_closed() {
        let mut d = Decoder::default();
        assert_eq!(d.next(&[0x88]), Err(TokenError::UnknownToken));
        // An xml column.
        let mut s = vec![tok::COLMETADATA, 1, 0, 0, 0, 0, 0, 1, 0, 0xF1, 0];
        s.extend(build::b_varchar("x"));
        let mut d = Decoder::default();
        assert_eq!(
            decode_all(&mut d, &s, 100),
            Err(TokenError::UnsupportedType)
        );
        // nvarchar(max) without a PLP cap.
        let mut s = vec![
            tok::COLMETADATA,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0xE7,
            0xFF,
            0xFF,
            9,
            4,
            0xD0,
            0,
            0x34,
        ];
        s.extend(build::b_varchar("x"));
        let mut d = Decoder::default();
        assert_eq!(
            decode_all(&mut d, &s, 100),
            Err(TokenError::UnsupportedType)
        );
        // Too many columns.
        let mut d = Decoder::new(Limits {
            max_columns: 1,
            plp_cap: 0,
        });
        let s = build::colmeta_int(&["a", "b"]);
        assert_eq!(decode_all(&mut d, &s, 100), Err(TokenError::Limit));
        // A row with no metadata.
        let mut d = Decoder::default();
        assert_eq!(d.next(&[tok::ROW]), Err(TokenError::Malformed));
        // A value longer than its column.
        let mut s = build::colmeta_nvarchar(&[("a", 2)]);
        s.extend(build::row_text(&[Some("abcdef")]));
        let mut d = Decoder::default();
        assert_eq!(decode_all(&mut d, &s, 100), Err(TokenError::Malformed));
    }

    #[test]
    fn envchange_routing_transaction_and_packet_size() {
        let mut d = Decoder::default();
        let mut s = build::envchange(20, &[0, 0]);
        s.extend(build::envchange(8, &[8, 1, 2, 3, 4, 5, 6, 7, 8, 0]));
        s.extend(build::envchange(13, &[0, 0]));
        let mut ps = build::b_varchar("8000");
        ps.extend(build::b_varchar("4096"));
        s.extend(build::envchange(4, &ps));
        assert_eq!(
            decode_all(&mut d, &s, 3).unwrap(),
            vec![
                Event::Routing,
                Event::Transaction,
                Event::Skipped,
                Event::PacketSize(8000)
            ]
        );
    }

    #[test]
    fn plp_is_capped_chunk_by_chunk() {
        let mut meta = vec![
            tok::COLMETADATA,
            1,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0xE7,
            0xFF,
            0xFF,
            9,
            4,
            0xD0,
            0,
            0x34,
        ];
        meta.extend(build::b_varchar("x"));
        let plp = |chunks: &[&[u8]], total: u64| {
            let mut v = vec![tok::ROW];
            v.extend(total.to_le_bytes());
            for c in chunks {
                v.extend((c.len() as u32).to_le_bytes());
                v.extend(*c);
            }
            v.extend(0u32.to_le_bytes());
            v
        };
        let mut s = meta.clone();
        s.extend(plp(&[b"a\0", b"b\0"], 4));
        let mut d = Decoder::new(Limits {
            max_columns: 1,
            plp_cap: 16,
        });
        let ev = decode_all(&mut d, &s, 1).unwrap();
        assert!(ev.contains(&Event::Value(0, Value::Text("ab".into()))));
        assert!(ev.contains(&Event::RowEnd));
        // Unknown total, second chunk past the cap.
        let mut s = meta.clone();
        s.extend(plp(&[&[0; 10], &[0; 10]], u64::MAX - 1));
        let mut d = Decoder::new(Limits {
            max_columns: 1,
            plp_cap: 16,
        });
        assert_eq!(decode_all(&mut d, &s, 1), Err(TokenError::Limit));
        // Declared total past the cap.
        let mut s = meta;
        s.extend(plp(&[&[0; 2]], 1 << 40));
        let mut d = Decoder::new(Limits {
            max_columns: 1,
            plp_cap: 16,
        });
        assert_eq!(decode_all(&mut d, &s, 1), Err(TokenError::Limit));
    }

    #[test]
    fn lone_surrogates_are_replaced() {
        assert_eq!(utf16_lossy(&[0x00, 0xD8, 0x41, 0x00]), "\u{FFFD}A");
        assert_eq!(utf16_lossy(&[0x41, 0x00, 0x42]), "A\u{FFFD}");
    }
}
