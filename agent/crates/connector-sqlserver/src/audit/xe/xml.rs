//! The bounded reader of Extended Events event XML (ADR-0051 decision 6,
//! "What is kept": "the event XML is parsed by a bounded reader (closed
//! element and attribute names; any other content skipped by length;
//! fuzzed)"; P9-A obligation L1).
//!
//! `sys.fn_xe_file_target_read_file` returns each event as an
//! `nvarchar(max)` XML text (measured on 2019 and 2022):
//!
//! ```text
//! <event name="sql_statement_completed" package="sqlserver" timestamp="…">
//!   <data name="row_count"><value>2</value></data>
//!   <data name="statement"><value><![CDATA[SELECT …]]></value></data>
//!   <action name="session_id" package="sqlserver"><value>51</value></action>
//!   …
//! </event>
//! ```
//!
//! The reader is an own, iterative parser of that closed shape, not a
//! general XML library:
//! - **No DTD, no entity of any kind but the five predefined ones and
//!   character references** (`<!DOCTYPE`, `<!ENTITY` and any other `&name;`
//!   end the parse): nothing is ever expanded or fetched.
//! - **Bounds**: the whole event ([`MAX_EVENT_BYTES`]), the depth
//!   ([`MAX_DEPTH`]), the elements ([`MAX_ELEMENTS`]), the attributes of an
//!   element ([`MAX_ATTRIBUTES`]) and their length, names
//!   ([`MAX_NAME_BYTES`]).
//! - **Closed names**: the root is `event`; only the `value` of the `data`
//!   and `action` elements named in [`Field`] is kept, and only for the
//!   event types that keep it (the `statement` of `rpc_completed` holds
//!   parameter values and the `batch_text` of `sql_batch_completed` the
//!   whole batch: both are read past, never stored, decision 6 M5); every
//!   other element and text is checked and skipped without being stored.
//!   The `message` of `error_reported` (it quotes values) is never stored.
//! - **Kept values**: the statement up to [`MAX_STATEMENT_BYTES`] (beyond:
//!   cut, never the agent's own, never analysed), every other field up to
//!   [`MAX_FIELD_BYTES`] (beyond: the event is malformed). The statement is
//!   zeroized on drop. A kept field present twice makes the event
//!   malformed.
//!
//! Every malformed event is an error (`XmlError`, without text); the caller
//! drops and counts it (`audit.records_dropped`), under panic isolation.

use zeroize::Zeroizing;

/// Largest event text read (UTF-8 bytes). The poll asks the server for
/// events of at most 128 KiB of UTF-16 (`sql::XE_EVENT_BYTES`), which is
/// at most 192 KiB of UTF-8.
pub(crate) const MAX_EVENT_BYTES: usize = 192 * 1024;
/// Longest statement kept (decision 6: 64 KiB, as SQL Server Audit's
/// reassembly); beyond, the statement is cut.
pub(crate) const MAX_STATEMENT_BYTES: usize = 64 * 1024;
/// Longest other kept value (names are `sysname`, 128 characters).
pub(crate) const MAX_FIELD_BYTES: usize = 512;
/// Deepest element nesting (`event` > `data` > `value` is 3).
pub(crate) const MAX_DEPTH: usize = 8;
/// Most elements per event.
pub(crate) const MAX_ELEMENTS: usize = 1024;
/// Most attributes per element.
pub(crate) const MAX_ATTRIBUTES: usize = 8;
/// Longest attribute value.
pub(crate) const MAX_ATTRIBUTE_BYTES: usize = 256;
/// Longest element or attribute name.
pub(crate) const MAX_NAME_BYTES: usize = 64;

/// Why an event was not read (no text from it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum XmlError {
    /// Above a bound.
    Bound,
    /// Not the expected XML (syntax, a DTD, an unknown entity, a root that
    /// is not `event`, a kept field twice, trailing content).
    Syntax,
}

/// The event types the source knows (anything else is `Other`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    SqlStatementCompleted,
    SpStatementCompleted,
    RpcCompleted,
    SqlBatchCompleted,
    ErrorReported,
    Login,
    Other,
}

impl Kind {
    pub(crate) fn of(name: &str) -> Self {
        match name {
            "sql_statement_completed" => Self::SqlStatementCompleted,
            "sp_statement_completed" => Self::SpStatementCompleted,
            "rpc_completed" => Self::RpcCompleted,
            "sql_batch_completed" => Self::SqlBatchCompleted,
            "error_reported" => Self::ErrorReported,
            "login" => Self::Login,
            _ => Self::Other,
        }
    }

    /// Statement-level events, the only ones that produce access events
    /// (decision 6, M5).
    pub(crate) fn is_statement(self) -> bool {
        matches!(
            self,
            Self::SqlStatementCompleted | Self::SpStatementCompleted
        )
    }
}

/// The kept fields: `data` (D) or `action` (A) names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Statement,
    RowCount,
    ObjectName,
    ErrorNumber,
    SessionId,
    ServerPrincipal,
    SessionPrincipal,
    ClientApp,
    Database,
    Activity,
    /// `sp_statement_completed`: `nest_level`, `offset`, `offset_end` and
    /// `object_type` (its map value and its text): the shape of a
    /// statistics build's internal statements (ADR-0051 refinement of
    /// 2026-10-15, case 1).
    NestLevel,
    Offset,
    OffsetEnd,
    ObjectType,
    ObjectTypeName,
}

/// The kept field of a `data` element of an event of `kind`.
fn data_field(kind: Kind, name: &str) -> Option<Field> {
    match (kind, name) {
        (Kind::SqlStatementCompleted | Kind::SpStatementCompleted, "statement") => {
            Some(Field::Statement)
        }
        (
            Kind::SqlStatementCompleted
            | Kind::SpStatementCompleted
            | Kind::RpcCompleted
            | Kind::SqlBatchCompleted,
            "row_count",
        ) => Some(Field::RowCount),
        // The procedure an RPC called (its `statement`, with the parameter
        // values, is never kept).
        (Kind::RpcCompleted, "object_name") => Some(Field::ObjectName),
        (Kind::ErrorReported, "error_number") => Some(Field::ErrorNumber),
        (Kind::SpStatementCompleted, "nest_level") => Some(Field::NestLevel),
        (Kind::SpStatementCompleted, "offset") => Some(Field::Offset),
        (Kind::SpStatementCompleted, "offset_end") => Some(Field::OffsetEnd),
        (Kind::SpStatementCompleted, "object_type") => Some(Field::ObjectType),
        _ => None,
    }
}

/// The kept field of an `action` element.
fn action_field(name: &str) -> Option<Field> {
    match name {
        "session_id" => Some(Field::SessionId),
        "server_principal_name" => Some(Field::ServerPrincipal),
        "session_server_principal_name" => Some(Field::SessionPrincipal),
        "client_app_name" => Some(Field::ClientApp),
        "database_name" => Some(Field::Database),
        "attach_activity_id" => Some(Field::Activity),
        // `client_hostname` is never kept (security review H1), nor any
        // other action.
        _ => None,
    }
}

/// What an event holds, closed fields only.
#[derive(Default)]
pub(crate) struct XeEvent {
    /// The event's name (`<event name="…">`), bounded.
    pub(crate) name: String,
    pub(crate) statement: Option<Zeroizing<String>>,
    /// The statement was longer than [`MAX_STATEMENT_BYTES`]: what is
    /// kept is its start.
    pub(crate) statement_cut: bool,
    pub(crate) row_count: Option<u64>,
    pub(crate) object_name: Option<String>,
    pub(crate) error_number: Option<i64>,
    pub(crate) session_id: Option<i64>,
    pub(crate) server_principal: Option<String>,
    pub(crate) session_principal: Option<String>,
    pub(crate) client_app: Option<String>,
    pub(crate) database: Option<String>,
    /// `attach_activity_id`: the activity GUID and the event's sequence in
    /// it (`TRACK_CAUSALITY = ON`).
    pub(crate) activity: Option<(String, u64)>,
    /// `sp_statement_completed` only.
    pub(crate) nest_level: Option<i64>,
    pub(crate) offset: Option<i64>,
    pub(crate) offset_end: Option<i64>,
    /// The `object_type` map value and its text (`20801`, `ADHOC`).
    pub(crate) object_type: Option<i64>,
    pub(crate) object_type_name: Option<String>,
}

impl std::fmt::Debug for XeEvent {
    // Never prints a value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XeEvent")
            .field("name", &self.name)
            .field("session_id", &self.session_id)
            .field("row_count", &self.row_count)
            .finish_non_exhaustive()
    }
}

impl XeEvent {
    pub(crate) fn kind(&self) -> Kind {
        Kind::of(&self.name)
    }

    fn set(&mut self, field: Field, text: Capture) -> Result<(), XmlError> {
        let Capture { text, cut } = text;
        let short = |t: Zeroizing<String>| -> Result<String, XmlError> {
            if cut || t.len() > MAX_FIELD_BYTES {
                return Err(XmlError::Bound);
            }
            Ok(t.to_string())
        };
        let number = |t: &str| -> Result<i64, XmlError> {
            t.trim().parse::<i64>().map_err(|_| XmlError::Syntax)
        };
        let dup = |present: bool| {
            if present {
                Err(XmlError::Syntax)
            } else {
                Ok(())
            }
        };
        match field {
            Field::Statement => {
                dup(self.statement.is_some())?;
                self.statement = Some(text);
                self.statement_cut = cut;
            }
            Field::RowCount => {
                dup(self.row_count.is_some())?;
                let n = number(&short(text)?)?;
                self.row_count = Some(u64::try_from(n).unwrap_or(0));
            }
            Field::ObjectName => {
                dup(self.object_name.is_some())?;
                self.object_name = Some(short(text)?);
            }
            Field::ErrorNumber => {
                dup(self.error_number.is_some())?;
                self.error_number = Some(number(&short(text)?)?);
            }
            Field::SessionId => {
                dup(self.session_id.is_some())?;
                self.session_id = Some(number(&short(text)?)?);
            }
            Field::ServerPrincipal => {
                dup(self.server_principal.is_some())?;
                self.server_principal = Some(short(text)?);
            }
            Field::SessionPrincipal => {
                dup(self.session_principal.is_some())?;
                self.session_principal = Some(short(text)?);
            }
            Field::ClientApp => {
                dup(self.client_app.is_some())?;
                self.client_app = Some(short(text)?);
            }
            Field::Database => {
                dup(self.database.is_some())?;
                self.database = Some(short(text)?);
            }
            Field::NestLevel => {
                dup(self.nest_level.is_some())?;
                self.nest_level = Some(number(&short(text)?)?);
            }
            Field::Offset => {
                dup(self.offset.is_some())?;
                self.offset = Some(number(&short(text)?)?);
            }
            Field::OffsetEnd => {
                dup(self.offset_end.is_some())?;
                self.offset_end = Some(number(&short(text)?)?);
            }
            Field::ObjectType => {
                dup(self.object_type.is_some())?;
                self.object_type = Some(number(&short(text)?)?);
            }
            Field::ObjectTypeName => {
                dup(self.object_type_name.is_some())?;
                self.object_type_name = Some(short(text)?);
            }
            Field::Activity => {
                dup(self.activity.is_some())?;
                let t = short(text)?;
                // `<GUID>-<sequence>`.
                let (guid, seq) = t.rsplit_once('-').ok_or(XmlError::Syntax)?;
                let seq = seq.trim().parse::<u64>().map_err(|_| XmlError::Syntax)?;
                self.activity = Some((guid.to_ascii_uppercase(), seq));
            }
        }
        Ok(())
    }
}

/// Text captured for a kept field.
struct Capture {
    text: Zeroizing<String>,
    cut: bool,
}

/// Where text goes: kept (with its bound) or checked and dropped.
enum Sink {
    Keep {
        buf: Zeroizing<String>,
        cap: usize,
        cut: bool,
    },
    Drop,
}

impl Sink {
    fn push(&mut self, s: &str) {
        if let Self::Keep { buf, cap, cut } = self {
            if *cut {
                return;
            }
            let room = cap.saturating_sub(buf.len());
            if s.len() <= room {
                buf.push_str(s);
            } else {
                let mut end = room;
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                buf.push_str(s.get(..end).unwrap_or_default());
                *cut = true;
            }
        }
    }

    fn push_char(&mut self, c: char) {
        let mut b = [0u8; 4];
        self.push(c.encode_utf8(&mut b));
    }
}

struct Parser<'a> {
    s: &'a str,
    pos: usize,
    elements: usize,
}

/// One element's start tag.
struct Start<'a> {
    name: &'a str,
    /// The `name` attribute.
    attr_name: Option<String>,
    empty: bool,
}

fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b':'
}

fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'-' | b'.')
}

impl<'a> Parser<'a> {
    fn bytes(&self) -> &'a [u8] {
        self.s.as_bytes()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes().get(self.pos).copied()
    }

    fn starts(&self, p: &str) -> bool {
        self.bytes()
            .get(self.pos..)
            .is_some_and(|r| r.starts_with(p.as_bytes()))
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_whitespace()) {
            self.pos += 1;
        }
    }

    /// Skips to just after `end`; `Err` when it never comes.
    fn skip_past(&mut self, end: &str) -> Result<(), XmlError> {
        let rest = self.s.get(self.pos..).ok_or(XmlError::Syntax)?;
        let i = rest.find(end).ok_or(XmlError::Syntax)?;
        self.pos += i + end.len();
        Ok(())
    }

    fn name(&mut self) -> Result<&'a str, XmlError> {
        let start = self.pos;
        if !self.peek().is_some_and(is_name_start) {
            return Err(XmlError::Syntax);
        }
        while self.peek().is_some_and(is_name_char) {
            self.pos += 1;
            if self.pos - start > MAX_NAME_BYTES {
                return Err(XmlError::Bound);
            }
        }
        self.s.get(start..self.pos).ok_or(XmlError::Syntax)
    }

    /// Comments, processing instructions and the XML declaration between
    /// elements. A DTD (`<!DOCTYPE`, `<!ENTITY`…) is refused.
    fn misc(&mut self) -> Result<bool, XmlError> {
        if self.starts("<!--") {
            self.pos += 4;
            self.skip_past("-->")?;
            return Ok(true);
        }
        if self.starts("<?") {
            self.pos += 2;
            self.skip_past("?>")?;
            return Ok(true);
        }
        if self.starts("<!") && !self.starts("<![CDATA[") {
            return Err(XmlError::Syntax);
        }
        Ok(false)
    }

    /// An attribute value (after `=`), entities decoded.
    fn attr_value(&mut self) -> Result<String, XmlError> {
        let quote = self.peek().ok_or(XmlError::Syntax)?;
        if quote != b'"' && quote != b'\'' {
            return Err(XmlError::Syntax);
        }
        self.pos += 1;
        let mut sink = Sink::Keep {
            buf: Zeroizing::new(String::new()),
            cap: MAX_ATTRIBUTE_BYTES,
            cut: false,
        };
        loop {
            let rest = self.s.get(self.pos..).ok_or(XmlError::Syntax)?;
            let stop = rest
                .bytes()
                .position(|b| b == quote || b == b'&' || b == b'<')
                .ok_or(XmlError::Syntax)?;
            sink.push(rest.get(..stop).ok_or(XmlError::Syntax)?);
            self.pos += stop;
            match self.peek() {
                Some(b'&') => {
                    let c = self.entity()?;
                    sink.push_char(c);
                }
                Some(b) if b == quote => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(XmlError::Syntax),
            }
        }
        match sink {
            Sink::Keep { cut: true, .. } => Err(XmlError::Bound),
            Sink::Keep { buf, .. } => Ok(buf.to_string()),
            Sink::Drop => Err(XmlError::Syntax),
        }
    }

    /// A start tag (after `<`).
    fn start(&mut self) -> Result<Start<'a>, XmlError> {
        self.elements += 1;
        if self.elements > MAX_ELEMENTS {
            return Err(XmlError::Bound);
        }
        let name = self.name()?;
        let mut attr_name = None;
        let mut seen: Vec<&str> = Vec::new();
        loop {
            let before = self.pos;
            self.skip_ws();
            match self.peek() {
                Some(b'>') => {
                    self.pos += 1;
                    return Ok(Start {
                        name,
                        attr_name,
                        empty: false,
                    });
                }
                Some(b'/') => {
                    self.pos += 1;
                    if self.peek() != Some(b'>') {
                        return Err(XmlError::Syntax);
                    }
                    self.pos += 1;
                    return Ok(Start {
                        name,
                        attr_name,
                        empty: true,
                    });
                }
                Some(_) if self.pos > before => {
                    let a = self.name()?;
                    if seen.contains(&a) {
                        return Err(XmlError::Syntax);
                    }
                    seen.push(a);
                    if seen.len() > MAX_ATTRIBUTES {
                        return Err(XmlError::Bound);
                    }
                    self.skip_ws();
                    if self.peek() != Some(b'=') {
                        return Err(XmlError::Syntax);
                    }
                    self.pos += 1;
                    self.skip_ws();
                    let v = self.attr_value()?;
                    if a == "name" {
                        attr_name = Some(v);
                    }
                }
                _ => return Err(XmlError::Syntax),
            }
        }
    }

    /// An end tag (after `</`) that must close `name`.
    fn end(&mut self, name: &str) -> Result<(), XmlError> {
        let n = self.name()?;
        if n != name {
            return Err(XmlError::Syntax);
        }
        self.skip_ws();
        if self.peek() != Some(b'>') {
            return Err(XmlError::Syntax);
        }
        self.pos += 1;
        Ok(())
    }

    /// An entity or character reference (at `&`).
    fn entity(&mut self) -> Result<char, XmlError> {
        let rest = self.s.get(self.pos + 1..).ok_or(XmlError::Syntax)?;
        let end = rest
            .bytes()
            .take(12)
            .position(|b| b == b';')
            .ok_or(XmlError::Syntax)?;
        let body = rest.get(..end).ok_or(XmlError::Syntax)?;
        let c = match body {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code =
                    if let Some(h) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
                        u32::from_str_radix(h, 16).map_err(|_| XmlError::Syntax)?
                    } else if let Some(d) = body.strip_prefix('#') {
                        d.parse::<u32>().map_err(|_| XmlError::Syntax)?
                    } else {
                        // No other entity exists here (no DTD).
                        return Err(XmlError::Syntax);
                    };
                match char::from_u32(code) {
                    Some(c) if code != 0 => c,
                    _ => return Err(XmlError::Syntax),
                }
            }
        };
        self.pos += end + 2;
        Ok(c)
    }

    /// Character data up to the next markup that is not a CDATA section,
    /// a comment or a reference, into `sink`.
    fn text(&mut self, sink: &mut Sink) -> Result<(), XmlError> {
        loop {
            let rest = self.s.get(self.pos..).ok_or(XmlError::Syntax)?;
            let stop = rest
                .bytes()
                .position(|b| b == b'<' || b == b'&')
                .unwrap_or(rest.len());
            sink.push(rest.get(..stop).ok_or(XmlError::Syntax)?);
            self.pos += stop;
            match self.peek() {
                None => return Ok(()),
                Some(b'&') => {
                    let c = self.entity()?;
                    sink.push_char(c);
                }
                Some(_) => {
                    if self.starts("<![CDATA[") {
                        self.pos += 9;
                        let rest = self.s.get(self.pos..).ok_or(XmlError::Syntax)?;
                        let end = rest.find("]]>").ok_or(XmlError::Syntax)?;
                        sink.push(rest.get(..end).ok_or(XmlError::Syntax)?);
                        self.pos += end + 3;
                    } else if self.starts("<!--") {
                        self.pos += 4;
                        self.skip_past("-->")?;
                    } else {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// The content of an element up to its end tag, at `depth`: child
    /// elements skipped (checked), text into `sink`.
    fn skip_content(&mut self, name: &str, depth: usize, sink: &mut Sink) -> Result<(), XmlError> {
        if depth > MAX_DEPTH {
            return Err(XmlError::Bound);
        }
        // An explicit stack of open element names (no recursion).
        let mut open: Vec<&'a str> = Vec::new();
        loop {
            if open.is_empty() {
                self.text(sink)?;
            } else {
                self.text(&mut Sink::Drop)?;
            }
            if self.peek().is_none() {
                return Err(XmlError::Syntax);
            }
            if self.misc()? {
                continue;
            }
            if self.starts("</") {
                self.pos += 2;
                match open.pop() {
                    Some(n) => self.end(n)?,
                    None => return self.end(name),
                }
                continue;
            }
            self.pos += 1;
            let s = self.start()?;
            if !s.empty {
                open.push(s.name);
                if depth + open.len() > MAX_DEPTH {
                    return Err(XmlError::Bound);
                }
            }
        }
    }
}

/// Reads one event's XML.
pub(crate) fn parse(xml: &str) -> Result<XeEvent, XmlError> {
    if xml.len() > MAX_EVENT_BYTES {
        return Err(XmlError::Bound);
    }
    let mut p = Parser {
        s: xml,
        pos: 0,
        elements: 0,
    };
    loop {
        p.skip_ws();
        if !p.misc()? {
            break;
        }
    }
    if p.peek() != Some(b'<') {
        return Err(XmlError::Syntax);
    }
    p.pos += 1;
    let root = p.start()?;
    if root.name != "event" {
        return Err(XmlError::Syntax);
    }
    let mut ev = XeEvent {
        name: root.attr_name.unwrap_or_default(),
        ..XeEvent::default()
    };
    if ev.name.len() > MAX_NAME_BYTES {
        return Err(XmlError::Bound);
    }
    let kind = ev.kind();
    if !root.empty {
        loop {
            // Text directly in `event` is checked and dropped.
            p.text(&mut Sink::Drop)?;
            if p.peek().is_none() {
                return Err(XmlError::Syntax);
            }
            if p.misc()? {
                continue;
            }
            if p.starts("</") {
                p.pos += 2;
                p.end("event")?;
                break;
            }
            p.pos += 1;
            let child = p.start()?;
            let field = match (child.name, child.attr_name.as_deref()) {
                ("data", Some(n)) => data_field(kind, n),
                ("action", Some(n)) => action_field(n),
                _ => None,
            };
            if child.empty {
                continue;
            }
            child_content(&mut p, child.name, field, &mut ev)?;
        }
    }
    // Only blanks and comments after the root.
    loop {
        p.skip_ws();
        if p.peek().is_none() {
            break;
        }
        if !p.misc()? {
            return Err(XmlError::Syntax);
        }
    }
    Ok(ev)
}

/// The content of a `data` / `action` element (depth 2): its first
/// `value` child kept when `field` is, everything else checked and
/// skipped.
fn child_content(
    p: &mut Parser<'_>,
    name: &str,
    field: Option<Field>,
    ev: &mut XeEvent,
) -> Result<(), XmlError> {
    let mut kept = false;
    let mut kept_text = false;
    loop {
        p.text(&mut Sink::Drop)?;
        if p.peek().is_none() {
            return Err(XmlError::Syntax);
        }
        if p.misc()? {
            continue;
        }
        if p.starts("</") {
            p.pos += 2;
            return p.end(name);
        }
        p.pos += 1;
        let s = p.start()?;
        let keep = match (field, s.name) {
            (Some(f), "value") if !kept => Some(f),
            // A map's text (`object_type`: `ADHOC`).
            (Some(Field::ObjectType), "text") if !kept_text => Some(Field::ObjectTypeName),
            _ => None,
        };
        let mut sink = match keep {
            Some(f) => Sink::Keep {
                buf: Zeroizing::new(String::new()),
                cap: if f == Field::Statement {
                    MAX_STATEMENT_BYTES
                } else {
                    MAX_FIELD_BYTES + 1
                },
                cut: false,
            },
            None => Sink::Drop,
        };
        if !s.empty {
            p.skip_content(s.name, 3, &mut sink)?;
        }
        if let (Some(f), Sink::Keep { buf, cut, .. }) = (keep, sink) {
            if f == Field::ObjectTypeName {
                kept_text = true;
            } else {
                kept = true;
            }
            ev.set(f, Capture { text: buf, cut })?;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    /// An event of the measured shape (2019, 2022).
    pub(crate) fn event(name: &str, data: &[(&str, &str)], actions: &[(&str, &str)]) -> String {
        let mut s = format!(
            "<event name=\"{name}\" package=\"sqlserver\" timestamp=\"2026-10-15T19:10:34.439Z\">"
        );
        for (n, v) in data {
            s.push_str(&format!("<data name=\"{n}\"><value>{v}</value></data>"));
        }
        for (n, v) in actions {
            s.push_str(&format!(
                "<action name=\"{n}\" package=\"sqlserver\"><value>{v}</value></action>"
            ));
        }
        s.push_str("</event>");
        s
    }

    #[test]
    fn reads_the_measured_shape() {
        let x = "<event name=\"sql_statement_completed\" package=\"sqlserver\" timestamp=\"2026-10-15T19:10:34.439Z\"><data name=\"duration\"><value>4</value></data><data name=\"row_count\"><value>2</value></data><data name=\"statement\"><value><![CDATA[SELECT TOP (2) id FROM retail.crm.customers WHERE id > 3]]></value></data><data name=\"parameterized_plan_handle\"><value></value></data><action name=\"session_id\" package=\"sqlserver\"><value>51</value></action><action name=\"database_name\" package=\"sqlserver\"><value><![CDATA[master]]></value></action><action name=\"client_app_name\" package=\"sqlserver\"><value><![CDATA[SQLCMD]]></value></action><action name=\"session_server_principal_name\" package=\"sqlserver\"><value><![CDATA[m_t]]></value></action><action name=\"server_principal_name\" package=\"sqlserver\"><value><![CDATA[m_t]]></value></action><action name=\"attach_activity_id\" package=\"package0\"><value>593CCAEF-721B-4D36-BBC7-038C82DE7C21-3</value></action></event>";
        let e = parse(x).unwrap();
        assert_eq!(e.kind(), Kind::SqlStatementCompleted);
        assert_eq!(
            e.statement.as_deref().map(String::as_str),
            Some("SELECT TOP (2) id FROM retail.crm.customers WHERE id > 3")
        );
        assert_eq!(e.row_count, Some(2));
        assert_eq!(e.session_id, Some(51));
        assert_eq!(e.server_principal.as_deref(), Some("m_t"));
        assert_eq!(e.session_principal.as_deref(), Some("m_t"));
        assert_eq!(e.database.as_deref(), Some("master"));
        assert_eq!(e.client_app.as_deref(), Some("SQLCMD"));
        assert_eq!(
            e.activity,
            Some(("593CCAEF-721B-4D36-BBC7-038C82DE7C21".to_owned(), 3))
        );
        assert!(!e.statement_cut);
        assert!(!format!("{e:?}").contains("SELECT"));
    }

    #[test]
    fn entities_cdata_and_text_elements() {
        let x = event(
            "sp_statement_completed",
            &[(
                "statement",
                "SELECT a FROM t WHERE b &lt; 3 AND c = N&apos;x&#x27;&#39;<![CDATA[]]]]><![CDATA[>]]>",
            )],
            &[("session_id", "7")],
        );
        let e = parse(&x).unwrap();
        assert_eq!(
            e.statement.as_deref().map(String::as_str),
            Some("SELECT a FROM t WHERE b < 3 AND c = N'x'']]>")
        );
        // A map value with its `text`, comments, a declaration.
        let x = "<?xml version=\"1.0\"?><!-- c --><event name=\"rpc_completed\"><data name=\"result\"><value>0</value><text><![CDATA[OK]]></text></data><data name=\"object_name\"><value>get_customers</value></data><data name=\"statement\"><value>exec get_customers @a = N'secret'</value></data><action name=\"session_id\"><value>9</value></action></event>\n";
        let e = parse(x).unwrap();
        assert_eq!(e.kind(), Kind::RpcCompleted);
        assert_eq!(e.object_name.as_deref(), Some("get_customers"));
        assert!(
            e.statement.is_none(),
            "rpc_completed text is never kept (M5)"
        );
        // error_reported: the number, never the message.
        let x = event(
            "error_reported",
            &[
                ("error_number", "18456"),
                ("message", "Login failed for user 'x'."),
            ],
            &[("session_server_principal_name", "x")],
        );
        let e = parse(&x).unwrap();
        assert_eq!(e.error_number, Some(18456));
        assert!(e.statement.is_none() && e.object_name.is_none());
        // sql_batch_completed: the batch text is never kept.
        let x = event(
            "sql_batch_completed",
            &[("batch_text", "SELECT 1"), ("row_count", "1")],
            &[],
        );
        let e = parse(&x).unwrap();
        assert!(e.statement.is_none());
        assert_eq!(e.row_count, Some(1));
    }

    #[test]
    fn refuses_dtds_entities_and_other_roots() {
        for bad in [
            "<!DOCTYPE event [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><event name=\"a\">&x;</event>",
            "<event name=\"a\"><data name=\"statement\"><value>&x;</value></data></event>",
            "<event name=\"a\"><data name=\"statement\"><value>&#0;</value></data></event>",
            "<other name=\"a\"></other>",
            "<event name=\"a\"></event><event name=\"b\"></event>",
            "<event name=\"a\"><data name=\"statement\"><value>x</value></data>",
            "<event name=\"a\" name=\"b\"></event>",
            "<event name=\"a\"><data name=\"x\"></value></data></event>",
            "<event name=\"a\"><![CDATA[x</event>",
            "<event name='a' b=c></event>",
            "",
            "text",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        // A kept field twice.
        let x = event(
            "sql_statement_completed",
            &[],
            &[("session_id", "1"), ("session_id", "2")],
        );
        assert_eq!(parse(&x).unwrap_err(), XmlError::Syntax);
    }

    #[test]
    fn bounds() {
        // Depth.
        let mut deep = String::from("<event name=\"a\"><data name=\"x\">");
        for _ in 0..MAX_DEPTH {
            deep.push_str("<v>");
        }
        for _ in 0..MAX_DEPTH {
            deep.push_str("</v>");
        }
        deep.push_str("</data></event>");
        assert_eq!(parse(&deep).unwrap_err(), XmlError::Bound);
        // Elements.
        let mut many = String::from("<event name=\"a\">");
        for _ in 0..=MAX_ELEMENTS {
            many.push_str("<t/>");
        }
        many.push_str("</event>");
        assert_eq!(parse(&many).unwrap_err(), XmlError::Bound);
        // Attributes.
        let attrs: String = (0..=MAX_ATTRIBUTES)
            .map(|i| format!(" a{i}=\"x\""))
            .collect();
        assert_eq!(
            parse(&format!("<event{attrs}></event>")).unwrap_err(),
            XmlError::Bound
        );
        // The whole event.
        let big = event("a", &[("statement", &"x".repeat(MAX_EVENT_BYTES))], &[]);
        assert_eq!(parse(&big).unwrap_err(), XmlError::Bound);
        // A long statement is cut, never dropped.
        let long = event(
            "sql_statement_completed",
            &[("statement", &"é".repeat(MAX_STATEMENT_BYTES))],
            &[],
        );
        let e = parse(&long).unwrap();
        assert!(e.statement_cut);
        assert!(e.statement.unwrap().len() <= MAX_STATEMENT_BYTES);
        // A long name is malformed.
        let x = event(
            "a",
            &[],
            &[("server_principal_name", &"p".repeat(MAX_FIELD_BYTES + 1))],
        );
        assert_eq!(parse(&x).unwrap_err(), XmlError::Bound);
    }
}
