//! Query text normalizer and shape analysis (ADR-0007, ADR-0012
//! obligation 5). A security component: see the property tests.
//!
//! Audit sources (the pgaudit log, `pg_stat_statements`) carry statement
//! text with literals: `WHERE email = 'jane.doe@example.com'`, passwords
//! typed in `ALTER ROLE … PASSWORD '…'`, connection strings in
//! `dblink_connect(…)`. The contract `AccessEvent` has **no** query text
//! field, so no statement text ever leaves the agent; this module is what
//! the connectors use to look at the text anyway:
//!
//! - [`analyze`] lexes the text (PostgreSQL dialect) and extracts, from
//!   literal-free tokens only, the statement kind, the relations it names,
//!   the `COPY` form and the shape features the signals need (`*` list,
//!   top-level `WHERE`, `LIMIT`). Names come from identifier tokens, never
//!   from inside a literal or a comment, and still go through
//!   [`crate::names`] before the uplink.
//! - [`QueryAnalysis::normalized`] is the ADR-0012 **DML allow-list**
//!   normalization: only statements that all start with `SELECT`,
//!   `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `VALUES`, `TABLE` or `WITH`
//!   are kept; comments are removed, every literal (`'…'`, `E'…'`,
//!   `U&'…'`, `N'…'`, `B'…'`, `X'…'`, `$tag$…$tag$`, numbers) and every
//!   bound parameter becomes `?`, identifiers go through the name
//!   normalizer, whitespace collapses, and the result is cut at
//!   [`MAX_NORMALIZED_CHARS`]. Anything else (utility statements, `COPY`,
//!   `DO`, `SET`, …) keeps no text.
//!
//! Fail-closed rules: text that does not lex (unterminated literal,
//! quoted identifier or comment), text above [`MAX_QUERY_BYTES`], and text
//! the caller marks as possibly truncated give no normalized text; a
//! truncated or unlexable text gives no shape either. Plain string literals
//! are read with `standard_conforming_strings = on`; when the text holds a
//! backslash and lexing it with `standard_conforming_strings = off` gives a
//! different token sequence, the reading is ambiguous and the analysis
//! keeps neither text, relations nor shape (only the statement kind when
//! both readings agree on it).

use std::fmt;

use crate::names;

/// Largest statement text analyzed, in bytes. Longer text is not lexed.
pub const MAX_QUERY_BYTES: usize = 1024 * 1024;
/// Longest normalized text, in characters (cut at a token boundary).
pub const MAX_NORMALIZED_CHARS: usize = 1024;
/// Most relations reported per statement (contract `objects.maxItems`).
pub const MAX_RELATIONS: usize = 16;
/// Most tokens lexed per statement.
const MAX_TOKENS: usize = 200_000;
/// Deepest parenthesis nesting followed by the shape analysis.
const MAX_DEPTH: usize = 256;

/// A lexical token. Literal and comment content is never kept.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// Unquoted identifier or keyword, ASCII-lowercased (PostgreSQL folds
    /// unquoted names).
    Word(String),
    /// Quoted identifier, unescaped.
    Quoted(String),
    /// Any literal: string, bit string, dollar-quoted, non-integer number.
    Literal,
    /// A plain decimal integer literal (row counts of `LIMIT` / `FETCH`).
    /// Never written to the normalized text.
    Int(u64),
    /// Bound parameter `$n`.
    Param,
    /// Operator or punctuation.
    Punct(String),
}

/// Why a text could not be lexed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexError {
    Unterminated,
    TooLong,
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 0x80
}

fn is_ident_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

fn is_op_char(b: u8) -> bool {
    matches!(
        b,
        b'+' | b'-'
            | b'*'
            | b'/'
            | b'<'
            | b'>'
            | b'='
            | b'~'
            | b'!'
            | b'@'
            | b'#'
            | b'%'
            | b'^'
            | b'&'
            | b'|'
            | b'`'
            | b'?'
    )
}

/// Lexes PostgreSQL statement text. `scs`: `standard_conforming_strings`.
fn lex(text: &str, scs: bool) -> Result<Vec<Tok>, LexError> {
    if text.len() > MAX_QUERY_BYTES {
        return Err(LexError::TooLong);
    }
    let b = text.as_bytes();
    let n = b.len();
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if out.len() >= MAX_TOKENS {
            return Err(LexError::TooLong);
        }
        let c = b[i];
        let next = b.get(i + 1).copied();
        // Whitespace.
        if matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            i += 1;
            continue;
        }
        // Line comment.
        if c == b'-' && next == Some(b'-') {
            while i < n && b[i] != b'\n' && b[i] != b'\r' {
                i += 1;
            }
            continue;
        }
        // Block comment, nested.
        if c == b'/' && next == Some(b'*') {
            let mut depth = 1usize;
            i += 2;
            while depth > 0 {
                if i + 1 >= n {
                    return Err(LexError::Unterminated);
                }
                if b[i] == b'/' && b[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        // Prefixed strings: E'…' (backslash escapes), U&'…', N'…', B'…',
        // X'…'; U&"…" is a quoted identifier.
        if matches!(c, b'e' | b'E') && next == Some(b'\'') {
            i = skip_string(b, i + 1, true)?;
            out.push(Tok::Literal);
            continue;
        }
        if matches!(c, b'u' | b'U') && next == Some(b'&') {
            match b.get(i + 2) {
                Some(b'\'') => {
                    i = skip_string(b, i + 2, false)?;
                    out.push(Tok::Literal);
                    continue;
                }
                Some(b'"') => {
                    let (end, name) = quoted_ident(text, i + 2)?;
                    i = end;
                    out.push(Tok::Quoted(name));
                    continue;
                }
                _ => {}
            }
        }
        if matches!(c, b'n' | b'N' | b'b' | b'B' | b'x' | b'X') && next == Some(b'\'') {
            i = skip_string(b, i + 1, !scs)?;
            out.push(Tok::Literal);
            continue;
        }
        match c {
            b'\'' => {
                i = skip_string(b, i, !scs)?;
                out.push(Tok::Literal);
            }
            b'"' => {
                let (end, name) = quoted_ident(text, i)?;
                i = end;
                out.push(Tok::Quoted(name));
            }
            b'$' => {
                if next.is_some_and(|d| d.is_ascii_digit()) {
                    i += 1;
                    while i < n && b[i].is_ascii_digit() {
                        i += 1;
                    }
                    out.push(Tok::Param);
                } else if let Some(tag_end) = dollar_tag(b, i) {
                    // `$tag$` … `$tag$`: find the same closing tag.
                    let tag = &b[i..=tag_end];
                    let body = tag_end + 1;
                    let close = find(&b[body..], tag).ok_or(LexError::Unterminated)?;
                    i = body + close + tag.len();
                    out.push(Tok::Literal);
                } else {
                    out.push(Tok::Punct("$".to_owned()));
                    i += 1;
                }
            }
            b'0'..=b'9' => {
                let start = i;
                i = skip_number(b, i);
                let digits = &text[start..i];
                match digits.parse::<u64>() {
                    Ok(v) if digits.bytes().all(|d| d.is_ascii_digit()) => out.push(Tok::Int(v)),
                    _ => out.push(Tok::Literal),
                }
            }
            b'.' if next.is_some_and(|d| d.is_ascii_digit()) => {
                i = skip_number(b, i);
                out.push(Tok::Literal);
            }
            _ if is_ident_start(c) => {
                let start = i;
                while i < n && is_ident_cont(b[i]) {
                    i += 1;
                }
                out.push(Tok::Word(text[start..i].to_ascii_lowercase()));
            }
            _ if is_op_char(c) => {
                let start = i;
                while i < n && is_op_char(b[i]) {
                    // A comment start ends the operator.
                    if i > start
                        && ((b[i] == b'-' && b.get(i + 1) == Some(&b'-'))
                            || (b[i] == b'/' && b.get(i + 1) == Some(&b'*')))
                    {
                        break;
                    }
                    if (b[i] == b'-' && b.get(i + 1) == Some(&b'-'))
                        || (b[i] == b'/' && b.get(i + 1) == Some(&b'*'))
                    {
                        break;
                    }
                    i += 1;
                }
                if i == start {
                    // Unreachable in practice (handled above); stay safe.
                    i += 1;
                }
                out.push(Tok::Punct(text[start..i].to_owned()));
            }
            _ => {
                // Punctuation `( ) [ ] , ; : .` and any other ASCII byte
                // (bytes >= 0x80 are identifier characters).
                out.push(Tok::Punct(char::from(c).to_string()));
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Skips a quoted string starting at `b[start] == '\''`. `backslash`: a
/// backslash escapes the next byte. Returns the index after the closing
/// quote.
fn skip_string(b: &[u8], start: usize, backslash: bool) -> Result<usize, LexError> {
    let mut i = start + 1;
    loop {
        match b.get(i) {
            None => return Err(LexError::Unterminated),
            Some(b'\\') if backslash => i += 2,
            Some(b'\'') => {
                if b.get(i + 1) == Some(&b'\'') {
                    i += 2;
                } else {
                    return Ok(i + 1);
                }
            }
            Some(_) => i += 1,
        }
    }
}

/// Reads a quoted identifier starting at `text[start] == '"'`.
fn quoted_ident(text: &str, start: usize) -> Result<(usize, String), LexError> {
    let b = text.as_bytes();
    let mut i = start + 1;
    let mut name = Vec::new();
    loop {
        match b.get(i) {
            None => return Err(LexError::Unterminated),
            Some(b'"') => {
                if b.get(i + 1) == Some(&b'"') {
                    name.push(b'"');
                    i += 2;
                } else {
                    return Ok((i + 1, String::from_utf8_lossy(&name).into_owned()));
                }
            }
            Some(&c) => {
                name.push(c);
                i += 1;
            }
        }
    }
}

/// End index of a dollar-quote tag `$tag$` / `$$` starting at `b[i]`.
fn dollar_tag(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    if b.get(j) == Some(&b'$') {
        return Some(j);
    }
    if !b.get(j).copied().is_some_and(is_ident_start) {
        return None;
    }
    while let Some(&c) = b.get(j) {
        if c == b'$' {
            return Some(j);
        }
        if !(c.is_ascii_alphanumeric() || c == b'_' || c >= 0x80) {
            return None;
        }
        j += 1;
    }
    None
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Skips a numeric literal (decimal, exponent, `0x` / `0o` / `0b`,
/// underscores; trailing letters are swallowed too: more is replaced, never
/// less).
fn skip_number(b: &[u8], mut i: usize) -> usize {
    while let Some(&c) = b.get(i) {
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' {
            if matches!(c, b'e' | b'E')
                && matches!(b.get(i + 1), Some(b'+' | b'-'))
                && b.get(i + 2).is_some_and(u8::is_ascii_digit)
            {
                i += 2;
            }
            i += 1;
        } else {
            break;
        }
    }
    i
}

/// Kind of a statement, from its leading keyword (after `WITH` for a
/// common table expression).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatementKind {
    /// `SELECT` (and `WITH … SELECT`).
    Select,
    /// `INSERT`.
    Insert,
    /// `UPDATE`.
    Update,
    /// `DELETE`.
    Delete,
    /// `MERGE`.
    Merge,
    /// `VALUES`.
    Values,
    /// `TABLE name`.
    Table,
    /// `COPY`.
    Copy,
    /// Schema change: `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `COMMENT`.
    Ddl,
    /// Privilege change: `GRANT`, `REVOKE`.
    Dcl,
    /// Anything else, or no statement.
    Other,
}

impl StatementKind {
    fn from_word(w: &str) -> Self {
        match w {
            "select" => Self::Select,
            "insert" => Self::Insert,
            "update" => Self::Update,
            "delete" => Self::Delete,
            "merge" => Self::Merge,
            "values" => Self::Values,
            "table" => Self::Table,
            "copy" => Self::Copy,
            "create" | "alter" | "drop" | "truncate" | "comment" => Self::Ddl,
            "grant" | "revoke" => Self::Dcl,
            _ => Self::Other,
        }
    }

    /// Whether the kind is on the DML allow-list (its normalized text may
    /// be kept).
    #[must_use]
    pub fn is_dml(self) -> bool {
        !matches!(self, Self::Copy | Self::Ddl | Self::Dcl | Self::Other)
    }

    /// Whether the statement reads rows (`SELECT`, `TABLE`, `VALUES`).
    #[must_use]
    pub fn is_read(self) -> bool {
        matches!(self, Self::Select | Self::Table | Self::Values)
    }
}

/// A relation named by a statement: raw identifiers from identifier tokens
/// (unquoted ones lowercased). Normalize them with [`crate::names`] before
/// they leave the agent.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RelationName {
    /// Schema, when the name is qualified.
    pub schema: Option<String>,
    /// Relation name.
    pub name: String,
}

impl fmt::Debug for RelationName {
    // Names are metadata but may embed values: never printed as is.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelationName(<redacted>)")
    }
}

/// Where `COPY` sends or takes its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyEndpoint {
    /// `STDOUT` / `STDIN`: the client (`psql \copy`, `pg_dump`).
    Client,
    /// A server-side file (`TO '/path'`).
    File,
    /// A server-side program (`TO PROGRAM '…'`).
    Program,
    /// Not recognized.
    Unknown,
}

/// A `COPY` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyInfo {
    /// `COPY … TO` (export) rather than `COPY … FROM` (import).
    pub to: bool,
    /// Data endpoint.
    pub endpoint: CopyEndpoint,
    /// The source is a whole relation (`COPY t TO`), or a query without a
    /// filter or with a large or absent limit (`COPY (SELECT … FROM t) TO`).
    pub whole_relation: bool,
}

/// Row limit of a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// No `LIMIT` / `FETCH`, or `LIMIT ALL`.
    None,
    /// A literal row count.
    Rows(u64),
    /// A parameter or an expression.
    Unknown,
}

/// Shape features of the main query (top level only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    /// `*` or `t.*` in the select list.
    pub star: bool,
    /// Top-level `WHERE`.
    pub filtered: bool,
    /// Top-level `GROUP BY` / `HAVING`, or an aggregate-only select list.
    pub aggregated: bool,
    /// A derived table or a function in `FROM`.
    pub derived: bool,
    /// Row limit.
    pub limit: Limit,
}

impl Shape {
    /// Whether the query reads whole relations: no filter, no aggregation,
    /// no derived table, and no limit or a limit of at least `large`.
    #[must_use]
    pub fn whole_relation(&self, large: u64) -> bool {
        !self.filtered
            && !self.aggregated
            && !self.derived
            && match self.limit {
                Limit::None => true,
                Limit::Rows(n) => n >= large,
                Limit::Unknown => false,
            }
    }
}

/// Normalized statement text (DML allow-list only). Never sent: the
/// contract has no field for it. Redacted `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct NormalizedQuery(String);

impl NormalizedQuery {
    /// The normalized text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NormalizedQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NormalizedQuery({} chars)", self.0.chars().count())
    }
}

/// Result of [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryAnalysis {
    kind: StatementKind,
    normalized: Option<NormalizedQuery>,
    relations: Vec<RelationName>,
    shape: Option<Shape>,
    copy: Option<CopyInfo>,
    statements: usize,
}

impl QueryAnalysis {
    fn unparsed(kind: StatementKind) -> Self {
        Self {
            kind,
            normalized: None,
            relations: Vec::new(),
            shape: None,
            copy: None,
            statements: 0,
        }
    }

    /// Kind of the first statement.
    #[must_use]
    pub fn kind(&self) -> StatementKind {
        self.kind
    }

    /// Normalized text: `None` unless every statement is on the DML
    /// allow-list and the text lexed unambiguously and completely.
    #[must_use]
    pub fn normalized(&self) -> Option<&NormalizedQuery> {
        self.normalized.as_ref()
    }

    /// Relations named by the text (at most [`MAX_RELATIONS`], first seen
    /// first, without duplicates).
    #[must_use]
    pub fn relations(&self) -> &[RelationName] {
        &self.relations
    }

    /// Shape of the first statement; `None` when not reliable (truncated,
    /// ambiguous or unlexable text, or not a query).
    #[must_use]
    pub fn shape(&self) -> Option<&Shape> {
        self.shape.as_ref()
    }

    /// `COPY` details, for a `COPY` statement.
    #[must_use]
    pub fn copy(&self) -> Option<&CopyInfo> {
        self.copy.as_ref()
    }

    /// Number of statements in the text (`;`-separated, non-empty).
    #[must_use]
    pub fn statements(&self) -> usize {
        self.statements
    }
}

/// Options of [`analyze`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnalyzeOptions {
    /// The text may have been cut by its source (`pg_stat_activity`,
    /// a bounded read): no normalized text and no shape are produced.
    pub possibly_truncated: bool,
    /// Limit from which a query counts as reading a whole relation.
    pub large_limit: u64,
}

impl AnalyzeOptions {
    /// Default: not truncated; a `LIMIT` of 10 000 rows or more counts as
    /// reading the whole relation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            possibly_truncated: false,
            large_limit: 10_000,
        }
    }

    /// Marks the text as possibly truncated.
    #[must_use]
    pub fn truncated(mut self, truncated: bool) -> Self {
        self.possibly_truncated = truncated;
        self
    }
}

/// Analyzes statement text. See the module documentation for what is kept.
#[must_use]
pub fn analyze(text: &str, opts: AnalyzeOptions) -> QueryAnalysis {
    let Ok(tokens) = lex(text, true) else {
        return QueryAnalysis::unparsed(first_kind_prefix(text));
    };
    if text.contains('\\') {
        match lex(text, false) {
            Ok(other) if other == tokens => {}
            other => {
                let k1 = first_kind(&tokens);
                let k2 = other.map_or(StatementKind::Other, |t| first_kind(&t));
                return QueryAnalysis::unparsed(if k1 == k2 { k1 } else { StatementKind::Other });
            }
        }
    }
    let statements = split_statements(&tokens);
    let kind = statements
        .first()
        .map_or(StatementKind::Other, |s| first_kind(s));
    let mut relations = Vec::new();
    for s in &statements {
        collect_relations(s, &mut relations);
    }
    let (shape, copy) = match statements.first() {
        Some(first) if !opts.possibly_truncated => match kind {
            StatementKind::Copy => (None, copy_info(first, opts.large_limit)),
            k if k.is_read() => (main_shape(first), None),
            _ => (None, None),
        },
        _ => (None, None),
    };
    let all_dml = !statements.is_empty() && statements.iter().all(|s| first_kind(s).is_dml());
    let normalized = (all_dml && !opts.possibly_truncated).then(|| normalize_tokens(&tokens));
    QueryAnalysis {
        kind,
        normalized,
        relations,
        shape,
        copy,
        statements: statements.len(),
    }
}

/// Kind from the first word of a text that did not lex: the prefix up to
/// the first quote or comment is lexed alone (it holds no literal).
fn first_kind_prefix(text: &str) -> StatementKind {
    let end = text
        .find(['\'', '"', '$', '-', '/'])
        .unwrap_or(text.len())
        .min(256);
    let Some(prefix) = text.get(..end) else {
        return StatementKind::Other;
    };
    lex(prefix, true).map_or(StatementKind::Other, |t| first_kind(&t))
}

/// Splits on top-level `;`, dropping empty statements.
fn split_statements(tokens: &[Tok]) -> Vec<&[Tok]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    for (i, t) in tokens.iter().enumerate() {
        match t {
            Tok::Punct(p) if p == "(" || p == "[" => depth += 1,
            Tok::Punct(p) if p == ")" || p == "]" => depth = depth.saturating_sub(1),
            Tok::Punct(p) if p == ";" && depth == 0 => {
                if i > start {
                    out.push(&tokens[start..i]);
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    if tokens.len() > start {
        out.push(&tokens[start..]);
    }
    out
}

fn word(t: Option<&Tok>) -> Option<&str> {
    match t {
        Some(Tok::Word(w)) => Some(w.as_str()),
        _ => None,
    }
}

fn is_punct(t: Option<&Tok>, p: &str) -> bool {
    matches!(t, Some(Tok::Punct(x)) if x == p)
}

/// Index of the main statement keyword: leading `(` skipped, and for
/// `WITH`, the first top-level statement keyword after the CTE list.
fn main_start(s: &[Tok]) -> Option<usize> {
    let mut i = 0;
    while is_punct(s.get(i), "(") {
        i += 1;
    }
    if word(s.get(i)) != Some("with") {
        return (i < s.len()).then_some(i);
    }
    let base = i;
    let mut depth = 0usize;
    for (j, t) in s.iter().enumerate().skip(i + 1) {
        match t {
            Tok::Punct(p) if p == "(" => depth += 1,
            Tok::Punct(p) if p == ")" => depth = depth.saturating_sub(1),
            Tok::Word(w) if depth == 0 => {
                if matches!(
                    w.as_str(),
                    "select" | "insert" | "update" | "delete" | "merge" | "values" | "table"
                ) {
                    return Some(j);
                }
            }
            _ => {}
        }
    }
    Some(base)
}

fn first_kind(s: &[Tok]) -> StatementKind {
    let Some(i) = main_start(s) else {
        return StatementKind::Other;
    };
    match word(s.get(i)) {
        // `WITH` without a recognized main statement.
        Some("with") => StatementKind::Other,
        Some(w) => StatementKind::from_word(w),
        None => StatementKind::Other,
    }
}

/// Keywords after which `(` opens a subquery or a list, not a function
/// call (so a `FROM` inside it may name a relation).
fn opens_query(w: &str) -> bool {
    matches!(
        w,
        "select"
            | "from"
            | "join"
            | "in"
            | "exists"
            | "any"
            | "all"
            | "some"
            | "lateral"
            | "as"
            | "values"
            | "where"
            | "on"
            | "and"
            | "or"
            | "not"
            | "union"
            | "intersect"
            | "except"
            | "copy"
            | "with"
            | "materialized"
            | "into"
            | "using"
            | "set"
            | "returning"
            | "then"
            | "else"
            | "when"
            | "case"
            | "array"
            | "by"
    )
}

/// Words that cannot be a relation name.
fn reserved(w: &str) -> bool {
    matches!(
        w,
        "select"
            | "from"
            | "where"
            | "join"
            | "on"
            | "using"
            | "as"
            | "lateral"
            | "only"
            | "values"
            | "set"
            | "group"
            | "order"
            | "limit"
            | "offset"
            | "fetch"
            | "union"
            | "intersect"
            | "except"
            | "with"
            | "returning"
            | "to"
            | "stdin"
            | "stdout"
            | "program"
            | "natural"
            | "left"
            | "right"
            | "inner"
            | "outer"
            | "full"
            | "cross"
            | "window"
            | "having"
            | "for"
            | "into"
            | "default"
            | "table"
    )
}

/// Reads a (possibly qualified) name at `i`. Returns the parts and the
/// index after the name.
fn qualified_name(s: &[Tok], mut i: usize) -> Option<(Vec<String>, usize)> {
    let mut parts = Vec::new();
    loop {
        match s.get(i) {
            Some(Tok::Word(w)) if parts.is_empty() && reserved(w) => return None,
            Some(Tok::Word(w)) => parts.push(w.clone()),
            Some(Tok::Quoted(q)) => parts.push(q.clone()),
            _ => return None,
        }
        i += 1;
        if is_punct(s.get(i), ".") && parts.len() < 3 {
            i += 1;
            continue;
        }
        return Some((parts, i));
    }
}

fn push_relation(parts: Vec<String>, out: &mut Vec<RelationName>) {
    let mut parts = parts;
    let Some(name) = parts.pop() else {
        return;
    };
    let schema = parts.pop();
    let r = RelationName { schema, name };
    if out.len() < MAX_RELATIONS && !out.contains(&r) {
        out.push(r);
    }
}

/// Names of the CTEs defined by a statement (never reported as relations).
fn cte_names(s: &[Tok]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while is_punct(s.get(i), "(") {
        i += 1;
    }
    if word(s.get(i)) != Some("with") {
        return out;
    }
    let mut depth = 0usize;
    for j in i + 1..s.len() {
        match &s[j] {
            Tok::Punct(p) if p == "(" => depth += 1,
            Tok::Punct(p) if p == ")" => depth = depth.saturating_sub(1),
            Tok::Word(w) | Tok::Quoted(w) if depth == 0 => {
                let prev_ok = j == i + 1
                    || is_punct(s.get(j - 1), ",")
                    || word(s.get(j - 1)) == Some("recursive");
                let next_ok = word(s.get(j + 1)) == Some("as") || is_punct(s.get(j + 1), "(");
                if prev_ok && next_ok && w != "recursive" {
                    out.push(w.clone());
                }
                if matches!(
                    w.as_str(),
                    "select" | "insert" | "update" | "delete" | "merge" | "values" | "table"
                ) && !next_ok
                {
                    break;
                }
            }
            _ => {}
        }
    }
    out
}

/// Collects the relations named after `FROM` (and its comma list),
/// `JOIN`, `UPDATE`, `INTO`, `COPY`, `USING`, and `TABLE` at a statement
/// or subquery start, outside function-call parentheses.
fn collect_relations(s: &[Tok], out: &mut Vec<RelationName>) {
    struct Frame {
        call: bool,
        in_from: bool,
    }
    let ctes = cte_names(s);
    let mut frames = vec![Frame {
        call: false,
        in_from: false,
    }];
    let prev_word = |i: usize| word(i.checked_sub(1).and_then(|j| s.get(j)));
    let mut i = 0;
    while i < s.len() {
        let in_call = frames.iter().any(|f| f.call);
        match &s[i] {
            Tok::Punct(p) if p == "(" => {
                let call = match i.checked_sub(1).and_then(|j| s.get(j)) {
                    Some(Tok::Word(w)) => !opens_query(w),
                    Some(Tok::Quoted(_)) => true,
                    _ => false,
                };
                if frames.len() < MAX_DEPTH {
                    frames.push(Frame {
                        call,
                        in_from: false,
                    });
                }
                i += 1;
            }
            Tok::Punct(p) if p == ")" => {
                if frames.len() > 1 {
                    frames.pop();
                }
                i += 1;
            }
            Tok::Punct(p) if p == "," && !in_call => {
                let in_from = frames.last().is_some_and(|f| f.in_from);
                i += 1;
                if in_from {
                    i = read_relation(s, i, &ctes, false, out);
                }
            }
            Tok::Word(w) if !in_call => {
                let w = w.as_str();
                let (reads, call_ok, from_list) = match w {
                    "from" | "using" => (true, false, true),
                    "join" => (true, false, false),
                    "into" | "copy" => (true, true, false),
                    // `UPDATE t SET …`, not `FOR UPDATE` / `DO UPDATE`.
                    "update" => (
                        !matches!(prev_word(i), Some("for" | "do" | "key" | "no")),
                        false,
                        false,
                    ),
                    "table" => (
                        i == 0
                            || is_punct(i.checked_sub(1).and_then(|j| s.get(j)), "(")
                            || matches!(
                                prev_word(i),
                                Some("union" | "intersect" | "except" | "all")
                            ),
                        false,
                        false,
                    ),
                    _ => (false, false, false),
                };
                if matches!(
                    w,
                    "where"
                        | "group"
                        | "having"
                        | "order"
                        | "limit"
                        | "offset"
                        | "fetch"
                        | "window"
                        | "union"
                        | "intersect"
                        | "except"
                        | "returning"
                        | "set"
                        | "values"
                        | "select"
                        | "for"
                        | "when"
                        | "to"
                ) {
                    if let Some(f) = frames.last_mut() {
                        f.in_from = false;
                    }
                }
                if from_list {
                    if let Some(f) = frames.last_mut() {
                        f.in_from = true;
                    }
                }
                i += 1;
                if reads {
                    i = read_relation(s, i, &ctes, call_ok, out);
                }
            }
            _ => i += 1,
        }
    }
}

/// Reads one relation name at `i` (after `ONLY` / `LATERAL`); a name
/// followed by `(` is a function call unless `call_ok` (`INTO t (cols)`,
/// `COPY t (cols)`). Returns the index to continue from.
fn read_relation(
    s: &[Tok],
    mut i: usize,
    ctes: &[String],
    call_ok: bool,
    out: &mut Vec<RelationName>,
) -> usize {
    while matches!(word(s.get(i)), Some("only" | "lateral")) {
        i += 1;
    }
    let Some((parts, next)) = qualified_name(s, i) else {
        return i;
    };
    if is_punct(s.get(next), "(") && !call_ok {
        return next;
    }
    let cte = parts.len() == 1 && ctes.contains(&parts[0]);
    if !cte {
        push_relation(parts, out);
    }
    next
}

/// Aggregates that reduce a relation to a few rows.
fn reducing_aggregate(w: &str) -> bool {
    matches!(
        w,
        "count"
            | "sum"
            | "avg"
            | "min"
            | "max"
            | "bool_and"
            | "bool_or"
            | "every"
            | "stddev"
            | "stddev_pop"
            | "stddev_samp"
            | "variance"
            | "var_pop"
            | "var_samp"
    )
}

/// Shape of the main query of a read statement (top level only).
fn main_shape(s: &[Tok]) -> Option<Shape> {
    let start = main_start(s)?;
    let base_depth = s[..start].iter().filter(|t| is_punct(Some(t), "(")).count();
    let mut depth = 0usize;
    let mut shape = Shape {
        star: false,
        filtered: false,
        aggregated: false,
        derived: false,
        limit: Limit::None,
    };
    let mut in_select_list = false;
    let mut select_list_aggregate = false;
    let mut after_from = false;
    let is_table = word(s.get(start)) == Some("table");
    let mut i = start;
    while i < s.len() {
        let t = &s[i];
        match t {
            Tok::Punct(p) if p == "(" => {
                if depth == base_depth && after_from {
                    // `FROM (subquery)` or `FROM f(…)`.
                    let prev = i.checked_sub(1).and_then(|j| s.get(j));
                    if matches!(word(prev), Some("from" | "join" | "lateral"))
                        || is_punct(prev, ",")
                        || matches!(prev, Some(Tok::Word(_) | Tok::Quoted(_)))
                    {
                        shape.derived = true;
                    }
                }
                depth += 1;
                i += 1;
                continue;
            }
            Tok::Punct(p) if p == ")" => {
                depth = depth.saturating_sub(1);
                i += 1;
                continue;
            }
            _ => {}
        }
        if depth != base_depth {
            i += 1;
            continue;
        }
        match t {
            Tok::Word(w) => match w.as_str() {
                "select" => in_select_list = true,
                "from" => {
                    in_select_list = false;
                    after_from = true;
                }
                "where" => {
                    in_select_list = false;
                    shape.filtered = true;
                }
                "group" | "having" => shape.aggregated = true,
                "limit" => match s.get(i + 1) {
                    Some(Tok::Word(a)) if a == "all" => {}
                    Some(Tok::Int(n)) => shape.limit = Limit::Rows(*n),
                    _ => shape.limit = Limit::Unknown,
                },
                "fetch" => {
                    // FETCH FIRST|NEXT [n] ROW|ROWS ONLY
                    shape.limit = match s.get(i + 2) {
                        Some(Tok::Int(n)) => Limit::Rows(*n),
                        Some(Tok::Word(r)) if r == "row" || r == "rows" => Limit::Rows(1),
                        _ => Limit::Unknown,
                    };
                }
                "union" | "intersect" | "except" => {
                    // Set operations: several queries, shape unreliable.
                    shape.derived = true;
                }
                w if in_select_list && reducing_aggregate(w) && is_punct(s.get(i + 1), "(") => {
                    select_list_aggregate = true;
                }
                _ => {}
            },
            Tok::Punct(p) if p == "*" && in_select_list => {
                let prev = i.checked_sub(1).and_then(|j| s.get(j));
                if matches!(word(prev), Some("select" | "distinct" | "all"))
                    || is_punct(prev, ",")
                    || is_punct(prev, ".")
                {
                    shape.star = true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if select_list_aggregate && !shape.star {
        shape.aggregated = true;
    }
    if is_table {
        shape.star = true;
    }
    Some(shape)
}

/// `COPY` details of a statement.
fn copy_info(s: &[Tok], large: u64) -> Option<CopyInfo> {
    let start = main_start(s)?;
    if word(s.get(start)) != Some("copy") {
        return None;
    }
    let mut i = start + 1;
    if word(s.get(i)) == Some("binary") {
        i += 1;
    }
    let whole_relation;
    if is_punct(s.get(i), "(") {
        // COPY (query) TO …
        let mut depth = 0usize;
        let open = i;
        let mut close = None;
        for (j, t) in s.iter().enumerate().skip(open) {
            if is_punct(Some(t), "(") {
                depth += 1;
            } else if is_punct(Some(t), ")") {
                depth -= 1;
                if depth == 0 {
                    close = Some(j);
                    break;
                }
            }
        }
        let close = close?;
        let inner = &s[open + 1..close];
        whole_relation = first_kind(inner).is_read()
            && main_shape(inner).is_some_and(|sh| sh.whole_relation(large));
        i = close + 1;
    } else {
        let (_, next) = qualified_name(s, i)?;
        i = next;
        if is_punct(s.get(i), "(") {
            // Column list.
            let mut depth = 0usize;
            while let Some(t) = s.get(i) {
                if is_punct(Some(t), "(") {
                    depth += 1;
                } else if is_punct(Some(t), ")") {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                i += 1;
            }
        }
        whole_relation = true;
    }
    let to = match word(s.get(i)) {
        Some("to") => true,
        Some("from") => false,
        _ => return None,
    };
    let endpoint = match s.get(i + 1) {
        Some(Tok::Word(w)) if w == "stdout" || w == "stdin" => CopyEndpoint::Client,
        Some(Tok::Word(w)) if w == "program" => CopyEndpoint::Program,
        Some(Tok::Literal) => CopyEndpoint::File,
        _ => CopyEndpoint::Unknown,
    };
    Some(CopyInfo {
        to,
        endpoint,
        whole_relation: to && whole_relation,
    })
}

/// Joins normalized tokens, cut at [`MAX_NORMALIZED_CHARS`].
fn normalize_tokens(tokens: &[Tok]) -> NormalizedQuery {
    let mut out = String::new();
    let mut chars = 0usize;
    for t in tokens {
        let piece: String = match t {
            Tok::Word(w) => {
                let n = names::normalize_path(w);
                if n.as_str() == "*" {
                    "\"*\"".to_owned()
                } else {
                    n.as_str().to_owned()
                }
            }
            Tok::Quoted(q) => format!("\"{}\"", names::normalize_path(q).as_str()),
            Tok::Literal | Tok::Int(_) | Tok::Param => "?".to_owned(),
            Tok::Punct(p) => p.clone(),
        };
        let len = piece.chars().count() + usize::from(!out.is_empty());
        if chars + len > MAX_NORMALIZED_CHARS {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&piece);
        chars += len;
    }
    NormalizedQuery(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &str) -> Option<String> {
        analyze(s, AnalyzeOptions::new())
            .normalized()
            .map(|n| n.as_str().to_owned())
    }

    fn rels(s: &str) -> Vec<(Option<String>, String)> {
        analyze(s, AnalyzeOptions::new())
            .relations()
            .iter()
            .map(|r| (r.schema.clone(), r.name.clone()))
            .collect()
    }

    fn r(schema: Option<&str>, name: &str) -> (Option<String>, String) {
        (schema.map(str::to_owned), name.to_owned())
    }

    #[test]
    fn literals_become_placeholders() {
        assert_eq!(
            norm("SELECT * FROM crm.customers WHERE email = 'jane.doe@example.com' AND id > 42")
                .unwrap(),
            "select * from crm . customers where email = ? and id > ?"
        );
        let q = "select E'a\\'b' , U&'d\\0061t' , N'x', B'0101', X'DEAD', $$dollar$$, $tag$ x $tag$, 1.5e10, .5, 0x1F, 1_000";
        let n = norm(q).unwrap();
        assert_eq!(n, "select ? , ? , ? , ? , ? , ? , ? , ? , ? , ? , ?", "{q}");
        assert_eq!(norm("select $1, $22").unwrap(), "select ? , ?");
    }

    #[test]
    fn comments_are_removed() {
        let n = norm(
            "SELECT 1 /* customer jean.dupont@example.test /* nested */ still */ -- tail\n, 2",
        )
        .unwrap();
        assert_eq!(n, "select ? , ?");
        // Unterminated comment: fails closed.
        assert!(norm("SELECT 1 /* open /* nested */").is_none());
        assert!(norm("SELECT 'open").is_none());
        assert!(norm("SELECT \"open").is_none());
        assert!(norm("SELECT $a$ open").is_none());
    }

    #[test]
    fn only_dml_keeps_text() {
        for q in [
            "ALTER ROLE app PASSWORD 'hunter2'",
            "CREATE USER MAPPING FOR u SERVER s OPTIONS (password 'x')",
            "COPY (SELECT 1) TO PROGRAM 'echo x'",
            "DO $$ BEGIN PERFORM 'x'; END $$",
            "SET application_name = 'x'",
            "COMMENT ON TABLE t IS 'x'",
            "PREPARE p AS SELECT 1",
            "EXECUTE p('x')",
            "EXPLAIN SELECT 1",
            "SELECT 1; ALTER ROLE r PASSWORD 'x'",
            "",
            ";",
        ] {
            assert!(norm(q).is_none(), "{q}");
        }
        for q in [
            "select 1",
            "(select 1)",
            "insert into t values (1)",
            "update t set a = 1",
            "delete from t",
            "merge into t using s on true when matched then delete",
            "values (1)",
            "table t",
            "with x as (select 1) select * from x",
            "select 1; select 2",
        ] {
            assert!(norm(q).is_some(), "{q}");
        }
    }

    #[test]
    fn truncated_text_keeps_no_text_and_no_shape() {
        let a = analyze("select * from t", AnalyzeOptions::new().truncated(true));
        assert!(a.normalized().is_none());
        assert!(a.shape().is_none());
        assert_eq!(a.kind(), StatementKind::Select);
        assert_eq!(a.relations().len(), 1);
    }

    #[test]
    fn ambiguous_backslashes_keep_nothing() {
        // With standard_conforming_strings = off, the literal ends later.
        let a = analyze(
            "select 'a\\' , secret_col from t where x = 'b'",
            AnalyzeOptions::new(),
        );
        assert!(a.normalized().is_none());
        assert!(a.relations().is_empty());
        assert!(a.shape().is_none());
        // A backslash that does not change the reading is fine.
        let a = analyze("select E'a\\nb' from t", AnalyzeOptions::new());
        assert!(a.normalized().is_some());
    }

    #[test]
    fn relations_are_extracted_from_identifiers_only() {
        assert_eq!(
            rels("SELECT a.x FROM crm.customers a JOIN billing.\"Invoices\" i ON true, ops.t"),
            vec![
                r(Some("crm"), "customers"),
                r(Some("billing"), "Invoices"),
                r(Some("ops"), "t")
            ]
        );
        assert_eq!(
            rels("select extract(year from ts) from t"),
            vec![r(None, "t")]
        );
        assert_eq!(rels("select * from generate_series(1, 3)"), vec![]);
        assert_eq!(
            rels("with c as (select * from crm.a) select * from c join b on true"),
            vec![r(Some("crm"), "a"), r(None, "b")]
        );
        assert_eq!(rels("select 'from secret' from t"), vec![r(None, "t")]);
        assert_eq!(
            rels("insert into crm.t (a) values (1)"),
            vec![r(Some("crm"), "t")]
        );
        assert_eq!(rels("update crm.t set a = 1"), vec![r(Some("crm"), "t")]);
        assert_eq!(rels("delete from only crm.t"), vec![r(Some("crm"), "t")]);
        assert_eq!(
            rels("copy crm.t (a, b) to stdout"),
            vec![r(Some("crm"), "t")]
        );
        assert_eq!(rels("table crm.t"), vec![r(Some("crm"), "t")]);
        assert_eq!(rels("select * from t for update"), vec![r(None, "t")]);
    }

    #[test]
    fn select_shapes() {
        let shape = |q: &str| *analyze(q, AnalyzeOptions::new()).shape().unwrap();
        let s = shape("select * from crm.customers");
        assert!(s.star && !s.filtered && s.whole_relation(10_000));
        let s = shape("select * from t where id = 1");
        assert!(s.filtered && !s.whole_relation(10_000));
        let s = shape("select count(*) from t");
        assert!(s.aggregated && !s.whole_relation(10_000));
        assert_eq!(
            shape("select * from t limit 50000").limit,
            Limit::Rows(50_000)
        );
        assert_eq!(
            shape("select * from t fetch first 10 rows only").limit,
            Limit::Rows(10)
        );
        assert!(!shape("select * from t limit 10").whole_relation(10_000));
        let s = shape("select a, b from t limit $1");
        assert_eq!(s.limit, Limit::Unknown);
        let s = shape("select a from t limit all");
        assert_eq!(s.limit, Limit::None);
        let s = shape("select * from (select * from t where x) s");
        assert!(s.derived);
        let s = shape("table crm.t");
        assert!(s.star && s.whole_relation(10));
        let s = shape("select * from t where exists (select 1)");
        assert!(s.filtered);
        let s = shape("select a from t union select a from u");
        assert!(!s.whole_relation(10));
    }

    #[test]
    fn copy_forms() {
        let copy = |q: &str| *analyze(q, AnalyzeOptions::new()).copy().unwrap();
        let c = copy("COPY crm.customers (id, email) TO stdout;");
        assert!(c.to && c.whole_relation);
        assert_eq!(c.endpoint, CopyEndpoint::Client);
        let c = copy("copy (select id from crm.customers) to '/tmp/x.csv'");
        assert!(c.whole_relation);
        assert_eq!(c.endpoint, CopyEndpoint::File);
        let c = copy("copy (select * from t where id = 1) to program 'gzip > /tmp/x'");
        assert!(!c.whole_relation);
        assert_eq!(c.endpoint, CopyEndpoint::Program);
        let c = copy("copy t from stdin");
        assert!(!c.to && !c.whole_relation);
        assert_eq!(
            analyze("copy t to stdout", AnalyzeOptions::new()).kind(),
            StatementKind::Copy
        );
        assert!(
            analyze("copy t to stdout", AnalyzeOptions::new())
                .normalized()
                .is_none()
        );
    }

    #[test]
    fn identifiers_that_look_like_values_are_masked_in_text() {
        let n = norm("select * from \"jane.doe@example.com\" where \"0612345678\" = 1").unwrap();
        assert!(!n.contains("jane"), "{n}");
        assert!(!n.contains("0612345678"), "{n}");
    }

    #[test]
    fn normalized_text_is_bounded() {
        let q = format!("select {} from t", vec!["col"; 5000].join(", "));
        let n = norm(&q).unwrap();
        assert!(n.chars().count() <= MAX_NORMALIZED_CHARS);
        assert!(norm(&"x".repeat(MAX_QUERY_BYTES + 1)).is_none());
    }

    #[test]
    fn debug_output_is_redacted() {
        let a = analyze("select * from \"jane@example.com\"", AnalyzeOptions::new());
        let d = format!("{a:?}");
        assert!(!d.contains("jane"), "{d}");
    }
}
