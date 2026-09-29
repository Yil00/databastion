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
//! - [`analyze`] lexes the text (PostgreSQL dialect, or MySQL / MariaDB with
//!   [`AnalyzeOptions::mysql`], see below) and extracts, from
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
//!
//! **MySQL / MariaDB dialect** ([`Dialect::Mysql`]). The session
//! `sql_mode` of a logged statement is unknown, so the text is lexed under
//! every reading it may have been written for: with and without
//! `NO_BACKSLASH_ESCAPES` (when it holds a backslash) and with and without
//! `ANSI_QUOTES` (when it holds a double quote). The readings must give the
//! same tokens, otherwise the text is ambiguous and keeps nothing but the
//! statement kind, as above. Lexical rules: `'…'` and `"…"` are strings
//! (quotes doubled, backslash escapes unless `NO_BACKSLASH_ESCAPES`);
//! under `ANSI_QUOTES`, `"…"` is an identifier, but its content is still
//! never read as a name (a `"…"` token is opaque in every reading);
//! `` `…` `` is a quoted identifier; `N'…'`, `X'…'`, `B'…'` and the
//! `_charset'…'` introducers are literals; `0x…`, `0b…` and numbers are
//! literals; `?` is a placeholder (digest text); `#…` and `-- …` (a double
//! dash followed by a space, a control character or the end) are line
//! comments; `/* … */` comments do not nest; an executable comment
//! (`/*! … */`, `/*!NNNNN … */`, MariaDB `/*M! … */`) is read as code,
//! and its content must lex completely before its first `*/` (a literal
//! running past it, or a nested comment, fails closed). A version
//! comment is only certain to run when it has no version or a five-digit
//! version below 5.7.0 (every supported server runs it; MariaDB skips
//! `/*!50700` to `/*!99999`); otherwise (six digits, 5.7.0 and later,
//! every MariaDB-only `/*M!`) the server may read
//! it as a comment, so that reading is lexed too and must agree. Text with
//! a byte >= 0x80 directly followed by `\` or a backtick (the trail byte
//! of a two-byte character in gbk, big5, sjis, cp932 or gb18030) keeps
//! only its kind, and so does text whose bytes are not UTF-8
//! ([`analyze_raw`]). Optimizer hints
//! (`/*+ … */`) are comments. The DML allow-list adds `REPLACE`; `CREATE`
//! / `ALTER` / `DROP` / `RENAME` `USER` / `ROLE` and `SET PASSWORD` are
//! DCL. `SELECT … INTO OUTFILE` / `INTO DUMPFILE` is reported
//! ([`StatementInfo::outfile`]), and the file name is never a relation.

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

/// SQL dialect of a statement text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Dialect {
    /// PostgreSQL (pgaudit, `pg_stat_statements`).
    #[default]
    Postgres,
    /// MySQL and MariaDB (`server_audit`, `audit_log`,
    /// `performance_schema`); see the module documentation.
    Mysql,
}

/// Lexing mode of a MySQL / MariaDB text: the two `sql_mode` flags that
/// change token boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MyMode {
    /// Backslash escapes in strings (no `NO_BACKSLASH_ESCAPES`).
    backslash: bool,
    /// `ANSI_QUOTES`: `"…"` is an identifier.
    ansi_quotes: bool,
    /// Version comments whose version may be above the server's
    /// ([`version_always_executed`] false) are comments.
    version_as_comment: bool,
}

/// Whether a version comment `/*!NNNNN` runs on every supported server:
/// a five-digit version below 5.7.0 (50700). MySQL 8.0+ runs every
/// five-digit version comment up to its own version, but MariaDB (10.6+)
/// skips `/*!50700` to `/*!99999` (measured on MariaDB 11.4.13), so from
/// 50700 up a supported server may read it as a comment. `/*!` without a
/// version always runs; MariaDB's `/*M!` runs only on MariaDB, so it is
/// never "always".
fn version_always_executed(mariadb_only: bool, digits: &[u8]) -> bool {
    if mariadb_only {
        return false;
    }
    if digits.is_empty() {
        return true;
    }
    digits.len() == 5
        && std::str::from_utf8(digits)
            .ok()
            .and_then(|d| d.parse::<u32>().ok())
            .is_some_and(|v| v < 50_700)
}

/// Longest version number of an executable comment (`/*!NNNNNN`).
const MAX_COMMENT_VERSION_DIGITS: usize = 6;

fn is_my_ident_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

fn is_my_op_char(b: u8) -> bool {
    matches!(
        b,
        b'+' | b'-' | b'*' | b'/' | b'<' | b'>' | b'=' | b'~' | b'!' | b'%' | b'^' | b'&' | b'|'
    )
}

/// `--` at `i` starts a MySQL comment: the second dash is followed by a
/// space, a control character or the end of the text.
fn my_dash_comment(b: &[u8], i: usize, end: usize) -> bool {
    b.get(i) == Some(&b'-')
        && b.get(i + 1) == Some(&b'-')
        && (i + 2 >= end || b.get(i + 2).is_none_or(|c| *c <= 0x20))
}

/// Lexes a MySQL / MariaDB text under one `sql_mode` reading.
fn lex_mysql(text: &str, mode: MyMode) -> Result<Vec<Tok>, LexError> {
    if text.len() > MAX_QUERY_BYTES {
        return Err(LexError::TooLong);
    }
    let mut out = Vec::new();
    lex_mysql_range(text, 0, text.len(), mode, false, &mut out)?;
    Ok(out)
}

/// Lexes `text[start..end]` into `out`. `in_comment`: the range is the
/// content of an executable comment (a comment start there fails).
fn lex_mysql_range(
    text: &str,
    start: usize,
    end: usize,
    mode: MyMode,
    in_comment: bool,
    out: &mut Vec<Tok>,
) -> Result<(), LexError> {
    let b = text.as_bytes();
    let mut i = start;
    while i < end {
        if out.len() >= MAX_TOKENS {
            return Err(LexError::TooLong);
        }
        let c = b[i];
        let next = if i + 1 < end { Some(b[i + 1]) } else { None };
        if matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            i += 1;
            continue;
        }
        // Line comments: `#…` and `-- …`.
        if c == b'#' || my_dash_comment(b, i, end) {
            if in_comment {
                // Where a line comment inside an executable comment ends
                // is not settled: fail closed.
                return Err(LexError::Unterminated);
            }
            while i < end && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && next == Some(b'*') {
            if in_comment {
                return Err(LexError::Unterminated);
            }
            let close = find(&b[i + 2..end], b"*/").ok_or(LexError::Unterminated)? + i + 2;
            // Executable comment: `/*!`, `/*!NNNNN`, `/*M!`, `/*M!NNNNNN`.
            let bang = match (b.get(i + 2), b.get(i + 3)) {
                (Some(b'!'), _) => Some(i + 3),
                (Some(b'M'), Some(b'!')) => Some(i + 4),
                _ => None,
            };
            if let Some(mut j) = bang {
                let digits_start = j;
                while j < close
                    && b[j].is_ascii_digit()
                    && j - digits_start < MAX_COMMENT_VERSION_DIGITS
                {
                    j += 1;
                }
                let mariadb_only = b.get(i + 2) == Some(&b'M');
                let always = version_always_executed(mariadb_only, &b[digits_start..j]);
                if always || !mode.version_as_comment {
                    lex_mysql_range(text, j.min(close), close, mode, true, out)?;
                }
            }
            i = close + 2;
            continue;
        }
        // Prefixed strings: N'…', X'…', B'…'.
        if matches!(c, b'n' | b'N' | b'b' | b'B' | b'x' | b'X') && next == Some(b'\'') {
            i = skip_quoted(b, i + 1, end, b'\'', mode.backslash)?;
            out.push(Tok::Literal);
            continue;
        }
        match c {
            b'\'' => {
                i = skip_quoted(b, i, end, b'\'', mode.backslash)?;
                out.push(Tok::Literal);
            }
            b'"' => {
                // A string, or an identifier under ANSI_QUOTES: opaque in
                // both readings (never a name).
                i = skip_quoted(b, i, end, b'"', mode.backslash && !mode.ansi_quotes)?;
                out.push(Tok::Literal);
            }
            b'`' => {
                let mut j = i + 1;
                let mut name = Vec::new();
                loop {
                    if j >= end {
                        return Err(LexError::Unterminated);
                    }
                    if b[j] == b'`' {
                        if j + 1 < end && b[j + 1] == b'`' {
                            name.push(b'`');
                            j += 2;
                            continue;
                        }
                        break;
                    }
                    name.push(b[j]);
                    j += 1;
                }
                i = j + 1;
                out.push(Tok::Quoted(String::from_utf8_lossy(&name).into_owned()));
            }
            b'?' => {
                out.push(Tok::Param);
                i += 1;
            }
            b'0'..=b'9' => {
                let from = i;
                i = skip_number(b, i).min(end);
                let digits = &text[from..i];
                match digits.parse::<u64>() {
                    Ok(v) if digits.bytes().all(|d| d.is_ascii_digit()) => out.push(Tok::Int(v)),
                    _ => out.push(Tok::Literal),
                }
            }
            b'.' if next.is_some_and(|d| d.is_ascii_digit()) => {
                i = skip_number(b, i).min(end);
                out.push(Tok::Literal);
            }
            _ if is_ident_start(c) || c == b'$' => {
                let from = i;
                while i < end && is_my_ident_cont(b[i]) {
                    i += 1;
                }
                out.push(Tok::Word(text[from..i].to_ascii_lowercase()));
            }
            _ if is_my_op_char(c) => {
                let from = i;
                while i < end && is_my_op_char(b[i]) {
                    if i > from
                        && ((b[i] == b'/' && i + 1 < end && b[i + 1] == b'*')
                            || my_dash_comment(b, i, end))
                    {
                        break;
                    }
                    i += 1;
                }
                out.push(Tok::Punct(text[from..i].to_owned()));
            }
            _ => {
                out.push(Tok::Punct(char::from(c).to_string()));
                i += 1;
            }
        }
    }
    Ok(())
}

/// Skips a string quoted with `q` starting at `b[start] == q`, within
/// `end`: the quote doubled is a quote; `backslash`: a backslash escapes
/// the next byte. Returns the index after the closing quote.
fn skip_quoted(
    b: &[u8],
    start: usize,
    end: usize,
    q: u8,
    backslash: bool,
) -> Result<usize, LexError> {
    let mut i = start + 1;
    loop {
        if i >= end {
            return Err(LexError::Unterminated);
        }
        let c = b[i];
        if c == b'\\' && backslash {
            i += 2;
        } else if c == q {
            if i + 1 < end && b[i + 1] == q {
                i += 2;
            } else {
                return Ok(i + 1);
            }
        } else {
            i += 1;
        }
    }
}

/// Every `sql_mode` reading a MySQL text may have been written for.
fn my_modes(text: &str) -> Vec<MyMode> {
    let backslash: &[bool] = if text.contains('\\') {
        &[true, false]
    } else {
        &[true]
    };
    let ansi: &[bool] = if text.contains('"') {
        &[false, true]
    } else {
        &[false]
    };
    let version: &[bool] = if text.contains("/*!") || text.contains("/*M!") {
        &[false, true]
    } else {
        &[false]
    };
    let mut out = Vec::new();
    for &bs in backslash {
        for &aq in ansi {
            for &vc in version {
                out.push(MyMode {
                    backslash: bs,
                    ansi_quotes: aq,
                    version_as_comment: vc,
                });
            }
        }
    }
    out
}

/// Multibyte character sets (gbk, big5, sjis, cp932, gb18030) can have a
/// `\` (0x5c) or a backtick (0x60) as the trail byte of a two-byte
/// character, which the server reads as part of the character and this
/// lexer as a quote or escape: text with a byte >= 0x80 directly followed
/// by one of them cannot be lexed reliably.
fn multibyte_hazard(b: &[u8]) -> bool {
    b.windows(2)
        .any(|w| w[0] >= 0x80 && (w[1] == b'\\' || w[1] == b'`'))
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
    /// Privilege change: `GRANT`, `REVOKE` (MySQL: also account and
    /// role statements, `SET PASSWORD`).
    Dcl,
    /// MySQL `HANDLER t …`: reads rows without a `SELECT`.
    Handler,
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
        !matches!(
            self,
            Self::Copy | Self::Ddl | Self::Dcl | Self::Handler | Self::Other
        )
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

/// One statement of a text (or of the body of a `DO` block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementInfo {
    /// Statement kind (`PERFORM` in a `DO` body counts as `SELECT`).
    pub kind: StatementKind,
    /// Relations it names (identifier tokens only).
    pub relations: Vec<RelationName>,
    /// Shape, for a read (`None` when truncated or not a read).
    pub shape: Option<Shape>,
    /// `COPY` details, for a `COPY`.
    pub copy: Option<CopyInfo>,
    /// From the body of a `DO` block.
    pub nested: bool,
    /// MySQL `SELECT … INTO OUTFILE` / `INTO DUMPFILE`: rows written to a
    /// file on the database server.
    pub outfile: bool,
    /// The leading unquoted words of the statement (at most
    /// [`MAX_LEAD_WORDS`], ASCII-lowercased, from code tokens only, never
    /// from a literal or a comment): the keywords of utility statements
    /// (`flush tables with read lock`, `show create table`). Never sent.
    pub lead: Vec<String>,
}

/// Most leading words kept in [`StatementInfo::lead`].
pub const MAX_LEAD_WORDS: usize = 6;

/// Result of [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryAnalysis {
    kind: StatementKind,
    normalized: Option<NormalizedQuery>,
    relations: Vec<RelationName>,
    shape: Option<Shape>,
    copy: Option<CopyInfo>,
    statements: usize,
    parts: Vec<StatementInfo>,
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
            parts: Vec::new(),
        }
    }

    /// Every statement of the text, then the statements of a `DO` block
    /// body (one level, `nested`), in order. Empty when the text did not
    /// lex unambiguously.
    #[must_use]
    pub fn parts(&self) -> &[StatementInfo] {
        &self.parts
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
    /// Dialect of the text.
    pub dialect: Dialect,
    /// The text cannot be trusted to lex like the server read it (bytes
    /// that were not UTF-8, an escape the source's format does not
    /// define): only the statement kind is kept, from the prefix before
    /// the first quote or comment.
    pub opaque: bool,
    /// The source has already transcoded the text to UTF-8 on the server
    /// (MySQL `performance_schema`, read through a utf8mb4 connection): its
    /// bytes are characters, not the client's multibyte encoding, so the
    /// gbk / sjis trail-byte guard does not apply. Bytes that are not UTF-8
    /// still make the text opaque.
    pub transcoded: bool,
}

impl AnalyzeOptions {
    /// Default: not truncated; a `LIMIT` of more than 10 000 rows counts
    /// as reading the whole relation (the agent's own sampling never goes
    /// beyond 10 000 rows).
    #[must_use]
    pub fn new() -> Self {
        Self {
            possibly_truncated: false,
            large_limit: 10_001,
            dialect: Dialect::Postgres,
            opaque: false,
            transcoded: false,
        }
    }

    /// Marks the text as transcoded to UTF-8 by its source (see
    /// [`AnalyzeOptions::transcoded`]).
    #[must_use]
    pub fn transcoded(mut self, transcoded: bool) -> Self {
        self.transcoded = transcoded;
        self
    }

    /// Marks the text as opaque (see [`AnalyzeOptions::opaque`]).
    #[must_use]
    pub fn opaque(mut self, opaque: bool) -> Self {
        self.opaque = opaque;
        self
    }

    /// Like [`new`](Self::new), for MySQL / MariaDB text.
    #[must_use]
    pub fn mysql() -> Self {
        Self {
            dialect: Dialect::Mysql,
            ..Self::new()
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
    if opts.dialect == Dialect::Mysql {
        return analyze_mysql(text, opts);
    }
    if opts.opaque {
        return QueryAnalysis::unparsed(first_kind_prefix(text));
    }
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
    let mut parts: Vec<StatementInfo> = statements
        .iter()
        .map(|s| statement_info(s, opts, false))
        .collect();
    // `DO $$ … $$`: the body is code; its statements are analyzed too (one
    // level), so a `COPY … TO PROGRAM` inside a block is seen.
    if statements.len() == 1 && word(statements[0].first()) == Some("do") {
        if let Some(body) = do_body(text) {
            // Same fail-closed rule as the outer text: a body whose
            // reading depends on `standard_conforming_strings` (any role
            // can `SET` it) gives no nested part.
            if let Some(inner) = lex_unambiguous(body) {
                for st in split_statements(&inner) {
                    if let Some(st) = plpgsql_statement(st) {
                        let info = statement_info(&st, opts, true);
                        for r in &info.relations {
                            if relations.len() < MAX_RELATIONS && !relations.contains(r) {
                                relations.push(r.clone());
                            }
                        }
                        if parts.len() < MAX_PARTS {
                            parts.push(info);
                        }
                    }
                }
            }
        }
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
        parts,
    }
}

/// [`analyze`] of statement text as raw bytes from its source: bytes that
/// are not UTF-8 make the text opaque (only the statement kind is kept);
/// the text is never decoded lossily for analysis.
#[must_use]
pub fn analyze_raw(raw: &[u8], opts: AnalyzeOptions) -> QueryAnalysis {
    match std::str::from_utf8(raw) {
        Ok(text) => analyze(text, opts),
        Err(e) => {
            // The valid prefix only, for the kind.
            let prefix = std::str::from_utf8(&raw[..e.valid_up_to()]).unwrap_or("");
            analyze(prefix, opts.opaque(true))
        }
    }
}

/// [`analyze`] for MySQL / MariaDB text: every `sql_mode` reading must
/// give the same tokens.
fn analyze_mysql(text: &str, opts: AnalyzeOptions) -> QueryAnalysis {
    if opts.opaque || (!opts.transcoded && multibyte_hazard(text.as_bytes())) {
        return QueryAnalysis::unparsed(my_kind_prefix(text));
    }
    let mut readings = my_modes(text).into_iter().map(|m| lex_mysql(text, m));
    let first = readings.next().unwrap_or(Err(LexError::Unterminated));
    let tokens = match first {
        Ok(t) => {
            let mut agree = true;
            let mut kinds_agree = true;
            for other in readings {
                match other {
                    Ok(o) if o == t => {}
                    Ok(o) => {
                        agree = false;
                        kinds_agree &= my_kind(&o) == my_kind(&t);
                    }
                    Err(_) => {
                        agree = false;
                        kinds_agree = false;
                    }
                }
            }
            if !agree {
                return QueryAnalysis::unparsed(if kinds_agree {
                    my_kind(&t)
                } else {
                    StatementKind::Other
                });
            }
            t
        }
        Err(_) => return QueryAnalysis::unparsed(my_kind_prefix(text)),
    };
    let statements = split_statements(&tokens);
    let kind = statements
        .first()
        .map_or(StatementKind::Other, |s| my_kind(s));
    let mut relations = Vec::new();
    for s in &statements {
        collect_relations_dialect(s, Dialect::Mysql, &mut relations);
    }
    let parts: Vec<StatementInfo> = statements
        .iter()
        .take(MAX_PARTS)
        .map(|s| statement_info(s, opts, false))
        .collect();
    let shape = match statements.first() {
        Some(first) if !opts.possibly_truncated && kind.is_read() => main_shape(first),
        _ => None,
    };
    let all_dml = !statements.is_empty() && statements.iter().all(|s| my_kind(s).is_dml());
    let normalized = (all_dml && !opts.possibly_truncated).then(|| normalize_tokens(&tokens));
    QueryAnalysis {
        kind,
        normalized,
        relations,
        shape,
        copy: None,
        statements: statements.len(),
        parts,
    }
}

/// Statement kind of a MySQL statement: [`first_kind`], plus `REPLACE`
/// (a write), `HANDLER`, and account / role statements as DCL.
fn my_kind(s: &[Tok]) -> StatementKind {
    let Some(i) = main_start(s) else {
        return StatementKind::Other;
    };
    let second = word(s.get(i + 1));
    match word(s.get(i)) {
        Some("replace") => StatementKind::Insert,
        Some("handler") => StatementKind::Handler,
        // Digest text writes `USER` as `SYSTEM_USER` (MySQL).
        Some("create" | "alter" | "drop" | "rename")
            if matches!(second, Some("user" | "role" | "system_user")) =>
        {
            StatementKind::Dcl
        }
        Some("set") if matches!(second, Some("password" | "role" | "default")) => {
            StatementKind::Dcl
        }
        _ => first_kind(s),
    }
}

/// Kind from the first word of a MySQL text that did not lex: the prefix
/// up to the first quote or comment is lexed alone (it holds no literal).
fn my_kind_prefix(text: &str) -> StatementKind {
    let end = text
        .find(['\'', '"', '`', '#', '-', '/'])
        .unwrap_or(text.len())
        .min(256);
    let Some(prefix) = text.get(..end) else {
        return StatementKind::Other;
    };
    let mode = MyMode {
        backslash: true,
        ansi_quotes: false,
        version_as_comment: true,
    };
    lex_mysql(prefix, mode).map_or(StatementKind::Other, |t| my_kind(&t))
}

/// The leading words of a statement (after leading parentheses).
fn lead_words(s: &[Tok]) -> Vec<String> {
    s.iter()
        .skip_while(|t| is_punct(Some(t), "("))
        .map_while(|t| match t {
            Tok::Word(w) => Some(w.clone()),
            _ => None,
        })
        .take(MAX_LEAD_WORDS)
        .collect()
}

/// `INTO OUTFILE '…'` / `INTO DUMPFILE '…'` anywhere in a statement (`?`
/// in digest text).
fn has_outfile(s: &[Tok]) -> bool {
    s.windows(3).any(|w| {
        matches!(&w[0], Tok::Word(i) if i == "into")
            && matches!(&w[1], Tok::Word(f) if f == "outfile" || f == "dumpfile")
            && matches!(w[2], Tok::Literal | Tok::Param)
    })
}

/// Lexes `text` when its reading does not depend on
/// `standard_conforming_strings`: without a backslash, or when both
/// readings give the same tokens. `None` otherwise, or when it does not
/// lex. Every sub-text holding code is lexed through this.
fn lex_unambiguous(text: &str) -> Option<Vec<Tok>> {
    let tokens = lex(text, true).ok()?;
    if text.contains('\\') && lex(text, false).ok()? != tokens {
        return None;
    }
    Some(tokens)
}

/// Most statements described per text.
const MAX_PARTS: usize = 64;

fn statement_info(s: &[Tok], opts: AnalyzeOptions, nested: bool) -> StatementInfo {
    let kind = match opts.dialect {
        Dialect::Mysql => my_kind(s),
        Dialect::Postgres => first_kind(s),
    };
    let mut relations = Vec::new();
    collect_relations_dialect(s, opts.dialect, &mut relations);
    let (shape, copy) = if opts.possibly_truncated {
        (None, None)
    } else {
        match kind {
            StatementKind::Copy => (None, copy_info(s, opts.large_limit)),
            k if k.is_read() => (main_shape(s), None),
            _ => (None, None),
        }
    };
    StatementInfo {
        kind,
        relations,
        shape,
        copy,
        nested,
        outfile: opts.dialect == Dialect::Mysql && has_outfile(s),
        lead: lead_words(s),
    }
}

/// The body of `DO [LANGUAGE x] $tag$ body $tag$` (dollar quoting only).
fn do_body(text: &str) -> Option<&str> {
    let b = text.as_bytes();
    let skip_ws = |mut i: usize| {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    };
    let mut i = skip_ws(0);
    if !text.get(i..i + 2)?.eq_ignore_ascii_case("do") {
        return None;
    }
    i = skip_ws(i + 2);
    let mut language_seen = false;
    if let Some(next) = language_clause(text, i)? {
        language_seen = true;
        i = skip_ws(next);
    }
    if b.get(i) != Some(&b'$') {
        return None;
    }
    let tag_end = dollar_tag(b, i)?;
    let tag = &b[i..=tag_end];
    let body = tag_end + 1;
    let close = find(&b[body..], tag)?;
    let mut j = skip_ws(body + close + tag.len());
    if let Some(next) = language_clause(text, j)? {
        if language_seen {
            return None;
        }
        j = skip_ws(next);
    }
    // Nothing else may follow (an optional `;`): anything unexpected, a
    // comment included, fails closed.
    if b.get(j) == Some(&b';') {
        j = skip_ws(j + 1);
    }
    if j != b.len() {
        return None;
    }
    text.get(body..body + close)
}

/// A `LANGUAGE <name>` clause at `i`: `Some(Some(end))` when it names
/// PL/pgSQL (`plpgsql` unquoted or single-quoted in any case, or
/// `"plpgsql"`), `Some(None)` when there is no clause, `None` when it names
/// another language or cannot be read (the body is then not analyzed:
/// other languages are not SQL).
fn language_clause(text: &str, i: usize) -> Option<Option<usize>> {
    let b = text.as_bytes();
    let is_kw = text
        .get(i..i + 8)
        .is_some_and(|w| w.eq_ignore_ascii_case("language"))
        && !b.get(i + 8).copied().is_some_and(is_ident_cont);
    if !is_kw {
        return Some(None);
    }
    let mut j = i + 8;
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    let (name, end, fold) = match b.get(j) {
        Some(b'\'') | Some(b'"') => {
            let q = b[j];
            let close = text.get(j + 1..)?.find(char::from(q))? + j + 1;
            if b.get(close + 1) == Some(&q) {
                return None; // doubled quote: not a plain name
            }
            (text.get(j + 1..close)?, close + 1, q == b'\'')
        }
        Some(c) if is_ident_start(*c) => {
            let mut k = j;
            while k < b.len() && is_ident_cont(b[k]) {
                k += 1;
            }
            (text.get(j..k)?, k, true)
        }
        _ => return None,
    };
    let plpgsql = if fold {
        name.eq_ignore_ascii_case("plpgsql")
    } else {
        name == "plpgsql"
    };
    plpgsql.then_some(Some(end))
}

/// A PL/pgSQL statement reduced to its SQL part: leading block keywords
/// (`BEGIN`, `DECLARE`…) skipped, `PERFORM` read as `SELECT`, and the
/// `INTO` target of a `SELECT` removed (a variable, not a relation).
fn plpgsql_statement(s: &[Tok]) -> Option<Vec<Tok>> {
    let start = s.iter().position(|t| {
        matches!(t, Tok::Word(w) if matches!(
            w.as_str(),
            "select" | "insert" | "update" | "delete" | "merge" | "copy" | "with" | "values"
                | "table" | "perform"
        ))
    })?;
    let mut out: Vec<Tok> = s[start..].to_vec();
    if word(out.first()) == Some("perform") {
        out[0] = Tok::Word("select".to_owned());
    }
    if first_kind(&out) == StatementKind::Select {
        let mut depth = 0usize;
        let mut i = 0;
        while i < out.len() {
            match &out[i] {
                Tok::Punct(p) if p == "(" => depth += 1,
                Tok::Punct(p) if p == ")" => depth = depth.saturating_sub(1),
                Tok::Word(w) if w == "into" && depth == 0 => {
                    let mut j = i + 1;
                    if word(out.get(j)) == Some("strict") {
                        j += 1;
                    }
                    while let Some((_, next)) = qualified_name(&out, j) {
                        j = next;
                        if is_punct(out.get(j), ",") {
                            j += 1;
                        } else {
                            break;
                        }
                    }
                    out.drain(i..j);
                    continue;
                }
                _ => {}
            }
            i += 1;
        }
    }
    Some(out)
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

/// [`collect_relations`], plus, in MySQL, the tables named by `SHOW CREATE
/// TABLE|VIEW t`, `SHOW COLUMNS|FIELDS|INDEX … FROM t` (through `FROM`),
/// `LOCK TABLES t …, u …` and `HANDLER t …`.
fn collect_relations_dialect(s: &[Tok], dialect: Dialect, out: &mut Vec<RelationName>) {
    collect_relations(s, out);
    if dialect != Dialect::Mysql {
        return;
    }
    let none: [String; 0] = [];
    let lead = lead_words(s);
    let lead: Vec<&str> = lead.iter().map(String::as_str).collect();
    let start = s.iter().take_while(|t| is_punct(Some(t), "(")).count();
    match lead.as_slice() {
        ["show", "create", "table" | "view", ..] => {
            read_relation(s, start + 3, &none, false, out);
        }
        ["handler", ..] => {
            read_relation(s, start + 1, &none, false, out);
        }
        ["lock", "tables" | "table", ..] => {
            // `LOCK TABLES t [[AS] a] READ [LOCAL] | [LOW_PRIORITY] WRITE, …`
            let mut i = start + 2;
            loop {
                let next = read_relation(s, i, &none, false, out);
                if next == i {
                    break;
                }
                i = next;
                while i < s.len() && !is_punct(s.get(i), ",") {
                    i += 1;
                }
                if i >= s.len() {
                    break;
                }
                i += 1;
            }
        }
        _ => {}
    }
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
    // MySQL `INTO OUTFILE '…'` / `INTO DUMPFILE '…'`: a file, not a relation.
    if matches!(word(s.get(i)), Some("outfile" | "dumpfile"))
        && matches!(s.get(i + 1), Some(Tok::Literal | Tok::Param))
    {
        return i + 2;
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
    // Open parentheses before the main keyword (a leading `(`), as a
    // running balance: closed CTE bodies do not count.
    let base_depth = s[..start].iter().fold(0usize, |d, t| {
        if is_punct(Some(t), "(") {
            d + 1
        } else if is_punct(Some(t), ")") {
            d.saturating_sub(1)
        } else {
            d
        }
    });
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
                "limit" => match (s.get(i + 1), s.get(i + 2), s.get(i + 3)) {
                    (Some(Tok::Word(a)), _, _) if a == "all" => {}
                    // MySQL `LIMIT offset, count`.
                    (Some(Tok::Int(_)), Some(Tok::Punct(p)), Some(Tok::Int(n))) if p == "," => {
                        shape.limit = Limit::Rows(*n);
                    }
                    (Some(Tok::Int(_) | Tok::Param), Some(Tok::Punct(p)), _) if p == "," => {
                        shape.limit = Limit::Unknown;
                    }
                    (Some(Tok::Int(n)), _, _) => shape.limit = Limit::Rows(*n),
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
    fn every_statement_is_described() {
        let a = analyze(
            "select 1; copy crm.customers to program 'x'",
            AnalyzeOptions::new(),
        );
        assert_eq!(a.parts().len(), 2);
        assert_eq!(a.parts()[0].kind, StatementKind::Select);
        let c = a.parts()[1].copy.unwrap();
        assert_eq!(c.endpoint, CopyEndpoint::Program);
        assert!(c.whole_relation);
    }

    #[test]
    fn do_block_bodies_are_analyzed() {
        let a = analyze(
            "DO $x$ DECLARE n int; BEGIN copy crm.customers to program 'curl -d @- h'; \
             select count(*) into n from crm.t; perform * from crm.u; END $x$",
            AnalyzeOptions::new(),
        );
        let nested: Vec<_> = a.parts().iter().filter(|p| p.nested).collect();
        assert_eq!(nested.len(), 3);
        assert_eq!(nested[0].copy.unwrap().endpoint, CopyEndpoint::Program);
        assert_eq!(
            nested[1].relations.len(),
            1,
            "INTO target is not a relation"
        );
        assert_eq!(nested[1].relations[0].name, "t");
        assert!(nested[2].shape.unwrap().whole_relation(10_001));
        assert!(a.normalized().is_none());
        assert!(
            analyze("do 'begin null; end'", AnalyzeOptions::new())
                .parts()
                .iter()
                .all(|p| !p.nested)
        );
    }

    #[test]
    fn ambiguous_do_bodies_give_no_nested_part() {
        // Valid with standard_conforming_strings = off: the literal runs
        // to the second quote, and `jane_dupont` is literal text.
        let a = analyze(
            "do $$ begin perform 'O\\'Brien from jane_dupont', 'D\\'Arc'; end $$",
            AnalyzeOptions::new(),
        );
        assert!(a.parts().iter().all(|p| !p.nested), "{:?}", a.parts().len());
        assert!(
            a.relations().iter().all(|r| r.name != "jane_dupont"),
            "literal text became a relation"
        );
        // A backslash that reads the same both ways is fine.
        let a = analyze(
            "do $$ begin perform E'a\\nb' from crm.t; end $$",
            AnalyzeOptions::new(),
        );
        assert_eq!(a.parts().iter().filter(|p| p.nested).count(), 1);
    }

    #[test]
    fn only_plpgsql_do_bodies_are_analyzed() {
        let nested = |q: &str| {
            let a = analyze(q, AnalyzeOptions::new());
            assert!(a.relations().iter().all(|r| r.name != "jane_dupont"), "{q}");
            a.parts().iter().filter(|p| p.nested).count()
        };
        // Other languages: never lexed as SQL.
        assert_eq!(
            nested(
                "do $$ const note = `select copied from jane_dupont`; plv8.elog(NOTICE, note); $$ language plv8"
            ),
            0
        );
        assert_eq!(
            nested("do language plperl $$ my $s = q{select a from jane_dupont}; $$"),
            0
        );
        assert_eq!(
            nested("do $$\n# select a from jane_dupont\nplpy.notice('x')\n$$ language plpython3u"),
            0
        );
        assert_eq!(
            nested("do $$ perform 1 from jane_dupont; $$ language 'plv8'"),
            0
        );
        assert_eq!(
            nested("do $$ perform 1 from jane_dupont; $$ language \"PLPGSQL\""),
            0
        );
        assert_eq!(
            nested("do $$ perform 1 from jane_dupont; $$ language plpgsql garbage"),
            0
        );
        assert_eq!(
            nested("do $$ perform 1 from jane_dupont; $$ -- language plv8"),
            0
        );
        assert_eq!(
            nested("do language plpgsql $$ perform 1 from jane_dupont; $$ language plpgsql"),
            0
        );
        assert_eq!(nested("do language $$ perform 1 from jane_dupont; $$"), 0);
        // PL/pgSQL: default, or named before / after, any case, quoted.
        let plpgsql = |q: &str| {
            let a = analyze(q, AnalyzeOptions::new());
            a.parts().iter().filter(|p| p.nested).count()
        };
        assert_eq!(plpgsql("do $$ begin perform 1 from crm.t; end $$"), 1);
        assert_eq!(plpgsql("do $$ begin perform 1 from crm.t; end $$;"), 1);
        assert_eq!(
            plpgsql("DO LANGUAGE PLpgSQL $$ begin perform 1 from crm.t; end $$"),
            1
        );
        assert_eq!(
            plpgsql("do $$ begin perform 1 from crm.t; end $$ language 'PLPGSQL'"),
            1
        );
        assert_eq!(
            plpgsql("do $$ begin perform 1 from crm.t; end $$ language \"plpgsql\""),
            1
        );
    }

    #[test]
    fn cte_queries_are_shaped_on_their_main_query() {
        let shape = |q: &str| *analyze(q, AnalyzeOptions::new()).shape().unwrap();
        let s = shape("with x as (select * from t) select * from x where id = 1");
        assert!(s.filtered, "{s:?}");
        let s = shape("with x as (select id from t where a) select count(*) from x");
        assert!(s.aggregated, "{s:?}");
        let s = shape("with x as (select * from t where a) select * from x");
        assert!(!s.filtered);
        let c = *analyze(
            "copy (with x as (select * from t) select * from x where id = 1) to stdout",
            AnalyzeOptions::new(),
        )
        .copy()
        .unwrap();
        assert!(!c.whole_relation);
        let c = *analyze(
            "copy (with x as (select * from t) select * from x) to stdout",
            AnalyzeOptions::new(),
        )
        .copy()
        .unwrap();
        assert!(c.whole_relation);
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

    fn my(s: &str) -> QueryAnalysis {
        analyze(s, AnalyzeOptions::mysql())
    }

    fn my_norm(s: &str) -> Option<String> {
        my(s).normalized().map(|n| n.as_str().to_owned())
    }

    fn my_rels(s: &str) -> Vec<(Option<String>, String)> {
        my(s)
            .relations()
            .iter()
            .map(|r| (r.schema.clone(), r.name.clone()))
            .collect()
    }

    #[test]
    fn mysql_literals_and_comments_become_placeholders() {
        assert_eq!(
            my_norm(
                "SELECT `a`, b FROM hr.employees WHERE email = 'jane@example.com' \
                 AND n = N'x' AND h = X'4A' AND bits = b'01' AND c = _utf8mb4'y' \
                 AND z = 0x1F AND w = 1.5e3 AND v = ? # tail jane@example.com\n \
                 -- another jane@example.com\n /* block jane@example.com */ LIMIT 5"
            )
            .unwrap(),
            "select \"a\" , b from hr . employees where email = ? and n = ? and h = ? and \
             bits = ? and c = _utf8mb4 ? and z = ? and w = ? and v = ? limit ?"
        );
        // `--` without a space is two minus signs, not a comment.
        assert_eq!(
            my_norm("select 1--2 from t").unwrap(),
            "select ? -- ? from t"
        );
        assert!(my_norm("select 'open").is_none());
        assert!(my_norm("select `open").is_none());
        assert!(my_norm("select /* open").is_none());
        assert!(my_norm("select \"open").is_none());
    }

    #[test]
    fn mysql_executable_comments_are_code() {
        let a = my("SELECT /*!40001 SQL_NO_CACHE */ * FROM `employees`");
        assert_eq!(a.parts()[0].lead, ["select", "sql_no_cache"]);
        assert_eq!(
            my_rels("SELECT /*!40001 SQL_NO_CACHE */ * FROM `employees`"),
            vec![r(None, "employees")]
        );
        assert!(a.shape().unwrap().whole_relation(10_001));
        // Always executed on a supported server: read as code.
        assert_eq!(
            my_norm("select /*!50000 'secret', */ a from t").unwrap(),
            "select ? , a from t"
        );
        for q in [
            "SELECT /*!40100 SQL_NO_CACHE */ * FROM t",
            "SELECT /*!32311 SQL_NO_CACHE */ * FROM t",
            "SELECT /*!40101 SQL_NO_CACHE */ * FROM t",
            "SELECT /*!50699 SQL_NO_CACHE */ * FROM t",
        ] {
            assert_eq!(my(q).parts()[0].lead, ["select", "sql_no_cache"], "{q}");
        }
        // Maybe a comment (MariaDB-only, or a version from 5.7.0, which
        // MariaDB skips): both readings must agree, otherwise only the kind
        // is kept. A filter or a limit hidden there must not make a
        // whole-table read look filtered.
        for q in [
            "select /*M!100500 'secret', */ a from t",
            "select a /*!80030 from Pa55word */ from t",
            "select a /*!100500 , b */ from t",
            "SELECT * FROM customers /*!50700 WHERE 1=1 */",
            "SELECT * FROM customers /*!57000 LIMIT 1 */",
            "SELECT * FROM customers /*!79999 WHERE id = 3 */",
        ] {
            let a = my(q);
            assert!(a.normalized().is_none() && a.relations().is_empty(), "{q}");
            assert_eq!(a.kind(), StatementKind::Select, "{q}");
        }
        assert_eq!(
            my_rels("select a from t /*!50700 */"),
            vec![r(None, "t")],
            "an empty maybe-comment reads the same"
        );
        // A literal running past the end of the executable comment, a
        // nested comment or a line comment inside it: fail closed.
        for q in [
            "select /*! 'a */ secret' from t",
            "select /*! /* x */ a from t",
            "select /*! # x */ a from t",
            "select /*! -- x */ a from t",
        ] {
            let a = my(q);
            assert!(a.normalized().is_none() && a.relations().is_empty(), "{q}");
        }
        // Optimizer hints are comments.
        assert_eq!(
            my_norm("select /*+ SET_VAR(sort_buffer_size = 16M) */ a from t").unwrap(),
            "select a from t"
        );
    }

    #[test]
    fn mysql_sql_mode_ambiguity_fails_closed() {
        // With NO_BACKSLASH_ESCAPES the first literal ends at `\'`.
        let a = my("select 'a\\' , secret_col from t where x = 'b'");
        assert!(a.normalized().is_none() && a.relations().is_empty());
        assert_eq!(a.kind(), StatementKind::Select);
        // Double quotes: a string, or an identifier under ANSI_QUOTES; the
        // content is never a name either way.
        let a = my("select \"jane@example.com\" from \"t\"");
        assert!(a.relations().is_empty());
        assert_eq!(a.normalized().unwrap().as_str(), "select ? from ?");
        // Backslash inside double quotes: read differently with ANSI_QUOTES.
        let a = my("select \"a\\\" , secret_col from t where x = \"b\"");
        assert!(a.normalized().is_none() && a.relations().is_empty());
        // A backslash that reads the same in every mode is fine.
        assert!(my("select 'a\\nb' from t").normalized().is_some());
    }

    #[test]
    fn mysql_multibyte_trail_bytes_fail_closed() {
        // gbk 0xBF 0x5C is one character on the server; here the 0x5C
        // would escape the quote. Valid UTF-8 cannot carry the raw pair, so
        // both the raw bytes and any such byte pair keep the kind only.
        let raw = b"select '\xBF\x5C' , 1 from t where x = ' from payroll.S3cr3t '";
        let a = analyze_raw(raw, AnalyzeOptions::mysql());
        assert!(a.relations().is_empty() && a.parts().is_empty());
        assert_eq!(a.kind(), StatementKind::Select);
        let a = my("select '\u{e9}\\' , 1 from t where x = ' from payroll.S3cr3t '");
        assert!(a.relations().is_empty() && a.parts().is_empty());
        let a = my("select `\u{e9}` from t");
        assert!(
            a.relations().is_empty(),
            "backtick after a multibyte character"
        );
        // A text the source transcoded to UTF-8 (performance_schema) is
        // made of characters: a CJK identifier stays readable.
        let cjk = "SELECT * FROM `hr` . `\u{5ba2}\u{6237}`";
        assert!(my(cjk).relations().is_empty());
        assert_eq!(
            analyze(cjk, AnalyzeOptions::mysql().transcoded(true))
                .relations()
                .len(),
            1
        );
        assert!(
            analyze_raw(
                b"select 1 from \xFF",
                AnalyzeOptions::mysql().transcoded(true)
            )
            .relations()
            .is_empty()
        );
        // Other non-ASCII text is fine.
        assert_eq!(my_rels("select 'caf\u{e9}' from t"), vec![r(None, "t")]);
        assert!(
            analyze_raw(b"select 1 from \xFF", AnalyzeOptions::mysql())
                .relations()
                .is_empty()
        );
    }

    #[test]
    fn mysql_backticks_and_qualified_names() {
        assert_eq!(
            my_rels("select * from `hr`.`em``ployees` e join sales.orders o using (id)"),
            vec![r(Some("hr"), "em`ployees"), r(Some("sales"), "orders")]
        );
        assert_eq!(
            my_rels("replace into hr.t (a) values (1)"),
            vec![r(Some("hr"), "t")]
        );
        assert_eq!(
            my("replace into t values (1)").kind(),
            StatementKind::Insert
        );
    }

    #[test]
    fn mysql_into_outfile_is_reported_and_not_a_relation() {
        for q in [
            "select * from hr.t into outfile '/tmp/jane.csv'",
            "select a into dumpfile '/tmp/jane' from hr.t",
            "SELECT * FROM hr.t INTO OUTFILE ? ",
        ] {
            let a = my(q);
            assert_eq!(a.relations().len(), 1, "{q}");
            assert_eq!(a.relations()[0].name, "t");
            assert!(a.parts()[0].outfile, "{q}");
        }
        assert!(!my("select * from hr.t into @x").parts()[0].outfile);
    }

    #[test]
    fn mysql_utility_statements_keep_no_text() {
        for q in [
            "CREATE USER 'u'@'%' IDENTIFIED BY 'Secr3t'",
            "ALTER USER 'u'@'%' IDENTIFIED BY <secret>",
            "SET PASSWORD FOR 'u'@'%' = PASSWORD(*****)",
            "GRANT SELECT ON hr.* TO 'u'@'%' IDENTIFIED BY 'Secr3t'",
            "CHANGE MASTER TO MASTER_PASSWORD='Secr3t'",
            "CHANGE REPLICATION SOURCE TO SOURCE_PASSWORD = 'Secr3t'",
            "CREATE SERVER s FOREIGN DATA WRAPPER mysql OPTIONS (PASSWORD 'Secr3t')",
            "SET @x = 'Secr3t'",
            "LOAD DATA INFILE '/tmp/x' INTO TABLE t",
            "HANDLER hr.t READ FIRST",
            "FLUSH TABLES WITH READ LOCK",
        ] {
            assert!(my_norm(q).is_none(), "{q}");
        }
        for (q, k) in [
            ("CREATE USER u IDENTIFIED BY 'x'", StatementKind::Dcl),
            (
                "CREATE SYSTEM_USER ? @? IDENTIFIED BY ?",
                StatementKind::Dcl,
            ),
            ("drop role r", StatementKind::Dcl),
            ("SET PASSWORD = 'x'", StatementKind::Dcl),
            ("CREATE TABLE t (a int)", StatementKind::Ddl),
            ("HANDLER t READ NEXT", StatementKind::Handler),
        ] {
            assert_eq!(my(q).kind(), k, "{q}");
        }
    }

    #[test]
    fn mysql_utility_relations_and_lead_words() {
        assert_eq!(
            my_rels("show create table `employees`"),
            vec![r(None, "employees")]
        );
        assert_eq!(
            my_rels("SHOW FIELDS FROM `employees`"),
            vec![r(None, "employees")]
        );
        assert_eq!(
            my_rels("LOCK TABLES `a` READ /*!32311 LOCAL */, hr.b AS x WRITE"),
            vec![r(None, "a"), r(Some("hr"), "b")]
        );
        assert_eq!(my_rels("handler hr.t read first"), vec![r(Some("hr"), "t")]);
        assert_eq!(
            my("FLUSH /*!40101 LOCAL */ TABLES WITH READ LOCK").parts()[0].lead,
            ["flush", "local", "tables", "with", "read", "lock"]
        );
    }

    #[test]
    fn mysql_limits() {
        let shape = |q: &str| *my(q).shape().unwrap();
        assert_eq!(shape("select * from t limit 10, 20").limit, Limit::Rows(20));
        assert_eq!(shape("select * from t limit ?, ?").limit, Limit::Unknown);
        assert_eq!(
            shape("select * from t limit 50000").limit,
            Limit::Rows(50_000)
        );
        assert!(!shape("select * from t where a = ?").whole_relation(10));
    }
}
