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

use zeroize::Zeroizing;

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
    /// MySQL `"…"`: a string literal, or an identifier under
    /// `ANSI_QUOTES` (the session mode is unknown). A literal everywhere a
    /// literal is expected, kept apart only to recognize a name position
    /// (`FROM "t"`, `"db"."t"`, `"f"(`). Its content is not kept: only
    /// whether it is an audit log administration function name
    /// ([`is_audit_function`]) or `LOAD_FILE` ([`is_file_function`]),
    /// whether it holds a non-ASCII character, and whether it is a
    /// built-in function name when quoted ([`BuiltinFunctions`],
    /// [`CallForm::Quoted`]), decided at lex time.
    DQuoted {
        audit_function: bool,
        file_function: bool,
        non_ascii: bool,
        builtin: bool,
    },
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

/// How an unqualified name stands before `(` in a MySQL / MariaDB text,
/// which decides how the server resolves the call (ADR-0045 decision 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CallForm {
    /// Unquoted, with `(` right after the name (`now(`).
    Plain,
    /// Unquoted, with whitespace or a comment before `(` (`now (`): the
    /// servers read a keyword function of `lex.h`'s `sql_functions` set
    /// as a plain identifier then, unless the session has `IGNORE_SPACE`
    /// (unknown to the agent).
    Spaced,
    /// Backquoted, or double-quoted (an identifier under `ANSI_QUOTES`):
    /// never a keyword, only a native function (or a stored one).
    Quoted,
}

/// The built-in function names of the server a MySQL / MariaDB text was
/// written for (ADR-0045 decisions 7 to 9), supplied by the caller: this
/// crate knows no server version. An unqualified call of a name it does not
/// accept is an unknown call ([`StatementInfo::unknown_call`]): possibly a
/// stored or loadable function, code that runs out of sight.
pub trait BuiltinFunctions: Send + Sync {
    /// Whether `name(`, written in `form`, calls a built-in function, or
    /// is a keyword that is not a call there (`IN (`, `VALUES (`).
    /// `name` is the name as written (any bytes, any case; never kept):
    /// compare it in place, ASCII-case-insensitively.
    fn is_builtin(&self, name: &[u8], form: CallForm) -> bool;
}

/// A [`BuiltinFunctions`] in [`AnalyzeOptions`] (compared by address).
#[derive(Clone, Copy)]
pub struct Builtins(pub &'static dyn BuiltinFunctions);

impl fmt::Debug for Builtins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Builtins")
    }
}

impl PartialEq for Builtins {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::addr_eq(self.0, other.0)
    }
}

impl Eq for Builtins {}

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
    lex_mysql_spaced(text, mode, None).map(|l| l.toks)
}

/// What the analysis of unknown calls needs to know of a MySQL token
/// besides the token itself ([`has_unknown_call`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TokFlags {
    /// A byte stands between the previous token and this one (`count
    /// (x)`, `count/**/(x)`: the server reads a keyword function name as a
    /// plain identifier unless `(` follows right away).
    spaced: bool,
    /// A [`Tok::Literal`] that the servers read as a name starting with
    /// digits (`1f`, [`my_digit_name`]).
    digit_name: bool,
}

/// The tokens of a MySQL text, with their [`TokFlags`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MyLexed {
    toks: Vec<Tok>,
    flags: Vec<TokFlags>,
    /// End of the last token pushed.
    last_end: usize,
}

impl MyLexed {
    fn push(&mut self, tok: Tok, start: usize, end: usize) {
        self.toks.push(tok);
        self.flags.push(TokFlags {
            spaced: start != self.last_end,
            digit_name: false,
        });
        self.last_end = end;
    }
}

/// [`lex_mysql`], with the spacing between tokens; `builtins` decides
/// whether a `"…"` token is a built-in function name (only compared in
/// place, see [`Tok::DQuoted`]).
fn lex_mysql_spaced(
    text: &str,
    mode: MyMode,
    builtins: Option<&dyn BuiltinFunctions>,
) -> Result<MyLexed, LexError> {
    if text.len() > MAX_QUERY_BYTES {
        return Err(LexError::TooLong);
    }
    let mut out = MyLexed::default();
    lex_mysql_range(text, 0, text.len(), mode, false, builtins, &mut out)?;
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
    builtins: Option<&dyn BuiltinFunctions>,
    out: &mut MyLexed,
) -> Result<(), LexError> {
    let b = text.as_bytes();
    let mut i = start;
    while i < end {
        if out.toks.len() >= MAX_TOKENS {
            return Err(LexError::TooLong);
        }
        let tok_start = i;
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
                    lex_mysql_range(text, j.min(close), close, mode, true, builtins, out)?;
                }
            }
            i = close + 2;
            continue;
        }
        // Prefixed strings: N'…', X'…', B'…'.
        if matches!(c, b'n' | b'N' | b'b' | b'B' | b'x' | b'X') && next == Some(b'\'') {
            i = skip_quoted(b, i + 1, end, b'\'', mode.backslash)?;
            out.push(Tok::Literal, tok_start, i);
            continue;
        }
        match c {
            b'\'' => {
                i = skip_quoted(b, i, end, b'\'', mode.backslash)?;
                out.push(Tok::Literal, tok_start, i);
            }
            b'"' => {
                // A string, or an identifier under ANSI_QUOTES: never
                // resolved to a name, but kept apart from other literals
                // so that a name position can be told (fail closed).
                let from = i + 1;
                i = skip_quoted(b, i, end, b'"', mode.backslash && !mode.ansi_quotes)?;
                // The content is only compared in place, never copied.
                let content = b.get(from..i.saturating_sub(1));
                out.push(
                    Tok::DQuoted {
                        audit_function: content.is_some_and(is_audit_function),
                        file_function: content.is_some_and(is_file_function),
                        non_ascii: content.is_some_and(|c| !c.is_ascii()),
                        builtin: content.is_some_and(|c| {
                            builtins.is_some_and(|f| f.is_builtin(c, CallForm::Quoted))
                        }),
                    },
                    tok_start,
                    i,
                );
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
                out.push(
                    Tok::Quoted(String::from_utf8_lossy(&name).into_owned()),
                    tok_start,
                    i,
                );
            }
            b'?' => {
                i += 1;
                out.push(Tok::Param, tok_start, i);
            }
            b'0'..=b'9' => {
                let from = i;
                i = skip_number(b, i).min(end);
                let digits = &text[from..i];
                match digits.parse::<u64>() {
                    Ok(v) if digits.bytes().all(|d| d.is_ascii_digit()) => {
                        out.push(Tok::Int(v), tok_start, i);
                    }
                    // A name that starts with digits (`1f`, `1_000`): the
                    // servers read it as an identifier, so `1f()` calls a
                    // stored function (ADR-0045 decision 9). Kept a
                    // literal (its content may be a value), marked.
                    _ => {
                        out.push(Tok::Literal, tok_start, i);
                        if my_digit_name(digits)
                            && let Some(f) = out.flags.last_mut()
                        {
                            f.digit_name = true;
                        }
                    }
                }
            }
            b'.' if next.is_some_and(|d| d.is_ascii_digit()) => {
                i = skip_number(b, i).min(end);
                out.push(Tok::Literal, tok_start, i);
            }
            _ if is_ident_start(c) || c == b'$' => {
                let from = i;
                while i < end && is_my_ident_cont(b[i]) {
                    i += 1;
                }
                out.push(Tok::Word(text[from..i].to_ascii_lowercase()), tok_start, i);
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
                out.push(Tok::Punct(text[from..i].to_owned()), tok_start, i);
            }
            _ => {
                i += 1;
                out.push(Tok::Punct(char::from(c).to_string()), tok_start, i);
            }
        }
    }
    Ok(())
}

/// A run that [`skip_number`] took for a number but that the MySQL and
/// MariaDB lexers read as an identifier: digits followed by a letter, `_`
/// or `$` (`1f`, `1_000`, `12abc`), unless it is a number (`1e5`, `1E+5`
/// is cut before the sign, `0x1F`, `0b101`). A run with a dot stays a
/// number.
fn my_digit_name(run: &str) -> bool {
    let b = run.as_bytes();
    if b.contains(&b'.') || b.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let hex = b.len() > 2
        && b[0] == b'0'
        && matches!(b[1], b'x' | b'X')
        && b[2..].iter().all(u8::is_ascii_hexdigit);
    let bin = b.len() > 2
        && b[0] == b'0'
        && matches!(b[1], b'b' | b'B')
        && b[2..].iter().all(|c| matches!(c, b'0' | b'1'));
    // `1e5` (`skip_number` swallows `e+5` / `e-5` too).
    let exponent = b
        .iter()
        .position(|c| matches!(c, b'e' | b'E'))
        .is_some_and(|e| {
            e > 0
                && b[..e].iter().all(u8::is_ascii_digit)
                && b.get(e + 1..).is_some_and(|rest| {
                    let digits = rest
                        .strip_prefix(b"+")
                        .or_else(|| rest.strip_prefix(b"-"))
                        .unwrap_or(rest);
                    !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)
                })
        });
    !(hex || bin || exponent)
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
    /// Schema change: `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `COMMENT`
    /// (role and account statements aside); MySQL also server
    /// configuration changes: `INSTALL` / `UNINSTALL` and a `SET` of a
    /// global or persisted variable.
    Ddl,
    /// Privilege change: `GRANT`, `REVOKE`, and the role and account
    /// statements: `CREATE` / `ALTER` / `DROP` `ROLE` / `USER` / `GROUP`
    /// (not PostgreSQL `USER MAPPING`, a foreign-server setting); MySQL
    /// also `RENAME USER`, `SET PASSWORD` / `ROLE` / `DEFAULT ROLE`. The
    /// same class as pgaudit's `ROLE`.
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
    /// MySQL: the statement calls a schema-qualified function (`db.f(…)`),
    /// a stored function that may read or write any table. Unqualified
    /// calls are [`Self::unknown_call`].
    pub routine_call: bool,
    /// MySQL: the statement calls an unqualified name that is not a
    /// built-in function of the server ([`AnalyzeOptions::builtins`],
    /// ADR-0045 decision 9): a stored function of the default database or
    /// a loadable function, code that runs out of sight. See
    /// [`has_unknown_call`] for the positions that are not calls. The name
    /// is compared in place and never kept.
    pub unknown_call: bool,
    /// MySQL: the statement calls an audit log administration function
    /// (`audit_log_filter_set_user(…)`, `audit_log_rotate()`…), which
    /// changes or reads the audit configuration or log; its kind is DDL.
    pub audit_function: bool,
    /// MySQL: a `"…"` token in a name position (an identifier under
    /// `ANSI_QUOTES`, never resolved): the objects cannot be told.
    pub dquoted_name: bool,
    /// MySQL: the statement holds a `"…"` token anywhere (a string, or a
    /// name under `ANSI_QUOTES` in a position [`Self::dquoted_name`] does
    /// not recognize): the fail-closed backstop of the Audit connector.
    pub dquoted: bool,
    /// MySQL: run by `ANALYZE` / `EXPLAIN ANALYZE` (the statement runs).
    pub analyze_wrapped: bool,
    /// MariaDB: the first statement of a `BEGIN NOT ATOMIC … END` block.
    pub compound: bool,
    /// MySQL: holds a subquery (`(SELECT …`, `(WITH …`).
    pub subquery: bool,
    /// MySQL: calls a function (a name followed by `(`).
    pub function_call: bool,
    /// MySQL: calls `LOAD_FILE(…)`, qualified or not, plain, backquoted or
    /// double-quoted: it reads a file on the database server that no audit
    /// source names (code that runs out of sight, like a stored function).
    pub file_read: bool,
    /// MySQL: calls a function whose name (plain, backquoted or
    /// double-quoted, qualified or not) holds a non-ASCII character, out
    /// of a table name position ([`has_non_ascii_call`]). Never a built-in
    /// function (MySQL 8.4 and MariaDB 11.4 resolve `LOAD_FÍLE(…)`,
    /// `LOAD_FİLE(…)`, `ＬOAD_FILE(…)` to a stored function of the default
    /// database): a stored function, code that runs out of sight (fail
    /// closed, #184 review M2).
    pub non_ascii_call: bool,
    /// MySQL: an `EXPLAIN` / `DESCRIBE` / `DESC` whose search for the
    /// statement it explains reached [`MAX_EXPLAIN_PREFIX_TOKENS`] without
    /// finding one (not valid SQL today): what it runs cannot be told, so
    /// it is never quiet (defence in depth, #168 review L3).
    pub explain_unbounded: bool,
    /// MySQL: shows the plan of the statement another connection runs:
    /// MariaDB `SHOW EXPLAIN` / `SHOW ANALYZE` (`[FORMAT = x] FOR id`),
    /// and `EXPLAIN` / `DESCRIBE` / `DESC` with a `FOR` word before any
    /// statement (`… [FORMAT = x] FOR CONNECTION id`). MariaDB 11.4 adds
    /// that statement's whole text as a note, and its JSON plan and MySQL
    /// 8.4's `FORMAT=TREE` show its conditions with their literals: a read
    /// of another session's statement text (ADR-0045 open question 3).
    pub explain_connection: bool,
    /// [`Self::relations`] reached [`MAX_RELATIONS`]: the statement may
    /// name more relations than were kept (a caller that must see every
    /// name fails closed).
    pub relations_full: bool,
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
    lexed: bool,
    audit_function: bool,
    file_read: bool,
    non_ascii_call: bool,
    unknown_call: bool,
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
            lexed: false,
            audit_function: false,
            file_read: false,
            non_ascii_call: false,
            unknown_call: false,
        }
    }

    /// MySQL: the text calls an unqualified name that is not a built-in
    /// function ([`StatementInfo::unknown_call`]): in a statement of a
    /// lexed text, or found by a raw scan of a text that did not lex (fail
    /// closed: also inside a literal or a comment).
    #[must_use]
    pub fn unknown_call(&self) -> bool {
        self.unknown_call || self.parts.iter().any(|p| p.unknown_call)
    }

    /// MySQL: the text calls an audit log administration function: in a
    /// statement of a lexed text, or found by a raw scan of a text that
    /// did not lex (fail closed: also inside a literal or a comment).
    #[must_use]
    pub fn audit_function(&self) -> bool {
        self.audit_function || self.parts.iter().any(|p| p.audit_function)
    }

    /// MySQL: the text calls `LOAD_FILE`: in a statement of a lexed text,
    /// or found by a raw scan of a text that did not lex (fail closed: also
    /// inside a literal or a comment).
    #[must_use]
    pub fn file_read(&self) -> bool {
        self.file_read || self.parts.iter().any(|p| p.file_read)
    }

    /// MySQL: the text calls a function whose name holds a non-ASCII
    /// character ([`StatementInfo::non_ascii_call`]): in a statement of a
    /// lexed text, or found by a raw scan of a text that did not lex (fail
    /// closed: also inside a literal or a comment).
    #[must_use]
    pub fn non_ascii_call(&self) -> bool {
        self.non_ascii_call || self.parts.iter().any(|p| p.non_ascii_call)
    }

    /// Whether the text lexed unambiguously: `false` when only the kind
    /// was kept (opaque, ambiguous or unlexable text), so the parts and
    /// relations say nothing about what the statement touched.
    #[must_use]
    pub fn lexed(&self) -> bool {
        self.lexed
    }

    /// Every statement of the text, then the statements of a `DO` block
    /// body (one level, `nested`), in order. Empty when the text did not
    /// lex unambiguously.
    #[must_use]
    pub fn parts(&self) -> &[StatementInfo] {
        &self.parts
    }

    /// Kind of the first statement; for a MySQL text that did not lex
    /// unambiguously ([`Self::lexed`] is `false`), the most reportable
    /// kind of any reading ([`most_reportable`]).
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
    /// MySQL: the built-in function names of the server the text was
    /// written for ([`StatementInfo::unknown_call`]). `None`: every
    /// unqualified call is unknown (fail closed).
    pub builtins: Option<Builtins>,
    /// MySQL: the text is a `performance_schema` digest (`DIGEST_TEXT`),
    /// which spaces every token and backquotes every identifier: an
    /// unquoted name before `(` was a keyword token, read as written right
    /// before `(` ([`CallForm::Plain`]).
    pub digest: bool,
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
            builtins: None,
            digest: false,
        }
    }

    /// The built-in function names of the server (see
    /// [`AnalyzeOptions::builtins`]).
    #[must_use]
    pub fn builtins(mut self, builtins: &'static dyn BuiltinFunctions) -> Self {
        self.builtins = Some(Builtins(builtins));
        self
    }

    /// Marks the text as a `performance_schema` digest (see
    /// [`AnalyzeOptions::digest`]).
    #[must_use]
    pub fn digest(mut self, digest: bool) -> Self {
        self.digest = digest;
        self
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
    if statements.len() == 1
        && word(statements[0].first()) == Some("do")
        && let Some(body) = do_body(text)
    {
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
        lexed: true,
        audit_function: false,
        file_read: false,
        non_ascii_call: false,
        unknown_call: false,
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
            let mut a = analyze(prefix, opts.opaque(true));
            // MySQL: an audit function call anywhere in the bytes.
            if opts.dialect == Dialect::Mysql && !a.audit_function && raw_audit_function(raw) {
                a.kind = most_reportable(a.kind, StatementKind::Ddl);
                a.audit_function = true;
            }
            // MySQL: a `LOAD_FILE` call anywhere in the bytes.
            if opts.dialect == Dialect::Mysql && !a.file_read && raw_file_function(raw) {
                a.file_read = true;
            }
            // MySQL: a call of a non-ASCII name anywhere in the bytes.
            if opts.dialect == Dialect::Mysql && !a.non_ascii_call && raw_non_ascii_call(raw) {
                a.non_ascii_call = true;
            }
            // MySQL: an unknown call anywhere in the bytes.
            if opts.dialect == Dialect::Mysql && !a.unknown_call && raw_unknown_call(raw, opts) {
                a.unknown_call = true;
            }
            a
        }
    }
}

/// A MySQL text that did not lex: `kind`, made DDL when a raw scan finds
/// an audit log administration function call ([`raw_audit_function`]),
/// and marked as reading a file when one finds a `LOAD_FILE` call
/// ([`raw_file_function`]) or as calling a non-ASCII name when one finds
/// such a call ([`raw_non_ascii_call`]), or a name that is not a built-in
/// function ([`raw_unknown_call`]).
fn my_unparsed(text: &str, kind: StatementKind, opts: AnalyzeOptions) -> QueryAnalysis {
    let mut a = QueryAnalysis::unparsed(kind);
    if raw_audit_function(text.as_bytes()) {
        a.kind = most_reportable(kind, StatementKind::Ddl);
        a.audit_function = true;
    }
    a.file_read = raw_file_function(text.as_bytes());
    a.non_ascii_call = raw_non_ascii_call(text.as_bytes());
    a.unknown_call = raw_unknown_call(text.as_bytes(), opts);
    a
}

/// [`analyze`] for MySQL / MariaDB text: every `sql_mode` reading must
/// give the same tokens.
fn analyze_mysql(text: &str, opts: AnalyzeOptions) -> QueryAnalysis {
    if opts.opaque || (!opts.transcoded && multibyte_hazard(text.as_bytes())) {
        return my_unparsed(text, my_kind_prefix(text), opts);
    }
    let builtins = opts.builtins.map(|b| b.0);
    let readings: Vec<Result<MyLexed, LexError>> = my_modes(text)
        .into_iter()
        .map(|m| lex_mysql_spaced(text, m, builtins))
        .collect();
    let (tokens, flags) = match readings.first() {
        Some(Ok(t))
            if readings
                .iter()
                .all(|r| r.as_ref().is_ok_and(|o| o.toks == t.toks)) =>
        {
            // A byte between two tokens in any reading (a version comment
            // read as code or as a comment) counts.
            let mut flags = t.flags.clone();
            for r in readings.iter().flatten() {
                for (f, o) in flags.iter_mut().zip(&r.flags) {
                    f.spaced |= o.spaced;
                    f.digit_name |= o.digit_name;
                }
            }
            (t.toks.clone(), flags)
        }
        _ => {
            // Readings that differ, or a reading that does not lex: the
            // most reportable kind of any reading (fail closed: a
            // statement one reading runs is never dropped because
            // another reading skips it).
            let kind = readings.iter().fold(StatementKind::Other, |k, r| {
                most_reportable(
                    k,
                    match r {
                        Ok(t) => my_kind_all(&t.toks),
                        Err(_) => my_kind_prefix(text),
                    },
                )
            });
            return my_unparsed(text, kind, opts);
        }
    };
    // MariaDB `SET STATEMENT var = value[, …] FOR <statement>`: the
    // statement after `FOR` is what runs.
    let originals = split_statements(&tokens);
    let statements: Vec<&[Tok]> = originals
        .iter()
        .map(|s| my_set_statement_body(s).unwrap_or(s))
        .collect();
    let kind = statements
        .first()
        .map_or(StatementKind::Other, |s| my_kind(s));
    let mut relations = Vec::new();
    for s in &statements {
        collect_relations_dialect(s, Dialect::Mysql, &mut relations);
    }
    let parts: Vec<StatementInfo> = statements
        .iter()
        .zip(&originals)
        .take(MAX_PARTS)
        .map(|(s, original)| {
            let mut info = statement_info(s, opts, false);
            // Every statement is a sub-slice of `tokens`.
            let at = offset_in(&tokens, s).unwrap_or(0);
            let s_flags = flags.get(at..at + s.len()).unwrap_or(&[]);
            let o_at = offset_in(&tokens, original).unwrap_or(0);
            let o_flags = flags.get(o_at..o_at + original.len()).unwrap_or(&[]);
            // `SET STATEMENT … FOR`: the assignments too.
            info.unknown_call = has_unknown_call(s, s_flags, info.kind, opts)
                || has_unknown_call(original, o_flags, info.kind, opts);
            let wrappers = my_wrappers(original);
            // `explain_analyze` on the statement after the wrappers too:
            // `SET STATEMENT … FOR EXPLAIN … ANALYZE …` whose `ANALYZE`
            // statement is not found within the bound.
            info.analyze_wrapped = wrappers.contains(&Wrapper::Analyze)
                || explain_analyze(original)
                || explain_analyze(s);
            info.compound = wrappers.contains(&Wrapper::Compound);
            info
        })
        .collect();
    let shape = match statements.first() {
        Some(first) if !opts.possibly_truncated && kind.is_read() => main_shape(first),
        _ => None,
    };
    // `LOAD DATA` is a write but not on the DML allow-list (its text
    // names a server or client file).
    let all_dml = !statements.is_empty()
        && statements
            .iter()
            .all(|s| my_kind(s).is_dml() && word(s.first()) != Some("load"));
    let normalized = (all_dml && !opts.possibly_truncated).then(|| normalize_tokens(&tokens));
    QueryAnalysis {
        kind,
        normalized,
        relations,
        shape,
        copy: None,
        statements: statements.len(),
        parts,
        lexed: true,
        audit_function: false,
        file_read: false,
        non_ascii_call: false,
        unknown_call: false,
    }
}

/// Most nested wrapper levels unwrapped (`SET STATEMENT … FOR`,
/// `ANALYZE`, `EXPLAIN ANALYZE`, `BEGIN NOT ATOMIC`, in any combination);
/// a deeper nesting is DDL (fail closed).
const MAX_SET_STATEMENT_DEPTH: usize = 8;

/// A statement prefix that runs the statement after it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wrapper {
    /// MariaDB `SET STATEMENT var = value[, …] FOR <statement>`.
    SetStatement,
    /// `EXPLAIN | DESCRIBE | DESC ANALYZE [FORMAT = x] <statement>`
    /// (MySQL) and MariaDB `ANALYZE [FORMAT = x] <statement>`: the
    /// statement runs, writes included.
    Analyze,
    /// MariaDB `[label:] BEGIN NOT ATOMIC <statement>; … END`: a compound
    /// statement run in place, like a procedure.
    Compound,
}

/// Most tokens between `EXPLAIN` and the statement it explains.
const MAX_EXPLAIN_PREFIX_TOKENS: usize = 32;

/// Whether an `EXPLAIN` / `DESCRIBE` / `DESC` holds an `ANALYZE` word
/// before its statement (or in its first [`MAX_EXPLAIN_PREFIX_TOKENS`]
/// tokens when no statement is found there): it runs something, and is
/// never quiet (fail closed).
fn explain_analyze(s: &[Tok]) -> bool {
    if !matches!(word(s.first()), Some("explain" | "describe" | "desc")) {
        return false;
    }
    let end = (1..s.len().min(MAX_EXPLAIN_PREFIX_TOKENS))
        .find(|&j| runs_statement_at(s, j, true))
        .unwrap_or(s.len().min(MAX_EXPLAIN_PREFIX_TOKENS));
    s[1..end]
        .iter()
        .any(|t| matches!(t, Tok::Word(w) if w == "analyze"))
}

/// Whether an `EXPLAIN` / `DESCRIBE` / `DESC` has more than
/// [`MAX_EXPLAIN_PREFIX_TOKENS`] tokens and no statement keyword in its
/// first [`MAX_EXPLAIN_PREFIX_TOKENS`] (the search of [`wrapper_level`]
/// hit its bound): an `ANALYZE` past the bound, or before a statement past
/// it, would run that statement. Such texts are not valid SQL today
/// (`EXPLAIN` takes a few options, then the statement); fail closed
/// whatever words they hold (#168 review L3). Short forms without a
/// statement (`DESCRIBE t`, `EXPLAIN FOR CONNECTION 1`) stay quiet.
fn explain_unbounded(s: &[Tok]) -> bool {
    matches!(word(s.first()), Some("explain" | "describe" | "desc"))
        && s.len() > MAX_EXPLAIN_PREFIX_TOKENS
        && !(1..MAX_EXPLAIN_PREFIX_TOKENS).any(|j| runs_statement_at(s, j, true))
}

/// See [`StatementInfo::explain_connection`]. An `EXPLAIN` whose
/// statement is not found within [`MAX_EXPLAIN_PREFIX_TOKENS`] is searched
/// for `FOR` up to that bound (`explain_unbounded` covers the rest).
fn explain_connection(s: &[Tok]) -> bool {
    match (word(s.first()), word(s.get(1))) {
        (Some("show"), Some("explain" | "analyze")) => true,
        (Some("explain" | "describe" | "desc"), _) => {
            let bound = s.len().min(MAX_EXPLAIN_PREFIX_TOKENS);
            let end = (1..bound)
                .find(|&j| runs_statement_at(s, j, true))
                .unwrap_or(bound);
            s[1..end]
                .iter()
                .any(|t| matches!(t, Tok::Word(w) if w == "for"))
        }
        _ => false,
    }
}

/// Skips `FORMAT = name` at `i`.
fn skip_format(s: &[Tok], i: usize) -> usize {
    if word(s.get(i)) == Some("format") && is_punct(s.get(i + 1), "=") {
        i + 3
    } else {
        i
    }
}

/// Whether a statement that a wrapper runs starts at `i`. A word right
/// after `@` is a variable name (`INTO @select`, `@@delete`), never a
/// statement keyword (#184 review L3).
fn runs_statement_at(s: &[Tok], i: usize, table_ok: bool) -> bool {
    let variable = i.checked_sub(1).is_some_and(|j| is_punct(s.get(j), "@"));
    is_punct(s.get(i), "(")
        || (!variable
            && match word(s.get(i)) {
                Some("select" | "update" | "delete" | "insert" | "replace" | "with" | "values") => {
                    true
                }
                Some("table") => table_ok,
                _ => false,
            })
}

/// One wrapper level ([`Wrapper`]): the tokens of the statement it runs.
fn wrapper_level(s: &[Tok]) -> Option<(&[Tok], Wrapper)> {
    match (word(s.first()), word(s.get(1))) {
        (Some("set"), Some("statement")) => {
            let mut depth = 0usize;
            for (j, t) in s.iter().enumerate().skip(2) {
                match t {
                    Tok::Punct(p) if p == "(" => depth += 1,
                    Tok::Punct(p) if p == ")" => depth = depth.saturating_sub(1),
                    Tok::Word(w) if depth == 0 && w == "for" => {
                        return Some((&s[j + 1..], Wrapper::SetStatement));
                    }
                    _ => {}
                }
            }
            None
        }
        // `ANALYZE` anywhere before the statement (`EXPLAIN ANALYZE
        // FORMAT=JSON INTO @x DELETE …`, `EXPLAIN FORMAT=JSON INTO @x
        // ANALYZE …`): the statement runs.
        (Some("explain" | "describe" | "desc"), _) => {
            let start = (1..s.len().min(MAX_EXPLAIN_PREFIX_TOKENS))
                .find(|&j| runs_statement_at(s, j, true))?;
            s[1..start]
                .iter()
                .any(|t| matches!(t, Tok::Word(w) if w == "analyze"))
                .then(|| (&s[start..], Wrapper::Analyze))
        }
        // `ANALYZE [NO_WRITE_TO_BINLOG | LOCAL] TABLE …` stays a utility.
        (Some("analyze"), _) => {
            let i = skip_format(s, 1);
            runs_statement_at(s, i, false).then(|| (&s[i..], Wrapper::Analyze))
        }
        _ => {
            // `[label:] BEGIN NOT ATOMIC`.
            let i = if is_punct(s.get(1), ":") { 2 } else { 0 };
            (word(s.get(i)) == Some("begin")
                && word(s.get(i + 1)) == Some("not")
                && word(s.get(i + 2)) == Some("atomic"))
            .then(|| (&s[i + 3..], Wrapper::Compound))
        }
    }
}

/// One wrapper level's statement ([`wrapper_level`]).
fn set_statement_level(s: &[Tok]) -> Option<&[Tok]> {
    wrapper_level(s).map(|(body, _)| body)
}

/// The statement that wrappers run ([`Wrapper`]: `SET STATEMENT … FOR`,
/// `ANALYZE`, `EXPLAIN ANALYZE`, `BEGIN NOT ATOMIC`), nested levels
/// included. `None` for any other statement, and for a nesting deeper
/// than [`MAX_SET_STATEMENT_DEPTH`] levels, which [`my_kind`] reads as DDL
/// (fail closed).
fn my_set_statement_body(s: &[Tok]) -> Option<&[Tok]> {
    let mut body = set_statement_level(s)?;
    for _ in 1..MAX_SET_STATEMENT_DEPTH {
        match set_statement_level(body) {
            Some(inner) => body = inner,
            None => return Some(body),
        }
    }
    set_statement_level(body).is_none().then_some(body)
}

/// The wrappers a statement passes through before the statement it runs
/// (bounded like [`my_set_statement_body`]).
fn my_wrappers(s: &[Tok]) -> Vec<Wrapper> {
    let mut out = Vec::new();
    let mut cur = s;
    while out.len() < MAX_SET_STATEMENT_DEPTH + 1 {
        let Some((body, w)) = wrapper_level(cur) else {
            break;
        };
        out.push(w);
        cur = body;
    }
    out
}

/// Whether a statement holds a subquery: `(` followed by `SELECT` or
/// `WITH`.
fn has_subquery(s: &[Tok]) -> bool {
    s.windows(2).any(|w| {
        is_punct(Some(&w[0]), "(")
            && matches!(word(w.get(1)), Some("select" | "with" | "table" | "values"))
    })
}

/// Whether a statement calls a function: a name followed by `(`.
fn has_function_call(s: &[Tok]) -> bool {
    s.windows(2).any(|w| {
        matches!(&w[0], Tok::Word(_) | Tok::Quoted(_) | Tok::DQuoted { .. })
            && is_punct(Some(&w[1]), "(")
    })
}

/// Rank of a kind for [`most_reportable`]: DCL, DDL, writes, reads,
/// anything else.
fn report_rank(k: StatementKind) -> u8 {
    match k {
        StatementKind::Dcl => 5,
        StatementKind::Ddl => 4,
        StatementKind::Insert
        | StatementKind::Update
        | StatementKind::Delete
        | StatementKind::Merge
        | StatementKind::Copy => 3,
        StatementKind::Select
        | StatementKind::Table
        | StatementKind::Values
        | StatementKind::Handler => 2,
        StatementKind::Other => 0,
    }
}

/// The more reportable of two kinds (DCL > DDL > write > read > other).
#[must_use]
pub fn most_reportable(a: StatementKind, b: StatementKind) -> StatementKind {
    if report_rank(b) > report_rank(a) {
        b
    } else {
        a
    }
}

/// The most reportable kind of the statements of a MySQL token stream.
fn my_kind_all(tokens: &[Tok]) -> StatementKind {
    split_statements(tokens)
        .into_iter()
        .fold(StatementKind::Other, |k, s| most_reportable(k, my_kind(s)))
}

/// A schema-qualified function call, `db.f(` (names plain or quoted),
/// that is not a table with a column list: in a write, after `INTO`,
/// `INSERT` / `REPLACE` and their modifiers, or `TABLE` (`LOAD DATA …
/// INTO TABLE db.t (a)`); in DDL or DCL, after `TABLE`, `EXISTS`, `ON`,
/// `VIEW` or `REFERENCES`. Nowhere else (`JOIN db.t ON db.f()` is a call).
fn has_qualified_call(s: &[Tok], kind: StatementKind) -> bool {
    let name = |t: &Tok| matches!(t, Tok::Word(_) | Tok::Quoted(_));
    let write = matches!(
        kind,
        StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge
    );
    let schema_change = matches!(kind, StatementKind::Ddl | StatementKind::Dcl);
    s.windows(4).enumerate().any(|(i, w)| {
        let table_before = table_name_before(s, i, write, schema_change);
        name(&w[0])
            && is_punct(Some(&w[1]), ".")
            && name(&w[2])
            && is_punct(Some(&w[3]), "(")
            && !table_before
    })
}

/// Whether the (possibly qualified) name starting at `i` stands where a
/// statement of this kind names a table followed by a column list
/// (`INSERT INTO t (a)`, `CREATE TABLE t (…)`, `REFERENCES t (id)`), not
/// a function call: `write` for `INSERT` / `UPDATE` / `DELETE` /
/// `REPLACE`, `schema_change` for DDL and DCL. A modifier (`IGNORE`,
/// `LOW_PRIORITY`, `DELAYED`, `HIGH_PRIORITY`) names a table next only in
/// the write's own head: after a `SELECT` and its modifiers (`INSERT …
/// SELECT HIGH_PRIORITY f(1)`), what follows is a select list (security
/// review of #184, N1).
fn table_name_before(s: &[Tok], i: usize, write: bool, schema_change: bool) -> bool {
    match i.checked_sub(1).and_then(|j| word(s.get(j))) {
        Some("into" | "insert" | "replace") => write,
        Some("ignore" | "low_priority" | "delayed" | "high_priority") => {
            write && !after_select_modifiers(s, i - 1)
        }
        Some("table") => write || schema_change,
        Some("view" | "references") => schema_change,
        // `CREATE INDEX i [USING …] ON t (a)`: not a join's `ON f(x)` in
        // the `SELECT` of a DDL statement (security review of #188, L3).
        Some("on") => {
            let before = &s[..i - 1];
            schema_change
                && before.iter().any(|t| word(Some(t)) == Some("index"))
                && !before.iter().any(|t| word(Some(t)) == Some("select"))
        }
        // `… IF NOT EXISTS t (a)`.
        Some("exists") => {
            schema_change
                && i >= 3
                && word(s.get(i - 2)) == Some("not")
                && word(s.get(i - 3)) == Some("if")
        }
        _ => false,
    }
}

/// Whether the modifier at `m` follows a `SELECT` through select (or
/// write) modifiers only (`SELECT DISTINCT HIGH_PRIORITY`).
fn after_select_modifiers(s: &[Tok], m: usize) -> bool {
    let mut j = m;
    while let Some(k) = j.checked_sub(1) {
        match word(s.get(k)) {
            Some("select") => return true,
            Some(
                "all"
                | "distinct"
                | "distinctrow"
                | "high_priority"
                | "straight_join"
                | "sql_small_result"
                | "sql_big_result"
                | "sql_buffer_result"
                | "sql_cache"
                | "sql_no_cache"
                | "sql_calc_found_rows"
                | "ignore"
                | "low_priority"
                | "delayed",
            ) => j = k,
            _ => return false,
        }
    }
    false
}

/// A call of a function whose name holds a non-ASCII character
/// ([`StatementInfo::non_ascii_call`]): a plain or backquoted name with a
/// byte >= 0x80, or a `"…"` token holding one, followed by `(`, unless the
/// name (with its qualifier) stands where the statement names a table
/// before a column list ([`table_name_before`]), or a common table
/// expression (`WITH [RECURSIVE] x (a) AS`). Code tokens only: never in a
/// literal or a comment.
fn has_non_ascii_call(s: &[Tok], kind: StatementKind) -> bool {
    let write = matches!(
        kind,
        StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge
    );
    let schema_change = matches!(kind, StatementKind::Ddl | StatementKind::Dcl);
    let name = |t: &Tok| matches!(t, Tok::Word(_) | Tok::Quoted(_) | Tok::DQuoted { .. });
    s.windows(2).enumerate().any(|(i, w)| {
        let non_ascii = match &w[0] {
            Tok::Word(n) | Tok::Quoted(n) => !n.is_ascii(),
            Tok::DQuoted { non_ascii, .. } => *non_ascii,
            _ => false,
        };
        if !non_ascii || !is_punct(Some(&w[1]), "(") {
            return false;
        }
        // The start of a qualified name (`db.t`).
        let mut start = i;
        while start >= 2 && is_punct(s.get(start - 1), ".") && s.get(start - 2).is_some_and(name) {
            start -= 2;
        }
        let cte = matches!(
            start.checked_sub(1).and_then(|j| word(s.get(j))),
            Some("with" | "recursive")
        );
        !cte && !table_name_before(s, start, write, schema_change)
    })
}

/// Where `part`, a sub-slice of `all`, starts in it (`None` when it is
/// not one). No unsafe code: addresses are compared as numbers.
fn offset_in(all: &[Tok], part: &[Tok]) -> Option<usize> {
    let size = std::mem::size_of::<Tok>();
    let start = (part.as_ptr() as usize).checked_sub(all.as_ptr() as usize)?;
    let at = start / size;
    (start % size == 0 && at.checked_add(part.len())? <= all.len()).then_some(at)
}

/// Whether the name at `i`, followed by the parenthesized list that
/// closes at `c`, is a common table expression's name and column list:
/// `WITH [RECURSIVE] name (a) AS (`, or `, name (a) AS (` after another
/// common table expression of the same `WITH` (`name [(…)] AS (…)`,
/// walked back to the `WITH`). Anything else followed by `AS` is a call
/// (`SELECT f() AS x`; security review of #188, H1). `opened[k]`: the
/// index of the `(` that the `)` at `k` closes.
fn cte_column_list(s: &[Tok], i: usize, c: usize, opened: &[Option<usize>]) -> bool {
    if word(s.get(c + 1)) != Some("as") || !is_punct(s.get(c + 2), "(") {
        return false;
    }
    let name =
        |t: Option<&Tok>| matches!(t, Some(Tok::Word(_) | Tok::Quoted(_) | Tok::DQuoted { .. }));
    let mut at = i;
    loop {
        let Some(p) = at.checked_sub(1) else {
            return false;
        };
        if matches!(word(s.get(p)), Some("with" | "recursive")) {
            return true;
        }
        if !is_punct(s.get(p), ",") {
            return false;
        }
        // The previous common table expression: `name [(…)] AS (…)`.
        let Some(body) = p
            .checked_sub(1)
            .and_then(|k| opened.get(k).copied().flatten())
        else {
            return false;
        };
        let Some(as_at) = body
            .checked_sub(1)
            .filter(|&k| word(s.get(k)) == Some("as"))
        else {
            return false;
        };
        let mut n = match as_at.checked_sub(1) {
            Some(k) => k,
            None => return false,
        };
        if is_punct(s.get(n), ")") {
            match opened
                .get(n)
                .copied()
                .flatten()
                .and_then(|o| o.checked_sub(1))
            {
                Some(k) => n = k,
                None => return false,
            }
        }
        if !name(s.get(n)) || matches!(word(s.get(n)), Some("with" | "recursive")) {
            return false;
        }
        at = n;
    }
}

/// What opened a parenthesis, for [`has_unknown_call`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opener {
    /// `CONVERT(`: a type follows its first comma (`CONVERT(x, CHAR(4))`).
    Convert,
    /// `COLUMNS (` (`JSON_TABLE`): column definitions, a type after each
    /// column name (`c VARCHAR(10) PATH '$.c'`).
    Columns,
    /// Any other parenthesis.
    Other,
}

/// One parenthesis level of [`has_unknown_call`].
#[derive(Debug, Clone, Copy)]
struct Level {
    opener: Opener,
    /// Commas seen at this level.
    commas: usize,
    /// A `SELECT` or `DELETE` was seen at this level and no `FROM` since:
    /// the next `FROM` starts a table list.
    query: bool,
    /// In a table list (`FROM`, `JOIN`, `STRAIGHT_JOIN`, `UPDATE`).
    tables: bool,
}

/// An unqualified call of a name that is not a built-in function
/// ([`StatementInfo::unknown_call`], ADR-0045 decision 9), in any
/// position: a select list, `WHERE`, `SET`, `DO`, `VALUES`, a `CALL`
/// argument. A name (plain, backquoted, double-quoted, or a name that
/// starts with digits) followed by `(`, compared in place with
/// [`AnalyzeOptions::builtins`] in its [`CallForm`] (`flags[i]`: a byte
/// before token `i`, a literal that is a name; a digest is read as plain;
/// a name that starts with digits is never built in). Not a call:
///
/// - a qualified name (`db.f(`: [`StatementInfo::routine_call`]);
/// - a table with a column list ([`table_name_before`]: `INSERT INTO t
///   (a)`, `REFERENCES t (id)`) or a common table expression's column
///   list (`WITH x (a) AS (`, `, y (b) AS (` in the same `WITH`:
///   [`cte_column_list`]); a call followed by `AS` is a call;
/// - a name after `AS` (`CAST(x AS DECIMAL(10, 2))`, a derived table's
///   column list `AS dt (a)`), after `)` (`MATCH (a) AGAINST (`, `OVER
///   (`, `(SELECT …) dt (a)`), after a literal (`'$' COLUMNS (`, `IGNORE
///   1 LINES (a)`), after `CHARACTER SET` / `CHARSET` (`LOAD DATA`), after
///   `PROCEDURE` or `CALL` (a procedure: `CALL` is reported on its own);
///   none of these is valid SQL before a call;
/// - a type: after `RETURNING` in parentheses (`JSON_VALUE(… RETURNING
///   DECIMAL(10, 2))`), after the first comma of `CONVERT(`, after a
///   column name in `COLUMNS (…)`;
/// - `JSON_TABLE` where a table list starts (`FROM JSON_TABLE(`, `JOIN`,
///   `, JSON_TABLE(` in the list): a table function, not a stored one
///   (MariaDB resolves `JSON_TABLE(` anywhere else to a stored function).
///
/// A name that is not a call in any of these positions on the servers
/// keeps a false positive at worst (fail closed: reported).
fn has_unknown_call(
    s: &[Tok],
    flags: &[TokFlags],
    kind: StatementKind,
    opts: AnalyzeOptions,
) -> bool {
    if opts.dialect != Dialect::Mysql {
        return false;
    }
    let write = matches!(
        kind,
        StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge
    );
    let schema_change = matches!(kind, StatementKind::Ddl | StatementKind::Dcl);
    let builtin =
        |name: &[u8], form: CallForm| opts.builtins.is_some_and(|b| b.0.is_builtin(name, form));
    // The index of the `)` closing the `(` at each index, for the common
    // table expression check (one pass).
    let mut close: Vec<Option<usize>> = vec![None; s.len()];
    let mut opened: Vec<Option<usize>> = vec![None; s.len()];
    let mut open: Vec<usize> = Vec::new();
    for (i, t) in s.iter().enumerate() {
        if is_punct(Some(t), "(") {
            open.push(i);
        } else if is_punct(Some(t), ")")
            && let Some(o) = open.pop()
        {
            close[o] = Some(i);
            opened[i] = Some(o);
        }
    }
    let top = Level {
        opener: Opener::Other,
        commas: 0,
        query: false,
        tables: false,
    };
    let mut levels: Vec<Level> = vec![top];
    for (i, t) in s.iter().enumerate() {
        let prev = i.checked_sub(1).and_then(|j| s.get(j));
        let level = levels.last().copied().unwrap_or(top);
        if is_punct(s.get(i + 1), "(") {
            let call = match t {
                Tok::Word(w) => {
                    let form = if !opts.digest && flags.get(i + 1).is_none_or(|f| f.spaced) {
                        CallForm::Spaced
                    } else {
                        CallForm::Plain
                    };
                    // `JSON_TABLE` where a table list starts.
                    let table_start = (matches!(word(prev), Some("join" | "straight_join"))
                        || (word(prev) == Some("from") && level.tables)
                        || (level.tables && is_punct(prev, ",")))
                        && w == "json_table";
                    (!table_start).then(|| !builtin(w.as_bytes(), form))
                }
                Tok::Quoted(n) => Some(!builtin(n.as_bytes(), CallForm::Quoted)),
                Tok::DQuoted { builtin, .. } => Some(!builtin),
                Tok::Literal if flags.get(i).is_some_and(|f| f.digit_name) => Some(true),
                _ => None,
            };
            if call == Some(true) {
                let after = |w: &[&str]| word(prev).is_some_and(|p| w.contains(&p));
                let not_a_call = is_punct(prev, ".")
                    || is_punct(prev, ")")
                    || matches!(
                        prev,
                        Some(Tok::Literal | Tok::Int(_) | Tok::Param | Tok::DQuoted { .. })
                    )
                    || after(&["as", "procedure", "call", "charset"])
                    || (after(&["set"])
                        && matches!(
                            i.checked_sub(2).and_then(|j| word(s.get(j))),
                            Some("character" | "char")
                        ))
                    || (after(&["returning"]) && levels.len() > 1)
                    || (level.opener == Opener::Convert && level.commas > 0 && is_punct(prev, ","))
                    || (level.opener == Opener::Columns
                        && matches!(prev, Some(Tok::Word(_) | Tok::Quoted(_))))
                    || table_name_before(s, i, write, schema_change)
                    || close[i + 1].is_some_and(|c| cte_column_list(s, i, c, &opened));
                if !not_a_call {
                    return true;
                }
            }
        }
        match t {
            Tok::Punct(p) if p == "(" => {
                let opener = match word(prev) {
                    Some("convert") => Opener::Convert,
                    Some("columns") => Opener::Columns,
                    _ => Opener::Other,
                };
                if levels.len() < MAX_DEPTH {
                    levels.push(Level {
                        opener,
                        commas: 0,
                        query: false,
                        tables: level.tables,
                    });
                }
            }
            Tok::Punct(p) if p == ")" => {
                if levels.len() > 1 {
                    levels.pop();
                }
            }
            Tok::Punct(p) if p == "," => {
                if let Some(l) = levels.last_mut() {
                    l.commas += 1;
                }
            }
            Tok::Word(w) => {
                if let Some(l) = levels.last_mut() {
                    match w.as_str() {
                        "select" | "delete" => {
                            l.query = true;
                            l.tables = false;
                        }
                        "from" => {
                            l.tables = l.query;
                            l.query = false;
                        }
                        "join" | "straight_join" | "update" => l.tables = true,
                        "where" | "group" | "having" | "order" | "limit" | "union" | "set"
                        | "values" | "value" | "on" | "using" | "for" | "window" | "lock"
                        | "procedure" | "into" | "except" | "intersect" => l.tables = false,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Raw-text scan for an unknown call ([`StatementInfo::unknown_call`]),
/// for a text that did not lex, with the rules of [`raw_audit_function`]
/// (fail closed: inside a literal or a comment too, and no position is
/// told apart but a qualified name): an identifier run (not only digits,
/// not after `.`) followed by `(` as described there, that
/// [`AnalyzeOptions::builtins`] does not accept in its form (quoted when a
/// backtick or a double quote stands right before it, plain when `(`
/// follows right after it, spaced otherwise). Compared in place.
fn raw_unknown_call(b: &[u8], opts: AnalyzeOptions) -> bool {
    let n = b.len();
    let mut i = 0;
    while i < n {
        if !is_my_ident_cont(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_my_ident_cont(b[i]) {
            i += 1;
        }
        let name = &b[start..i];
        if name.iter().all(u8::is_ascii_digit) {
            continue;
        }
        let before = start.checked_sub(1).map(|j| b[j]);
        if before == Some(b'.') || !raw_call_follows(b, i) {
            continue;
        }
        let form = if matches!(before, Some(b'`' | b'"')) {
            CallForm::Quoted
        } else if b.get(i) == Some(&b'(') {
            CallForm::Plain
        } else {
            CallForm::Spaced
        };
        if !opts.builtins.is_some_and(|f| f.0.is_builtin(name, form)) {
            return true;
        }
    }
    false
}

/// A server-side `LOAD DATA INFILE` / `LOAD XML INFILE` (no `LOCAL`), at
/// the start of the statement or after `SET STATEMENT … FOR`: it reads a
/// file on the database server (with the `FILE` privilege), which no
/// audit source names; the table it loads is named as a write (#184
/// review L2). `LOCAL` reads a file of the client host.
fn server_file_load(s: &[Tok]) -> bool {
    (0..s.len()).any(|k| {
        word(s.get(k)) == Some("load")
            && matches!(word(s.get(k + 1)), Some("data" | "xml"))
            && (k == 0 || word(s.get(k - 1)) == Some("for"))
            && s[k + 2..]
                .iter()
                .map(|t| word(Some(t)))
                .take_while(|w| *w != Some("infile"))
                .all(|w| w != Some("local"))
    })
}

/// Whether a function name is one of the audit log administration
/// functions of MySQL Enterprise Audit and the Percona `audit_log_filter`
/// component (same names): `audit_log_filter_*`, `audit_log_encryption_*`,
/// `audit_log_read`, `audit_log_read_bookmark`, `audit_log_rotate`.
/// MariaDB `server_audit` and the Percona `audit_log` plugin have no
/// functions (system variables only).
fn is_audit_function(name: &[u8]) -> bool {
    // Compared in place, on bytes (no copy: `name` may be literal
    // content, and only ASCII names match).
    let starts = |p: &[u8]| name.len() > p.len() && name[..p.len()].eq_ignore_ascii_case(p);
    starts(b"audit_log_filter_")
        || starts(b"audit_log_encryption_")
        || [
            b"audit_log_read".as_slice(),
            b"audit_log_read_bookmark",
            b"audit_log_rotate",
        ]
        .iter()
        .any(|n| name.eq_ignore_ascii_case(n))
}

/// A call of an audit log administration function ([`is_audit_function`]),
/// qualified or not: its name (plain or quoted) followed by `(`. Code
/// tokens only: never in a literal or a comment.
fn has_audit_function(s: &[Tok]) -> bool {
    s.windows(2).any(|w| {
        (matches!(&w[0], Tok::Word(n) | Tok::Quoted(n) if is_audit_function(n.as_bytes()))
            || matches!(
                w[0],
                Tok::DQuoted {
                    audit_function: true,
                    ..
                }
            ))
            && is_punct(Some(&w[1]), "(")
    })
}

/// Whether a function name is `LOAD_FILE` (ASCII case-insensitive): it
/// reads a file on the database server (with the `FILE` privilege and a
/// permissive `secure_file_priv`), table files included, and no audit
/// source records which file.
fn is_file_function(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"load_file")
}

/// A call of `LOAD_FILE` ([`is_file_function`]), qualified or not: its
/// name (plain, backquoted or double-quoted) followed by `(`. Code tokens
/// only (executable comments are code), never in a literal or a comment;
/// a text that does not lex is scanned raw ([`raw_file_function`]).
fn has_file_function(s: &[Tok]) -> bool {
    s.windows(2).any(|w| {
        (matches!(&w[0], Tok::Word(n) | Tok::Quoted(n) if is_file_function(n.as_bytes()))
            || matches!(
                w[0],
                Tok::DQuoted {
                    file_function: true,
                    ..
                }
            ))
            && is_punct(Some(&w[1]), "(")
    })
}

/// Raw-text scan for a call of an audit log administration function, for
/// a text that did not lex (fail closed: a name inside a literal or a
/// comment counts too, and nothing is required before the name, so
/// `/*!80000audit_log_rotate*/()` matches): a function name
/// ([`is_audit_function`], ASCII case-insensitive, the whole identifier
/// run that starts there), optionally followed by a closing quote or
/// backtick, then whitespace, comments, ends of comments (`*/`) and
/// executable comment openers (`/*!NNNNN`, `/*M!NNNNN`), then `(`.
/// Compared in place: no copy of the text is made.
fn raw_audit_function(b: &[u8]) -> bool {
    raw_call(b, b"audit_log_", is_audit_function)
}

/// Raw-text scan for a call of `LOAD_FILE` ([`is_file_function`]), for a
/// text that did not lex, with the rules of [`raw_audit_function`] (fail
/// closed: inside a literal or a comment too, no boundary before the
/// name, so `/*!80000LOAD_FILE*/(` and `x_load_file(` match).
fn raw_file_function(b: &[u8]) -> bool {
    raw_call(b, b"load_file", is_file_function)
}

/// Raw-text scan for a call of a name holding a non-ASCII character
/// ([`StatementInfo::non_ascii_call`]), for a text that did not lex, with
/// the rules of [`raw_audit_function`] (fail closed: inside a literal or a
/// comment too, and no table name position is told apart): an identifier
/// run holding a byte >= 0x80, then `(` as described there.
fn raw_non_ascii_call(b: &[u8]) -> bool {
    let n = b.len();
    let mut i = 0;
    while i < n {
        if !is_my_ident_cont(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_my_ident_cont(b[i]) {
            i += 1;
        }
        if !b[start..i].is_ascii() && raw_call_follows(b, i) {
            return true;
        }
    }
    false
}

/// The raw scan of [`raw_audit_function`] and [`raw_file_function`]: an
/// identifier run that starts with `head` (ASCII case-insensitive) and
/// that `is_name` accepts, then `(` as described there.
fn raw_call(b: &[u8], head: &[u8], is_name: fn(&[u8]) -> bool) -> bool {
    let n = b.len();
    for start in 0..n.saturating_sub(head.len() - 1) {
        if !b[start..start + head.len()].eq_ignore_ascii_case(head) {
            continue;
        }
        let mut j = start;
        while j < n && is_my_ident_cont(b[j]) {
            j += 1;
        }
        if is_name(&b[start..j]) && raw_call_follows(b, j) {
            return true;
        }
    }
    false
}

/// Whether, after a name ending at `j`, a raw text holds a call: an
/// optional closing quote or backtick, then whitespace (the lexer's set,
/// `0x0b` and `0x0c` included), comments, ends of comments (`*/`) and
/// executable comment openers (`/*!NNNNN`, `/*M!NNNNN`), then `(`. An
/// executable comment is read both ways, as code (a server at or above
/// its version) and skipped whole (below it, or the other flavor), and
/// either reaching `(` is a call (`f/*!99999 abs*/()` runs `f()` on a
/// server below 9.99.99; security review of #188, L2).
fn raw_call_follows(b: &[u8], mut j: usize) -> bool {
    if matches!(b.get(j), Some(b'"' | b'`')) {
        j += 1;
    }
    raw_call_follows_from(b, j, 8)
}

/// [`raw_call_follows`] after the optional closing quote; `depth` bounds
/// the readings of nested executable comment openers.
fn raw_call_follows_from(b: &[u8], mut j: usize, depth: u8) -> bool {
    let n = b.len();
    loop {
        match b.get(j) {
            Some(b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) => j += 1,
            Some(b'*') if b.get(j + 1) == Some(&b'/') => j += 2,
            Some(b'/') if b.get(j + 1) == Some(&b'*') => {
                let bang = match (b.get(j + 2), b.get(j + 3)) {
                    (Some(b'!'), _) => Some(j + 3),
                    (Some(b'M' | b'm'), Some(b'!')) => Some(j + 4),
                    _ => None,
                };
                if let Some(mut k) = bang {
                    // Skipped whole: what follows its end.
                    if depth > 0
                        && let Some(e) = find(&b[j + 2..], b"*/")
                        && raw_call_follows_from(b, j + 2 + e + 2, depth - 1)
                    {
                        return true;
                    }
                    while k < n && b[k].is_ascii_digit() {
                        k += 1;
                    }
                    j = k;
                } else {
                    match find(&b[j + 2..], b"*/") {
                        Some(e) => j += e + 4,
                        None => break,
                    }
                }
            }
            Some(b'#') => {
                while j < n && b[j] != b'\n' {
                    j += 1;
                }
            }
            Some(b'-') if my_dash_comment(b, j, n) => {
                while j < n && b[j] != b'\n' {
                    j += 1;
                }
            }
            _ => break,
        }
    }
    b.get(j) == Some(&b'(')
}

/// A `"…"` token ([`Tok::DQuoted`]) in a name position, where it can only
/// be an identifier under `ANSI_QUOTES` (as a string it would be a syntax
/// error): after `FROM`, `JOIN`, `STRAIGHT_JOIN`, `UPDATE`, `INTO`,
/// `TABLE` or `HANDLER`; after a comma in a table list (`FROM`, `JOIN`,
/// `UPDATE` context, tracked per parenthesis depth, so `FROM (SELECT 1)
/// x, "t"` and `USE INDEX (i), "t"` count); alone between parentheses in
/// such a context (`FROM ("t")`); next to a `.`; or right before `(`.
fn has_dquoted_name(s: &[Tok]) -> bool {
    // The table-list context of each open parenthesis level; a new level
    // starts with its parent's context (`FROM ((t))`).
    let mut ctx: Vec<bool> = vec![false];
    for (i, t) in s.iter().enumerate() {
        let prev = i.checked_sub(1).and_then(|j| s.get(j));
        let next = s.get(i + 1);
        let in_list = ctx.last().copied().unwrap_or(false);
        match t {
            Tok::DQuoted { .. } => {
                let after_keyword = matches!(
                    word(prev),
                    Some(
                        "from" | "join" | "straight_join" | "update" | "into" | "table" | "handler"
                    )
                );
                let listed = in_list && is_punct(prev, ",");
                let parenthesized = in_list && is_punct(prev, "(") && is_punct(next, ")");
                let dotted = is_punct(prev, ".") || is_punct(next, ".");
                let called = is_punct(next, "(");
                if after_keyword || listed || parenthesized || dotted || called {
                    return true;
                }
            }
            Tok::Word(w) => {
                let set = match w.as_str() {
                    "from" | "join" | "straight_join" | "update" | "handler" => Some(true),
                    "where" | "group" | "having" | "order" | "limit" | "union" | "set"
                    | "values" | "value" | "select" | "on" | "using" | "for" | "window"
                    | "lock" | "procedure" | "into" => Some(false),
                    _ => None,
                };
                if let (Some(v), Some(c)) = (set, ctx.last_mut()) {
                    *c = v;
                }
            }
            Tok::Punct(p) if p == "(" => {
                if ctx.len() < MAX_DEPTH {
                    ctx.push(in_list);
                }
            }
            Tok::Punct(p) if p == ")" => {
                if ctx.len() > 1 {
                    ctx.pop();
                }
            }
            Tok::Punct(p) if p == ";" => ctx = vec![false],
            _ => {}
        }
    }
    false
}

/// A MySQL `SET` that assigns a global or persisted system variable in
/// any of its assignments: `SET GLOBAL x = …`, `SET PERSIST` /
/// `PERSIST_ONLY`, `SET @@global.x = …` (also after a comma: `SET
/// autocommit = 1, GLOBAL x = …`). Reading `@@global.x` on the right of
/// `=` is not an assignment.
fn my_sets_global(s: &[Tok]) -> bool {
    if word(s.first()) != Some("set") {
        return false;
    }
    let scope = |t: Option<&Tok>| matches!(word(t), Some("global" | "persist" | "persist_only"));
    let mut depth = 0usize;
    for (j, t) in s.iter().enumerate() {
        match t {
            Tok::Punct(p) if p == "(" => depth += 1,
            Tok::Punct(p) if p == ")" => depth = depth.saturating_sub(1),
            _ if depth == 0 && (j == 0 || is_punct(Some(t), ",")) => {
                let next = s.get(j + 1);
                // `@@` lexes as two `@` punctuation tokens.
                let at_at = is_punct(next, "@") && is_punct(s.get(j + 2), "@");
                if scope(next) || (at_at && scope(s.get(j + 3))) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Statement kind of a MySQL statement: [`first_kind`], plus `REPLACE`
/// (a write), `HANDLER`, account / role statements as DCL, and server
/// configuration changes as DDL: `INSTALL` / `UNINSTALL` (plugins,
/// libraries, components) and a `SET` of a global or persisted variable
/// ([`my_sets_global`]). A MariaDB `SET STATEMENT … FOR <statement>` has
/// the kind of its statement.
fn my_kind(s: &[Tok]) -> StatementKind {
    let s = my_set_statement_body(s).unwrap_or(s);
    if set_statement_level(s).is_some() || has_audit_function(s) {
        // A `SET STATEMENT` nested deeper than MAX_SET_STATEMENT_DEPTH, or
        // a call of an audit log administration function.
        return StatementKind::Ddl;
    }
    let Some(i) = main_start(s) else {
        return StatementKind::Other;
    };
    let second = word(s.get(i + 1));
    match word(s.get(i)) {
        Some("replace") => StatementKind::Insert,
        // `LOAD DATA` / `LOAD XML … INTO TABLE t`: rows written to `t`.
        Some("load") if matches!(second, Some("data" | "xml")) => StatementKind::Insert,
        Some("handler") => StatementKind::Handler,
        Some("install" | "uninstall") => StatementKind::Ddl,
        Some("set") if my_sets_global(&s[i..]) => StatementKind::Ddl,
        // Digest text writes `USER` as `SYSTEM_USER` (MySQL).
        Some("create" | "alter" | "drop" | "rename")
            if matches!(second, Some("user" | "role" | "system_user")) =>
        {
            StatementKind::Dcl
        }
        Some("set") if matches!(second, Some("password" | "role" | "default")) => {
            StatementKind::Dcl
        }
        // `RENAME TABLE` (account renames are DCL, above).
        Some("rename") => StatementKind::Ddl,
        _ => first_kind(s),
    }
}

/// Longest prefix [`my_kind_prefix`] reads.
const MAX_KIND_PREFIX_BYTES: usize = 4096;

/// The code of a MySQL text up to its first quote (a literal or a quoted
/// name, whose end cannot be trusted in a text that did not lex), with
/// comments removed. Executable comments (`/*!…*/`, `/*M!…*/`) are kept
/// as code when `versioned_as_code`, removed otherwise. Also returns
/// whether the text was cut before its end.
fn my_prefix_code(text: &str, versioned_as_code: bool) -> (Zeroizing<String>, bool) {
    let b = text.as_bytes();
    let mut n = b.len().min(MAX_KIND_PREFIX_BYTES);
    while n > 0 && !text.is_char_boundary(n) {
        n -= 1;
    }
    // Zeroized: it may hold code before a password literal's cut.
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut in_versioned = false;
    let mut i = 0;
    while i < n {
        let c = b[i];
        let next = b.get(i + 1).copied();
        match c {
            b'\'' | b'"' | b'`' => return (prefix_string(out), true),
            b'#' => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
                out.push(b' ');
            }
            b'-' if my_dash_comment(b, i, b.len()) => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
                out.push(b' ');
            }
            b'*' if in_versioned && next == Some(b'/') => {
                in_versioned = false;
                i += 2;
                out.push(b' ');
            }
            b'/' if next == Some(b'*') => {
                let bang = match (b.get(i + 2), b.get(i + 3)) {
                    (Some(b'!'), _) => Some(i + 3),
                    (Some(b'M'), Some(b'!')) => Some(i + 4),
                    _ => None,
                };
                match bang {
                    Some(mut j) if versioned_as_code && !in_versioned => {
                        let from = j;
                        while j < n
                            && b[j].is_ascii_digit()
                            && j - from < MAX_COMMENT_VERSION_DIGITS
                        {
                            j += 1;
                        }
                        in_versioned = true;
                        i = j;
                    }
                    _ => match find(&b[i + 2..n], b"*/") {
                        Some(k) => i += k + 4,
                        None => return (prefix_string(out), true),
                    },
                }
                out.push(b' ');
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    (prefix_string(out), n < b.len())
}

/// The bytes of [`my_prefix_code`] as a string, moved (not copied). They
/// are whole characters of a `&str` (cut at ASCII bytes or a character
/// boundary), so always UTF-8; anything else gives an empty string.
fn prefix_string(mut out: Zeroizing<Vec<u8>>) -> Zeroizing<String> {
    Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *out)).unwrap_or_else(|e| {
            drop(Zeroizing::new(e.into_bytes()));
            String::new()
        }),
    )
}

/// Kind of a MySQL text that did not lex (or is opaque): its code up to
/// the first quote, comments skipped, under both readings of executable
/// comments, the most reportable. A `SET` (after `SET STATEMENT … FOR`)
/// whose text is cut there is DDL: what it assigns cannot be told, and it
/// may set a global variable (fail closed).
fn my_kind_prefix(text: &str) -> StatementKind {
    let mode = MyMode {
        backslash: true,
        ansi_quotes: false,
        version_as_comment: true,
    };
    [true, false]
        .into_iter()
        .fold(StatementKind::Other, |k, versioned| {
            let (code, cut) = my_prefix_code(text, versioned);
            let Ok(tokens) = lex_mysql(&code, mode) else {
                return k;
            };
            let mut kind = my_kind_all(&tokens);
            if cut {
                let last = split_statements(&tokens).last().copied().unwrap_or(&[]);
                let body = my_set_statement_body(last).unwrap_or(last);
                if word(body.first()) == Some("set") {
                    kind = most_reportable(kind, StatementKind::Ddl);
                }
            }
            most_reportable(k, kind)
        })
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
            && matches!(w[2], Tok::Literal | Tok::DQuoted { .. } | Tok::Param)
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
    let relations_full = relations.len() >= MAX_RELATIONS;
    StatementInfo {
        kind,
        relations,
        relations_full,
        shape,
        copy,
        nested,
        outfile: opts.dialect == Dialect::Mysql && has_outfile(s),
        lead: lead_words(s),
        routine_call: opts.dialect == Dialect::Mysql && has_qualified_call(s, kind),
        // Set by `analyze_mysql`, which has the spacing of the tokens.
        unknown_call: false,
        audit_function: opts.dialect == Dialect::Mysql && has_audit_function(s),
        dquoted_name: opts.dialect == Dialect::Mysql && has_dquoted_name(s),
        dquoted: s.iter().any(|t| matches!(t, Tok::DQuoted { .. })),
        analyze_wrapped: false,
        compound: false,
        subquery: opts.dialect == Dialect::Mysql && has_subquery(s),
        function_call: opts.dialect == Dialect::Mysql && has_function_call(s),
        file_read: opts.dialect == Dialect::Mysql && (has_file_function(s) || server_file_load(s)),
        non_ascii_call: opts.dialect == Dialect::Mysql && has_non_ascii_call(s, kind),
        explain_unbounded: opts.dialect == Dialect::Mysql && explain_unbounded(s),
        explain_connection: opts.dialect == Dialect::Mysql && explain_connection(s),
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
        // Role and account statements are privilege changes (pgaudit's
        // `ROLE` class), `CREATE USER MAPPING` is not.
        Some("create" | "alter" | "drop")
            if matches!(word(s.get(i + 1)), Some("role" | "user" | "group"))
                && !(word(s.get(i + 1)) == Some("user")
                    && word(s.get(i + 2)) == Some("mapping")) =>
        {
            StatementKind::Dcl
        }
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
        // `INSERT` / `REPLACE` without `INTO`: `INSERT [LOW_PRIORITY |
        // DELAYED | HIGH_PRIORITY] [IGNORE] t …`.
        ["insert" | "replace", ..] => {
            let mut i = start + 1;
            while matches!(
                word(s.get(i)),
                Some("low_priority" | "delayed" | "high_priority" | "ignore")
            ) {
                i += 1;
            }
            if word(s.get(i)) != Some("into") {
                read_relation(s, i, &none, true, out);
            }
        }
        // `LOAD DATA | XML … INTO TABLE t`.
        ["load", "data" | "xml", ..] => {
            if let Some(i) = s
                .windows(2)
                .position(|w| word(w.first()) == Some("into") && word(w.get(1)) == Some("table"))
            {
                read_relation(s, i + 2, &none, true, out);
            }
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
        // Inside a function call's parentheses (`EXTRACT(YEAR FROM d)`),
        // unless a subquery opens there again: `CONCAT((SELECT … FROM t))`
        // and `DO (SELECT … FROM t)` name `t`.
        let in_call = frames.last().is_some_and(|f| f.call);
        match &s[i] {
            Tok::Punct(p) if p == "(" => {
                let subquery = matches!(word(s.get(i + 1)), Some("select" | "with"));
                let call = !subquery
                    && (in_call
                        || match i.checked_sub(1).and_then(|j| s.get(j)) {
                            Some(Tok::Word(w)) => !opens_query(w),
                            Some(Tok::Quoted(_)) => true,
                            _ => false,
                        });
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
                    // A table list (`UPDATE a x, b y SET …`, MySQL).
                    "update" => {
                        let real = !matches!(prev_word(i), Some("for" | "do" | "key" | "no"));
                        (real, false, real)
                    }
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
                ) && let Some(f) = frames.last_mut()
                {
                    f.in_from = false;
                }
                if from_list && let Some(f) = frames.last_mut() {
                    f.in_from = true;
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
    // MySQL `UPDATE [LOW_PRIORITY] [IGNORE] t …`: modifiers, not names.
    if word(i.checked_sub(1).and_then(|j| s.get(j))) == Some("update") {
        while matches!(word(s.get(i)), Some("low_priority" | "ignore")) {
            i += 1;
        }
    }
    // MySQL `INTO OUTFILE '…'` / `INTO DUMPFILE '…'`: a file, not a relation.
    if matches!(word(s.get(i)), Some("outfile" | "dumpfile"))
        && matches!(
            s.get(i + 1),
            Some(Tok::Literal | Tok::DQuoted { .. } | Tok::Param)
        )
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
            Tok::Literal | Tok::DQuoted { .. } | Tok::Int(_) | Tok::Param => "?".to_owned(),
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

    /// Server configuration changes (they can turn the Audit sources off)
    /// are DDL, also from a text that does not lex; session settings stay
    /// `Other`. A MariaDB `SET STATEMENT … FOR` has its statement's kind,
    /// relations and shape.
    #[test]
    fn mysql_server_configuration_and_set_statement() {
        for q in [
            "SET GLOBAL server_audit_logging = OFF",
            "set global server_audit_events = ''",
            "SET @@global.server_audit_logging = 0",
            "SET @@GLOBAL.audit_log_disable = ON",
            "SET autocommit = 1, GLOBAL server_audit_logging = OFF",
            "SET PERSIST audit_log_disable = ON",
            "SET PERSIST_ONLY performance_schema = OFF",
            "SET @@persist.audit_log_flush = ON",
            "SET GLOBAL `server_audit_logging` = ?",
            "SET GLOBAL TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            "SET GLOBAL server_audit_excl_users = 'x\\'",
            "UNINSTALL PLUGIN server_audit",
            "UNINSTALL SONAME 'server_audit'",
            "UNINSTALL COMPONENT 'file://component_audit_log_filter'",
            "INSTALL PLUGIN server_audit SONAME 'server_audit'",
            "INSTALL COMPONENT 'file://component_audit_log_filter'",
            "TRUNCATE performance_schema.events_statements_history_long",
        ] {
            assert_eq!(my(q).kind(), StatementKind::Ddl, "{q}");
            assert!(my_norm(q).is_none(), "{q}");
        }
        for q in [
            "SET SESSION sql_mode = 'ANSI_QUOTES'",
            "SET autocommit = 1",
            "SET @x = @@global.server_audit_logging",
            "SET @@session.sql_log_off = 1",
            "SET sql_mode = CONCAT(@@global.sql_mode, ',x')",
            "SET NAMES utf8mb4",
            "SET STATEMENT max_statement_time = 1 FOR SHOW TABLES",
        ] {
            assert_eq!(my(q).kind(), StatementKind::Other, "{q}");
        }
        let a = my(
            "SET STATEMENT max_statement_time = 1.5, sql_mode = 'x' FOR \
             UPDATE performance_schema.setup_consumers SET enabled = 'NO'",
        );
        assert_eq!(a.kind(), StatementKind::Update);
        assert_eq!(
            a.relations()
                .iter()
                .map(|r| (r.schema.clone(), r.name.clone()))
                .collect::<Vec<_>>(),
            vec![r(Some("performance_schema"), "setup_consumers")]
        );
        let a = my("SET STATEMENT max_statement_time = 1 FOR SELECT * FROM hr.t");
        assert_eq!(a.kind(), StatementKind::Select);
        assert!(a.shape().is_some_and(|s| s.whole_relation(10_001)));
        assert_eq!(a.parts()[0].lead, ["select"]);
    }

    /// Security review of #168: texts whose readings differ or that do not
    /// lex keep the most reportable kind of any reading; nested `SET
    /// STATEMENT`, `LOAD DATA`, `RENAME TABLE`, `INSERT` without `INTO`,
    /// schema-qualified function calls.
    #[test]
    fn mysql_fail_closed_kinds_and_hidden_changes() {
        let raw = |q: &str| analyze_raw(q.as_bytes(), AnalyzeOptions::mysql());
        for (q, k) in [
            ("SET /*M! GLOBAL */ x = 'm'", StatementKind::Ddl),
            ("/*!80000 SET GLOBAL x = 'm' */", StatementKind::Ddl),
            ("SET /**/ GLOBAL x = 'x\u{e9}\\'", StatementKind::Ddl),
            ("SET -- c\n GLOBAL x = 'x\u{e9}\\'", StatementKind::Ddl),
            ("SET # c\n GLOBAL x = 'x\u{e9}\\'", StatementKind::Ddl),
            (
                "SET STATEMENT m='' FOR SET GLOBAL x = LEFT('\u{e9}\\', 0)",
                StatementKind::Ddl,
            ),
            ("SET @x = 'x\u{e9}\\'", StatementKind::Ddl),
            (
                "SET STATEMENT m=1 /*M! FOR UPDATE t SET a = 'b' */",
                StatementKind::Update,
            ),
            ("/*M! SELECT * FROM hr.c */", StatementKind::Select),
            ("/*!80000 SELECT * FROM hr.c */", StatementKind::Select),
            ("/*!80000 GRANT ALL ON *.* TO u */", StatementKind::Dcl),
            ("SELECT 'x\u{e9}\\' FROM t", StatementKind::Select),
        ] {
            let a = raw(q);
            assert_eq!(a.kind(), k, "{q}");
            assert!(!a.lexed(), "{q}");
        }
        let lexed = my("SELECT a FROM t");
        assert!(lexed.lexed());
        assert_eq!(
            most_reportable(StatementKind::Select, StatementKind::Dcl),
            StatementKind::Dcl
        );
        assert_eq!(
            most_reportable(StatementKind::Update, StatementKind::Other),
            StatementKind::Update
        );
        let nested = |n: usize| {
            format!(
                "{}UPDATE performance_schema.setup_consumers SET enabled = 'NO'",
                "SET STATEMENT a = 1 FOR ".repeat(n)
            )
        };
        for n in 1..=MAX_SET_STATEMENT_DEPTH {
            let a = my(&nested(n));
            assert_eq!(a.kind(), StatementKind::Update, "{n}");
            assert_eq!(
                a.parts()[0].relations,
                vec![RelationName {
                    schema: Some("performance_schema".into()),
                    name: "setup_consumers".into()
                }],
                "{n}"
            );
        }
        assert_eq!(
            my(&nested(MAX_SET_STATEMENT_DEPTH + 1)).kind(),
            StatementKind::Ddl
        );
        assert_eq!(
            my("LOAD DATA INFILE '/x' INTO TABLE hr.t").kind(),
            StatementKind::Insert
        );
        assert!(my_norm("LOAD DATA INFILE '/x' INTO TABLE hr.t").is_none());
        assert_eq!(
            my_rels("LOAD XML LOCAL INFILE '/x' IGNORE INTO TABLE `hr`.`t` (a)"),
            vec![r(Some("hr"), "t")]
        );
        assert_eq!(
            my_rels("INSERT LOW_PRIORITY IGNORE hr.t (a) VALUES (1)"),
            vec![r(Some("hr"), "t")]
        );
        assert_eq!(my_rels("REPLACE hr.t SET a = 1"), vec![r(Some("hr"), "t")]);
        assert_eq!(my("RENAME TABLE a TO b").kind(), StatementKind::Ddl);
        assert_eq!(my("RENAME USER a TO b").kind(), StatementKind::Dcl);
        let call = |q: &str| my(q).parts().iter().any(|p| p.routine_call);
        for q in [
            "SELECT hr.f(1)",
            "DO `hr`.`f`()",
            "SET @x = hr . f ()",
            "SELECT a FROM t WHERE b = hr.f(a)",
            "INSERT INTO t VALUES (hr.f(1))",
        ] {
            assert!(call(q), "{q}");
        }
        for q in [
            "INSERT INTO hr.t (a) VALUES (1)",
            "INSERT hr.t (a) VALUES (1)",
            "REPLACE INTO hr.t (a) VALUES (1)",
            "INSERT IGNORE hr.t (a) VALUES (1)",
            "CREATE TABLE hr.t (a int)",
            "CREATE TABLE IF NOT EXISTS hr.t (a int)",
            "CREATE INDEX i ON hr.t (a)",
            "SELECT COUNT(*), t.a FROM hr.t",
            "LOAD DATA INFILE '/x' INTO TABLE hr.t (a)",
        ] {
            assert!(!call(q), "{q}");
        }
    }

    /// Re-review of #168, N2 / N3: audit administration functions are DDL,
    /// qualified or not, in any statement, never from a literal or a
    /// comment; table column lists are excluded from qualified calls only
    /// in the statements that have them.
    #[test]
    fn mysql_audit_functions_and_call_contexts() {
        for q in [
            "SELECT audit_log_filter_set_filter('log_none', '{\"filter\": {\"log\": false}}')",
            "SELECT audit_log_filter_set_user('%', 'log_none')",
            "SELECT AUDIT_LOG_FILTER_REMOVE_USER('%')",
            "SELECT audit_log_filter_remove_filter('log_all')",
            "SELECT audit_log_filter_flush()",
            "SELECT audit_log_read()",
            "SELECT audit_log_read(audit_log_read_bookmark())",
            "SELECT audit_log_read_bookmark()",
            "SELECT audit_log_rotate()",
            "SELECT audit_log_encryption_password_set('x')",
            "SELECT audit_log_encryption_password_get()",
            "SELECT mysql.audit_log_filter_set_user('%', 'log_none')",
            "SELECT `audit_log_filter_set_user`('%', 'log_none')",
            "DO audit_log_filter_remove_user('%')",
            "SET @x = audit_log_filter_remove_user('%')",
            "SELECT a FROM t WHERE audit_log_rotate() IS NOT NULL",
            "SELECT 1; SELECT audit_log_rotate()",
        ] {
            let a = my(q);
            let most = a
                .parts()
                .iter()
                .fold(StatementKind::Other, |k, p| most_reportable(k, p.kind));
            assert_eq!(most, StatementKind::Ddl, "{q}");
            assert!(a.parts().iter().any(|p| p.audit_function), "{q}");
        }
        // Prefix path (text that does not lex): still DDL.
        assert_eq!(
            analyze_raw(
                "SELECT audit_log_filter_set_user('\u{e9}\\', 'x')".as_bytes(),
                AnalyzeOptions::mysql()
            )
            .kind(),
            StatementKind::Ddl
        );
        for q in [
            "SELECT 'audit_log_rotate()'",
            "SELECT 1 /* audit_log_rotate() */",
            "SELECT audit_log_rotate FROM t",
            "SELECT audit_log_session_filter_id()",
        ] {
            assert_ne!(my(q).kind(), StatementKind::Ddl, "{q}");
        }
        let call = |q: &str| my(q).parts().iter().any(|p| p.routine_call);
        assert!(call(
            "SELECT a FROM hr.t JOIN hr.u ON hr.disable_consumers() LIMIT 1"
        ));
        assert!(call("SELECT a FROM hr.t WHERE EXISTS hr.f(1)"));
        assert!(call("SELECT * FROM hr.t INTO @x; SELECT hr.f()"));
        assert!(!call("CREATE INDEX i ON db.t (a)"));
        assert!(!call("INSERT INTO db.t (a) VALUES (1)"));
        assert!(!call(
            "ALTER TABLE db.t ADD FOREIGN KEY (a) REFERENCES db.u (a)"
        ));
    }

    /// Re-review of d162baa, P1 / P2: `"…"` in a name position, and the
    /// raw audit-function scan of texts that do not lex.
    #[test]
    fn mysql_dquoted_names_and_raw_audit_scan() {
        let dq = |q: &str| my(q).parts().iter().any(|p| p.dquoted_name);
        for q in [
            "SELECT * FROM \"hr\".\"customers\"",
            "SELECT * FROM \"t\"",
            "SELECT * FROM hr.a, \"b\"",
            "SELECT * FROM a JOIN \"b\" ON 1",
            "UPDATE \"t\" SET a = 1",
            "INSERT INTO \"t\" VALUES (1)",
            "DELETE FROM \"t\"",
            "TRUNCATE TABLE \"t\"",
            "SELECT \"t\".a FROM t",
            "SELECT \"f\"(1)",
        ] {
            assert!(dq(q), "{q}");
        }
        for q in [
            "SELECT * FROM (\"t\")",
            "SELECT * FROM ((\"t\"))",
            "SELECT * FROM (SELECT 1) x, \"t\"",
            "SELECT * FROM a AS x, \"t\"",
            "SELECT * FROM a STRAIGHT_JOIN \"t\"",
            "SELECT * FROM a USE INDEX (i), \"t\"",
            "HANDLER \"t\" OPEN",
            "HANDLER \"t\" READ FIRST",
        ] {
            assert!(dq(q), "{q}");
        }
        // Not a name position (the connector's backstop still adds `*`).
        for q in [
            "SELECT a FROM t WHERE a = \"x\"",
            "SELECT a FROM t WHERE a IN (\"x\")",
            "SELECT \"x\", CONCAT(\"a\", \"b\")",
            "INSERT INTO t VALUES (\"x\", \"y\")",
            "INSERT INTO t (a, b) VALUES (\"x\", \"y\")",
            "UPDATE t SET a = \"x\", b = \"y\" WHERE c IN (\"p\", \"q\")",
            "SELECT a FROM t AS \"alias\" WHERE b = \"x\" LIMIT 1",
            "SELECT * FROM t INTO OUTFILE \"/tmp/x\"",
        ] {
            assert!(!dq(q), "{q}");
        }
        assert!(my_norm("SELECT a FROM t WHERE a = \"x\"").is_some_and(|n| !n.contains('x')));
        assert!(has_outfile(
            &lex_mysql(
                "SELECT * FROM t INTO OUTFILE \"/x\"",
                MyMode {
                    backslash: true,
                    ansi_quotes: false,
                    version_as_comment: false
                }
            )
            .unwrap()
        ));
        assert_eq!(
            my("SELECT \"audit_log_rotate\"()").kind(),
            StatementKind::Ddl
        );
        assert_ne!(my("SELECT \"audit_log_rotate\"").kind(), StatementKind::Ddl);
        assert!(my("SELECT a FROM t WHERE b = \"x\"").parts()[0].dquoted);
        assert!(!my("SELECT a FROM t WHERE b = 'x'").parts()[0].dquoted);
        for t in [
            "x = 'a\\' AND audit_log_filter_remove_user('%')",
            "x AUDIT_LOG_ROTATE /* c */ ()",
            "x `audit_log_read` -- c\n (1)",
            "x \"audit_log_filter_set_user\" # c\n ('%')",
        ] {
            assert!(raw_audit_function(t.as_bytes()), "{t}");
        }
        // No left boundary (fail closed), executable comments skipped.
        for t in [
            "my_audit_log_rotate()",
            "x /*!80000audit_log_rotate*/()",
            "x /*!audit_log_rotate*/ ()",
            "x /*M!100000 audit_log_filter_flush */ /*!80000 (*/ )",
            "x audit_log_rotate /*!80000 */ ()",
        ] {
            assert!(raw_audit_function(t.as_bytes()), "{t}");
        }
        for t in [
            "audit_log_rotate",
            "audit_log_rotated()",
            "audit_log_session_filter_id()",
        ] {
            assert!(!raw_audit_function(t.as_bytes()), "{t}");
        }
        let a = analyze_raw(
            "SELECT a FROM t WHERE x = '\u{e9}\\' AND audit_log_filter_remove_user('%')".as_bytes(),
            AnalyzeOptions::mysql(),
        );
        assert!(!a.lexed() && a.audit_function());
        assert_eq!(a.kind(), StatementKind::Ddl);
        let mut raw = b"SELECT a FROM t WHERE x = '\xff' AND audit_log_rotate()".to_vec();
        raw.push(b' ');
        let a = analyze_raw(&raw, AnalyzeOptions::mysql());
        assert!(a.audit_function() && a.kind() == StatementKind::Ddl);
    }

    /// Re-review of 07b04d6, H1: a subquery inside a call or `DO` names its
    /// relations; `FROM` inside a call is not a table.
    #[test]
    fn subqueries_inside_calls_name_their_relations() {
        assert_eq!(
            my_rels("SELECT CONCAT('a', (SELECT GROUP_CONCAT(e) FROM hr.c))"),
            vec![r(Some("hr"), "c")]
        );
        assert_eq!(
            my_rels("DO (SELECT COUNT(*) FROM hr.c)"),
            vec![r(Some("hr"), "c")]
        );
        assert_eq!(
            my_rels("SET @x = (SELECT e FROM hr.c), @y := COALESCE((SELECT 1 FROM hr.d), 0)"),
            vec![r(Some("hr"), "c"), r(Some("hr"), "d")]
        );
        assert!(my_rels("SELECT EXTRACT(YEAR FROM d), TRIM(LEADING 'x' FROM y)").is_empty());
        assert!(my_rels("SELECT CONCAT(TRIM(x FROM y), SUBSTRING(z FROM 2))").is_empty());
    }

    /// #168 review L2: `LOAD_FILE(` reads a server file; matched on code
    /// (plain, backquoted, double-quoted, in an executable comment), never
    /// in a literal or a comment, and by a raw scan of a text that does not
    /// lex.
    #[test]
    fn mysql_load_file_calls() {
        for q in [
            "SELECT LOAD_FILE('/etc/passwd')",
            "select load_file ( '/etc/passwd' )",
            "SELECT Load_File /* c */ ('/etc/passwd')",
            "SET @x = LOAD_FILE('/var/lib/mysql/hr/customers.ibd')",
            "SET @x := `LOAD_FILE`('/etc/passwd')",
            "SELECT \"load_file\"('/etc/passwd')",
            "SELECT /*!LOAD_FILE*/('/etc/passwd')",
            "SELECT /*!40000 LOAD_FILE*/('/etc/passwd')",
            "DO LOAD_FILE('/etc/passwd')",
            "SELECT a FROM t WHERE LOAD_FILE('/etc/passwd') IS NOT NULL",
            "SHOW DATABASES WHERE LOAD_FILE('/etc/passwd') LIKE 'r%'",
            "INSERT INTO t VALUES (LOAD_FILE('/etc/passwd'))",
            "SELECT 1; SELECT LOAD_FILE('/etc/passwd')",
            // Digest texts.
            "SELECT `LOAD_FILE` (?)",
            "SELECT LOAD_FILE (?)",
        ] {
            let a = my(q);
            assert!(a.lexed(), "{q}");
            assert!(a.file_read(), "{q}");
            assert!(a.parts().iter().any(|p| p.file_read), "{q}");
        }
        for q in [
            "SELECT 'LOAD_FILE(x)'",
            "SELECT 1 /* LOAD_FILE('/etc/passwd') */",
            "SELECT 1 -- LOAD_FILE('/etc/passwd')",
            "SELECT load_file FROM t",
            "SELECT \"load_file\" FROM t",
            "SELECT load_files('/x')",
            "SELECT my_load_file('/x')",
            "SET NAMES utf8mb4",
        ] {
            assert!(!my(q).file_read(), "{q}");
        }
        // Readings that differ (a MariaDB-only executable comment), and a
        // text that does not lex: raw scan.
        for q in [
            "SELECT /*M! LOAD_FILE */('/etc/passwd')",
            "SELECT 1 /*M! , LOAD_FILE('/etc/passwd') */",
            "SELECT LOAD_FILE('/etc/x\u{e9}\\')",
            "SELECT a FROM t WHERE b = '\u{e9}\\' AND LOAD_FILE('/etc/passwd') IS NULL",
        ] {
            let a = my(q);
            assert!(!a.lexed() && a.file_read(), "{q}");
        }
        let mut raw = b"SELECT a FROM t WHERE x = '\xff' AND LOAD_FILE('/etc/passwd')".to_vec();
        raw.push(b' ');
        assert!(analyze_raw(&raw, AnalyzeOptions::mysql()).file_read());
        for t in [
            "x = 'a\\' AND load_file('/x')",
            "x LOAD_FILE /* c */ ('/x')",
            "x `load_file` -- c\n ('/x')",
            "x \"LOAD_FILE\" # c\n ('/x')",
            "x /*!80000load_file*/('/x')",
            "x_load_file('/x')",
        ] {
            assert!(raw_file_function(t.as_bytes()), "{t}");
        }
        for t in ["load_file", "load_files('/x')", "load_file_x('/x')"] {
            assert!(!raw_file_function(t.as_bytes()), "{t}");
        }
        assert!(!my("SELECT 'a\u{e9}\\'").file_read());
    }

    /// #184 review M2: a call of a name holding a non-ASCII character is
    /// never a built-in function (MySQL 8.4 and MariaDB 11.4 look
    /// `LOAD_FÍLE`, `LOAD_FİLE`, `LOAD_FILÉ` and `ＬOAD_FILE` up as stored
    /// functions): fail closed. Table names before a column list are not
    /// calls.
    #[test]
    fn mysql_non_ascii_calls() {
        for q in [
            "SELECT LOAD_F\u{cd}LE('/etc/hostname')",
            "SELECT LOAD_F\u{130}LE('/etc/hostname')",
            "SELECT LOAD_FIL\u{c9}('/etc/hostname')",
            "SELECT \u{ff2c}OAD_FILE('/etc/hostname')",
            "SELECT `load_f\u{131}le` /* c */ ('/x')",
            "SELECT \"LOAD_F\u{cd}LE\"('/x')",
            "SELECT a FROM t JOIN u ON f\u{e9}(a)",
            "SELECT hr.f\u{e9}(a) FROM t",
            "INSERT INTO t VALUES (f\u{e9}(1))",
            "INSERT INTO t (a) SELECT f\u{e9}(1)",
            "SET @x = caf\u{e9}(1)",
            // After a select modifier inside a write (#184 review N1).
            "INSERT INTO t SELECT HIGH_PRIORITY f\u{e9}(1)",
            "INSERT INTO t SELECT DISTINCT HIGH_PRIORITY hr.f\u{e9}(1)",
        ] {
            let a = my(q);
            assert!(a.lexed(), "{q}");
            assert!(a.non_ascii_call(), "{q}");
            assert!(!a.file_read(), "{q}");
        }
        for q in [
            "SELECT 'caf\u{e9}(1)'",
            "SELECT 1 /* f\u{e9}(1) */",
            "SELECT nom_\u{e9} FROM caf\u{e9}",
            "INSERT INTO `client\u{e8}le` (nom) VALUES ('x')",
            "INSERT INTO hr.`client\u{e8}le` (nom) VALUES ('x')",
            "REPLACE INTO caf\u{e9} (a) VALUES (1)",
            "INSERT LOW_PRIORITY IGNORE caf\u{e9} (a) VALUES (1)",
            "INSERT HIGH_PRIORITY caf\u{e9} (a) SELECT 1",
            "CREATE TABLE caf\u{e9} (a INT)",
            "CREATE TABLE IF NOT EXISTS hr.caf\u{e9} (a INT, FOREIGN KEY (a) REFERENCES th\u{e9} (id))",
            "WITH ct\u{e9} (a) AS (SELECT 1) SELECT a FROM ct\u{e9}",
            "SELECT LOAD_FILE('/x')",
        ] {
            assert!(!my(q).non_ascii_call(), "{q}");
        }
        // A text that does not lex, and raw bytes: raw scan.
        let a = my("SELECT f\u{e9}('/x\u{e9}\\')");
        assert!(!a.lexed() && a.non_ascii_call());
        let raw = b"SELECT a FROM t WHERE x = '\xff' AND f\xc3\xa9 ('/x') ";
        assert!(analyze_raw(raw, AnalyzeOptions::mysql()).non_ascii_call());
        for t in [
            "f\u{e9}(",
            "`f\u{e9}`\x0b(",
            "\"\u{ff2c}OAD_FILE\" /* c */ (",
            "x\u{e9} -- c\n (",
        ] {
            assert!(raw_non_ascii_call(t.as_bytes()), "{t:?}");
        }
        for t in ["f\u{e9}", "f\u{e9} x(", "fe(", "'\u{e9}' ("] {
            assert!(!raw_non_ascii_call(t.as_bytes()), "{t:?}");
        }
    }

    /// #184 review L1: the raw scans skip the lexer's whitespace set,
    /// vertical tab and form feed included.
    #[test]
    fn mysql_raw_scans_skip_every_whitespace() {
        for ws in [" ", "\t", "\n", "\r", "\x0b", "\x0c"] {
            let t = format!("x LOAD_FILE{ws}('/x')");
            assert!(raw_file_function(t.as_bytes()), "{t:?}");
            let t = format!("x audit_log_rotate{ws}()");
            assert!(raw_audit_function(t.as_bytes()), "{t:?}");
        }
        // A text that does not lex (a trail-byte hazard).
        let q = "SELECT a FROM t WHERE b = '\u{e9}\\' AND LOAD_FILE\x0b('/etc/passwd') IS NULL";
        let a = my(q);
        assert!(!a.lexed() && a.file_read(), "{q:?}");
        let q = "SELECT '\u{e9}\\', audit_log_rotate\x0c()";
        assert!(my(q).audit_function(), "{q:?}");
    }

    /// #184 review L3: a word right after `@` is a variable name, never
    /// the statement an `EXPLAIN` runs.
    #[test]
    fn mysql_explain_variable_named_like_a_keyword() {
        for q in [
            "EXPLAIN FORMAT=JSON INTO @select ANALYZE DELETE FROM t",
            "EXPLAIN FORMAT=JSON INTO @delete ANALYZE UPDATE t SET a = 1",
            "EXPLAIN FORMAT=TREE INTO @table ANALYZE SELECT * FROM hr.t",
        ] {
            let a = my(q);
            assert!(a.lexed(), "{q}");
            assert!(a.parts()[0].analyze_wrapped, "{q}");
            assert_ne!(a.kind(), StatementKind::Other, "{q}");
        }
        assert_eq!(
            my("EXPLAIN FORMAT=JSON INTO @select ANALYZE DELETE FROM t").kind(),
            StatementKind::Delete
        );
        // A variable alone is no statement: the `SELECT` after it is.
        let a = my("EXPLAIN FORMAT=JSON INTO @x SELECT 1");
        assert!(!a.parts()[0].analyze_wrapped);
    }

    /// #184 review L2: a server-side `LOAD DATA` / `LOAD XML` reads a
    /// server file; `LOCAL` reads a client file. The table stays a write.
    #[test]
    fn mysql_server_file_loads() {
        for q in [
            "LOAD DATA INFILE '/var/lib/mysql/hr/customers.ibd' INTO TABLE hr.t",
            "load data low_priority infile '/x' replace into table t (a)",
            "LOAD DATA CONCURRENT INFILE '/x' IGNORE INTO TABLE t",
            "LOAD XML INFILE '/x' INTO TABLE hr.t ROWS IDENTIFIED BY '<r>'",
            "SET STATEMENT max_statement_time = 1 FOR LOAD DATA INFILE '/x' INTO TABLE t",
        ] {
            let a = my(q);
            assert!(a.file_read(), "{q}");
            assert_eq!(a.kind(), StatementKind::Insert, "{q}");
            assert!(!a.relations().is_empty(), "{q}");
        }
        for q in [
            "LOAD DATA LOCAL INFILE '/x' INTO TABLE hr.t",
            "LOAD DATA LOW_PRIORITY LOCAL INFILE '/x' INTO TABLE t",
            "LOAD XML LOCAL INFILE '/x' INTO TABLE hr.t",
            "LOAD INDEX INTO CACHE t",
            "SELECT 'LOAD DATA INFILE'",
        ] {
            assert!(!my(q).file_read(), "{q}");
        }
    }

    /// #168 review L3: an `EXPLAIN` / `DESCRIBE` whose statement keyword
    /// is not found within the prefix bound is never quiet, whatever it
    /// holds; the short forms are unchanged.
    #[test]
    fn mysql_explain_prefix_bound() {
        let junk = "FORMAT = TREE ".repeat(11);
        for lead in ["EXPLAIN", "DESCRIBE", "DESC", "explain"] {
            for tail in [
                "ANALYZE DELETE FROM t",
                "DELETE FROM t",
                "SELECT * FROM hr.customers",
                "",
            ] {
                let q = format!("{lead} {junk}{tail}");
                let a = my(&q);
                assert!(a.lexed(), "{q}");
                assert!(a.parts()[0].explain_unbounded, "{q}");
            }
        }
        // Behind `SET STATEMENT … FOR`, `ANALYZE` past the bound too.
        let q = format!("SET STATEMENT a = 1 FOR EXPLAIN {junk}ANALYZE DELETE FROM t");
        assert!(my(&q).parts()[0].explain_unbounded, "{q}");
        let q = format!("SET STATEMENT a = 1 FOR EXPLAIN ANALYZE {junk}DELETE FROM t");
        let a = my(&q);
        let p = &a.parts()[0];
        assert!(p.explain_unbounded && p.analyze_wrapped, "{q}");
        // Within the bound: as before.
        for q in [
            "EXPLAIN SELECT * FROM t",
            "EXPLAIN FORMAT=JSON INTO @x SELECT 1",
            "DESCRIBE t",
            "DESC hr.t a",
            "EXPLAIN FOR CONNECTION 12",
            "EXPLAIN EXTENDED SELECT 1",
            "SHOW TABLES",
        ] {
            assert!(!my(q).parts()[0].explain_unbounded, "{q}");
        }
        // A statement keyword just within the bound is found.
        let near = format!("EXPLAIN {}SELECT 1", "FORMAT = TREE ".repeat(10));
        assert!(!my(&near).parts()[0].explain_unbounded, "{near}");
        let a = my(&format!(
            "EXPLAIN {}ANALYZE DELETE FROM t",
            "FORMAT = TREE ".repeat(10)
        ));
        assert!(a.parts()[0].analyze_wrapped);
    }

    /// A statement naming [`MAX_RELATIONS`] relations or more says so: the
    /// later ones are not kept.
    #[test]
    fn mysql_relations_full() {
        let names = |n: usize| {
            (0..n)
                .map(|i| format!("hr.t{i}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        for (n, full) in [(1, false), (14, false), (15, true), (16, true), (40, true)] {
            let q = format!("SELECT * FROM {}, performance_schema.threads", names(n));
            let a = my(&q);
            let p = &a.parts()[0];
            assert_eq!(p.relations_full, full, "{n}");
            assert_eq!(p.relations.len(), (n + 1).min(MAX_RELATIONS), "{n}");
        }
    }

    /// ADR-0045 open question 3: the plan of another connection's
    /// statement shows its text (MariaDB 11.4: a note; MySQL 8.4
    /// `FORMAT=TREE`: its literals). Explaining a statement does not.
    #[test]
    fn mysql_explain_of_another_connection() {
        for q in [
            "SHOW EXPLAIN FOR 12",
            "show explain format=json for 12",
            "SHOW ANALYZE FOR 12",
            "SHOW ANALYZE FORMAT = JSON FOR 12",
            "EXPLAIN FOR CONNECTION 12",
            "EXPLAIN FORMAT=TREE FOR CONNECTION 12",
            "EXPLAIN FORMAT = JSON FOR CONNECTION 12",
            "DESCRIBE FOR CONNECTION 12",
            "desc for connection 12",
            "EXPLAIN EXTENDED FOR CONNECTION 12",
            "SET STATEMENT max_statement_time = 1 FOR SHOW EXPLAIN FOR 12",
            "SET STATEMENT max_statement_time = 1 FOR EXPLAIN FOR CONNECTION 12",
            "/* x */ EXPLAIN /* y */ FOR CONNECTION 12",
        ] {
            let a = my(q);
            assert!(a.lexed(), "{q}");
            assert!(a.parts()[0].explain_connection, "{q}");
        }
        for q in [
            "EXPLAIN SELECT * FROM t FOR UPDATE",
            "EXPLAIN (SELECT a FROM t) FOR UPDATE",
            "EXPLAIN FORMAT=JSON SELECT * FROM t WHERE a = 1 FOR SHARE",
            "DESCRIBE t",
            "DESC hr.t a",
            "EXPLAIN t",
            "SHOW TABLES",
            "SHOW PROCESSLIST",
            "SELECT 1 FOR UPDATE",
        ] {
            assert!(!my(q).parts()[0].explain_connection, "{q}");
        }
    }

    /// Re-review of a2684a2: `ANALYZE` / `EXPLAIN ANALYZE` / `BEGIN NOT
    /// ATOMIC` wrappers, composable with `SET STATEMENT`; multi-table
    /// `UPDATE` lists.
    #[test]
    fn mysql_analyze_and_compound_wrappers() {
        for (q, k) in [
            ("ANALYZE UPDATE t SET a = 1", StatementKind::Update),
            ("ANALYZE FORMAT=JSON DELETE FROM t", StatementKind::Delete),
            ("ANALYZE SELECT * FROM t", StatementKind::Select),
            ("ANALYZE (SELECT * FROM t)", StatementKind::Select),
            (
                "EXPLAIN ANALYZE INSERT INTO t VALUES (1)",
                StatementKind::Insert,
            ),
            ("DESC ANALYZE FORMAT=TREE TABLE t", StatementKind::Table),
            (
                "SET STATEMENT a=1 FOR EXPLAIN ANALYZE DELETE FROM t",
                StatementKind::Delete,
            ),
            (
                "BEGIN NOT ATOMIC UPDATE t SET a = 1; END",
                StatementKind::Update,
            ),
            ("ANALYZE TABLE t", StatementKind::Other),
            ("ANALYZE LOCAL TABLE t", StatementKind::Other),
            ("EXPLAIN SELECT * FROM t", StatementKind::Other),
            ("BEGIN", StatementKind::Other),
        ] {
            assert_eq!(my(q).kind(), k, "{q}");
        }
        let a = my("EXPLAIN ANALYZE DELETE FROM t");
        assert!(a.parts()[0].analyze_wrapped && !a.parts()[0].compound);
        let a = my("BEGIN NOT ATOMIC SELECT 1; END");
        assert!(a.parts()[0].compound);
        assert!(!my("ANALYZE TABLE t").parts()[0].analyze_wrapped);
        let deep = format!(
            "{}ANALYZE DELETE FROM t",
            "SET STATEMENT a = 1 FOR ".repeat(MAX_SET_STATEMENT_DEPTH)
        );
        assert_eq!(my(&deep).kind(), StatementKind::Ddl);
        assert_eq!(
            my_rels("UPDATE hr.a x, hr.b y SET x.v = y.v"),
            vec![r(Some("hr"), "a"), r(Some("hr"), "b")]
        );
        assert!(my("SHOW TABLES WHERE (SELECT 1) = 1").parts()[0].subquery);
        assert!(my("SET @x = NOW()").parts()[0].function_call);
    }

    /// Security review of #85: PostgreSQL role statements are privilege
    /// changes on every source (pgaudit's `ROLE` class), including a text
    /// that does not lex (cut at its first quote).
    #[test]
    fn postgres_role_statements_are_dcl() {
        let kind = |q: &str| analyze(q, AnalyzeOptions::new()).kind();
        for q in [
            "CREATE ROLE r LOGIN PASSWORD $1",
            "create user u with password $1",
            "ALTER ROLE r WITH PASSWORD $1",
            "ALTER USER u VALID UNTIL $1",
            "ALTER ROLE r SET search_path = public",
            "DROP ROLE IF EXISTS r",
            "DROP USER u",
            "CREATE GROUP g",
            "ALTER GROUP g ADD USER u",
            "DROP GROUP g",
            "GRANT SELECT ON t TO r",
            "REVOKE r FROM u",
            "ALTER ROLE r PASSWORD 'unterminated",
        ] {
            assert_eq!(kind(q), StatementKind::Dcl, "{q}");
        }
        for q in [
            "CREATE USER MAPPING FOR u SERVER s OPTIONS (password $1)",
            "ALTER USER MAPPING FOR u SERVER s OPTIONS (SET password $1)",
            "DROP USER MAPPING FOR u SERVER s",
            "CREATE TABLE roles (a int)",
            "ALTER TABLE users ADD COLUMN g int",
        ] {
            assert_eq!(kind(q), StatementKind::Ddl, "{q}");
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

    /// A test list: native (`n`), keywords (`k`, plain or spaced) and
    /// keyword functions read as keywords only right before `(` (`s`).
    struct TestBuiltins;

    impl BuiltinFunctions for TestBuiltins {
        fn is_builtin(&self, name: &[u8], form: CallForm) -> bool {
            const N: [&str; 5] = [
                "concat",
                "ifnull",
                "load_file",
                "row_number",
                "last_insert_id",
            ];
            const K: [&str; 29] = [
                "if",
                "in",
                "values",
                "char",
                "decimal",
                "exists",
                "as",
                "select",
                "not",
                "and",
                "or",
                "over",
                "row",
                "match",
                "database",
                "interval",
                "cast",
                "convert",
                "json_value",
                "trim",
                "extract",
                "from",
                "join",
                "on",
                "where",
                "union",
                "all",
                "using",
                "partition",
            ];
            const S: [&str; 4] = ["count", "now", "substr", "max"];
            let is = |l: &[&str]| l.iter().any(|n| n.as_bytes().eq_ignore_ascii_case(name));
            is(&N) || (form != CallForm::Quoted && is(&K)) || (form == CallForm::Plain && is(&S))
        }
    }

    static TEST_BUILTINS: TestBuiltins = TestBuiltins;

    fn uc_opts() -> AnalyzeOptions {
        AnalyzeOptions::mysql().builtins(&TEST_BUILTINS)
    }

    fn unknown(s: &str) -> bool {
        analyze(s, uc_opts()).unknown_call()
    }

    /// ADR-0045 decision 9: unqualified calls of names that are not built
    /// in, in every position and quoting.
    #[test]
    fn unknown_calls_are_found() {
        for q in [
            "SELECT f()",
            "select F ( 1 )",
            "DO f()",
            "SET @x = f()",
            "SET @x := 1, @y = f(2)",
            "SELECT a FROM hr.t WHERE b = f(1)",
            "SELECT * FROM hr.t WHERE b IN (SELECT g(c) FROM u)",
            "INSERT INTO t (a) VALUES (f())",
            "UPDATE t SET a = f(a) WHERE b = 1",
            "DELETE FROM t WHERE a = f()",
            "CALL p(f())",
            "SELECT 1 FROM DUAL WHERE NOT f()",
            "SELECT CASE WHEN f() THEN 1 END",
            "SELECT 1f()",
            "SELECT 12_3()",
            // Keyword functions with whitespace or a comment before `(`:
            // identifiers then.
            "SELECT now ()",
            "SELECT count (*) FROM t",
            "SELECT now/**/()",
            "SELECT now/*!*/()",
            "SELECT now\n()",
            // Quoted: never a keyword.
            "SELECT `now`()",
            "SELECT `count`(*) FROM t",
            "SELECT `if`(1, 2, 3)",
            "SELECT `f`()",
            "SELECT `get customer`(1)",
            // `ANSI_QUOTES`.
            "SELECT \"f\"()",
            "SELECT \"now\"()",
            // Executable comments are code.
            "SELECT /*!50000 f() */",
            "SELECT /*!f*/()",
            // `JSON_TABLE` out of a table list (MariaDB: a stored
            // function).
            "SELECT json_table(1)",
            "SELECT TRIM('a' FROM json_table(1))",
            "SELECT EXTRACT(DAY FROM f(1))",
            "SELECT a FROM t FOR SYSTEM_TIME FROM json_table() TO NOW()",
            // After `SET STATEMENT … FOR`.
            "SET STATEMENT max_statement_time = 1 FOR SELECT f()",
            // An executable comment read both ways (security review of
            // #188, L2): skipped below its version, `f()` runs.
            "SELECT f/*!99999 abs*/()",
            "SELECT f/*!999999 abs*/()",
            "SELECT f/*M!999999 abs*/()",
            "SELECT f /*!99999 abs */ (1), 'x\u{e9}\\'",
            // `ON` / `EXISTS` inside DDL (security review of #188, L3).
            "CREATE TABLE x AS SELECT * FROM hr.a JOIN hr.b ON f(a.k)",
            "CREATE VIEW v AS SELECT 1 FROM hr.t JOIN hr.u ON f(1)",
            "CREATE TABLE x AS SELECT 1 FROM hr.t WHERE EXISTS (SELECT f(1))",
            // Followed by `AS` (security review of #188, H1).
            "SELECT f() AS x",
            "SELECT f(1) AS a FROM hr.t",
            "SELECT CAST(f() AS CHAR)",
            "INSERT INTO hr.t SELECT f() AS x",
            "SET @x = (SELECT f() AS y)",
            "DO (SELECT f() AS y)",
            "CREATE TABLE x AS SELECT f(a) AS c FROM hr.t",
            "SELECT f(1) AS \"x\"",
            "SELECT f(1) AS (x)",
            "SELECT a, f(1) AS (x)",
            "WITH x AS (SELECT f(1) AS y) SELECT * FROM x",
            "WITH x (a) AS (SELECT 1) SELECT g(a) AS b FROM x",
            "WITH x AS (SELECT 1) SELECT 1, f(2) AS (y)",
            // A select modifier inside a write is not the write's head
            // (security review of #184, N1).
            "INSERT INTO hr.t SELECT HIGH_PRIORITY f(1)",
            "INSERT IGNORE INTO hr.t SELECT DISTINCT HIGH_PRIORITY f(1)",
            "REPLACE INTO hr.t SELECT SQL_NO_CACHE HIGH_PRIORITY `f`(1)",
            // A text that does not lex: a raw scan.
            "SELECT f('a",
            "SELECT 'a\\' , f(1)",
        ] {
            assert!(unknown(q), "{q}");
        }
    }

    #[test]
    fn built_in_calls_and_non_call_positions_are_not_unknown() {
        for q in [
            "SELECT now(), count(*), max(a), substr(b, 1) FROM t",
            "SELECT NOW(), COUNT(*) FROM t",
            "SELECT concat ('a'), `concat`('b'), \"concat\"('c'), ifnull (1, 2)",
            "SELECT IF (a, 1, 2), CHAR (65), DATABASE ()",
            "SELECT LAST_INSERT_ID()",
            "SELECT 1",
            "SELECT a FROM t WHERE b IN (1, 2) AND EXISTS (SELECT 1) OR NOT (c)",
            "INSERT INTO t (a, b) VALUES (1, 2), (3, 4)",
            "INSERT t (a) VALUE (1)",
            "REPLACE INTO hr.t (a) VALUES (1)",
            "INSERT INTO t (a) VALUES (1) ON DUPLICATE KEY UPDATE a = VALUES(a)",
            "INSERT LOW_PRIORITY IGNORE t (a) VALUES (1)",
            "INSERT HIGH_PRIORITY INTO t (a) SELECT 1",
            "REPLACE DELAYED t (a) VALUES (1)",
            "WITH x (a) AS (SELECT 1) SELECT * FROM x",
            "WITH x AS (SELECT 1), y (b, c) AS (SELECT 2, 3) SELECT * FROM y",
            "WITH RECURSIVE r (n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT n FROM r",
            "WITH x (a) AS (SELECT 1), y AS (SELECT 2), `z` (b) AS (SELECT 3) SELECT * FROM z",
            "WITH RECURSIVE \"q\" (a) AS (SELECT 1), r (b, c) AS (SELECT 2, 3) SELECT 1",
            "CREATE INDEX i ON t (a)",
            "CREATE UNIQUE INDEX i USING BTREE ON hr.t (a, b)",
            "CREATE INDEX IF NOT EXISTS i ON t (a)",
            "CREATE TABLE IF NOT EXISTS t (a INT)",
            "CREATE TABLE IF NOT EXISTS hr.t (a INT)",
            "CREATE TABLE IF NOT EXISTS `t` (a INT)",
            "SELECT CAST(a AS DECIMAL(10, 2)), CAST(b AS nchar(4)), CAST(c AS datetime(6)) FROM t",
            "SELECT CONVERT(a, nchar(4)), CONVERT(b, datetime(6)) FROM t",
            "SELECT JSON_VALUE(j, '$.a' RETURNING decimal(4, 2)) FROM t",
            "SELECT MATCH (a) AGAINST ('x' IN BOOLEAN MODE) FROM t",
            "SELECT row_number() OVER (ORDER BY a) FROM t",
            "SELECT a FROM t WINDOW w AS (ORDER BY a)",
            "SELECT * FROM (SELECT 1, 2) AS dt (a, b)",
            "SELECT * FROM (SELECT 1, 2) dt (a, b)",
            "SELECT * FROM JSON_TABLE('[]', '$[*]' COLUMNS (a varchar(10) PATH '$', \
             NESTED PATH '$.b' COLUMNS (b datetime(6) PATH '$'))) jt",
            "SELECT * FROM t JOIN JSON_TABLE('[]', '$' COLUMNS (a INT PATH '$')) jt ON TRUE",
            "SELECT * FROM t, JSON_TABLE('[]', '$' COLUMNS (a INT PATH '$')) jt",
            "LOAD DATA LOCAL INFILE 'f' INTO TABLE t CHARACTER SET latin1 \
             FIELDS TERMINATED BY ',' IGNORE 1 LINES (a, b) SET c = 1",
            "SELECT hr.f()",
            "SELECT `hr`.`f`()",
            "SELECT 1e5, 0x1F, 0b101, 1.5e3",
            "SELECT a FROM t PARTITION (p0)",
            "SELECT INTERVAL (1) DAY + NOW()",
            "SELECT ROW (1, 2) = ROW (1, 2)",
            "SELECT 'f(1)' /* g() */ -- h()\n",
        ] {
            assert!(!unknown(q), "{q}");
        }
        // Qualified calls are routine calls, not unknown ones.
        let a = analyze("SELECT hr.f()", uc_opts());
        assert!(a.parts()[0].routine_call && !a.unknown_call());
        // Also after a select modifier inside a write (#184 review N1).
        let a = analyze("INSERT INTO t SELECT HIGH_PRIORITY hr.f(1)", uc_opts());
        assert!(a.parts()[0].routine_call && !a.unknown_call());
        let a = analyze("INSERT HIGH_PRIORITY hr.t (a) SELECT 1", uc_opts());
        assert!(!a.parts()[0].routine_call && !a.unknown_call());
    }

    /// Without a list, every unqualified call is unknown (fail closed).
    #[test]
    fn no_list_means_every_call_is_unknown() {
        assert!(my("SELECT now()").unknown_call());
        assert!(!analyze("SELECT now()", AnalyzeOptions::new()).unknown_call());
    }

    /// A digest spaces every token and backquotes every identifier: an
    /// unquoted name was a keyword written right before `(`.
    #[test]
    fn digests_read_unquoted_names_as_keywords() {
        let d = |q: &str| analyze(q, uc_opts().digest(true)).unknown_call();
        assert!(!d("SELECT COUNT ( * ) , NOW ( ) , `concat` ( ? ) FROM `t`"));
        assert!(d("SELECT `count` ( * ) FROM `t`"));
        assert!(d("SELECT `f` ( )"));
        assert!(d("SELECT F ( )"));
        assert!(unknown("SELECT COUNT ( * ) FROM `t`"));
    }

    /// The unknown-call analysis never changes the relations, the kind
    /// nor the other flags.
    #[test]
    fn unknown_calls_keep_the_relations() {
        for q in [
            "SELECT f(a) FROM hr.t JOIN hr.u ON f(b)",
            "INSERT INTO hr.t (a) SELECT g(b) FROM hr.u",
            "UPDATE hr.t SET a = f(a)",
        ] {
            let with = analyze(q, uc_opts());
            let without = my(q);
            assert!(with.unknown_call(), "{q}");
            assert_eq!(with.relations(), without.relations(), "{q}");
            assert_eq!(with.kind(), without.kind(), "{q}");
        }
    }
}
