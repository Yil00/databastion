//! Firebird statement analysis for the system audit trace (ADR-0060
//! decision 6, "Statement text", and its refinements R8, R12, R27 and
//! R36): the Firebird mode of the query normalizer.
//!
//! The statement text of a trace record is client text, verbatim. The
//! agent never sends it (the contract has no field for it):
//! [`analyze_firebird`] reduces it to a statement kind, a closed set of
//! flags and the relation and procedure names it reads or writes
//! (identifier tokens only, never a literal).
//!
//! - **Lexing**: `--` and `/* … */` comments removed; every literal
//!   (`'…'` with `''`, the alternate quoting `q'<c>…<c>'` with every
//!   delimiter pair the server accepts, `x'…'`, `n'…'`, introducers such
//!   as `_UTF8 '…'`, numbers, `0x…`) reduced to a token without content.
//!   `"…"` is an identifier in dialect 3 and a string in dialect 1, and the
//!   client's dialect is not in the log: where it stands as a relation or
//!   procedure name, the two readings give different relation sets
//!   ([`FirebirdAnalysis::dialects_differ`]). A text that ends inside a
//!   comment, a literal or a quoted identifier is
//!   [`FirebirdAnalysis::unterminated`] (R12 item 3: evidence of a split
//!   when the text is not cut); everything after the opening quote is
//!   dropped (security review L10).
//! - **Password-bearing statements** (the #82 rule): any `PASSWORD` word,
//!   and `CREATE` / `ALTER` / `RECREATE` `USER`, `ALTER CURRENT USER`,
//!   `CREATE DATABASE`, `CONNECT`, `CREATE` / `ALTER` / `DROP MAPPING`,
//!   keep their kind only ([`FirebirdAnalysis::credential`]): no name is
//!   kept from them.
//! - **Flags**: server-side copies (`ALTER DATABASE BEGIN BACKUP`, `ADD
//!   FILE`, `ADD DIFFERENCE FILE`, `CREATE SHADOW`:
//!   `signature.backup_database`), remote data access (`EXECUTE STATEMENT
//!   … ON EXTERNAL`, `CREATE TABLE … EXTERNAL`:
//!   `signature.remote_data_access`), code (`EXECUTE BLOCK`, PSQL bodies,
//!   procedures, `EXECUTE STATEMENT`, calls of functions outside the
//!   built-in list), and the shape of a top-level `SELECT`.
//!
//! Unquoted identifiers are ASCII only on Firebird 4.0 and 5.0 and stored
//! upper-cased (ADR-0060 R4, open question 11): they are upper-cased here
//! with ASCII rules.

use super::MAX_QUERY_BYTES;

/// Most tokens lexed per statement.
const MAX_TOKENS: usize = 200_000;
/// Longest identifier kept (Firebird 4.0+: 63 characters): a longer word
/// is cut, which can only make a closed-list match fail.
const MAX_WORD_CHARS: usize = 255;
/// Most relation and procedure names kept per statement.
const MAX_NAMES: usize = 256;
/// A row limit at or below this exempts a read from
/// `shape.full_table_read` (decision 6, "Signals").
pub const FULL_READ_LIMIT: u64 = 10_000;

/// Statement kind of a Firebird text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FirebirdKind {
    /// `SELECT`, `WITH … SELECT`.
    Select,
    /// `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `UPDATE OR INSERT`.
    Write,
    /// `EXECUTE PROCEDURE`.
    ExecuteProcedure,
    /// `EXECUTE BLOCK` (PSQL).
    ExecuteBlock,
    /// DDL (`CREATE`, `ALTER`, `RECREATE`, `DROP`, `COMMENT ON`, …).
    Ddl,
    /// `GRANT`, `REVOKE`, users, roles and mappings, password-bearing.
    Dcl,
    /// `SET TRANSACTION`, `COMMIT`, `ROLLBACK` (R24 item 3: may carry a
    /// transaction trigger's block).
    Transaction,
    /// `ALTER SESSION RESET` (R34 item 1: may carry a block).
    SessionReset,
    /// The other statements of R8 case (b): `SAVEPOINT`, `RELEASE
    /// SAVEPOINT`, `SET BIND`, `SET TIME ZONE`, `SET DECFLOAT`, `SET
    /// SESSION IDLE TIMEOUT`, `SET STATEMENT TIMEOUT`.
    Session,
    /// Anything else, or an empty text.
    #[default]
    Other,
}

impl FirebirdKind {
    /// A statement of R8 case (b): it reads no relation.
    #[must_use]
    pub fn cannot_read(self) -> bool {
        matches!(self, Self::Transaction | Self::SessionReset | Self::Session)
    }
}

/// The analysis of one statement text. Holds identifier names only.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FirebirdAnalysis {
    /// The statement kind.
    pub kind: FirebirdKind,
    /// `?` placeholders outside literals and comments (the parameter
    /// lines a trace record may carry).
    pub placeholders: usize,
    /// The text ends inside a comment, a string literal or a quoted
    /// identifier (or is above [`MAX_QUERY_BYTES`] or the token bound).
    pub unterminated: bool,
    /// A `"…"` token stands where a relation or procedure name is read:
    /// the dialect 1 and dialect 3 readings give different relation sets.
    pub dialects_differ: bool,
    /// Relations the text reads or writes, in the dialect 3 reading:
    /// unquoted names upper-cased (ASCII), quoted names as written. Common
    /// table expression names are left out. Empty for a password-bearing
    /// text.
    pub relations: Vec<String>,
    /// Procedures called (`EXECUTE PROCEDURE p`, `FROM p(…)`).
    pub procedures: Vec<String>,
    /// More names than the bound were found: the lists are not complete
    /// (review of part 1, L5), and the text does not parse.
    pub names_truncated: bool,
    /// Kind only (the #82 rule).
    pub credential: bool,
    /// `signature.backup_database` (R27, R36).
    pub backup: bool,
    /// `signature.remote_data_access`.
    pub remote_access: bool,
    /// `EXECUTE STATEMENT` in the text (PSQL).
    pub execute_statement: bool,
    /// A PSQL body (`EXECUTE BLOCK`, `CREATE PROCEDURE`, triggers,
    /// functions, packages): no name is taken from it (ADR-0023 decision
    /// 7); `*`, always reported.
    pub psql: bool,
    /// A call of a function outside the built-in list (unqualified), or
    /// of a packaged or qualified function.
    pub unknown_call: bool,
    /// R12 item 1: one `SELECT` whose top-level select list holds only
    /// built-in aggregate functions and constants, with no `GROUP BY` and
    /// no set operation.
    pub aggregate_only: bool,
    /// A top-level `SELECT` without `WHERE`, `GROUP BY` / `HAVING`, an
    /// aggregate in its select list, or a row limit (`FIRST`, `ROWS`,
    /// `FETCH FIRST|NEXT`) of at most [`FULL_READ_LIMIT`] rows.
    pub unrestricted_select: bool,
}

impl FirebirdAnalysis {
    /// The text parses in R8 item 1's meaning: lexed whole, and both
    /// dialect readings give the same relation set.
    #[must_use]
    pub fn parses(&self) -> bool {
        !self.unterminated && !self.dialects_differ && !self.names_truncated
    }

    /// The text calls code (R8 case (c)): `EXECUTE BLOCK`, a PSQL body, a
    /// procedure, a function outside the built-in list, or `EXECUTE
    /// STATEMENT`.
    #[must_use]
    pub fn calls_code(&self) -> bool {
        self.psql || !self.procedures.is_empty() || self.unknown_call || self.execute_statement
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// An unquoted word, upper-cased.
    Word(String),
    /// `"…"` (dialect 3: an identifier, as written).
    Quoted(String),
    /// A string or non-integer literal (content dropped).
    Literal,
    /// An integer literal: its value only for the row-limit rule, never
    /// kept in the analysis (`None` past `u64`).
    Number(Option<u64>),
    /// A parameter: `?` (true) or a named one, `:name` (false).
    Param(bool),
    Punct(char),
}

/// The words of the built-in functions of Firebird 4.0 and 5.0 (and the
/// keywords that take parentheses), checked per image by the engine-matrix
/// drift test (decision 9). Anything else followed by `(` is a call of
/// code the trace does not show.
/// The built-in word list, for the connector's engine-matrix drift test
/// (decision 9): every word must be a keyword of the server's
/// `RDB$KEYWORDS`.
#[doc(hidden)]
#[must_use]
pub fn builtin_words() -> &'static [&'static str] {
    BUILTINS
}

const BUILTINS: &[&str] = &[
    "ABS",
    "ACOS",
    "ACOSH",
    "ALL",
    "AND",
    "ANY",
    "ANY_VALUE",
    "AS",
    "ASCII_CHAR",
    "ASCII_VAL",
    "ASIN",
    "ASINH",
    "ATAN",
    "ATAN2",
    "ATANH",
    "AVG",
    "BASE64_DECODE",
    "BASE64_ENCODE",
    "BETWEEN",
    "BIGINT",
    "BIN_AND",
    "BIN_NOT",
    "BIN_OR",
    "BIN_SHL",
    "BIN_SHR",
    "BIN_XOR",
    "BINARY",
    "BIT_LENGTH",
    "BLOB",
    "BLOB_APPEND",
    "BOOLEAN",
    "BY",
    "CASE",
    "CAST",
    "CEIL",
    "CEILING",
    "CHAR",
    "CHAR_LENGTH",
    "CHAR_TO_UUID",
    "CHARACTER",
    "CHARACTER_LENGTH",
    "COALESCE",
    "COMPARE_DECFLOAT",
    "CONTAINING",
    "CORR",
    "COS",
    "COSH",
    "COT",
    "COUNT",
    "COVAR_POP",
    "COVAR_SAMP",
    "CRYPT_HASH",
    "CUME_DIST",
    "CURRENT_TIME",
    "CURRENT_TIMESTAMP",
    "DATEADD",
    "DATEDIFF",
    "DECFLOAT",
    "DECIMAL",
    "DECODE",
    "DECRYPT",
    "DENSE_RANK",
    "DISTINCT",
    "DOUBLE",
    "ELSE",
    "ENCRYPT",
    "EXISTS",
    "EXP",
    "EXTRACT",
    "FILTER",
    "FIRST_DAY",
    "FIRST_VALUE",
    "FLOAT",
    "FLOOR",
    "FROM",
    "GEN_ID",
    "GEN_UUID",
    "HASH",
    "HAVING",
    "HEX_DECODE",
    "HEX_ENCODE",
    "IIF",
    "IN",
    "INT",
    "INTEGER",
    "INT128",
    "IS",
    "LAG",
    "LAST_DAY",
    "LAST_VALUE",
    "LATERAL",
    "LEAD",
    "LEFT",
    "LIKE",
    "LIST",
    "LN",
    "LOCALTIME",
    "LOCALTIMESTAMP",
    "LOG",
    "LOG10",
    "LOWER",
    "LPAD",
    "MAKE_DBKEY",
    "MAX",
    "MAXVALUE",
    "MIN",
    "MINVALUE",
    "MOD",
    "NCHAR",
    "NORMALIZE_DECFLOAT",
    "NOT",
    "NTH_VALUE",
    "NTILE",
    "NULLIF",
    "NUMERIC",
    "OCTET_LENGTH",
    "ON",
    "OR",
    "OVER",
    "OVERLAY",
    "PARTITION",
    "PERCENT_RANK",
    "PI",
    "POSITION",
    "POWER",
    "QUANTIZE",
    "RAND",
    "RANK",
    "RDB$ERROR",
    "RDB$GET_CONTEXT",
    "RDB$GET_TRANSACTION_CN",
    "RDB$ROLE_IN_USE",
    "RDB$SET_CONTEXT",
    "RDB$SYSTEM_PRIVILEGE",
    "REGR_AVGX",
    "REGR_AVGY",
    "REGR_COUNT",
    "REGR_INTERCEPT",
    "REGR_R2",
    "REGR_SLOPE",
    "REGR_SXX",
    "REGR_SXY",
    "REGR_SYY",
    "REPLACE",
    "RETURNING",
    "REVERSE",
    "RIGHT",
    "ROUND",
    "ROW_NUMBER",
    "ROWS",
    "RPAD",
    "RSA_DECRYPT",
    "RSA_ENCRYPT",
    "RSA_PRIVATE",
    "RSA_PUBLIC",
    "RSA_SIGN_HASH",
    "RSA_VERIFY_HASH",
    "SELECT",
    "SIGN",
    "SIMILAR",
    "SIN",
    "SINGULAR",
    "SINH",
    "SMALLINT",
    "SOME",
    "SQRT",
    "STARTING",
    "STDDEV_POP",
    "STDDEV_SAMP",
    "SUBSTRING",
    "SUM",
    "TAN",
    "TANH",
    "THEN",
    "TIME",
    "TIMESTAMP",
    "TOTALORDER",
    "TRIM",
    "TRUNC",
    "UNICODE_CHAR",
    "UNICODE_VAL",
    "UPPER",
    "USING",
    "UUID_TO_CHAR",
    "VALUES",
    "VAR_POP",
    "VAR_SAMP",
    "VARBINARY",
    "VARCHAR",
    "WHEN",
    "WHERE",
    "WINDOW",
    "WITH",
];

/// Built-in aggregate functions (R12 item 1).
const AGGREGATES: &[&str] = &["COUNT", "SUM", "AVG", "MIN", "MAX", "LIST"];

/// Lexes `text`: `None` past the token bound.
fn lex(text: &str) -> (Vec<Tok>, bool) {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut unterminated = false;
    while i < b.len() {
        if out.len() >= MAX_TOKENS {
            return (out, true);
        }
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'-' if b.get(i + 1) == Some(&b'-') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => match find(b, i + 2, b"*/") {
                Some(e) => i = e + 2,
                None => {
                    unterminated = true;
                    break;
                }
            },
            b'\'' => match string_end(b, i + 1, b'\'') {
                Some(e) => {
                    out.push(Tok::Literal);
                    i = e;
                }
                None => {
                    unterminated = true;
                    break;
                }
            },
            b'"' => match quoted(b, i + 1) {
                Some((name, e)) => {
                    out.push(Tok::Quoted(name));
                    i = e;
                }
                None => {
                    unterminated = true;
                    break;
                }
            },
            b'q' | b'Q' if b.get(i + 1) == Some(&b'\'') && i + 2 < b.len() => {
                let open = b[i + 2];
                let close = match open {
                    b'(' => b')',
                    b'{' => b'}',
                    b'[' => b']',
                    b'<' => b'>',
                    c => c,
                };
                match find(b, i + 3, &[close, b'\'']) {
                    Some(e) => {
                        out.push(Tok::Literal);
                        i = e + 2;
                    }
                    None => {
                        unterminated = true;
                        break;
                    }
                }
            }
            b'x' | b'X' | b'n' | b'N' if b.get(i + 1) == Some(&b'\'') => {
                match string_end(b, i + 2, b'\'') {
                    Some(e) => {
                        out.push(Tok::Literal);
                        i = e;
                    }
                    None => {
                        unterminated = true;
                        break;
                    }
                }
            }
            b'0'..=b'9' => {
                let s = i;
                i += 1;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.') {
                    // Exponents: `1e-5`.
                    if (b[i] == b'e' || b[i] == b'E') && matches!(b.get(i + 1), Some(b'-' | b'+')) {
                        i += 1;
                    }
                    i += 1;
                }
                let lit = &text[s..i];
                out.push(if lit.bytes().all(|c| c.is_ascii_digit()) {
                    Tok::Number(lit.parse().ok())
                } else {
                    Tok::Literal
                });
            }
            b'.' if b.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                i += 1;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.') {
                    i += 1;
                }
                out.push(Tok::Literal);
            }
            b'?' => {
                out.push(Tok::Param(true));
                i += 1;
            }
            b':' if b
                .get(i + 1)
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'"') =>
            {
                // A named parameter or a PSQL variable: never a name.
                i += 1;
                if b[i] == b'"' {
                    match quoted(b, i + 1) {
                        Some((_, e)) => i = e,
                        None => {
                            unterminated = true;
                            break;
                        }
                    }
                } else {
                    while i < b.len() && word_byte(b[i]) {
                        i += 1;
                    }
                }
                out.push(Tok::Param(false));
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let s = i;
                while i < b.len() && word_byte(b[i]) {
                    i += 1;
                }
                let w: String = text[s..i]
                    .chars()
                    .take(MAX_WORD_CHARS)
                    .map(|c| c.to_ascii_uppercase())
                    .collect();
                out.push(Tok::Word(w));
            }
            c if c.is_ascii() => {
                out.push(Tok::Punct(c as char));
                i += 1;
            }
            _ => {
                // A non-ASCII character outside a literal: not a valid
                // unquoted identifier (R4); kept as punctuation.
                let len = text[i..].chars().next().map_or(1, char::len_utf8);
                out.push(Tok::Punct('\u{FFFD}'));
                i += len;
            }
        }
    }
    (out, unterminated)
}

fn word_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

fn find(b: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    if from > b.len() {
        return None;
    }
    b[from..]
        .windows(pat.len())
        .position(|w| w == pat)
        .map(|p| from + p)
}

/// The index after the closing quote of a string starting at `from`
/// (`''` escapes).
fn string_end(b: &[u8], mut i: usize, q: u8) -> Option<usize> {
    while i < b.len() {
        if b[i] == q {
            if b.get(i + 1) == Some(&q) {
                i += 2;
                continue;
            }
            return Some(i + 1);
        }
        i += 1;
    }
    None
}

fn quoted(b: &[u8], from: usize) -> Option<(String, usize)> {
    let e = string_end(b, from, b'"')?;
    let inner = std::str::from_utf8(&b[from..e - 1]).ok()?;
    Some((
        inner
            .replace("\"\"", "\"")
            .chars()
            .take(MAX_WORD_CHARS)
            .collect(),
        e,
    ))
}

fn is_word(t: Option<&Tok>, w: &str) -> bool {
    matches!(t, Some(Tok::Word(x)) if x == w)
}

fn words_at(toks: &[Tok], i: usize, ws: &[&str]) -> bool {
    ws.iter()
        .enumerate()
        .all(|(k, w)| is_word(toks.get(i + k), w))
}

/// Analyzes one statement text from a trace record.
#[must_use]
pub fn analyze_firebird(text: &str) -> FirebirdAnalysis {
    let mut a = FirebirdAnalysis::default();
    if text.len() > MAX_QUERY_BYTES {
        a.unterminated = true;
        return a;
    }
    let (toks, unterminated) = lex(text);
    a.unterminated = unterminated;
    a.placeholders = toks
        .iter()
        .filter(|t| matches!(t, Tok::Param(true)))
        .count();
    a.kind = kind(&toks);
    // The #82 rule: kind only.
    let password = toks
        .iter()
        .any(|t| matches!(t, Tok::Word(w) if w == "PASSWORD"));
    let identity = match toks.as_slice() {
        [Tok::Word(c), rest @ ..]
            if c == "CREATE" || c == "ALTER" || c == "RECREATE" || c == "DROP" =>
        {
            let rest = if words_at(rest, 0, &["OR", "ALTER"]) {
                &rest[2..]
            } else {
                rest
            };
            words_at(rest, 0, &["USER"])
                || words_at(rest, 0, &["CURRENT", "USER"])
                || words_at(rest, 0, &["MAPPING"])
                || words_at(rest, 0, &["GLOBAL", "MAPPING"])
                || (c == "CREATE" && words_at(rest, 0, &["DATABASE"]))
                || (c == "CREATE" && words_at(rest, 0, &["SCHEMA"]))
        }
        [Tok::Word(c), ..] => c == "CONNECT",
        _ => false,
    };
    // Flags, shape and kind are computed on the token stream for every
    // text (review of part 1, M3): a `PASSWORD` word keeps the statement's
    // kind (Dcl only for the identity statements of the #82 rule) and its
    // flags (`EXECUTE STATEMENT … ON EXTERNAL … PASSWORD` is remote data
    // access), and only its names are not kept. Literal contents are
    // never in the tokens.
    a.credential = password || identity;
    if identity {
        a.kind = FirebirdKind::Dcl;
    }
    flags(&toks, &mut a);
    if !a.psql {
        names(&toks, &mut a);
        shape(&toks, &mut a);
    }
    if a.credential {
        a.relations.clear();
        a.procedures.clear();
    }
    a
}

fn kind(toks: &[Tok]) -> FirebirdKind {
    use FirebirdKind as K;
    let Some(Tok::Word(first)) = toks.first() else {
        return K::Other;
    };
    match first.as_str() {
        "SELECT" | "WITH" => K::Select,
        "INSERT" | "UPDATE" | "DELETE" | "MERGE" => K::Write,
        "EXECUTE" if is_word(toks.get(1), "PROCEDURE") => K::ExecuteProcedure,
        "EXECUTE" if is_word(toks.get(1), "BLOCK") => K::ExecuteBlock,
        "GRANT" | "REVOKE" => K::Dcl,
        "CREATE" | "ALTER" | "RECREATE" | "DROP" | "DECLARE" | "COMMENT" => {
            if words_at(toks, 0, &["ALTER", "SESSION", "RESET"]) {
                return K::SessionReset;
            }
            let rest = if words_at(toks, 1, &["OR", "ALTER"]) {
                &toks[3..]
            } else {
                &toks[1..]
            };
            if words_at(rest, 0, &["ROLE"]) {
                K::Dcl
            } else {
                K::Ddl
            }
        }
        "SET" if words_at(toks, 1, &["TRANSACTION"]) => K::Transaction,
        "COMMIT" | "ROLLBACK" if !words_at(toks, 1, &["TO"]) => K::Transaction,
        "ROLLBACK" | "SAVEPOINT" | "RELEASE" => K::Session,
        "SET"
            if words_at(toks, 1, &["BIND"])
                || words_at(toks, 1, &["TIME", "ZONE"])
                || words_at(toks, 1, &["DECFLOAT"])
                || words_at(toks, 1, &["SESSION", "IDLE", "TIMEOUT"])
                || words_at(toks, 1, &["STATEMENT", "TIMEOUT"]) =>
        {
            K::Session
        }
        _ => K::Other,
    }
}

fn flags(toks: &[Tok], a: &mut FirebirdAnalysis) {
    let ddl_head = matches!(toks.first(), Some(Tok::Word(w)) if matches!(w.as_str(), "CREATE" | "ALTER" | "RECREATE"));
    let rest = if ddl_head && words_at(toks, 1, &["OR", "ALTER"]) {
        &toks[3..]
    } else if ddl_head {
        &toks[1..]
    } else {
        &[][..]
    };
    // PSQL bodies.
    if a.kind == FirebirdKind::ExecuteBlock
        || ["PROCEDURE", "TRIGGER", "FUNCTION", "PACKAGE"]
            .iter()
            .any(|w| words_at(rest, 0, &[w]))
    {
        a.psql = true;
    }
    // Server-side copies (decision 6, Signals; R36).
    let db = words_at(toks, 0, &["ALTER", "DATABASE"]) || words_at(toks, 0, &["ALTER", "SCHEMA"]);
    if db {
        for i in 2..toks.len() {
            if words_at(toks, i, &["BEGIN", "BACKUP"])
                || words_at(toks, i, &["ADD", "FILE"])
                || words_at(toks, i, &["ADD", "DIFFERENCE", "FILE"])
            {
                a.backup = true;
            }
        }
    }
    if words_at(rest, 0, &["SHADOW"]) && ddl_head && is_word(toks.first(), "CREATE") {
        a.backup = true;
    }
    // Remote data access.
    for i in 0..toks.len() {
        if words_at(toks, i, &["EXECUTE", "STATEMENT"]) {
            a.execute_statement = true;
        }
        if words_at(toks, i, &["ON", "EXTERNAL"]) {
            a.remote_access = true;
        }
    }
    if ddl_head
        && (words_at(rest, 0, &["TABLE"]) || words_at(rest, 0, &["GLOBAL", "TEMPORARY", "TABLE"]))
        && toks
            .iter()
            .any(|t| matches!(t, Tok::Word(w) if w == "EXTERNAL"))
    {
        a.remote_access = true;
    }
}

/// The relation and procedure names of a DML text, and the calls.
fn names(toks: &[Tok], a: &mut FirebirdAnalysis) {
    // Common table expressions.
    let mut ctes: Vec<String> = Vec::new();
    if is_word(toks.first(), "WITH") {
        let mut i = 1;
        if is_word(toks.get(i), "RECURSIVE") {
            i += 1;
        }
        let mut depth = 0usize;
        let mut expect_name = true;
        while i < toks.len() {
            match &toks[i] {
                Tok::Punct('(') => depth += 1,
                Tok::Punct(')') => depth = depth.saturating_sub(1),
                Tok::Punct(',') if depth == 0 => expect_name = true,
                Tok::Word(w) if depth == 0 && w == "SELECT" => break,
                Tok::Word(w) if depth == 0 && expect_name => {
                    ctes.push(w.clone());
                    expect_name = false;
                }
                Tok::Quoted(q) if depth == 0 && expect_name => {
                    ctes.push(q.clone());
                    expect_name = false;
                }
                _ => {}
            }
            i += 1;
        }
    }
    let ddl = a.kind == FirebirdKind::Ddl || a.kind == FirebirdKind::Dcl;
    let mut truncated = false;
    let mut push = |v: &mut Vec<String>, n: String| {
        if v.contains(&n) {
            return;
        }
        if v.len() < MAX_NAMES {
            v.push(n);
        } else {
            truncated = true;
        }
    };
    // The word that opened each enclosing parenthesis: `FROM` inside
    // `EXTRACT(… FROM …)`, `SUBSTRING`, `TRIM`, `OVERLAY` is no relation.
    let mut openers: Vec<Option<&str>> = Vec::new();
    let mut i = 0usize;
    while i < toks.len() {
        let t = &toks[i];
        match t {
            Tok::Punct('(') => openers.push(match toks.get(i.wrapping_sub(1)) {
                Some(Tok::Word(w)) => Some(w.as_str()),
                _ => None,
            }),
            Tok::Punct(')') => {
                openers.pop();
            }
            _ => {}
        }
        let in_function = matches!(
            openers.last(),
            Some(Some(
                "EXTRACT" | "SUBSTRING" | "TRIM" | "OVERLAY" | "POSITION"
            ))
        );
        let introduces = match t {
            Tok::Word(w) => {
                (matches!(w.as_str(), "FROM" | "JOIN" | "INTO" | "USING")
                    && !in_function
                    && !(w == "FROM" && is_word(toks.get(i.wrapping_sub(1)), "DISTINCT")))
                    || (w == "UPDATE" && i == 0 && !is_word(toks.get(1), "OR"))
                    || (w == "PROCEDURE" && is_word(toks.get(i.wrapping_sub(1)), "EXECUTE"))
            }
            _ => false,
        };
        // A function call: a word followed by `(` outside the contexts
        // above. `pkg.f(` and `schema`-like qualified calls are unknown.
        if let (Tok::Word(w), Some(Tok::Punct('('))) = (t, toks.get(i + 1)) {
            let after_name = i > 0 && is_name_position(toks, i);
            if !after_name && !ddl && !BUILTINS.contains(&w.as_str()) && !introduces {
                a.unknown_call = true;
            }
            if matches!(toks.get(i.wrapping_sub(1)), Some(Tok::Punct('.'))) {
                a.unknown_call = true;
            }
        }
        // A quoted name followed by `(` (`"F"()`, `"P"."F"()`) is a call
        // of code outside the built-in list (review of part 1, M2), unless
        // it stands where a relation name does (`INSERT INTO "T" (…)`).
        if let (Tok::Quoted(_), Some(Tok::Punct('('))) = (t, toks.get(i + 1))
            && !(i > 0 && is_name_position(toks, i))
            && !ddl
        {
            a.unknown_call = true;
        }
        if !introduces || ddl {
            i += 1;
            continue;
        }
        let proc = matches!(t, Tok::Word(w) if w == "PROCEDURE");
        // A relation list: names separated by commas (FROM a, b).
        let mut j = i + 1;
        loop {
            match toks.get(j) {
                Some(Tok::Word(w)) if !is_clause_word(w) => {
                    let called = matches!(toks.get(j + 1), Some(Tok::Punct('(')));
                    if proc || (called && !matches!(t, Tok::Word(w) if w == "INTO")) {
                        push(&mut a.procedures, w.clone());
                    } else if !ctes.contains(w) {
                        push(&mut a.relations, w.clone());
                    }
                }
                Some(Tok::Quoted(q)) => {
                    a.dialects_differ = true;
                    if proc || matches!(toks.get(j + 1), Some(Tok::Punct('('))) {
                        push(&mut a.procedures, q.clone());
                    } else if !ctes.contains(q) {
                        push(&mut a.relations, q.clone());
                    }
                }
                _ => break,
            }
            // Skip an alias and a column list up to the next `,` at the
            // same level; stop at anything else.
            j += 1;
            if matches!(toks.get(j), Some(Tok::Punct('.'))) {
                // A qualified name: not a Firebird 4.0 / 5.0 relation.
                a.dialects_differ = true;
                break;
            }
            if is_word(toks.get(j), "AS") {
                j += 1;
            }
            if matches!(toks.get(j), Some(Tok::Word(w)) if !is_clause_word(w))
                || matches!(toks.get(j), Some(Tok::Quoted(_)))
            {
                j += 1;
            }
            if matches!(toks.get(j), Some(Tok::Punct(','))) && is_word(toks.get(i), "FROM") {
                j += 1;
                continue;
            }
            break;
        }
        i += 1;
    }
    a.names_truncated |= truncated;
}

/// The word at `i` is in a position where a name, not a call, stands:
/// after `INTO` (`INSERT INTO t (cols)`), `TABLE`, `PROCEDURE`, `FROM` or
/// `JOIN` (a selectable procedure, handled as a procedure), or a type
/// name after `AS` / `TYPE OF`.
fn is_name_position(toks: &[Tok], i: usize) -> bool {
    matches!(
        toks.get(i - 1),
        Some(Tok::Word(p)) if matches!(p.as_str(), "INTO" | "TABLE" | "PROCEDURE" | "FROM" | "JOIN" | "USING" | "UPDATE")
    )
}

fn is_clause_word(w: &str) -> bool {
    matches!(
        w,
        "SELECT"
            | "WHERE"
            | "GROUP"
            | "ORDER"
            | "HAVING"
            | "UNION"
            | "JOIN"
            | "LEFT"
            | "RIGHT"
            | "FULL"
            | "INNER"
            | "OUTER"
            | "CROSS"
            | "NATURAL"
            | "ON"
            | "SET"
            | "VALUES"
            | "DEFAULT"
            | "RETURNING"
            | "ROWS"
            | "FETCH"
            | "OFFSET"
            | "FOR"
            | "PLAN"
            | "WITH"
            | "LATERAL"
            | "MATCHING"
            | "WHEN"
            | "WINDOW"
            | "AS"
    )
}

/// The shape of a top-level `SELECT` (decision 6, Signals; R12 item 1).
fn shape(toks: &[Tok], a: &mut FirebirdAnalysis) {
    if a.kind != FirebirdKind::Select {
        return;
    }
    // The main SELECT: after the CTEs.
    let mut start = 0usize;
    let mut depth = 0usize;
    if is_word(toks.first(), "WITH") {
        for (k, t) in toks.iter().enumerate() {
            match t {
                Tok::Punct('(') => depth += 1,
                Tok::Punct(')') => depth = depth.saturating_sub(1),
                Tok::Word(w) if depth == 0 && w == "SELECT" => {
                    start = k;
                    break;
                }
                _ => {}
            }
        }
    }
    let main = &toks[start..];
    let mut depth = 0usize;
    let (mut filtered, mut grouped, mut set_op, mut limited) = (false, false, false, false);
    let mut from_at = None;
    for (k, t) in main.iter().enumerate() {
        match t {
            Tok::Punct('(') => depth += 1,
            Tok::Punct(')') => depth = depth.saturating_sub(1),
            Tok::Word(w) if depth == 0 => match w.as_str() {
                "WHERE" => filtered = true,
                "GROUP" | "HAVING" => grouped = true,
                "UNION" | "INTERSECT" | "EXCEPT" => set_op = true,
                "FROM" if from_at.is_none() => from_at = Some(k),
                "FIRST" | "ROWS" => {
                    limited |= small_limit(main.get(k + 1));
                }
                "FETCH" if matches!(main.get(k + 1), Some(Tok::Word(n)) if n == "FIRST" || n == "NEXT") =>
                {
                    limited |= small_limit(main.get(k + 2));
                }
                _ => {}
            },
            _ => {}
        }
    }
    // The select list: between SELECT and FROM at the top level.
    let list = &main[1..from_at.unwrap_or(main.len()).max(1)];
    let mut aggregate = false;
    let mut only_aggregates_and_constants = !list.is_empty();
    let mut d = 0usize;
    let mut k = 0usize;
    while k < list.len() {
        match &list[k] {
            Tok::Punct('(') => d += 1,
            Tok::Punct(')') => d = d.saturating_sub(1),
            Tok::Word(w) if d == 0 => {
                if AGGREGATES.contains(&w.as_str())
                    && matches!(list.get(k + 1), Some(Tok::Punct('(')))
                {
                    aggregate = true;
                } else if !matches!(w.as_str(), "AS" | "DISTINCT" | "ALL") {
                    // An alias after an aggregate is allowed.
                    let alias = matches!(
                        list.get(k.wrapping_sub(1)),
                        Some(Tok::Punct(')') | Tok::Word(_))
                    );
                    if !alias {
                        only_aggregates_and_constants = false;
                    }
                }
            }
            Tok::Literal | Tok::Number(_) | Tok::Punct(',' | '*' | '+' | '-' | '/') if d == 0 => {}
            // A quoted name is a column or a call, not a constant
            // (review of part 1, M2).
            Tok::Quoted(_) if d == 0 => only_aggregates_and_constants = false,
            _ if d > 0 => {}
            _ => only_aggregates_and_constants = false,
        }
        k += 1;
    }
    a.aggregate_only =
        aggregate && only_aggregates_and_constants && !grouped && !set_op && from_at.is_some();
    a.unrestricted_select = from_at.is_some() && !filtered && !grouped && !aggregate && !limited;
}

/// A row limit of at most [`FULL_READ_LIMIT`] rows (a parameter or an
/// expression is not known to be small: fail closed).
fn small_limit(t: Option<&Tok>) -> bool {
    matches!(t, Some(Tok::Number(Some(n))) if *n <= FULL_READ_LIMIT)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use proptest::prelude::*;

    fn a(t: &str) -> FirebirdAnalysis {
        analyze_firebird(t)
    }

    #[test]
    fn kinds() {
        use FirebirdKind as K;
        for (t, k) in [
            ("SELECT * FROM T", K::Select),
            (
                "with c as (select 1 x from rdb$database) select * from c",
                K::Select,
            ),
            ("INSERT INTO T (ID) VALUES (3)", K::Write),
            (
                "update or insert into t (id) values (1) matching (id)",
                K::Write,
            ),
            ("DELETE FROM T WHERE ID = 1", K::Write),
            ("EXECUTE PROCEDURE P(1)", K::ExecuteProcedure),
            ("EXECUTE BLOCK AS BEGIN END", K::ExecuteBlock),
            ("CREATE TABLE T (ID INT)", K::Ddl),
            ("GRANT SELECT ON T TO R", K::Dcl),
            ("CREATE ROLE R", K::Dcl),
            ("SET TRANSACTION READ ONLY", K::Transaction),
            ("COMMIT", K::Transaction),
            ("ROLLBACK", K::Transaction),
            ("ROLLBACK TO SAVEPOINT S", K::Session),
            ("ALTER SESSION RESET", K::SessionReset),
            ("SET SESSION IDLE TIMEOUT 2 MINUTE", K::Session),
            ("SET BIND OF DECFLOAT TO DOUBLE PRECISION", K::Session),
            ("", K::Other),
        ] {
            assert_eq!(a(t).kind, k, "{t}");
        }
        assert!(K::Transaction.cannot_read() && !K::Select.cannot_read());
    }

    /// The #82 rule: password-bearing and identity statements keep their
    /// kind only.
    #[test]
    fn password_bearing_statements_keep_their_kind_only() {
        for t in [
            "CREATE USER MARKERUSER PASSWORD 'marker-password-1'",
            "alter user u password 'x'",
            "CREATE OR ALTER USER U PASSWORD 'x' USING PLUGIN Srp",
            "ALTER CURRENT USER SET PASSWORD 'x'",
            "CREATE DATABASE '/x.fdb' USER 'a' PASSWORD 'b'",
            "CONNECT '/x.fdb' USER 'a' PASSWORD 'b'",
            "CREATE MAPPING M USING PLUGIN SRP FROM USER A TO USER B",
        ] {
            let r = a(t);
            assert!(r.credential, "{t}");
            assert_eq!(r.kind, FirebirdKind::Dcl, "{t}");
            assert!(r.relations.is_empty() && r.procedures.is_empty(), "{t}");
        }
        // Review of part 1, M3: a PASSWORD word elsewhere keeps the kind
        // and the flags; only the names go.
        let r = a(
            "EXECUTE BLOCK AS DECLARE X INT; BEGIN EXECUTE STATEMENT 'select 1 from t' ON EXTERNAL 'h:/d' AS USER 'u' PASSWORD 'marker' INTO :X; END",
        );
        assert!(r.credential && r.remote_access && r.psql);
        assert_eq!(r.kind, FirebirdKind::ExecuteBlock);
        let r = a("SELECT C.*, 1 AS PASSWORD FROM SECRET C");
        assert!(r.credential && r.unrestricted_select && r.relations.is_empty());
        assert_eq!(r.kind, FirebirdKind::Select);
    }

    /// Review of part 1, M2: quoted calls are code.
    #[test]
    fn quoted_calls_are_code() {
        assert!(a("SELECT \"F\"() FROM MON$DATABASE").unknown_call);
        assert!(a("SELECT \"P\".\"F\"(1) FROM T").unknown_call);
        assert!(!a("INSERT INTO \"T\" (A) VALUES (1)").unknown_call);
        let r = a("SELECT COUNT(*), \"F\"(1) FROM T_EMPTY");
        assert!(r.unknown_call && !r.aggregate_only);
        assert!(!a("SELECT COUNT(*), \"X\" FROM T").aggregate_only);
    }

    #[test]
    fn placeholders_outside_literals() {
        assert_eq!(
            a("SELECT * FROM T WHERE A = ? AND B = '?' /* ? */").placeholders,
            1
        );
        assert_eq!(a("SELECT 1 FROM T").placeholders, 0);
    }

    /// R36: the four server-side copy forms, with or without comments and
    /// in any case.
    #[test]
    fn backup_forms() {
        for t in [
            "ALTER DATABASE BEGIN BACKUP",
            "alter database /* x */ begin backup",
            "CREATE SHADOW 1 '/tmp/app.shd'",
            "ALTER DATABASE ADD FILE '/tmp/app2.fdb'",
            "ALTER DATABASE ADD DIFFERENCE FILE '/tmp/app.delta'",
            "ALTER SCHEMA BEGIN BACKUP",
        ] {
            assert!(a(t).backup, "{t}");
        }
        for t in [
            "ALTER DATABASE END BACKUP",
            "ALTER DATABASE DROP DIFFERENCE FILE",
            "DROP SHADOW 1",
            "SELECT 'ALTER DATABASE BEGIN BACKUP' FROM RDB$DATABASE",
            "-- ALTER DATABASE BEGIN BACKUP\nSELECT 1 FROM RDB$DATABASE",
        ] {
            assert!(!a(t).backup, "{t}");
        }
    }

    #[test]
    fn remote_access_and_code() {
        let r = a("CREATE TABLE EXT_EXPORT EXTERNAL FILE '/x' (A CHAR(10))");
        assert!(r.remote_access);
        let r = a("EXECUTE BLOCK AS BEGIN EXECUTE STATEMENT 'x' ON EXTERNAL DATA SOURCE 'y'; END");
        assert!(r.remote_access && r.psql && r.execute_statement && r.calls_code());
        let r = a("SELECT MY_UDF(X) FROM T");
        assert!(r.unknown_call && r.calls_code());
        let r = a("SELECT PKG.F(X) FROM T");
        assert!(r.unknown_call);
        let r = a(
            "SELECT COUNT(*), CAST(X AS VARCHAR(10)), SUBSTRING(Y FROM 1 FOR 2), EXTRACT(YEAR FROM D) FROM T",
        );
        assert!(!r.unknown_call, "{r:?}");
        assert_eq!(r.relations, ["T"]);
        let r = a("SELECT * FROM SEL_PROC(1)");
        assert_eq!(r.procedures, ["SEL_PROC"]);
        assert!(r.relations.is_empty() && r.calls_code());
        let r = a("EXECUTE PROCEDURE P1");
        assert_eq!(r.procedures, ["P1"]);
        let r = a("CREATE PROCEDURE P AS BEGIN SELECT 1 FROM T INTO :X; END");
        assert!(r.psql && r.relations.is_empty());
    }

    #[test]
    fn relations_and_dialects() {
        let r = a(
            "SELECT a.x FROM customers a JOIN orders o ON o.c = a.id WHERE a.id IN (SELECT id FROM vip)",
        );
        assert_eq!(r.relations, ["CUSTOMERS", "ORDERS", "VIP"]);
        assert!(r.parses());
        let r = a("SELECT * FROM t1, t2 x, t3");
        assert_eq!(r.relations, ["T1", "T2", "T3"]);
        let r = a("INSERT INTO T (ID) VALUES (3)");
        assert_eq!(r.relations, ["T"]);
        let r = a("UPDATE T SET A = 1");
        assert_eq!(r.relations, ["T"]);
        let r = a("MERGE INTO T USING S ON T.ID = S.ID WHEN MATCHED THEN DELETE");
        assert_eq!(r.relations, ["T", "S"]);
        let r = a("WITH c AS (SELECT * FROM base) SELECT * FROM c");
        assert_eq!(r.relations, ["BASE"]);
        let r = a("SELECT * FROM \"Customer Notes\"");
        assert_eq!(r.relations, ["Customer Notes"]);
        assert!(r.dialects_differ && !r.parses());
        let r = a("SELECT \"x\" FROM T WHERE A IS DISTINCT FROM B");
        assert_eq!(r.relations, ["T"]);
        assert!(!r.dialects_differ);
    }

    #[test]
    fn literals_and_comments_are_never_names() {
        for t in [
            "SELECT 'FROM SECRET' FROM T",
            "SELECT q'{FROM SECRET}' FROM T",
            "SELECT q'!FROM SECRET!' FROM T",
            "SELECT x'46524F4D' FROM T",
            "SELECT _UTF8 'FROM SECRET' FROM T",
            "SELECT 1 /* FROM SECRET */ FROM T -- FROM SECRET",
            "SELECT n'FROM SECRET' FROM T",
        ] {
            let r = a(t);
            assert_eq!(r.relations, ["T"], "{t}");
            assert!(r.parses(), "{t}");
        }
        for t in [
            "SELECT 'abc FROM T",
            "SELECT /* x FROM T",
            "SELECT \"x FROM T",
            "SELECT q'(x) FROM T",
        ] {
            let r = a(t);
            assert!(r.unterminated, "{t}");
            assert!(r.relations.is_empty(), "{t}");
        }
    }

    #[test]
    fn shapes() {
        assert!(a("SELECT * FROM T").unrestricted_select);
        assert!(a("SELECT FIRST 20000 * FROM T").unrestricted_select);
        assert!(a("SELECT * FROM T ROWS ?").unrestricted_select);
        assert!(!a("SELECT FIRST 10 * FROM T").unrestricted_select);
        assert!(!a("SELECT * FROM T FETCH FIRST 100 ROWS ONLY").unrestricted_select);
        assert!(!a("SELECT * FROM T ROWS 5").unrestricted_select);
        assert!(!a("SELECT * FROM T WHERE ID = 1").unrestricted_select);
        assert!(!a("SELECT COUNT(*) FROM T").unrestricted_select);
        assert!(!a("SELECT A, COUNT(*) FROM T GROUP BY A").unrestricted_select);
        assert!(!a("INSERT INTO T VALUES (1)").unrestricted_select);
        assert!(a("SELECT COUNT(*) FROM T_EMPTY").aggregate_only);
        assert!(a("SELECT COUNT(*) AS N, MAX(X) FROM T").aggregate_only);
        assert!(!a("SELECT COUNT(*), A FROM T").aggregate_only);
        assert!(!a("SELECT A, COUNT(*) FROM T GROUP BY A").aggregate_only);
        assert!(!a("SELECT COUNT(*) FROM T UNION SELECT COUNT(*) FROM U").aggregate_only);
        assert!(!a("SELECT * FROM T").aggregate_only);
    }

    proptest! {
        #[test]
        fn arbitrary_text_never_panics(t in "\\PC{0,300}") {
            let _ = analyze_firebird(&t);
        }

        /// A literal's content never becomes a name.
        #[test]
        fn literal_content_is_never_a_name(v in "[A-Za-z0-9 ,()]{0,40}") {
            let r = analyze_firebird(&format!("SELECT '{}' FROM T", v.replace('\'', "''")));
            prop_assert_eq!(r.relations, vec!["T".to_owned()]);
        }
    }
}
