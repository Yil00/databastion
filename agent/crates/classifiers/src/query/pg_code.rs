//! The code a PostgreSQL text runs besides reading relations (ADR-0049
//! decision 8): the functions it calls, the operators it applies and the
//! types it casts to, as written, for a caller that holds the per-version
//! built-in lists and the per-database collision probe
//! (`connector-postgres`). Version-independent grammar facts only: which
//! keywords are reserved in a given major version is the caller's
//! business.
//!
//! Like [`super::pg_scan`], the scan reads identifier and operator tokens
//! only, never the content of a literal or a comment, and keeps names only
//! (folded or decoded as the server does). It is deliberately coarse and
//! errs on the side of reporting: a construct it does not recognize is
//! reported as a call, an operator or a type, which the caller then finds
//! not built in (`*`). Only grammar positions that cannot be a function
//! call, an operator or a type are left out (an alias with its column
//! list, `ORDER BY (`, `FILTER (`, `OVER (`, `GROUP BY CUBE (`…).
//!
//! Queries (`SELECT`, `TABLE`, `VALUES`, `INSERT`, `UPDATE`, `DELETE`,
//! `MERGE`, `WITH …`) are scanned whole; the statements that wrap a query
//! (`EXPLAIN`, `PREPARE … AS`, `DECLARE … CURSOR FOR`, `CREATE TABLE /
//! MATERIALIZED VIEW … AS`, `COPY (…) TO`) from their query on, with a
//! `PREPARE`'s parameter types; `COPY` of a relation not at all; every
//! other statement whole (fail closed). The body of a `DO` block is not
//! scanned: its statements reach the sources as statements of their own.

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::pg_scan::{NameAt, PgScan, Segment, close_of, ident};
use super::{MAX_DEPTH, RelationName, Tok, is_punct, main_start, word};

/// Most distinct names kept per kind (calls, operators, types); beyond,
/// [`PgCode::overflow`] is set and the caller fails closed.
pub const MAX_CODE_NAMES: usize = 256;

/// A function or type name in a code position.
#[derive(Clone, PartialEq, Eq)]
pub struct PgCodeName {
    /// The name (its last part) and its schema when qualified.
    pub name: RelationName,
    /// The last part was a quoted identifier: never a keyword.
    pub quoted: bool,
    /// Calls: the name follows an operand (`x LIKE (…)`, `a JOIN (…)`),
    /// where a type-or-function-name keyword is infix syntax.
    pub after_operand: bool,
}

impl fmt::Debug for PgCodeName {
    // Names are metadata but may embed values: never printed as is.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PgCodeName")
    }
}

/// An operator as written: a symbol (`=`, `+`, `~~` implied by `LIKE`…),
/// with the schema of `OPERATOR(schema.op)` when given.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PgOperatorUse {
    /// `OPERATOR(schema.op)`: the schema.
    pub schema: Option<String>,
    /// The symbol; empty for an `OPERATOR(…)` form the scan cannot read.
    pub symbol: String,
}

impl fmt::Debug for PgOperatorUse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PgOperatorUse")
    }
}

/// The code uses of a text ([`PgScan::code`]).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PgCode {
    /// Every `name(` that may be a function call (keywords included: the
    /// caller tells grammar forms apart per version).
    pub calls: Vec<PgCodeName>,
    /// Operators, written or implied by a keyword (`LIKE` is `~~`, `IN`,
    /// `CASE`, `NULLIF`, `IS DISTINCT FROM`, `USING (…)` and `NATURAL` are
    /// `=` (a simple `CASE x WHEN`), `BETWEEN` is `>=` and `<=`…).
    pub operators: Vec<PgOperatorUse>,
    /// Target types of casts (`::t`, `CAST(… AS t)`, `TREAT`,
    /// `XMLSERIALIZE`, `RETURNING t` of the SQL/JSON functions, the types of
    /// a column definition list) and of typed literals (`t '…'`). For a
    /// multi-word type, its first word (`double precision` excepted). An
    /// empty name: a type position the scan could not read.
    pub types: Vec<PgCodeName>,
    /// A bound parameter (`$n`): its type is the client's, not the text's.
    pub params: bool,
    /// A construct that coerces values with no call, operator or cast in
    /// the text (`UNION`, `CASE`, `VALUES`, `COALESCE`, `ARRAY`, `INSERT`,
    /// `UPDATE`…).
    pub coercion: bool,
    /// More than [`MAX_CODE_NAMES`] distinct names of a kind.
    pub overflow: bool,
}

impl fmt::Debug for PgCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgCode")
            .field("calls", &self.calls.len())
            .field("operators", &self.operators.len())
            .field("types", &self.types.len())
            .field("params", &self.params)
            .field("coercion", &self.coercion)
            .field("overflow", &self.overflow)
            .finish()
    }
}

impl PgCode {
    /// Whether the text uses no code at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
            && self.operators.is_empty()
            && self.types.is_empty()
            && !self.coercion
            && !self.overflow
    }

    fn push_call(&mut self, c: PgCodeName) {
        if !self.calls.contains(&c) {
            if self.calls.len() >= MAX_CODE_NAMES {
                self.overflow = true;
            } else {
                self.calls.push(c);
            }
        }
    }

    fn push_type(&mut self, c: PgCodeName) {
        if !self.types.contains(&c) {
            if self.types.len() >= MAX_CODE_NAMES {
                self.overflow = true;
            } else {
                self.types.push(c);
            }
        }
    }

    fn push_operator(&mut self, schema: Option<String>, symbol: &str) {
        let o = PgOperatorUse {
            schema,
            symbol: symbol.to_owned(),
        };
        if !self.operators.contains(&o) {
            if self.operators.len() >= MAX_CODE_NAMES {
                self.overflow = true;
            } else {
                self.operators.push(o);
            }
        }
    }
}

impl PgScan {
    /// The code uses of the text's query statements (see the module
    /// documentation).
    #[must_use]
    pub fn code(&self) -> PgCode {
        let mut out = PgCode::default();
        if let Some(seg) = self.segments.first() {
            code_of(seg, &mut out);
        }
        out
    }

    /// Whether a statement of the text (or of its `DO` block) creates,
    /// replaces, alters or drops a function, procedure, routine, aggregate,
    /// operator, type, domain, cast or extension, or drops a schema, owned
    /// objects or anything with `CASCADE` (ADR-0049 decision 8: the
    /// collision probe of that database is stale).
    #[must_use]
    pub fn routine_ddl(&self) -> bool {
        self.segments.iter().any(|s| {
            statement_ranges(&s.tokens)
                .into_iter()
                .any(|(a, b)| routine_ddl_at(&s.tokens[a..b]))
        })
    }
}

/// PostgreSQL's reserved keywords on any supported version (14 to 18):
/// never a bare alias, a column or a generic function or type name.
fn reserved(w: &str) -> bool {
    matches!(
        w,
        "all"
            | "analyse"
            | "analyze"
            | "and"
            | "any"
            | "array"
            | "as"
            | "asc"
            | "asymmetric"
            | "both"
            | "case"
            | "cast"
            | "check"
            | "collate"
            | "column"
            | "constraint"
            | "create"
            | "current_catalog"
            | "current_date"
            | "current_role"
            | "current_time"
            | "current_timestamp"
            | "current_user"
            | "default"
            | "deferrable"
            | "desc"
            | "distinct"
            | "do"
            | "else"
            | "end"
            | "except"
            | "false"
            | "fetch"
            | "for"
            | "foreign"
            | "from"
            | "grant"
            | "group"
            | "having"
            | "in"
            | "initially"
            | "intersect"
            | "into"
            | "lateral"
            | "leading"
            | "limit"
            | "localtime"
            | "localtimestamp"
            | "not"
            | "null"
            | "offset"
            | "on"
            | "only"
            | "or"
            | "order"
            | "placing"
            | "primary"
            | "references"
            | "returning"
            | "select"
            | "session_user"
            | "some"
            | "symmetric"
            | "system_user"
            | "table"
            | "then"
            | "to"
            | "trailing"
            | "true"
            | "union"
            | "unique"
            | "user"
            | "using"
            | "variadic"
            | "when"
            | "where"
            | "window"
            | "with"
    )
}

/// Non-reserved words that stand before an expression in the grammar
/// (`ORDER BY x`, `x ESCAPE y`, `AT TIME ZONE x`, `x BETWEEN y`): what
/// follows them is not "after an operand".
fn leads_expression(w: &str) -> bool {
    reserved(w)
        || matches!(
            w,
            "by" | "escape"
                | "uescape"
                | "zone"
                | "at"
                | "set"
                | "partition"
                | "preceding"
                | "following"
                | "nulls"
                | "first"
                | "last"
                | "next"
                | "cube"
                | "rollup"
                | "sets"
                | "return"
                | "recursive"
                | "materialized"
                | "over"
                | "filter"
                | "rows"
                | "range"
                | "groups"
                | "between"
                | "like"
                | "ilike"
                | "similar"
                | "is"
                | "isnull"
                | "notnull"
                | "overlaps"
                | "join"
                | "exists"
                | "values"
                | "row"
                | "operator"
        )
}

/// Whether `t` ends an operand (`x`, `'…'`, `1`, `$1`, `)`, `]`).
fn operand_end(t: Option<&Tok>) -> bool {
    match t {
        Some(Tok::Quoted(_) | Tok::Literal | Tok::Int(_) | Tok::Param) => true,
        Some(Tok::Punct(p)) => p == ")" || p == "]",
        Some(Tok::Word(w)) => !leads_expression(w),
        _ => false,
    }
}

/// An operator token (only operator characters).
fn is_operator(p: &str) -> bool {
    !p.is_empty()
        && p.bytes().all(|b| {
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
        })
}

/// Splits an operator token as PostgreSQL's lexer does: a multi-character
/// operator cannot end in `+` or `-` unless it holds one of
/// `~ ! @ # % ^ & | \` ?` (`=-1` is `=` then `-`).
fn split_operator(p: &str) -> Vec<&str> {
    let special = p.bytes().any(|b| {
        matches!(
            b,
            b'~' | b'!' | b'@' | b'#' | b'%' | b'^' | b'&' | b'|' | b'`' | b'?'
        )
    });
    if special || p.len() <= 1 {
        return vec![p];
    }
    let mut end = p.len();
    while end > 1 && matches!(p.as_bytes()[end - 1], b'+' | b'-') {
        end -= 1;
    }
    let mut out = vec![&p[..end]];
    for k in end..p.len() {
        out.push(&p[k..=k]);
    }
    out
}

/// Top-level statements of `t` (`;`-separated, non-empty), as ranges.
fn statement_ranges(t: &[Tok]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    for (i, x) in t.iter().enumerate() {
        match x {
            Tok::Punct(p) if p == "(" || p == "[" => depth += 1,
            Tok::Punct(p) if p == ")" || p == "]" => depth = depth.saturating_sub(1),
            Tok::Punct(p) if p == ";" && depth == 0 => {
                if i > start {
                    out.push((start, i));
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    if t.len() > start {
        out.push((start, t.len()));
    }
    out
}

/// A `CREATE` / `ALTER` / `DROP` of an object that changes how a name
/// resolves to code ([`PgScan::routine_ddl`]), anywhere in the statement
/// (a PL/pgSQL body puts `BEGIN` or a label first).
fn routine_ddl_at(s: &[Tok]) -> bool {
    let mut drop = false;
    for k in 0..s.len() {
        let lead = word(s.get(k));
        if !matches!(lead, Some("create" | "alter" | "drop"))
            || is_punct(s.get(k.wrapping_sub(1)), ".")
        {
            continue;
        }
        drop |= lead == Some("drop");
        let mut j = k + 1;
        if lead == Some("create")
            && word(s.get(j)) == Some("or")
            && word(s.get(j + 1)) == Some("replace")
        {
            j += 2;
        }
        if matches!(
            word(s.get(j)),
            Some(
                "function"
                    | "procedure"
                    | "routine"
                    | "aggregate"
                    | "operator"
                    | "type"
                    | "domain"
                    | "cast"
                    | "extension"
            )
        ) || (lead == Some("drop") && matches!(word(s.get(j)), Some("owned" | "schema")))
        {
            return true;
        }
    }
    drop && s.iter().any(|t| word(Some(t)) == Some("cascade"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A parenthesized expression, subquery or list.
    Group,
    /// The arguments of a call.
    Call,
    /// `CAST(`, `TREAT(`, `XMLSERIALIZE(`: `AS` introduces a type.
    Cast,
    /// `XMLPARSE(`: `DOCUMENT` / `CONTENT` first.
    XmlParse,
    /// `XMLROOT(`: `VERSION '…'`.
    XmlRoot,
    /// A column alias or column definition list (`AS t (a int, b text)`).
    Defs,
}

struct Frame {
    kind: Kind,
    /// Within a `GROUP BY` clause (`CUBE (`, `ROLLUP (` are grammar).
    group_by: bool,
    /// Within a `WITH` list (`, x (c) AS (` is a CTE column list).
    with_list: bool,
}

impl Frame {
    fn new(kind: Kind) -> Self {
        Self {
            kind,
            group_by: false,
            with_list: false,
        }
    }
}

/// The scan state of one statement.
struct Scan<'a> {
    t: &'a [Tok],
    lo: usize,
    hi: usize,
    by_start: &'a HashMap<usize, &'a NameAt>,
    aliases: &'a HashSet<usize>,
    frames: Vec<Frame>,
    /// The kind of the frame the next `(` opens.
    pending: Option<Kind>,
}

/// Where the code of the statement `t[a..b]` is: the range to scan, and
/// the type positions of a `PREPARE` parameter list. A query is scanned
/// whole; a statement that wraps one (`EXPLAIN [ANALYZE] [(…)]`,
/// `PREPARE p [(types)] AS`, `DECLARE c … CURSOR … FOR`, `CREATE … TABLE /
/// MATERIALIZED VIEW … AS`) from its query on (security review of #211,
/// H1: the query runs, or is planned with its immutable and stable calls
/// folded); `COPY (query)` its query; `COPY` of a relation nothing (its
/// options are keywords and literals); any other statement whole (fail
/// closed).
fn scope(
    t: &[Tok],
    a: usize,
    b: usize,
    depth: usize,
    types: &mut Vec<usize>,
) -> Option<(usize, usize)> {
    let s = &t[a..b];
    let m = main_start(s)?;
    let i = a + m;
    if depth > 8 {
        return Some((a, b));
    }
    match word(t.get(i)) {
        Some("select" | "table" | "values" | "insert" | "update" | "delete" | "merge" | "with") => {
            Some((a, b))
        }
        Some("copy") => {
            if is_punct(t.get(i + 1), "(") {
                Some((i + 2, close_of(t, i + 1).saturating_sub(1).min(b)))
            } else {
                None
            }
        }
        Some("explain") => {
            let mut j = i + 1;
            while matches!(word(t.get(j)), Some("analyze" | "analyse" | "verbose")) {
                j += 1;
            }
            if is_punct(t.get(j), "(") {
                j = close_of(t, j);
            }
            if j >= b {
                return Some((a, b));
            }
            scope(t, j, b, depth + 1, types)
        }
        Some("prepare") => {
            let mut j = i + 2;
            if is_punct(t.get(j), "(") {
                // `PREPARE p (type, …)`: each entry starts a type.
                let close = close_of(t, j).min(b);
                types.push(j + 1);
                let mut d = 0usize;
                for (k, x) in t
                    .iter()
                    .enumerate()
                    .take(close.saturating_sub(1))
                    .skip(j + 1)
                {
                    match x {
                        Tok::Punct(p) if p == "(" || p == "[" => d += 1,
                        Tok::Punct(p) if p == ")" || p == "]" => d = d.saturating_sub(1),
                        Tok::Punct(p) if p == "," && d == 0 => types.push(k + 1),
                        _ => {}
                    }
                }
                j = close;
            }
            if word(t.get(j)) == Some("as") && j + 1 < b {
                scope(t, j + 1, b, depth + 1, types)
            } else {
                Some((a, b))
            }
        }
        Some("declare") => match top_level_word(t, i + 1, b, &["for"]) {
            Some(f) if f + 1 < b => scope(t, f + 1, b, depth + 1, types),
            _ => Some((a, b)),
        },
        Some("create") => {
            let creates_relation = t[i..b]
                .iter()
                .take(8)
                .any(|x| matches!(word(Some(x)), Some("table" | "materialized")));
            match creates_relation
                .then(|| top_level_query_as(t, i + 1, b))
                .flatten()
            {
                Some(k) => scope(t, k + 1, b, depth + 1, types),
                None => Some((a, b)),
            }
        }
        _ => Some((a, b)),
    }
}

/// The first of `words` at parenthesis depth 0 in `t[from..to]`.
fn top_level_word(t: &[Tok], from: usize, to: usize, words: &[&str]) -> Option<usize> {
    let mut d = 0usize;
    for (k, x) in t.iter().enumerate().take(to).skip(from) {
        match x {
            Tok::Punct(p) if p == "(" || p == "[" => d += 1,
            Tok::Punct(p) if p == ")" || p == "]" => d = d.saturating_sub(1),
            Tok::Word(w) if d == 0 && words.contains(&w.as_str()) => return Some(k),
            _ => {}
        }
    }
    None
}

/// The `AS` of `CREATE … AS <query>` at depth 0 in `t[from..to]`: one
/// followed by a query (`SELECT`, `WITH`, `VALUES`, `TABLE`, `EXECUTE`,
/// `(`).
fn top_level_query_as(t: &[Tok], from: usize, to: usize) -> Option<usize> {
    let mut d = 0usize;
    for (k, x) in t.iter().enumerate().take(to).skip(from) {
        match x {
            Tok::Punct(p) if p == "(" || p == "[" => d += 1,
            Tok::Punct(p) if p == ")" || p == "]" => d = d.saturating_sub(1),
            Tok::Word(w) if d == 0 && w == "as" => {
                let next = t.get(k + 1);
                if is_punct(next, "(")
                    || matches!(
                        word(next),
                        Some("select" | "with" | "values" | "table" | "execute")
                    )
                {
                    return Some(k);
                }
            }
            _ => {}
        }
    }
    None
}

fn code_of(seg: &Segment, out: &mut PgCode) {
    let t = &seg.tokens;
    let by_start: HashMap<usize, &NameAt> = seg.names.iter().map(|n| (n.start, n)).collect();
    let aliases: HashSet<usize> = seg.aliases.iter().copied().collect();
    for (a, b) in statement_ranges(t) {
        let mut types = Vec::new();
        let Some((lo, hi)) = scope(t, a, b, 0, &mut types) else {
            continue;
        };
        if !types.is_empty() {
            // The `PREPARE` parameter types (before its query).
            let mut scan = Scan {
                t,
                lo: a,
                hi: b,
                by_start: &by_start,
                aliases: &aliases,
                frames: vec![Frame::new(Kind::Group)],
                pending: None,
            };
            for j in types {
                scan.type_at(j, out);
            }
        }
        let mut scan = Scan {
            t,
            lo,
            hi,
            by_start: &by_start,
            aliases: &aliases,
            frames: vec![Frame::new(Kind::Group)],
            pending: None,
        };
        scan.run(out);
    }
}

impl<'a> Scan<'a> {
    fn prev(&self, i: usize) -> Option<&'a Tok> {
        let t: &'a [Tok] = self.t;
        if i > self.lo { t.get(i - 1) } else { None }
    }

    fn at(&self, i: usize) -> Option<&'a Tok> {
        let t: &'a [Tok] = self.t;
        if i < self.hi { t.get(i) } else { None }
    }

    fn top(&self) -> Kind {
        self.frames.last().map_or(Kind::Group, |f| f.kind)
    }

    fn run(&mut self, out: &mut PgCode) {
        let mut i = self.lo;
        while i < self.hi {
            i = self.step(i, out);
        }
    }

    /// Handles the token at `i`; returns the index of the next one.
    #[allow(clippy::too_many_lines)]
    fn step(&mut self, i: usize, out: &mut PgCode) -> usize {
        let t = self.t;
        let prev = self.prev(i);
        match &t[i] {
            Tok::Param => out.params = true,
            Tok::Punct(p) => match p.as_str() {
                "(" => {
                    let kind = self.pending.take().unwrap_or(Kind::Group);
                    if self.frames.len() < MAX_DEPTH {
                        self.frames.push(Frame::new(kind));
                    }
                }
                ")" => {
                    if self.frames.len() > 1 {
                        self.frames.pop();
                    }
                }
                ":" if is_punct(self.at(i + 1), ":") => return self.type_at(i + 2, out),
                _ if is_operator(p) => self.operator(p, prev, out),
                _ => {}
            },
            Tok::Word(w) if !is_punct(prev, ".") => {
                let next = self.at(i + 1);
                match w.as_str() {
                    "operator" if is_punct(next, "(") => return self.operator_form(i + 1, out),
                    "as" if self.top() == Kind::Cast => return self.type_at(i + 1, out),
                    "returning" if self.top() == Kind::Call => return self.type_at(i + 1, out),
                    "as" => {
                        // `f(…) AS (a int, …)`: a column definition list
                        // (not `AS (query)` of a CTE).
                        if is_punct(prev, ")")
                            && is_punct(next, "(")
                            && !matches!(
                                word(self.at(i + 2)),
                                Some(
                                    "select"
                                        | "with"
                                        | "values"
                                        | "table"
                                        | "insert"
                                        | "update"
                                        | "delete"
                                        | "merge"
                                )
                            )
                        {
                            self.pending = Some(Kind::Defs);
                        }
                    }
                    "like" => {
                        out.push_operator(None, "~~");
                        out.push_operator(None, "!~~");
                    }
                    "ilike" => {
                        out.push_operator(None, "~~*");
                        out.push_operator(None, "!~~*");
                    }
                    "similar" if word(next) == Some("to") => {
                        out.push_operator(None, "~");
                        out.push_operator(None, "!~");
                    }
                    "between" => {
                        out.coercion = true;
                        for o in [">=", "<=", "<", ">"] {
                            out.push_operator(None, o);
                        }
                    }
                    "in" => {
                        out.coercion = true;
                        out.push_operator(None, "=");
                        out.push_operator(None, "<>");
                    }
                    "distinct" if word(prev) == Some("is") || word(prev) == Some("not") => {
                        out.push_operator(None, "=");
                    }
                    // A simple `CASE x WHEN` compares with `=`; a searched
                    // `CASE WHEN` does not.
                    "case" => {
                        out.coercion = true;
                        if word(next) != Some("when") {
                            out.push_operator(None, "=");
                        }
                    }
                    "nullif" => {
                        out.coercion = true;
                        out.push_operator(None, "=");
                    }
                    "using" if is_punct(next, "(") => out.push_operator(None, "="),
                    "natural" => out.push_operator(None, "="),
                    "union" | "intersect" | "except" | "values" | "coalesce" | "greatest"
                    | "least" | "array" | "insert" | "update" | "merge" => out.coercion = true,
                    _ => {}
                }
                if let Some(f) = self.frames.last_mut() {
                    match w.as_str() {
                        "group" if word(next) == Some("by") => f.group_by = true,
                        "having" | "window" | "order" | "limit" | "offset" | "fetch" | "for"
                        | "union" | "intersect" | "except" | "returning" => f.group_by = false,
                        "with" if !matches!(word(next), Some("ordinality" | "time")) => {
                            f.with_list = true;
                        }
                        "select" | "insert" | "update" | "delete" | "merge" | "values"
                        | "table" => {
                            f.with_list = false;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        // A column definition list: `name type` entries.
        if self.top() == Kind::Defs
            && (is_punct(prev, "(") || is_punct(prev, ","))
            && ident(self.at(i)).is_some()
            && ident(self.at(i + 1)).is_some()
        {
            return self.type_at(i + 1, out);
        }
        if let Some(&n) = self.by_start.get(&i)
            && !is_punct(prev, ".")
        {
            return self.name_at(n, out);
        }
        i + 1
    }

    /// A written operator token.
    fn operator(&mut self, p: &str, prev: Option<&Tok>, out: &mut PgCode) {
        // `name := value` and `name => value`: named arguments.
        if p == "=>" || (p.starts_with('=') && is_punct(prev, ":")) {
            return;
        }
        // `*` is an operator only between operands (not `SELECT *`,
        // `count(*)`, `t.*`).
        if p == "*" && !operand_end(prev) {
            return;
        }
        for o in split_operator(p) {
            out.push_operator(None, if o == "!=" { "<>" } else { o });
        }
    }

    /// `OPERATOR(` at `open`: `[schema.]op )`.
    fn operator_form(&mut self, open: usize, out: &mut PgCode) -> usize {
        let t = self.t;
        let mut k = open + 1;
        let mut schema: Option<String> = None;
        while let Some(part) = ident(self.at(k)) {
            if !is_punct(self.at(k + 1), ".") {
                break;
            }
            schema = Some(part.to_owned());
            k += 2;
        }
        match (self.at(k), self.at(k + 1)) {
            (Some(Tok::Punct(op)), Some(Tok::Punct(close))) if is_operator(op) && close == ")" => {
                out.push_operator(schema, if op == "!=" { "<>" } else { op });
                k + 2
            }
            _ => {
                // Unreadable: an operator that is never built in.
                out.push_operator(Some(String::new()), "");
                close_of(t, open).min(self.hi)
            }
        }
    }

    /// A type position at `j` (after `::`, `AS` of a cast, `RETURNING`, or
    /// a column name of a definition list): the type name, then its
    /// modifiers, multi-word tail and array bounds, consumed.
    fn type_at(&mut self, j: usize, out: &mut PgCode) -> usize {
        let t = self.t;
        let Some(&n) = (j < self.hi).then(|| self.by_start.get(&j)).flatten() else {
            out.push_type(PgCodeName {
                name: RelationName {
                    schema: None,
                    name: String::new(),
                },
                quoted: true,
                after_operand: false,
            });
            return j.min(self.hi);
        };
        let quoted = matches!(t.get(n.end.wrapping_sub(1)), Some(Tok::Quoted(_)));
        let mut name = n.name.clone();
        let mut k = n.end;
        let keyword = !quoted && name.schema.is_none();
        let multi = keyword
            && matches!(
                name.name.as_str(),
                "double"
                    | "character"
                    | "char"
                    | "national"
                    | "nchar"
                    | "bit"
                    | "varchar"
                    | "timestamp"
                    | "time"
                    | "interval"
            );
        if keyword && name.name == "double" && word(self.at(k)) == Some("precision") {
            name.name = "double precision".to_owned();
            k += 1;
        }
        out.push_type(PgCodeName {
            name,
            quoted,
            after_operand: false,
        });
        loop {
            match self.at(k) {
                Some(Tok::Punct(p)) if p == "(" || p == "[" => {
                    k = if p == "(" {
                        close_of(t, k)
                    } else {
                        let mut e = k;
                        while e < self.hi && !is_punct(t.get(e), "]") {
                            e += 1;
                        }
                        e + 1
                    };
                }
                Some(Tok::Word(w)) if w == "array" => k += 1,
                Some(Tok::Word(w))
                    if multi
                        && matches!(
                            w.as_str(),
                            "varying"
                                | "character"
                                | "char"
                                | "precision"
                                | "with"
                                | "without"
                                | "time"
                                | "zone"
                                | "local"
                                | "year"
                                | "month"
                                | "day"
                                | "hour"
                                | "minute"
                                | "second"
                                | "to"
                        ) =>
                {
                    k += 1;
                }
                _ => break,
            }
        }
        k.min(self.hi)
    }

    /// A name chain at its first token.
    fn name_at(&mut self, n: &'a NameAt, out: &mut PgCode) -> usize {
        let t = self.t;
        let start = n.start;
        let end = n.end;
        let prev = self.prev(start);
        let next = self.at(end);
        let quoted = matches!(t.get(end.wrapping_sub(1)), Some(Tok::Quoted(_)));
        let bare = (n.name.schema.is_none() && !quoted).then_some(n.name.name.as_str());
        let after = operand_end(prev);
        let kind = self.top();
        if is_punct(next, "(") {
            // A reserved keyword (on every supported version) is grammar,
            // never a call: `IN (`, `ANY (`, `CAST (`, `AS (`.
            if let Some(w) = bare
                && reserved(w)
                && w != "system_user"
            {
                self.pending = Some(if w == "cast" { Kind::Cast } else { Kind::Group });
                return end;
            }
            if self.call_position(start, prev, bare, after) {
                out.push_call(PgCodeName {
                    name: n.name.clone(),
                    quoted,
                    after_operand: after,
                });
                self.pending = Some(match bare {
                    Some("cast" | "treat" | "xmlserialize") => Kind::Cast,
                    Some("xmlparse") => Kind::XmlParse,
                    Some("xmlroot") => Kind::XmlRoot,
                    _ => Kind::Call,
                });
            } else if self.aliases.contains(&start)
                || word(prev) == Some("as")
                || is_punct(prev, ")")
            {
                // An alias with its column alias or definition list.
                self.pending = Some(Kind::Defs);
            }
            return end;
        }
        if matches!(next, Some(Tok::Literal)) && !after && self.typed_literal(prev, bare, kind) {
            out.push_type(PgCodeName {
                name: n.name.clone(),
                quoted,
                after_operand: false,
            });
        }
        end
    }

    /// Whether `name (` at `start` may be a function call.
    fn call_position(
        &self,
        start: usize,
        prev: Option<&Tok>,
        bare: Option<&str>,
        after: bool,
    ) -> bool {
        // An alias with its column list (`FROM f() a (c)`, `AS a (c)`),
        // and anything right after `)` (`FILTER (`, `OVER (`,
        // `REPEATABLE (`): a call never follows `)` directly.
        if self.aliases.contains(&start) || word(prev) == Some("as") || is_punct(prev, ")") {
            return false;
        }
        // `INSERT INTO t (cols)`, a CTE name with its column list.
        if matches!(word(prev), Some("into" | "with" | "recursive"))
            || (is_punct(prev, ",") && self.frames.last().is_some_and(|f| f.with_list))
        {
            return false;
        }
        let pw = word(prev);
        match bare {
            Some("by") => !matches!(pw, Some("order" | "group" | "partition")),
            Some("first" | "next") => pw != Some("fetch"),
            Some("zone") => pw != Some("time"),
            Some("sets") => pw != Some("grouping"),
            Some("conflict") => pw != Some("on"),
            Some("materialized") => !matches!(pw, Some("as" | "not")),
            Some("cube" | "rollup") => {
                !(self.frames.last().is_some_and(|f| f.group_by)
                    && (matches!(pw, Some("by")) || is_punct(prev, ",") || is_punct(prev, "(")))
            }
            Some("join") => {
                !(after
                    || matches!(
                        pw,
                        Some("left" | "right" | "full" | "inner" | "cross" | "natural" | "outer")
                    ))
            }
            // `UPDATE t SET (a, b) = …`
            Some("set") => !matches!(prev, Some(Tok::Word(_) | Tok::Quoted(_))),
            _ => true,
        }
    }

    /// Whether `name '…'` (not after an operand) is a typed literal.
    fn typed_literal(&self, prev: Option<&Tok>, bare: Option<&str>, kind: Kind) -> bool {
        let pw = word(prev);
        match bare {
            Some(w) if reserved(w) => false,
            Some("by") => !matches!(pw, Some("order" | "group" | "partition")),
            Some("first" | "next") => pw != Some("fetch"),
            Some("document" | "content") => {
                !(matches!(kind, Kind::XmlParse | Kind::Cast) && is_punct(prev, "("))
            }
            Some("version") => kind != Kind::XmlRoot,
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::pg_scan;
    use super::*;

    fn code(text: &str) -> PgCode {
        pg_scan(text).unwrap().code()
    }

    fn calls(text: &str) -> Vec<String> {
        code(text)
            .calls
            .into_iter()
            .map(|c| match c.name.schema {
                Some(s) => format!("{s}.{}", c.name.name),
                None if c.quoted => format!("\"{}\"", c.name.name),
                None => c.name.name,
            })
            .collect()
    }

    fn ops(text: &str) -> Vec<String> {
        code(text)
            .operators
            .into_iter()
            .map(|o| match o.schema {
                Some(s) => format!("{s}.{}", o.symbol),
                None => o.symbol,
            })
            .collect()
    }

    fn types(text: &str) -> Vec<String> {
        code(text)
            .types
            .into_iter()
            .map(|c| match c.name.schema {
                Some(s) => format!("{s}.{}", c.name.name),
                None if c.quoted => format!("\"{}\"", c.name.name),
                None => c.name.name,
            })
            .collect()
    }

    #[test]
    fn calls_are_found_with_their_schema() {
        assert_eq!(
            calls(
                "SELECT my_f(), crm.f(1), \"Length\"(x), pg_catalog.lower(relname) FROM pg_class"
            ),
            ["my_f", "crm.f", "\"Length\"", "pg_catalog.lower"]
        );
        // A call in FROM, LATERAL, a subquery, a CTE, WHERE.
        assert_eq!(
            calls(
                "WITH x AS (SELECT a() FROM pg_class) SELECT 1 FROM pg_class c, LATERAL b(c.oid) \
                 WHERE c.oid IN (SELECT d(oid) FROM pg_proc)"
            ),
            ["a", "b", "d"]
        );
        // Literals and comments hold no call.
        assert!(calls("SELECT 'my_f()' /* g() */ FROM pg_class").is_empty());
        // Grammar forms are reported (the caller tells keywords apart).
        assert_eq!(
            calls("SELECT coalesce(a, 1), cast(b AS int), exists(SELECT 1) FROM pg_class"),
            ["coalesce", "exists"]
        );
    }

    #[test]
    fn positions_that_are_not_calls() {
        for q in [
            // Aliases with column lists.
            "SELECT t.c FROM (VALUES (1)) AS t(c) CROSS JOIN pg_class",
            "SELECT a.c FROM pg_class a (c)",
            "SELECT s.x FROM pg_catalog.generate_series(1, 2) s(x)",
            // Clause syntax.
            "SELECT relname FROM pg_class ORDER BY (relname)",
            "SELECT count(*) FILTER (WHERE true) OVER (PARTITION BY (relkind)) FROM pg_class",
            "SELECT relkind FROM pg_class GROUP BY CUBE (relkind), ROLLUP (relname)",
            "SELECT relkind FROM pg_class GROUP BY GROUPING SETS ((relkind))",
            "SELECT 1 FROM pg_class TABLESAMPLE system (1) REPEATABLE (2)",
            "SELECT 1 FROM pg_class FETCH FIRST (1) ROWS ONLY",
            "INSERT INTO pg_temp.t (a) VALUES (1) ON CONFLICT (a) DO NOTHING",
            "WITH RECURSIVE r (n) AS (SELECT 1) SELECT n FROM r",
            "WITH a AS (SELECT 1), b (n) AS (SELECT 2) SELECT 1",
            "WITH x AS MATERIALIZED (SELECT 1) SELECT 1",
            "SELECT 1 FROM pg_class a LEFT JOIN (pg_namespace n CROSS JOIN pg_am m) ON true",
            "UPDATE pg_temp.t SET (a, b) = (1, 2)",
            "SELECT 1 FROM pg_class AT TIME ZONE (x)",
        ] {
            let c = calls(q);
            assert!(
                c.iter().all(
                    |n| !["c", "x", "by", "filter", "over", "cube", "rollup", "sets"]
                        .contains(&n.as_str())
                        && ![
                            "repeatable",
                            "first",
                            "a",
                            "conflict",
                            "r",
                            "b",
                            "materialized"
                        ]
                        .contains(&n.as_str())
                        && !["join", "t", "set", "zone", "partition"].contains(&n.as_str())
                ),
                "{q}: {c:?}"
            );
        }
        // `CUBE (` outside GROUP BY is a call (the `cube` extension).
        assert_eq!(calls("SELECT cube(1) FROM pg_class"), ["cube"]);
        // `BY (` elsewhere is a call of a function named `by`.
        assert_eq!(calls("SELECT by(1) FROM pg_class"), ["by"]);
        // `LIKE (…)` after an operand is marked so.
        let c = code("SELECT 1 FROM pg_class WHERE relname LIKE ('x') AND left(relname, 1) = 'p'");
        let like = c.calls.iter().find(|n| n.name.name == "like").unwrap();
        assert!(like.after_operand);
        let left = c.calls.iter().find(|n| n.name.name == "left").unwrap();
        assert!(!left.after_operand);
        // After `ORDER BY`, a name is not after an operand.
        let c = code("SELECT 1 FROM pg_class ORDER BY like(relname, 'x')");
        assert!(
            c.calls
                .iter()
                .any(|n| n.name.name == "like" && !n.after_operand)
        );
    }

    #[test]
    fn operators_written_and_implied() {
        assert_eq!(
            ops("SELECT a + b, c || d, e @> f, -g FROM pg_class WHERE x <> 1 AND y != 2"),
            ["+", "||", "@>", "-", "<>"]
        );
        // `*` only between operands.
        assert!(ops("SELECT *, count(*), c.* FROM pg_class c").is_empty());
        assert_eq!(ops("SELECT 2 * relpages FROM pg_class"), ["*"]);
        // PostgreSQL's split of a trailing `+` / `-`.
        assert_eq!(ops("SELECT 1 FROM pg_class WHERE relpages=-1"), ["=", "-"]);
        assert_eq!(ops("SELECT a @- b FROM pg_class"), ["@-"]);
        // OPERATOR(schema.op) and OPERATOR(op).
        assert_eq!(
            ops(
                "SELECT 1 FROM pg_class WHERE a OPERATOR(pg_catalog.~) 'x' AND b OPERATOR(+++) c \
                 AND d OPERATOR(public.===) e"
            ),
            ["pg_catalog.~", "+++", "public.==="]
        );
        // Implied.
        assert_eq!(
            ops("SELECT 1 FROM pg_class WHERE relname LIKE 'x'"),
            ["~~", "!~~"]
        );
        assert_eq!(
            ops("SELECT 1 FROM pg_class WHERE relname ILIKE 'x'"),
            ["~~*", "!~~*"]
        );
        assert_eq!(
            ops("SELECT 1 FROM pg_class WHERE relname IN ('a')"),
            ["=", "<>"]
        );
        assert_eq!(
            ops("SELECT 1 FROM pg_class WHERE a IS NOT DISTINCT FROM b"),
            ["="]
        );
        assert_eq!(
            ops("SELECT 1 FROM pg_class a JOIN pg_class b USING (oid)"),
            ["="]
        );
        assert_eq!(ops("SELECT nullif(a, b) FROM pg_class"), ["="]);
        assert_eq!(
            ops("SELECT CASE relkind WHEN 'r' THEN 1 END FROM pg_class"),
            ["="]
        );
        assert!(ops("SELECT CASE WHEN relhasindex THEN 1 END FROM pg_class").is_empty());
        // Named arguments are not operators.
        assert!(ops("SELECT f(a => 1, b := 2) FROM pg_class").is_empty());
        // An unreadable OPERATOR form.
        assert_eq!(
            code("SELECT a OPERATOR(x.) b FROM pg_class")
                .operators
                .len(),
            1
        );
    }

    #[test]
    fn types_of_casts_and_typed_literals() {
        assert_eq!(
            types(
                "SELECT a::text, b::pg_catalog.int4, c::\"MyType\", d::public.dom[], \
                 CAST(e AS numeric(10, 2)), f::double precision, g::character varying(3), \
                 h::timestamp(3) with time zone, i::int ARRAY FROM pg_class"
            ),
            [
                "text",
                "pg_catalog.int4",
                "\"MyType\"",
                "public.dom",
                "numeric",
                "double precision",
                "character",
                "timestamp",
                "int"
            ]
        );
        assert_eq!(
            types("SELECT date '2020-01-01', interval '1 day', public.t 'x' FROM pg_class"),
            ["date", "interval", "public.t"]
        );
        // Not typed literals.
        assert!(
            types(
                "SELECT 'a', x LIKE 'b' ESCAPE 'c', y AT TIME ZONE 'UTC', \
                 xmlparse(document '<a/>'), xmlroot(x, version '1.0') FROM pg_class \
                 WHERE z = 'd' AND w BETWEEN 'e' AND 'f' ORDER BY 'g'"
            )
            .is_empty()
        );
        // SQL/JSON RETURNING inside a call, XMLSERIALIZE, TREAT, a column
        // definition list.
        assert_eq!(
            types(
                "SELECT json_serialize(x RETURNING bytea), xmlserialize(document x AS text) \
                 FROM pg_catalog.json_to_record('{}') AS r (a int, b public.dom)"
            ),
            ["bytea", "text", "int", "public.dom"]
        );
        // A `::` with no type name: an unreadable type.
        assert_eq!(code("SELECT a::(b) FROM pg_class").types.len(), 1);
    }

    #[test]
    fn params_coercion_and_scope() {
        assert!(code("SELECT 1 FROM pg_class WHERE relname = $1").params);
        assert!(!code("SELECT 1 FROM pg_class WHERE relname = '$1'").params);
        assert!(code("SELECT relname FROM pg_class UNION SELECT 'x'").coercion);
        assert!(!code("SELECT relname FROM pg_class").coercion);
        assert!(code("SELECT relname FROM pg_class").is_empty());
        // COPY: only its query; any other statement is scanned whole (fail
        // closed).
        assert_eq!(calls("SET search_path TO my_f(1)"), ["my_f"]);
        assert!(code("COPY pg_class TO STDOUT (FORMAT csv, DELIMITER ',')").is_empty());
        assert_eq!(
            calls("COPY (SELECT my_f() FROM pg_class) TO STDOUT WITH (FORMAT csv)"),
            ["my_f"]
        );
        // Every statement of a text.
        assert_eq!(calls("SELECT 1; SELECT my_f() FROM pg_class"), ["my_f"]);
        // A DO body is not scanned for code (its statements are logged on
        // their own), but is for DDL.
        assert!(code("DO $$ BEGIN PERFORM my_f() FROM pg_class; END $$").is_empty());
    }

    /// Security review of #211, H1: the statements that wrap a query are
    /// scanned from their query on.
    #[test]
    fn wrapped_queries() {
        for (q, want) in [
            (
                "PREPARE p AS SELECT public.f() FROM pg_catalog.pg_class LIMIT 1",
                &["public.f"][..],
            ),
            (
                "EXPLAIN SELECT public.f(1) FROM pg_catalog.pg_class LIMIT 1",
                &["public.f"][..],
            ),
            (
                "EXPLAIN ANALYZE VERBOSE SELECT length(42) FROM pg_class",
                &["length"][..],
            ),
            (
                "EXPLAIN (ANALYZE, FORMAT JSON) SELECT public.f() FROM pg_class",
                &["public.f"][..],
            ),
            (
                "DECLARE c NO SCROLL CURSOR WITH HOLD FOR SELECT public.f() FROM pg_class",
                &["public.f"][..],
            ),
            (
                "CREATE TEMP TABLE tt (a) AS SELECT public.f() FROM pg_catalog.pg_class",
                &["public.f"][..],
            ),
            (
                "CREATE UNLOGGED TABLE IF NOT EXISTS tt AS SELECT length(42) FROM pg_class \
                 WITH NO DATA",
                &["length"][..],
            ),
            (
                "CREATE MATERIALIZED VIEW mv AS SELECT public.f() FROM pg_class",
                &["public.f"][..],
            ),
            (
                "EXPLAIN ANALYZE CREATE TABLE t AS SELECT public.f() FROM pg_class",
                &["public.f"][..],
            ),
        ] {
            assert_eq!(calls(q), want, "{q}");
        }
        // A `PREPARE`'s parameter types, then its query.
        let c = code("PREPARE p (integer, public.dom) AS SELECT $1 FROM pg_class");
        assert_eq!(
            types("PREPARE p (integer, public.dom) AS SELECT $1 FROM pg_class"),
            ["integer", "public.dom"]
        );
        assert!(c.params && c.calls.is_empty());
        // Implied operators in a wrapped query.
        assert_eq!(
            ops("DECLARE c CURSOR FOR SELECT 1 FROM pg_class WHERE relname IN ('a')"),
            ["=", "<>"]
        );
    }

    #[test]
    fn routine_ddl_statements() {
        for q in [
            "CREATE FUNCTION public.length(integer) RETURNS integer LANGUAGE sql AS 'SELECT 1'",
            "create or replace function f() returns int as $$select 1$$ language sql",
            "ALTER FUNCTION f() SET SCHEMA public",
            "DROP FUNCTION IF EXISTS f()",
            "CREATE PROCEDURE p() LANGUAGE sql AS $$ $$",
            "ALTER ROUTINE f() RENAME TO g",
            "CREATE AGGREGATE a (int) (sfunc = int4pl, stype = int)",
            "CREATE OPERATOR public.+ (leftarg = int, rightarg = int, function = f)",
            "CREATE OPERATOR CLASS c FOR TYPE t USING btree AS OPERATOR 1 <",
            "CREATE TYPE t AS ENUM ('a')",
            "ALTER TYPE t ADD VALUE 'b'",
            "CREATE DOMAIN d AS int CHECK (VALUE > 0)",
            "CREATE CAST (integer AS text) WITH FUNCTION f(integer)",
            "DROP CAST (integer AS text)",
            "CREATE EXTENSION citext",
            "ALTER EXTENSION citext UPDATE",
            "DROP SCHEMA s",
            "DROP OWNED BY alice",
            "DROP TABLE t CASCADE",
            "SELECT 1; CREATE FUNCTION f() RETURNS int AS 'select 1' LANGUAGE sql",
            "DO $$ BEGIN CREATE FUNCTION f() RETURNS int AS 'select 1' LANGUAGE sql; END $$",
        ] {
            assert!(pg_scan(q).unwrap().routine_ddl(), "{q}");
        }
        for q in [
            "CREATE TABLE t (a int)",
            "DROP TABLE t",
            "SELECT 'CREATE FUNCTION f()' FROM pg_class",
            "ALTER TABLE t ADD COLUMN function int",
        ] {
            assert!(!pg_scan(q).unwrap().routine_ddl(), "{q}");
        }
    }

    #[test]
    fn names_are_kept_once_and_bounded() {
        let mut q = String::from("SELECT ");
        for k in 0..300 {
            q.push_str(&format!("f{k}(), f{k}(), "));
        }
        q.push_str("1 FROM pg_class");
        let c = code(&q);
        assert_eq!(c.calls.len(), MAX_CODE_NAMES);
        assert!(c.overflow);
        assert!(format!("{c:?}").contains("calls: 256"));
        assert!(!format!("{c:?}").contains("f1"));
    }
}
