//! Token-level scan of a PostgreSQL statement text for callers that hold
//! their own name lists (ADR-0049): the names the text uses (qualified or
//! not, called or not, as a `FROM` item or elsewhere), and the facts of the
//! "no-text shape" of ADR-0049 decision 2, decided against the caller's
//! list ([`PgScan::no_text_shape`]), and the "no-secret shape" of ADR-0050
//! decision 2, the same rules on a set of secret columns
//! ([`PgScan::no_secret_shape`]).
//!
//! Like [`super::analyze`], the scan reads identifier tokens only, never
//! the content of a literal or a comment, and keeps no text: names are
//! folded (unquoted) or decoded (`U&"…"`) as the server does. A text that
//! does not lex unambiguously gives no scan ([`pg_scan`] is `None`): the
//! caller fails closed. A single `DO` block is scanned with its body (one
//! level, when the body lexes; a body that does not lex gives no scan).
//!
//! The shape test proves the **absence** of access to a text column; it is
//! deliberately coarse and over-reports: every rule refuses a construct
//! that could read or rename the column without naming it, and a construct
//! the parser does not recognize is a refusal, never a pass.

use std::collections::{HashMap, HashSet};
use std::fmt;

use super::{
    RelationName, Tok, do_body, is_punct, lex_unambiguous, opens_query, split_statements, word,
};

/// How the caller lists a name it is asked about ([`PgItemClass::Listed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgListed {
    /// A view whose rows hold the text column: quiet only in the no-text
    /// shape.
    View,
    /// A set-returning function whose rows hold the text column: quiet only
    /// in the no-text shape, and only as a `FROM` item (or inside
    /// `ROWS FROM (…)`).
    SetFunction,
    /// No shape exemption: any appearance reads the text.
    Always,
}

/// What a name is for the caller ([`PgScan::no_text_shape`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgItemClass {
    /// On the caller's list.
    Listed(PgListed),
    /// A catalog relation (or a catalog function in `FROM`): holds no
    /// text the shape is about.
    Catalog,
    /// Anything else (an application relation, a user view or function).
    Other,
}

/// One use of a name in the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgNameUse {
    /// The name: its last part, and the part before it as the schema
    /// (`db.schema.name` keeps `schema`).
    pub name: RelationName,
    /// Followed by `(`: a call (or a type modifier, a column list…).
    pub call: bool,
    /// A `FROM` item (also after `JOIN`, a `FROM`-list comma, `USING` of
    /// `DELETE` / `MERGE`, and inside `ROWS FROM (…)`).
    pub from_item: bool,
}

/// A name with its token range.
#[derive(Clone)]
pub(super) struct NameAt {
    pub(super) name: RelationName,
    pub(super) call: bool,
    pub(super) start: usize,
    pub(super) end: usize,
}

/// A `FROM` item of a segment.
#[derive(Clone)]
struct FromItem {
    /// Index in `Segment::names`.
    name: usize,
    /// Token index of its alias (for a `ROWS FROM` item: the alias of the
    /// whole `ROWS FROM`).
    alias: Option<usize>,
}

/// One token sequence: the text, or the body of its `DO` block.
pub(super) struct Segment {
    pub(super) tokens: Vec<Tok>,
    pub(super) names: Vec<NameAt>,
    items: Vec<FromItem>,
    /// Aliases of parenthesized joins (`(a JOIN b ON …) AS j`): a whole-row
    /// reference to one reads every column of the joined items.
    join_aliases: Vec<usize>,
    /// An alias the `FROM` parser recorded (of an item, a join or a
    /// subquery) is followed by `(`: a column alias list, whatever the
    /// alias's word (security review H1).
    column_list: bool,
    /// Token index of every alias the `FROM` parser recorded.
    pub(super) aliases: Vec<usize>,
}

/// The scan of a PostgreSQL text ([`pg_scan`]). Holds identifier tokens
/// only (no literal, no comment); its `Debug` prints nothing of them.
pub struct PgScan {
    pub(super) segments: Vec<Segment>,
}

impl fmt::Debug for PgScan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PgScan")
    }
}

/// Scans a PostgreSQL text: `None` when it does not lex unambiguously
/// (see [`super::analyze`]), or when it is one `DO` block whose body does
/// not.
#[must_use]
pub fn pg_scan(text: &str) -> Option<PgScan> {
    let tokens = lex_unambiguous(text)?;
    let mut bodies: Vec<Vec<Tok>> = Vec::new();
    let statements = split_statements(&tokens);
    if statements.len() == 1
        && word(statements[0].first()) == Some("do")
        && let Some(body) = do_body(text)
    {
        bodies.push(lex_unambiguous(body)?);
    }
    let mut segments = Vec::with_capacity(1 + bodies.len());
    for t in std::iter::once(tokens).chain(bodies) {
        let names = names_of(&t);
        let (items, join_aliases, column_list, aliases) = from_items(&t, &names);
        segments.push(Segment {
            tokens: t,
            names,
            items,
            join_aliases,
            column_list,
            aliases,
        });
    }
    Some(PgScan { segments })
}

impl PgScan {
    /// Every use of a name in the text (and in the body of its `DO`
    /// block), in order.
    #[must_use]
    pub fn names(&self) -> Vec<PgNameUse> {
        let mut out = Vec::new();
        for s in &self.segments {
            let items: HashSet<usize> = s.items.iter().map(|i| i.name).collect();
            for (k, n) in s.names.iter().enumerate() {
                out.push(PgNameUse {
                    name: n.name.clone(),
                    call: n.call,
                    from_item: items.contains(&k),
                });
            }
        }
        out
    }

    /// The `FROM` items of the text, with whether each is a call.
    #[must_use]
    pub fn from_items(&self) -> Vec<(RelationName, bool)> {
        let mut out = Vec::new();
        for s in &self.segments {
            for i in &s.items {
                let n = &s.names[i.name];
                out.push((n.name.clone(), n.call));
            }
        }
        out
    }

    /// Whether every listed name the text uses is read in the no-text
    /// shape of ADR-0049 decision 2, `columns` being the text columns
    /// (compared after folding). `classify(name, call)` places a name.
    /// `true` also when the text uses no listed name.
    ///
    /// Refused (so `false`):
    /// - a name listed [`PgListed::Always`], anywhere;
    /// - a `FROM` item classified [`PgItemClass::Other`] next to a listed
    ///   one (the text decides only on catalogs and listed entries);
    /// - an identifier token equal to one of `columns`, anywhere;
    /// - a `*` token, except in the exact sequence `count(*)`;
    /// - a whole-row reference: an occurrence of a listed view or function
    ///   name, of the alias of a listed `FROM` item, or of a parenthesized
    ///   join's alias, outside its own `FROM` item and not followed by `.`
    ///   and a column name (a listed set-returning function called outside
    ///   `FROM` is one, and so is `TABLE <view>`);
    /// - a column alias list anywhere (`AS a (c1, …)`, `) j (c1)`, `AS (…)`
    ///   after a call, a CTE column list), whatever the alias's word (an
    ///   alias the `FROM` parser recorded, or any identifier after `AS`,
    ///   followed by `(`), except on a parenthesized `VALUES` list of
    ///   constants (ADR-0049 refinement of 2026-10-11);
    /// - `NATURAL`;
    /// - `COPY` of a listed name (`COPY <entry> TO …` copies every column;
    ///   ADR-0050 decision 2).
    #[must_use]
    pub fn no_text_shape(
        &self,
        columns: &[&str],
        classify: &dyn Fn(&RelationName, bool) -> PgItemClass,
    ) -> bool {
        self.segments
            .iter()
            .all(|s| segment_shape(s, columns, classify, false))
    }

    /// [`Self::no_text_shape`] for the "no-secret shape" of ADR-0050
    /// decision 2 (`columns`: the secret columns of every listed entry the
    /// text names), with one addition: a `FROM` item that is an unqualified
    /// reference to a CTE the text defines **before** it (`WITH me AS
    /// (…) … FROM … , me`) is not an item the text cannot decide on: its
    /// query is part of the text and is held to the same rules (its
    /// columns, `*`, whole rows, aliases), so it counts as a catalog when
    /// the caller places it as [`PgItemClass::Other`]. A name used before
    /// any CTE of that name is defined (`WITH a AS (SELECT … FROM b), b AS
    /// …`: the first `b` is a relation) is the caller's.
    #[must_use]
    pub fn no_secret_shape(
        &self,
        columns: &[&str],
        classify: &dyn Fn(&RelationName, bool) -> PgItemClass,
    ) -> bool {
        self.segments
            .iter()
            .all(|s| segment_shape(s, columns, classify, true))
    }
}

/// The name of an identifier token (folded or decoded).
pub(super) fn ident(t: Option<&Tok>) -> Option<&str> {
    match t {
        Some(Tok::Word(w) | Tok::Quoted(w)) => Some(w.as_str()),
        _ => None,
    }
}

/// Dotted identifier chains: `a`, `a.b`, `a.b.c` (longer chains keep their
/// last two parts), each with whether `(` follows.
fn names_of(s: &[Tok]) -> Vec<NameAt> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if ident(s.get(i)).is_none() || (i > 0 && is_punct(s.get(i - 1), ".")) {
            i += 1;
            continue;
        }
        let mut parts: Vec<&str> = Vec::new();
        let mut j = i;
        loop {
            if let Some(p) = ident(s.get(j)) {
                parts.push(p);
            }
            if is_punct(s.get(j + 1), ".") && ident(s.get(j + 2)).is_some() {
                j += 2;
            } else {
                break;
            }
        }
        let name = parts.last().map_or(String::new(), |p| (*p).to_owned());
        let schema = (parts.len() >= 2).then(|| parts[parts.len() - 2].to_owned());
        out.push(NameAt {
            name: RelationName { schema, name },
            call: is_punct(s.get(j + 1), "("),
            start: i,
            end: j + 1,
        });
        i = j + 1;
    }
    out
}

/// Words that end a `FROM` item without an `AS`: PostgreSQL's reserved
/// keywords (and the type / function name keywords) that cannot be a bare
/// alias. Anything else after an item is taken as its alias (a wrong guess
/// over-reports, never misses).
fn alias_stop(w: &str) -> bool {
    matches!(
        w,
        "all"
            | "and"
            | "any"
            | "array"
            | "as"
            | "asc"
            | "both"
            | "case"
            | "cast"
            | "check"
            | "collate"
            | "column"
            | "constraint"
            | "create"
            | "default"
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
            | "intersect"
            | "into"
            | "lateral"
            | "limit"
            | "not"
            | "null"
            | "offset"
            | "on"
            | "only"
            | "or"
            | "order"
            | "returning"
            | "select"
            | "some"
            | "table"
            | "then"
            | "to"
            | "true"
            | "union"
            | "unique"
            | "using"
            | "when"
            | "where"
            | "window"
            | "with"
            | "cross"
            | "full"
            | "inner"
            | "join"
            | "left"
            | "natural"
            | "outer"
            | "right"
            | "tablesample"
    )
}

/// The alias after a `FROM` item ending before `i` (`WITH ORDINALITY`
/// skipped): its token index, and where to continue.
fn alias_at(s: &[Tok], mut i: usize) -> (Option<usize>, usize) {
    if word(s.get(i)) == Some("with") && word(s.get(i + 1)) == Some("ordinality") {
        i += 2;
    }
    if word(s.get(i)) == Some("as") {
        // After `AS`, any keyword is a valid alias.
        return if ident(s.get(i + 1)).is_some() {
            (Some(i + 1), i + 2)
        } else {
            (None, i + 1)
        };
    }
    match s.get(i) {
        Some(Tok::Quoted(_)) => (Some(i), i + 1),
        Some(Tok::Word(w)) if !alias_stop(w) => (Some(i), i + 1),
        _ => (None, i),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    Call,
    Group,
    RowsFrom,
}

/// What follows the `)` of a frame.
#[derive(Clone, PartialEq, Eq)]
enum After {
    Nothing,
    /// The alias of these items (a call item, or the items of `ROWS FROM`).
    Items(Vec<usize>),
    /// A parenthesized join's alias.
    Join,
    /// A subquery's alias (not a range variable of a listed item).
    Subquery,
}

struct Frame {
    open: Open,
    in_from: bool,
    after: After,
    /// Token index of its `(`.
    start: usize,
}

/// Whether the alias at `alias` is followed by `(` (a column alias list).
fn listed_columns(s: &[Tok], alias: Option<usize>) -> bool {
    alias.is_some_and(|a| is_punct(s.get(a + 1), "("))
}

/// The `FROM` items of `s`, the aliases of its parenthesized joins, and
/// whether a recorded alias has a column alias list (one on a subquery of
/// constant `VALUES` rows excepted, ADR-0049 refinement of 2026-10-11).
fn from_items(s: &[Tok], names: &[NameAt]) -> (Vec<FromItem>, Vec<usize>, bool, Vec<usize>) {
    let by_start: HashMap<usize, usize> = names
        .iter()
        .enumerate()
        .map(|(k, n)| (n.start, k))
        .collect();
    let mut items: Vec<FromItem> = Vec::new();
    let mut joins: Vec<usize> = Vec::new();
    let mut column_list = false;
    // Every alias the parser recorded (of an item, a join or a subquery).
    let mut aliases: Vec<usize> = Vec::new();
    let mut frames = vec![Frame {
        open: Open::Group,
        in_from: false,
        after: After::Nothing,
        start: 0,
    }];
    let mut expect = false;
    let mut i = 0;
    while i < s.len() {
        if expect {
            expect = false;
            while matches!(word(s.get(i)), Some("lateral" | "only")) {
                i += 1;
            }
            if is_punct(s.get(i), "(") {
                let sub = matches!(
                    word(s.get(i + 1)),
                    Some("select" | "with" | "values" | "table")
                );
                if frames.len() < super::MAX_DEPTH {
                    frames.push(Frame {
                        open: Open::Group,
                        in_from: !sub,
                        after: if sub { After::Subquery } else { After::Join },
                        start: i,
                    });
                }
                i += 1;
                expect = !sub;
                continue;
            }
            if word(s.get(i)) == Some("rows")
                && word(s.get(i + 1)) == Some("from")
                && is_punct(s.get(i + 2), "(")
            {
                if frames.len() < super::MAX_DEPTH {
                    frames.push(Frame {
                        open: Open::RowsFrom,
                        in_from: true,
                        after: After::Items(Vec::new()),
                        start: i + 2,
                    });
                }
                i += 3;
                expect = true;
                continue;
            }
            if let Some(&k) = by_start.get(&i) {
                let n = &names[k];
                let idx = items.len();
                items.push(FromItem {
                    name: k,
                    alias: None,
                });
                let in_rows_from = frames.last().is_some_and(|f| f.open == Open::RowsFrom);
                if in_rows_from
                    && let Some(After::Items(v)) = frames.last_mut().map(|f| &mut f.after)
                {
                    v.push(idx);
                }
                if n.call {
                    if frames.len() < super::MAX_DEPTH {
                        frames.push(Frame {
                            open: Open::Call,
                            in_from: false,
                            after: if in_rows_from {
                                After::Nothing
                            } else {
                                After::Items(vec![idx])
                            },
                            start: n.end,
                        });
                    }
                    i = n.end + 1;
                } else {
                    let (alias, next) = alias_at(s, n.end);
                    column_list |= listed_columns(s, alias);
                    aliases.extend(alias);
                    items[idx].alias = alias;
                    i = next;
                }
                continue;
            }
        }
        let in_call = frames.last().is_some_and(|f| f.open == Open::Call);
        match &s[i] {
            Tok::Punct(p) if p == "(" => {
                let sub = matches!(
                    word(s.get(i + 1)),
                    Some("select" | "with" | "values" | "table")
                );
                let call = !sub
                    && (in_call
                        || match i.checked_sub(1).and_then(|j| s.get(j)) {
                            Some(Tok::Word(w)) => !opens_query(w),
                            Some(Tok::Quoted(_)) => true,
                            _ => false,
                        });
                if frames.len() < super::MAX_DEPTH {
                    frames.push(Frame {
                        open: if call { Open::Call } else { Open::Group },
                        in_from: false,
                        after: After::Nothing,
                        start: i,
                    });
                }
                i += 1;
            }
            Tok::Punct(p) if p == ")" => {
                i += 1;
                if frames.len() > 1
                    && let Some(f) = frames.pop()
                {
                    match f.after {
                        After::Nothing => {}
                        After::Items(v) => {
                            let (alias, next) = alias_at(s, i);
                            column_list |= listed_columns(s, alias);
                            aliases.extend(alias);
                            for k in v {
                                items[k].alias = alias;
                            }
                            i = next;
                        }
                        After::Join => {
                            let (alias, next) = alias_at(s, i);
                            column_list |= listed_columns(s, alias);
                            aliases.extend(alias);
                            joins.extend(alias);
                            i = next;
                        }
                        After::Subquery => {
                            let (alias, next) = alias_at(s, i);
                            aliases.extend(alias);
                            column_list |=
                                listed_columns(s, alias) && !constant_values(s, f.start, i - 1);
                            i = next;
                        }
                    }
                }
            }
            Tok::Punct(p) if p == "," && !in_call => {
                if frames.last().is_some_and(|f| f.in_from) {
                    expect = true;
                }
                i += 1;
            }
            Tok::Word(w) if !in_call => {
                let prev = word(i.checked_sub(1).and_then(|j| s.get(j)));
                match w.as_str() {
                    // `IS [NOT] DISTINCT FROM x` is an expression.
                    "from" if prev != Some("distinct") => {
                        if let Some(f) = frames.last_mut() {
                            f.in_from = true;
                        }
                        expect = true;
                    }
                    "join" => {
                        if let Some(f) = frames.last_mut() {
                            f.in_from = true;
                        }
                        expect = true;
                    }
                    // `DELETE … USING t`, `MERGE … USING t`; not
                    // `JOIN … USING (cols)`.
                    "using" if !is_punct(s.get(i + 1), "(") => expect = true,
                    "update" if !matches!(prev, Some("for" | "do" | "key" | "no")) => {
                        expect = true;
                    }
                    "where" | "group" | "having" | "order" | "limit" | "offset" | "fetch"
                    | "window" | "union" | "intersect" | "except" | "returning" | "set"
                    | "values" | "select" | "for" | "when" | "then" | "into" => {
                        if let Some(f) = frames.last_mut() {
                            f.in_from = false;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    (items, joins, column_list, aliases)
}

/// Keywords after which `<name> (` is a call, not an alias with a column
/// list (`SELECT f(`, `WHERE f(`, `AND f(`…).
fn call_context(w: &str) -> bool {
    matches!(
        w,
        "select"
            | "distinct"
            | "all"
            | "where"
            | "and"
            | "or"
            | "not"
            | "on"
            | "when"
            | "then"
            | "else"
            | "case"
            | "by"
            | "having"
            | "from"
            | "join"
            | "lateral"
            | "only"
            | "using"
            | "in"
            | "is"
            | "like"
            | "ilike"
            | "similar"
            | "to"
            | "between"
            | "symmetric"
            | "asymmetric"
            | "returning"
            | "set"
            | "values"
            | "limit"
            | "offset"
            | "fetch"
            | "first"
            | "next"
            | "row"
            | "rows"
            | "exists"
            | "any"
            | "some"
            | "array"
            | "escape"
            | "over"
            | "filter"
            | "partition"
            | "order"
            | "group"
            | "desc"
            | "asc"
            | "nulls"
            | "last"
            | "union"
            | "intersect"
            | "except"
            | "into"
            | "update"
            | "delete"
            | "insert"
            | "table"
            | "with"
            | "recursive"
            | "materialized"
            | "do"
            | "return"
            | "perform"
            | "if"
            | "elsif"
            | "loop"
            | "while"
            | "execute"
            | "call"
            | "collate"
            | "at"
            | "isnull"
            | "notnull"
            | "unknown"
            | "true"
            | "false"
            | "null"
            | "overlaps"
            | "tablesample"
            | "copy"
            | "default"
    )
}

/// Keywords that legitimately stand between a name (or `)`) and `(`
/// without being an alias (`x IN (`, `FILTER (`, `WITHIN GROUP (`…).
fn paren_keyword(w: &str) -> bool {
    matches!(
        w,
        "in" | "exists"
            | "any"
            | "all"
            | "some"
            | "filter"
            | "over"
            | "values"
            | "using"
            | "on"
            | "row"
            | "array"
            | "group"
            | "and"
            | "or"
            | "not"
            | "when"
            | "then"
            | "else"
            | "where"
            | "having"
            | "by"
            | "select"
            | "from"
            | "join"
            | "lateral"
            | "like"
            | "ilike"
            | "between"
            | "symmetric"
            | "is"
            | "to"
            | "returning"
            | "with"
            | "operator"
            | "distinct"
            | "union"
            | "intersect"
            | "except"
            | "limit"
            | "offset"
            | "set"
            | "sets"
            | "zone"
            | "overlaps"
            | "repeatable"
            | "columns"
            | "for"
            | "placing"
            | "return"
            | "call"
            | "varying"
            | "second"
            | "as"
    )
}

/// Index of the `(` matching the `)` at `close`.
fn open_of(s: &[Tok], close: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut j = close;
    loop {
        match s.get(j) {
            Some(Tok::Punct(p)) if p == ")" => depth += 1,
            Some(Tok::Punct(p)) if p == "(" => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(j);
                }
            }
            None => return None,
            _ => {}
        }
        j = j.checked_sub(1)?;
    }
}

/// Index after the `)` matching the `(` at `open`.
pub(super) fn close_of(s: &[Tok], open: usize) -> usize {
    let mut depth = 0usize;
    for (j, t) in s.iter().enumerate().skip(open) {
        match t {
            Tok::Punct(p) if p == "(" => depth += 1,
            Tok::Punct(p) if p == ")" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
    }
    s.len()
}

/// `( VALUES (<constants>), … )` from `open` to `close`: rows of literals,
/// parameters and signs only, which cannot carry another relation's
/// column (ADR-0049 refinement of 2026-10-11, `postgres_exporter`'s
/// `(VALUES ('active'), …) AS tmp(state)`).
fn constant_values(s: &[Tok], open: usize, close: usize) -> bool {
    word(s.get(open + 1)) == Some("values")
        && s.get(open + 2..close).is_some_and(|inner| {
            inner.iter().all(|t| match t {
                Tok::Literal | Tok::Int(_) | Tok::Param => true,
                Tok::Punct(p) => matches!(p.as_str(), "(" | ")" | "," | "-" | "+"),
                _ => false,
            })
        })
}

/// `AS MATERIALIZED (` of a CTE: the `(` opens its query (a column alias
/// list cannot start with a reserved word, nor be `(update t …)`).
fn cte_materialized(s: &[Tok], open: usize) -> bool {
    match word(s.get(open + 1)) {
        Some("select" | "with" | "values" | "table") => true,
        Some("insert" | "update" | "delete" | "merge") => {
            !matches!(s.get(open + 2), Some(Tok::Punct(p)) if p == "," || p == ")")
        }
        _ => false,
    }
}

/// A column alias list anywhere in `s` (ADR-0049 decision 2), found
/// lexically as a backstop of the `FROM` parser's aliases
/// ([`Segment::column_list`]): `AS <any identifier> (` outside the direct
/// frame of `CAST(…)` (whatever the identifier's word, security review
/// H1), `<alias> (` after `)` or after another name, `) AS (`, and a CTE
/// column list.
fn alias_list(s: &[Tok]) -> bool {
    // The direct frame of a `cast` call, where `AS <type>(n)` is a type
    // modifier. Not inherited by nested parentheses (a subquery inside
    // `CAST` is checked like any other).
    let mut cast: Vec<bool> = Vec::new();
    for i in 0..s.len() {
        match &s[i] {
            Tok::Punct(p) if p == "(" => {
                let in_cast = cast.last().copied().unwrap_or(false);
                let prev = i.checked_sub(1).and_then(|j| s.get(j));
                let y = i.checked_sub(1).and_then(|j| s.get(j));
                let x = i.checked_sub(2).and_then(|j| s.get(j));
                let is_cast = word(prev) == Some("cast");
                // `) AS (` (a column definition list) unless a query
                // follows.
                if word(y) == Some("as")
                    && is_punct(x, ")")
                    && !matches!(
                        word(s.get(i + 1)),
                        Some("select" | "with" | "values" | "table")
                    )
                {
                    return true;
                }
                // After `AS`, any identifier is an alias (`AS zone (c)`,
                // `AS set (c)`), except a CTE's `AS MATERIALIZED (query)`.
                let cte = word(x) == Some("as")
                    && word(y) == Some("materialized")
                    && cte_materialized(s, i);
                let after_as = word(x) == Some("as") && ident(y).is_some();
                let y_name = !cte
                    && (after_as
                        || match y {
                            Some(Tok::Quoted(_)) => true,
                            Some(Tok::Word(w)) => !paren_keyword(w),
                            _ => false,
                        });
                if y_name && !in_cast {
                    let flagged = match x {
                        Some(Tok::Word(w)) if w == "as" => true,
                        Some(Tok::Punct(p)) if p == ")" => true,
                        Some(Tok::Word(w)) => !call_context(w),
                        Some(Tok::Quoted(_)) => true,
                        _ => false,
                    };
                    if flagged {
                        // The `)` (or `) AS`) before the alias closes a list
                        // of constant `VALUES` rows: allowed.
                        let close = match x {
                            Some(Tok::Punct(p)) if p == ")" => i.checked_sub(2),
                            Some(Tok::Word(w))
                                if w == "as"
                                    && is_punct(i.checked_sub(3).and_then(|j| s.get(j)), ")") =>
                            {
                                i.checked_sub(3)
                            }
                            _ => None,
                        };
                        let constant = close
                            .and_then(|c| open_of(s, c).map(|o| (o, c)))
                            .is_some_and(|(o, c)| constant_values(s, o, c));
                        if !constant {
                            return true;
                        }
                    }
                }
                cast.push(is_cast);
            }
            Tok::Punct(p) if p == ")" => {
                cast.pop();
            }
            Tok::Word(w) if w == "with" && cte_column_list(s, i) => return true,
            _ => {}
        }
    }
    false
}

/// A CTE column list in the `WITH` list starting at `with` (`WITH x (c1) AS`,
/// `, y (c1) AS`).
fn cte_column_list(s: &[Tok], with: usize) -> bool {
    let mut j = with + 1;
    if word(s.get(j)) == Some("recursive") {
        j += 1;
    }
    loop {
        if ident(s.get(j)).is_none() {
            return false;
        }
        if is_punct(s.get(j + 1), "(") {
            return true;
        }
        if word(s.get(j + 1)) != Some("as") {
            return false;
        }
        let mut k = j + 2;
        if word(s.get(k)) == Some("not") {
            k += 1;
        }
        if word(s.get(k)) == Some("materialized") {
            k += 1;
        }
        if !is_punct(s.get(k), "(") {
            return false;
        }
        k = close_of(s, k);
        // `SEARCH … SET …`, `CYCLE … USING …` clauses, then `,` and the
        // next CTE, or the main statement.
        loop {
            match s.get(k) {
                Some(Tok::Punct(p)) if p == "," => {
                    if is_punct(s.get(k + 2), "(") && ident(s.get(k + 1)).is_some() {
                        return true;
                    }
                    if word(s.get(k + 2)) == Some("as") {
                        break;
                    }
                    k += 1;
                }
                Some(Tok::Punct(p)) if p == "(" => return false,
                Some(Tok::Word(w))
                    if matches!(
                        w.as_str(),
                        "select" | "insert" | "update" | "delete" | "merge" | "values" | "table"
                    ) =>
                {
                    return false;
                }
                None => return false,
                _ => k += 1,
            }
        }
        j = k + 1;
    }
}

/// The end (exclusive token index) of the scope of a `WITH` at `with`:
/// the `)` that closes the parentheses enclosing it (a subquery's `WITH`
/// is visible in that subquery only), or the end of its statement (`;`)
/// or of the text.
fn with_scope_end(s: &[Tok], with: usize) -> usize {
    let mut depth = 0usize;
    for (j, t) in s.iter().enumerate().skip(with + 1) {
        match t {
            Tok::Punct(p) if p == "(" => depth += 1,
            Tok::Punct(p) if p == ")" => match depth.checked_sub(1) {
                Some(d) => depth = d,
                None => return j,
            },
            Tok::Punct(p) if p == ";" && depth == 0 => return j,
            _ => {}
        }
    }
    s.len()
}

/// CTEs a text defines, anywhere (a nested `WITH` too): each name with
/// the token index of its definition and the end of its scope
/// ([`with_scope_end`]): a reference counts as the CTE only after its
/// definition and within the query whose `WITH` defines it, or a query
/// nested in it (security review of PR #217, L1: a CTE of a sibling
/// subquery is not visible). `WITH ORDINALITY` is not one.
fn cte_defs(s: &[Tok]) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    for (i, t) in s.iter().enumerate() {
        if word(Some(t)) != Some("with") {
            continue;
        }
        let scope_end = with_scope_end(s, i);
        let mut j = i + 1;
        if word(s.get(j)) == Some("recursive") {
            j += 1;
        }
        'list: while let Some(name) = ident(s.get(j)) {
            if name == "ordinality" {
                break;
            }
            let mut k = j + 1;
            if is_punct(s.get(k), "(") {
                k = close_of(s, k);
            }
            if word(s.get(k)) != Some("as") {
                break;
            }
            out.push((name.to_owned(), j, scope_end));
            k += 1;
            if word(s.get(k)) == Some("not") {
                k += 1;
            }
            if word(s.get(k)) == Some("materialized") {
                k += 1;
            }
            if !is_punct(s.get(k), "(") {
                break;
            }
            k = close_of(s, k);
            // `SEARCH … SET …`, `CYCLE … USING …`, then `,` and the next
            // CTE, or the main statement.
            loop {
                match s.get(k) {
                    Some(Tok::Punct(p)) if p == "," => {
                        j = k + 1;
                        continue 'list;
                    }
                    Some(Tok::Punct(p)) if p == "(" || p == ")" || p == ";" => break 'list,
                    Some(Tok::Word(w))
                        if matches!(
                            w.as_str(),
                            "select"
                                | "insert"
                                | "update"
                                | "delete"
                                | "merge"
                                | "values"
                                | "table"
                        ) =>
                    {
                        break 'list;
                    }
                    None => break 'list,
                    _ => k += 1,
                }
            }
        }
    }
    out
}

/// [`PgScan::no_text_shape`] (and, with `ctes`, [`PgScan::no_secret_shape`])
/// on one segment.
fn segment_shape(
    s: &Segment,
    columns: &[&str],
    classify: &dyn Fn(&RelationName, bool) -> PgItemClass,
    ctes: bool,
) -> bool {
    let t = &s.tokens;
    let mut class: Vec<PgItemClass> = s.names.iter().map(|n| classify(&n.name, n.call)).collect();
    if ctes {
        // An unqualified reference to a CTE defined earlier in the text.
        let defs = cte_defs(t);
        for item in &s.items {
            let n = &s.names[item.name];
            if class[item.name] == PgItemClass::Other
                && !n.call
                && n.name.schema.is_none()
                && defs
                    .iter()
                    .any(|(name, at, end)| *name == n.name.name && *at < n.start && n.start < *end)
            {
                class[item.name] = PgItemClass::Catalog;
            }
        }
    }
    let listed = |k: usize| matches!(class[k], PgItemClass::Listed(_));
    if !(0..s.names.len()).any(listed) {
        return true;
    }
    // Names with no shape exemption.
    if class.contains(&PgItemClass::Listed(PgListed::Always)) {
        return false;
    }
    // The text decides only on catalogs and listed entries.
    if s.items.iter().any(|i| class[i.name] == PgItemClass::Other) {
        return false;
    }
    // The text columns, anywhere.
    if t.iter()
        .any(|x| ident(Some(x)).is_some_and(|w| columns.contains(&w)))
    {
        return false;
    }
    // `COPY <listed entry>` (old syntax `COPY BINARY <entry>` too).
    for (k, n) in s.names.iter().enumerate() {
        if !listed(k) {
            continue;
        }
        let before = |d: usize| word(n.start.checked_sub(d).and_then(|j| t.get(j)));
        if before(1) == Some("copy") || (before(1) == Some("binary") && before(2) == Some("copy")) {
            return false;
        }
    }
    // `*`, except `count(*)`.
    for (i, x) in t.iter().enumerate() {
        if let Tok::Punct(p) = x
            && p.contains('*')
        {
            let count = p == "*"
                && word(i.checked_sub(2).and_then(|j| t.get(j))) == Some("count")
                && is_punct(i.checked_sub(1).and_then(|j| t.get(j)), "(")
                && is_punct(t.get(i + 1), ")");
            if !count {
                return false;
            }
        }
    }
    if t.iter().any(|x| word(Some(x)) == Some("natural")) {
        return false;
    }
    if s.column_list || alias_list(t) {
        return false;
    }
    // Range variables: the listed names, the aliases of listed items and
    // of parenthesized joins. Their own `FROM` item tokens are exempt.
    let mut vars: HashSet<&str> = HashSet::new();
    let mut own: HashSet<usize> = HashSet::new();
    for (k, n) in s.names.iter().enumerate() {
        if listed(k) {
            vars.insert(n.name.name.as_str());
        }
    }
    for item in &s.items {
        let n = &s.names[item.name];
        if listed(item.name) {
            own.extend(n.start..n.end);
            if let Some(a) = item.alias {
                own.insert(a);
                if let Some(name) = ident(t.get(a)) {
                    vars.insert(name);
                }
            }
        }
    }
    for &a in &s.join_aliases {
        own.insert(a);
        if let Some(name) = ident(t.get(a)) {
            vars.insert(name);
        }
    }
    for (i, x) in t.iter().enumerate() {
        let Some(name) = ident(Some(x)) else {
            continue;
        };
        if own.contains(&i) || !vars.contains(name) {
            continue;
        }
        // `<var>.<column>`, the column not being a text column.
        let column_ref = is_punct(t.get(i + 1), ".")
            && ident(t.get(i + 2)).is_some_and(|c| !columns.contains(&c));
        if !column_ref {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(r: &RelationName, call: bool) -> PgItemClass {
        let schema = r.schema.as_deref();
        match (schema, r.name.as_str(), call) {
            (None | Some("pg_catalog"), "pg_stat_activity", false) => {
                PgItemClass::Listed(PgListed::View)
            }
            (None | Some("pg_catalog"), "pg_stat_get_activity", true) => {
                PgItemClass::Listed(PgListed::SetFunction)
            }
            (None | Some("pg_catalog"), "pg_stat_get_backend_activity", true) => {
                PgItemClass::Listed(PgListed::Always)
            }
            (Some("pg_catalog"), _, _) => PgItemClass::Catalog,
            (None, n, false) if n.starts_with("pg_") => PgItemClass::Catalog,
            _ => PgItemClass::Other,
        }
    }

    fn quiet(text: &str) -> bool {
        pg_scan(text).unwrap().no_text_shape(&["query"], &classify)
    }

    #[test]
    fn names_are_qualified_called_and_placed() {
        let s =
            pg_scan("SELECT a.pid FROM pg_catalog.pg_stat_activity a, x.f(1) JOIN \"T\" ON true")
                .unwrap();
        let n: Vec<(Option<String>, String, bool, bool)> = s
            .names()
            .into_iter()
            .map(|u| (u.name.schema, u.name.name, u.call, u.from_item))
            .collect();
        assert!(n.contains(&(
            Some("pg_catalog".to_owned()),
            "pg_stat_activity".to_owned(),
            false,
            true
        )));
        assert!(n.contains(&(Some("x".to_owned()), "f".to_owned(), true, true)));
        assert!(n.contains(&(None, "T".to_owned(), false, true)));
        assert!(n.contains(&(Some("a".to_owned()), "pid".to_owned(), false, false)));
        // Literals and comments hold no name.
        let s = pg_scan("SELECT 'pg_stat_activity' /* pg_stat_activity */ FROM t").unwrap();
        assert!(!s.names().iter().any(|u| u.name.name == "pg_stat_activity"));
        // `U&` decoded, quoted kept as is.
        let s = pg_scan(r#"SELECT 1 FROM U&"\0070g_stat_activity", "PG_STAT_ACTIVITY""#).unwrap();
        let names: Vec<String> = s.names().into_iter().map(|u| u.name.name).collect();
        assert!(names.contains(&"pg_stat_activity".to_owned()), "{names:?}");
        assert!(names.contains(&"PG_STAT_ACTIVITY".to_owned()), "{names:?}");
        // A DO body is scanned too; one that does not lex gives no scan.
        let s = pg_scan("DO $$ BEGIN PERFORM 1 FROM pg_stat_activity; END $$").unwrap();
        assert!(
            s.names()
                .iter()
                .any(|u| u.name.name == "pg_stat_activity" && u.from_item)
        );
        assert!(pg_scan("DO $$ BEGIN PERFORM 'x; END $$").is_none());
        assert!(pg_scan("SELECT 'x").is_none());
    }

    #[test]
    fn the_no_text_shape() {
        for q in [
            "SELECT state, count(*) FROM pg_stat_activity GROUP BY state",
            "SELECT pid FROM pg_stat_activity WHERE state = 'idle'",
            "SELECT a.pid, a.usename FROM pg_catalog.pg_stat_activity AS a WHERE a.state <> $1",
            "SELECT pg_stat_activity.pid FROM pg_stat_activity",
            "SELECT s.pid FROM pg_stat_get_activity(NULL) s",
            "SELECT pid FROM ROWS FROM (pg_stat_get_activity(NULL)) WITH ORDINALITY AS r",
            "SELECT a.pid FROM pg_stat_activity a JOIN pg_catalog.pg_database d ON d.oid = a.datid",
            "SELECT j.pid FROM pg_stat_activity a JOIN pg_stat_activity b USING (pid) AS j",
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle' \
             AND state_change < now() - interval '10 minutes'",
            "SELECT CAST(pid AS numeric(10, 0)) FROM pg_stat_activity",
            "SELECT datname, count(*) FILTER (WHERE state = 'active') FROM pg_stat_activity \
             GROUP BY datname",
            // postgres_exporter's activity query (refinement: constant VALUES).
            "SELECT pg_database.datname, tmp.state, COALESCE(count,0) as count, \
             COALESCE(max_tx_duration,0) as max_tx_duration FROM ( VALUES ('active'), \
             ('idle'), ('idle in transaction'), ('idle in transaction (aborted)'), \
             ('fastpath function call'), ('disabled') ) AS tmp(state) CROSS JOIN pg_database \
             LEFT JOIN ( SELECT datname, state, count(*) AS count, \
             MAX(EXTRACT(EPOCH FROM now() - xact_start))::float AS max_tx_duration \
             FROM pg_stat_activity GROUP BY datname,state) AS tmp2 \
             ON tmp.state = tmp2.state AND pg_database.datname = tmp2.datname",
        ] {
            assert!(quiet(q), "{q}");
        }
        for q in [
            "SELECT query FROM pg_stat_activity",
            "SELECT \"query\" FROM pg_stat_activity",
            r#"SELECT U&"\0071uery" FROM pg_stat_activity"#,
            "SELECT query(a) FROM pg_stat_activity a",
            "SELECT count(*) FILTER (WHERE query LIKE '%x%') FROM pg_stat_activity",
            "SELECT * FROM pg_stat_activity",
            "SELECT a.* FROM pg_stat_activity a",
            "SELECT row_to_json(a) FROM pg_stat_activity a",
            "SELECT a::text FROM pg_stat_activity a",
            "SELECT (a).* FROM pg_stat_activity a",
            "SELECT a FROM pg_stat_activity a",
            "SELECT pg_catalog.pg_stat_activity FROM pg_catalog.pg_stat_activity",
            "SELECT row_to_json(pg_stat_get_activity) FROM pg_stat_get_activity(NULL)",
            "SELECT pg_stat_get_activity::text FROM pg_catalog.pg_stat_get_activity(NULL)",
            "SELECT row_to_json(pg_stat_get_activity) FROM ROWS FROM (pg_stat_get_activity(NULL))",
            "SELECT pg_stat_get_activity::text FROM pg_stat_get_activity(NULL) WITH ORDINALITY",
            "SELECT state FROM pg_stat_activity state",
            "SELECT NULL::pg_stat_activity FROM pg_stat_activity",
            "SELECT a.c FROM pg_stat_activity AS a (c, d, e)",
            "SELECT a.c FROM pg_stat_activity a (c)",
            "SELECT x.c FROM (SELECT a.pid FROM pg_stat_activity a) x (c)",
            "SELECT j.c FROM (pg_stat_activity a CROSS JOIN pg_database d) AS j (c)",
            "SELECT row_to_json(j) FROM (pg_stat_activity a CROSS JOIN pg_database d) j",
            "SELECT s.c FROM pg_stat_get_activity(NULL) AS s (c)",
            "SELECT s.c FROM pg_stat_get_activity(NULL) AS (c int)",
            "SELECT r.c FROM ROWS FROM (pg_stat_get_activity(NULL)) AS r (c)",
            "SELECT r.c FROM pg_stat_get_activity(NULL) WITH ORDINALITY AS r (c, n)",
            "WITH x (c) AS (SELECT a.pid FROM pg_stat_activity a) SELECT x.c FROM x",
            "WITH y AS (SELECT 1), x (c) AS (SELECT a.pid FROM pg_stat_activity a) SELECT 1",
            "SELECT b.pid FROM pg_stat_activity a NATURAL JOIN pg_stat_activity b",
            "TABLE pg_stat_activity",
            "SELECT pg_stat_get_activity(NULL)",
            "SELECT pg_stat_get_backend_activity(1) FROM pg_class",
            "SELECT a.pid FROM pg_stat_activity a, public.v",
            "SELECT a.pid FROM pg_stat_activity a, public.f() f",
            "SELECT a.pid FROM pg_stat_activity a WHERE a = a",
            "SELECT 1 FROM pg_stat_activity a WHERE a IS DISTINCT FROM NULL",
            "SELECT 1 FROM pg_stat_activity WHERE x IS DISTINCT FROM pg_stat_activity",
            "SELECT 2 * a.pid FROM pg_stat_activity a",
            "SELECT 1 FROM pg_stat_activity, (VALUES ((SELECT 1))) AS v (c)",
        ] {
            assert!(!quiet(q), "{q}");
        }
        // Nothing listed: quiet.
        assert!(quiet("SELECT * FROM crm.customer"));
    }

    /// The probes of security review H1, each a text read.
    const KEYWORD_ALIAS_PROBES: [&str; 10] = [
        "SELECT zone.c7 FROM pg_stat_activity zone (c1, c2, c3, c4, c5, c6, c7)",
        "SELECT filter.c FROM pg_stat_activity filter (c)",
        "SELECT zone.c FROM pg_stat_activity AS zone (c)",
        "SELECT second.c FROM pg_stat_get_activity(NULL) AS second (c)",
        "SELECT columns.c FROM (pg_stat_activity a CROSS JOIN pg_database d) columns (c)",
        "SELECT set.c FROM pg_stat_activity AS set (c)",
        "SELECT call.c FROM pg_stat_activity call (c)",
        "SELECT v.c FROM pg_stat_activity values (c)",
        "SELECT x.c FROM pg_stat_get_activity(NULL) WITH ORDINALITY AS zone (c, n)",
        "SELECT x.c FROM ROWS FROM (pg_stat_get_activity(NULL)) AS columns (c)",
    ];

    /// Security review H1: an alias that is a keyword of the lexical lists
    /// (`zone`, `filter`, `second`, `columns`, `set`, `call`, `values`)
    /// still has its column alias list refused, by the `FROM` parser's
    /// aliases and by the `AS <identifier> (` backstop.
    #[test]
    fn keyword_aliases_with_column_lists() {
        for q in KEYWORD_ALIAS_PROBES {
            assert!(!quiet(q), "{q}");
        }
        // Each check alone.
        for q in [
            "SELECT zone.c7 FROM pg_stat_activity zone (c1, c2, c3, c4, c5, c6, c7)",
            "SELECT filter.c FROM pg_stat_activity filter (c)",
            "SELECT columns.c FROM (pg_stat_activity a CROSS JOIN pg_database d) columns (c)",
            "SELECT call.c FROM pg_stat_activity call (c)",
            "SELECT x.c FROM (SELECT a.pid FROM pg_stat_activity a) zone (c)",
        ] {
            assert!(pg_scan(q).unwrap().segments[0].column_list, "{q}");
        }
        for q in [
            "SELECT zone.c FROM pg_stat_activity AS zone (c)",
            "SELECT second.c FROM pg_stat_get_activity(NULL) AS second (c)",
            "SELECT set.c FROM pg_stat_activity AS set (c)",
            "SELECT x.c FROM ROWS FROM (pg_stat_get_activity(NULL)) AS columns (c)",
        ] {
            assert!(alias_list(&pg_scan(q).unwrap().segments[0].tokens), "{q}");
        }
        // A subquery inside `CAST` is not covered by the cast's exemption.
        assert!(!quiet(
            "SELECT CAST((SELECT x.c FROM pg_stat_activity AS x (c) LIMIT 1) AS int)"
        ));
        // Not a column list: a CTE's `AS [NOT] MATERIALIZED (query)` and
        // type modifiers in `CAST` (a CTE reference is itself an item the
        // text cannot decide on, so these are checked on the backstop).
        for q in [
            "WITH x AS MATERIALIZED (SELECT a.pid FROM pg_stat_activity a) SELECT x.pid FROM x",
            "WITH x AS NOT MATERIALIZED (SELECT a.pid FROM pg_stat_activity a) \
             SELECT x.pid FROM x",
            "WITH x AS MATERIALIZED (UPDATE t SET c = 1 RETURNING c) SELECT 1",
            "SELECT CAST(pid AS numeric(10, 0)), CAST(backend_start AS timestamp(3)) \
             FROM pg_stat_activity",
        ] {
            let scan = pg_scan(q).unwrap();
            assert!(!alias_list(&scan.segments[0].tokens), "{q}");
            assert!(!scan.segments[0].column_list, "{q}");
        }
        assert!(quiet(
            "SELECT CAST(pid AS numeric(10, 0)), CAST(backend_start AS timestamp(3)) \
             FROM pg_stat_activity"
        ));
        // `AS MATERIALIZED (c)` on an item is an alias with a column list.
        assert!(!quiet(
            "SELECT materialized.c FROM pg_stat_activity AS materialized (c)"
        ));
    }

    fn secret_classify(r: &RelationName, call: bool) -> PgItemClass {
        let schema = r.schema.as_deref();
        match (schema, r.name.as_str(), call) {
            (
                None | Some("pg_catalog"),
                "pg_roles" | "pg_authid" | "pg_proc" | "pg_db_role_setting",
                // A relation followed by `(` (`COPY pg_authid (rolname)`).
                _,
            ) => PgItemClass::Listed(PgListed::View),
            (None | Some("pg_catalog"), "pg_largeobject", false) => {
                PgItemClass::Listed(PgListed::Always)
            }
            (Some("pg_catalog"), _, _) => PgItemClass::Catalog,
            (None, n, false) if n.starts_with("pg_") => PgItemClass::Catalog,
            _ => PgItemClass::Other,
        }
    }

    const SECRET: [&str; 5] = [
        "rolpassword",
        "rolconfig",
        "proconfig",
        "setconfig",
        "passwd",
    ];

    fn no_secret(text: &str) -> bool {
        pg_scan(text)
            .unwrap()
            .no_secret_shape(&SECRET, &secret_classify)
    }

    /// ADR-0050 decision 2: the no-secret shape on a set of columns, with
    /// `COPY` refused and earlier CTEs counted as catalogs.
    #[test]
    fn the_no_secret_shape() {
        for q in [
            "SELECT r.rolname FROM pg_roles r WHERE r.rolsuper",
            "SELECT rolname, rolsuper FROM pg_catalog.pg_roles ORDER BY 1",
            "SELECT p.proname, p.prorettype FROM pg_proc p",
            "SELECT count(*) FROM pg_authid",
            "WITH me AS (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER) \
             SELECT (SELECT count(*) FROM pg_catalog.pg_class c, me WHERE c.relowner = me.oid)",
            "WITH RECURSIVE c AS (SELECT 1 AS n UNION ALL SELECT c.n + 1 FROM c WHERE c.n < 3) \
             SELECT p.proname FROM pg_proc p, c WHERE p.pronargs = c.n",
            "COPY (SELECT r.rolname FROM pg_roles r) TO STDOUT",
            "SELECT f FROM pg_catalog.unnest(ARRAY[1]) AS f JOIN pg_proc q ON q.oid = f",
        ] {
            assert!(no_secret(q), "{q}");
        }
        for q in [
            "SELECT rolconfig FROM pg_roles",
            "SELECT r.rolname FROM pg_roles r ORDER BY r.rolconfig",
            "SELECT a.rolname FROM pg_authid a WHERE a.rolpassword LIKE 'md5%'",
            "SELECT s.setconfig AS x FROM pg_db_role_setting s",
            "SELECT 1 AS setconfig FROM pg_db_role_setting s",
            "SELECT 1 FROM pg_roles JOIN pg_db_role_setting USING (setconfig)",
            "SELECT * FROM pg_roles",
            "SELECT r.* FROM pg_roles r",
            "SELECT row_to_json(r) FROM pg_roles r",
            "SELECT r::text FROM pg_roles r",
            "SELECT (r).* FROM pg_roles r",
            "SELECT pg_db_role_setting FROM pg_db_role_setting",
            "SELECT r.c FROM pg_roles r (c)",
            "SELECT b.rolname FROM pg_roles a NATURAL JOIN pg_roles b",
            "TABLE pg_roles",
            "COPY pg_catalog.pg_authid TO STDOUT",
            "COPY pg_authid (rolname) TO STDOUT",
            "COPY BINARY pg_db_role_setting TO STDOUT",
            "SELECT r.rolname FROM pg_roles r, public.v",
            "SELECT r.rolname FROM pg_roles r, f() x",
            "SELECT l.loid FROM pg_largeobject l",
            // A CTE named after its use is a relation; a CTE that reads a
            // whole row or a secret column, or has a column list, fails.
            "WITH a AS (SELECT b.x FROM b), b AS (SELECT 1 AS y) \
             SELECT r.rolname FROM a, pg_roles r",
            "WITH x AS (SELECT r FROM pg_roles r) SELECT 1 FROM x",
            "WITH x AS (SELECT r.rolconfig FROM pg_roles r) SELECT 1 FROM x",
            "WITH x (c) AS (SELECT r.oid FROM pg_roles r) SELECT x.c FROM x",
            "WITH x AS (SELECT t.c FROM app.t t) SELECT r.rolname FROM pg_roles r, x",
        ] {
            assert!(!no_secret(q), "{q}");
        }
        // The no-text shape keeps CTE references as items it cannot decide
        // on (ADR-0049 unchanged).
        let q = "WITH me AS (SELECT r.oid FROM pg_roles r) SELECT 1 FROM pg_proc p, me \
                 WHERE p.proowner = me.oid";
        assert!(no_secret(q));
        assert!(!pg_scan(q).unwrap().no_text_shape(&SECRET, &secret_classify));
        // A CTE of a sibling subquery is not visible: `v` is a relation
        // (security review of PR #217, L1); an enclosing query's CTE is.
        for q in [
            "SELECT r.rolname FROM (WITH v AS (SELECT 1) SELECT 1) q, pg_roles r, v x",
            "SELECT r.rolname FROM (WITH v AS (SELECT 1) SELECT 1) q, pg_roles r, v",
            "SELECT (SELECT 1 FROM (WITH v AS (SELECT 1) SELECT 1) q), r.rolname \
             FROM pg_roles r, v",
        ] {
            assert!(!no_secret(q), "{q}");
        }
        assert!(no_secret(
            "WITH v AS (SELECT 1 AS a) SELECT r.rolname FROM pg_roles r, (SELECT v.a FROM v) q"
        ));
        assert!(no_secret(
            "SELECT r.rolname FROM pg_roles r, (WITH v AS (SELECT 1 AS a) SELECT v.a FROM v) q"
        ));
        // `WITH ORDINALITY` defines no CTE.
        assert!(
            cte_defs(
                &pg_scan("SELECT 1 FROM f() WITH ORDINALITY AS o, o")
                    .unwrap()
                    .segments[0]
                    .tokens
            )
            .is_empty()
        );
    }
}
