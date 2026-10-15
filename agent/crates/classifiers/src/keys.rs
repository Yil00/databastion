//! Redis / Valkey key names normalized into key patterns (ADR-0052
//! decision 7, contract `KeyPattern`). A security component (ADR-0009): a
//! key name is often the most sensitive string of the server.
//!
//! Two stages:
//!
//! 1. **Per key** ([`split_key`]): a name that is not valid UTF-8, or longer
//!    than [`MAX_KEY_BYTES`], becomes `*` as a whole. Otherwise it is
//!    NFKC-folded and split into **segments** on `:`, `/`, `|` and `.`
//!    (and `{` / `}`, so the content of a Cluster hash tag is a segment),
//!    and each segment into **tokens** on `_`, `-` and `#`. Values are
//!    located in the whole name (as is, and with every separator read as a
//!    space, so a value split across segments is found): every segment a
//!    match touches becomes `*` (consecutive ones one `*`), and the matched
//!    text is kept, zeroized, to be classified as a value under the field
//!    `#key` ([`KeyUnits::name_values`]). A token becomes `*` when it holds
//!    a digit (record identifiers of any length: `user:42:email` gives
//!    `user:*:email`), looks generated (hexadecimal, mixed case or
//!    high-entropy, 16 characters or more, checked on the whole segment
//!    with its `_` and `-` too; a lowercase run no word has), holds a
//!    character `Identifier` forbids or one unassigned in the agent's
//!    Unicode tables, is a
//!    common first name, or otherwise looks like a value
//!    ([`crate::names::segment_looks_like_value`]); a first segment naming
//!    a URL scheme becomes `*`.
//! 2. **Per walk** ([`PatternBuilder`]): the tokens left are compared
//!    across the keys of one database walk. A position (a token, with the
//!    tokens before it as its prefix and the shape of the name) holding
//!    more than [`COLLAPSE_THRESHOLD`] distinct values becomes `*`
//!    (cardinality), and so does a position where 2 or more distinct values
//!    precede the same suffix (record-id rule, at every position, the
//!    first included: `session:jdupont` and `session:amartin` give
//!    `session:*`, `phone:1` and `addressbook:2` give `*:*`). During the
//!    walk the builder keeps, per position, at most 17 keyed hashes of its
//!    distinct literals (no key-name text), for at most [`MAX_POSITIONS`]
//!    positions (past it a new position is `*`, fail closed) and
//!    [`MAX_TEMPLATES`] templates (a key whose template cannot be kept is
//!    not tracked); patterns are emitted only by
//!    [`PatternBuilder::finish`], after the walk, with at most 4 rounds of
//!    collapse and merge.
//!
//! Every emitted pattern passes the final gate [`is_key_pattern`]: the
//! contract `KeyPattern` pattern **and** its `not` rules (digit runs per
//! segment and across separators, IPv4, IPv6, MAC, percent escapes, URL
//! scheme), else it is `*`. Raw key names are never logged and never leave
//! this module but as the sample keys the connector reads, in zeroized
//! buffers.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::LazyLock;

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::names::{self, NormalizedName};

/// Longest key name examined; a longer one is `*` as a whole.
pub const MAX_KEY_BYTES: usize = 4096;
/// A position with more distinct values than this collapses (decision 7).
pub const COLLAPSE_THRESHOLD: usize = 16;
/// Literals tracked per position and prefix (one more than the threshold).
pub const MAX_TRACKED_LITERALS: usize = COLLAPSE_THRESHOLD + 1;
/// Distinct templates kept per database walk (decision 6: at most 1 024
/// patterns; beyond, new ones are not sampled).
pub const MAX_TEMPLATES: usize = 1024;
/// Most units (tokens) of a key considered; a longer name is `*`.
pub const MAX_UNITS: usize = 64;
/// Collapse rounds at the end of the walk.
const MAX_ROUNDS: usize = 4;
/// Contract `KeyPattern.maxLength` (characters).
pub const MAX_KEY_PATTERN_CHARS: usize = 256;

/// The contract `KeyPattern.pattern`, verbatim (checked against
/// `shared/protocol/openapi.yaml` by `tests/keys_contract.rs`).
pub const KEY_PATTERN_PATTERN: &str = r#"^[^@=:;/|.\\'"`<>(),\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]+([:/|.][^@=:;/|.\\'"`<>(),\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]+)*$"#;

/// The contract `KeyPattern.not.pattern`, verbatim (same check).
pub const KEY_PATTERN_NOT: &str = r#"(^|[:/|.])[0-9\p{Nd}\p{Zs}_+-]{9,}([:/|.]|$)|[0-9\p{Nd}][0-9\p{Nd}\p{Zs}\p{Pd}_+.\uFF0E:/|-]{7,}[0-9\p{Nd}]|(^|[:/|.])[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([:/|.]|$)|[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}|(^|[:/|.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}([:/|.]|$)|%[0-9A-Fa-f]{2}|(^|[:/|.])((?:[0-9][0-9A-Fa-f]{0,3}|[A-Fa-f][0-9][0-9A-Fa-f]{0,2}|[A-Fa-f]{2}[0-9][0-9A-Fa-f]?|[A-Fa-f]{3}[0-9]):[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|[0-9A-Fa-f]{1,4}:(?:[0-9][0-9A-Fa-f]{0,3}|[A-Fa-f][0-9][0-9A-Fa-f]{0,2}|[A-Fa-f]{2}[0-9][0-9A-Fa-f]?|[A-Fa-f]{3}[0-9]):[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:(?:[0-9][0-9A-Fa-f]{0,3}|[A-Fa-f][0-9][0-9A-Fa-f]{0,2}|[A-Fa-f]{2}[0-9][0-9A-Fa-f]?|[A-Fa-f]{3}[0-9]):[0-9A-Fa-f]{1,4}|[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}:(?:[0-9][0-9A-Fa-f]{0,3}|[A-Fa-f][0-9][0-9A-Fa-f]{0,2}|[A-Fa-f]{2}[0-9][0-9A-Fa-f]?|[A-Fa-f]{3}[0-9]))([:/|.]|$)|^ *([Jj][Aa][Vv][Aa][Ss][Cc][Rr][Ii][Pp][Tt]|[Dd][Aa][Tt][Aa]|[Vv][Bb][Ss][Cc][Rr][Ii][Pp][Tt]|[Ff][Ii][Ll][Ee]|[Hh][Tt][Tt][Pp][Ss]?|[Mm][Aa][Ii][Ll][Tt][Oo]) *([:/|.]|$)"#;

/// Compiled contract patterns (the linear-time `regex` engine; the
/// contract's ECMAScript syntax used here is a common subset, checked by a
/// differential property test against `regress`).
#[allow(clippy::expect_used, reason = "constant patterns, compiled in tests")]
static GATE: LazyLock<(regex::Regex, regex::Regex)> = LazyLock::new(|| {
    (
        regex::Regex::new(KEY_PATTERN_PATTERN).expect("KeyPattern pattern compiles"),
        regex::Regex::new(KEY_PATTERN_NOT).expect("KeyPattern not pattern compiles"),
    )
});

/// Whether `s` is a valid contract `KeyPattern`: length, pattern and every
/// `not` rule. The final gate of every pattern this module emits.
#[must_use]
pub fn is_key_pattern(s: &str) -> bool {
    let len = s.chars().count();
    if len == 0 || len > MAX_KEY_PATTERN_CHARS {
        return false;
    }
    let (pattern, not) = &*GATE;
    pattern.is_match(s) && !not.is_match(s) && !has_unassigned(s)
}

/// Code points unassigned in this agent's Unicode tables (`\p{Cn}`).
#[allow(clippy::expect_used, reason = "constant pattern, compiled in tests")]
static UNASSIGNED: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\p{Cn}").expect("unassigned class compiles"));

/// Whether `s` holds a code point unassigned in this agent's Unicode
/// tables. The console's engine may know it (as a digit, say: U+11DE0 to
/// U+11DE9 are `Nd` in Unicode 17), so the gate refuses it rather than
/// guess (security review L1); the normalizer treats it as a value.
fn has_unassigned(s: &str) -> bool {
    UNASSIGNED.is_match(s)
}

/// URL schemes refused as a first segment (contract `KeyPattern`).
const URL_SCHEMES: [&str; 7] = [
    "javascript",
    "data",
    "vbscript",
    "file",
    "http",
    "https",
    "mailto",
];

/// Segment separators (decision 7), and the hash-tag braces.
fn is_segment_sep(c: char) -> bool {
    matches!(c, ':' | '/' | '|' | '.' | '{' | '}')
}

/// Token separators inside a segment.
fn is_token_sep(c: char) -> bool {
    matches!(c, '_' | '-' | '#')
}

/// A string zeroized on drop (key-name literals, values found in names).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Secret(String);

impl Secret {
    /// The text. Never log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Hash for Secret {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(…)")
    }
}

/// Bytes zeroized on drop (raw key names kept as sample keys).
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// A copy of `bytes`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// The bytes. Never log them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(…)")
    }
}

/// One token of a normalized name.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Tok {
    /// Replaced by `*`.
    Wild,
    /// Kept as is (until the walk's rules decide).
    Lit(Secret),
}

/// A token and the separators before it (empty for the first one).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Unit {
    sep: String,
    tok: Tok,
}

/// A key name after the per-key rules.
#[derive(Debug, Clone)]
pub struct KeyUnits {
    units: Vec<Unit>,
    /// Text of the values found in the name (classifier matches), to be
    /// classified under `#key`.
    pub name_values: Vec<Secret>,
}

impl KeyUnits {
    fn wildcard() -> Self {
        Self {
            units: vec![Unit {
                sep: String::new(),
                tok: Tok::Wild,
            }],
            name_values: Vec::new(),
        }
    }

    /// The pattern of this key alone (no walk rules), through the final
    /// gate. Used for names met outside a walk (tests, fuzzing).
    #[must_use]
    pub fn pattern(&self) -> NormalizedName {
        NormalizedName::key_pattern(render(&self.units))
    }
}

fn render(units: &[Unit]) -> String {
    let mut out = String::new();
    for u in units {
        out.push_str(&u.sep);
        match &u.tok {
            Tok::Wild => out.push('*'),
            Tok::Lit(s) => out.push_str(s.expose()),
        }
    }
    out
}

/// Whether a token looks like a value by itself.
fn token_is_value(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    if token
        .chars()
        .any(|c| names::is_numeric_like(c) || c.is_numeric())
    {
        return true;
    }
    if token.chars().any(|c| {
        names::is_forbidden_char(c)
            || matches!(
                c,
                '@' | '=' | ';' | '\\' | '\'' | '"' | '`' | '<' | '>' | '(' | ')' | ',' | '%' | '+'
            )
            || c.is_whitespace()
    }) {
        return true;
    }
    if has_unassigned(token) || looks_generated(token) {
        return true;
    }
    names::segment_looks_like_value(token)
}

/// Whether a token, or a whole segment with its `_` and `-` (so a
/// base64url string is not first cut into ordinary-looking tokens), looks
/// generated (security review M4):
/// - 16 characters or more of `[A-Za-z0-9_-]` that are all hexadecimal,
///   or mix case with 3 or more lower-to-upper changes, or whose
///   character entropy reaches 90 % of the most a string of that length
///   over its alphabet can have (`log2(min(n, alphabet))`);
/// - a run of 8 or more lowercase letters that no word has: 5 consonants
///   in a row, or (12 letters or more) fewer than 20 % vowels (`y`
///   counted as a vowel).
fn looks_generated(token: &str) -> bool {
    if lowercase_runs_look_generated(token) {
        return true;
    }
    let n = token.chars().count();
    if n < 16 {
        return false;
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return false;
    }
    if token.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    let changes = token
        .chars()
        .zip(token.chars().skip(1))
        .filter(|(a, b)| a.is_ascii_lowercase() && b.is_ascii_uppercase())
        .count();
    if changes >= 3 {
        return true;
    }
    let has = |f: fn(&char) -> bool| token.chars().any(|c| f(&c));
    let alphabet = usize::from(has(char::is_ascii_lowercase)) * 26
        + usize::from(has(char::is_ascii_uppercase)) * 26
        + usize::from(has(char::is_ascii_digit)) * 10
        + usize::from(has(|c| *c == '_' || *c == '-')) * 2;
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for c in token.chars() {
        *counts.entry(c).or_default() += 1;
    }
    #[allow(clippy::cast_precision_loss, reason = "lengths far below 2^52")]
    let (entropy, ceiling) = (
        counts
            .values()
            .map(|&k| {
                let p = k as f64 / n as f64;
                -p * p.log2()
            })
            .sum::<f64>(),
        (n.min(alphabet.max(2)) as f64).log2(),
    );
    entropy >= 0.9 * ceiling
}

/// The lowercase heuristic of [`looks_generated`].
fn lowercase_runs_look_generated(token: &str) -> bool {
    let is_vowel = |c: char| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'y');
    token
        .split(|c: char| !c.is_ascii_lowercase())
        .filter(|run| run.len() >= 8)
        .any(|run| {
            let mut consonants = 0usize;
            let mut longest = 0usize;
            let mut vowels = 0usize;
            for c in run.chars() {
                if is_vowel(c) {
                    vowels += 1;
                    consonants = 0;
                } else {
                    consonants += 1;
                    longest = longest.max(consonants);
                }
            }
            longest >= 5 || (run.len() >= 12 && vowels * 5 < run.len())
        })
}

/// Applies the per-key rules (see the module documentation).
#[must_use]
pub fn split_key(raw: &[u8]) -> KeyUnits {
    if raw.is_empty() || raw.len() > MAX_KEY_BYTES {
        return KeyUnits::wildcard();
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        return KeyUnits::wildcard();
    };
    let mut folded: String = text.nfkc().collect();
    let result = split_folded(&folded);
    folded.zeroize();
    result
}

/// A segment of the folded name: its byte range and the separators before
/// it.
struct Seg {
    start: usize,
    end: usize,
    sep_start: usize,
}

fn split_folded(s: &str) -> KeyUnits {
    if s.is_empty() || s.len() > MAX_KEY_BYTES {
        return KeyUnits::wildcard();
    }
    // Segments and the separator runs before them.
    let mut segs: Vec<Seg> = Vec::new();
    let mut sep_start = 0;
    let mut start: Option<usize> = None;
    for (i, c) in s.char_indices() {
        if is_segment_sep(c) {
            if let Some(st) = start.take() {
                segs.push(Seg {
                    start: st,
                    end: i,
                    sep_start,
                });
                sep_start = i;
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(st) = start {
        segs.push(Seg {
            start: st,
            end: s.len(),
            sep_start,
        });
    }
    let trailing_sep = segs.last().is_some_and(|l| l.end < s.len());
    if segs.is_empty() {
        return KeyUnits::wildcard();
    }
    // Values located in the whole name, as is and with every separator
    // read as a space (same byte length: ASCII for ASCII).
    let spaced: String = s
        .chars()
        .map(|c| {
            if is_segment_sep(c) || is_token_sep(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    let mut spans = names::key_value_spans(s);
    spans.extend(names::key_value_spans(&spaced));
    let touched = |seg: &Seg| {
        spans
            .iter()
            .any(|r| r.start < seg.end.max(seg.start + 1) && seg.start < r.end)
    };
    let mut units: Vec<Unit> = Vec::new();
    let mut name_values: Vec<Secret> = Vec::new();
    let mut in_value: Option<usize> = None;
    for (idx, seg) in segs.iter().enumerate() {
        let sep = s.get(seg.sep_start..seg.start).unwrap_or("").to_owned();
        let text = s.get(seg.start..seg.end).unwrap_or("");
        if touched(seg) {
            // Consecutive touched segments: one `*`, one value.
            match in_value {
                Some(_) => {}
                None => {
                    units.push(Unit {
                        sep,
                        tok: Tok::Wild,
                    });
                }
            }
            in_value = Some(in_value.unwrap_or(seg.start));
            continue;
        }
        if let Some(vs) = in_value.take() {
            let prev_end = segs
                .get(idx.wrapping_sub(1))
                .map_or(seg.sep_start, |p| p.end);
            if let Some(v) = s.get(vs..prev_end) {
                name_values.push(Secret(v.to_owned()));
            }
        }
        let first = units.is_empty();
        if first
            && URL_SCHEMES
                .iter()
                .any(|scheme| text.trim().eq_ignore_ascii_case(scheme))
        {
            units.push(Unit {
                sep,
                tok: Tok::Wild,
            });
            continue;
        }
        // A generated-looking segment, `_` and `-` included, is one `*`.
        if looks_generated(text) {
            units.push(Unit {
                sep,
                tok: Tok::Wild,
            });
            continue;
        }
        // Tokens of the segment.
        let mut tok_sep = sep;
        let mut tok_start: Option<usize> = None;
        let mut pending: Vec<(String, &str)> = Vec::new();
        for (i, c) in text.char_indices() {
            if is_token_sep(c) {
                if let Some(ts) = tok_start.take() {
                    pending.push((std::mem::take(&mut tok_sep), text.get(ts..i).unwrap_or("")));
                }
                tok_sep.push(c);
            } else if tok_start.is_none() {
                tok_start = Some(i);
            }
        }
        if let Some(ts) = tok_start {
            pending.push((std::mem::take(&mut tok_sep), text.get(ts..).unwrap_or("")));
        }
        if pending.is_empty() || !tok_sep.is_empty() {
            // A segment made of token separators only, or ending with one:
            // the whole segment is one `*`.
            let sep = pending
                .first()
                .map_or(tok_sep.clone(), |(sp, _)| sp.clone());
            units.push(Unit {
                sep,
                tok: Tok::Wild,
            });
            continue;
        }
        for (sp, t) in pending {
            let tok = if token_is_value(t) {
                Tok::Wild
            } else {
                Tok::Lit(Secret(t.to_owned()))
            };
            units.push(Unit { sep: sp, tok });
        }
    }
    if let Some(vs) = in_value {
        let end = segs.last().map_or(s.len(), |l| l.end);
        if let Some(v) = s.get(vs..end) {
            name_values.push(Secret(v.to_owned()));
        }
    }
    if trailing_sep || units.len() > MAX_UNITS {
        // A trailing separator cannot be a `KeyPattern`; too many tokens:
        // the whole name.
        return KeyUnits {
            units: KeyUnits::wildcard().units,
            name_values,
        };
    }
    KeyUnits { units, name_values }
}

/// What the connector keeps per pattern and kind (a Redis type) during the
/// walk.
#[derive(Debug, Default)]
pub struct Group {
    /// Keys of the walk under this pattern.
    pub count: u64,
    /// The first keys met (at most the builder's `samples`), to sample.
    pub samples: Vec<SecretBytes>,
    /// Values found in the names (at most the builder's `samples`).
    pub name_values: Vec<Secret>,
}

impl Group {
    fn merge(&mut self, other: Self, cap: usize) {
        self.count = self.count.saturating_add(other.count);
        for s in other.samples {
            if self.samples.len() < cap {
                self.samples.push(s);
            }
        }
        for v in other.name_values {
            if self.name_values.len() < cap {
                self.name_values.push(v);
            }
        }
    }
}

/// A pattern emitted after the walk.
#[derive(Debug)]
pub struct EmittedPattern {
    /// The normalized pattern (a contract `KeyPattern`, or `*`).
    pub pattern: NormalizedName,
    /// The connector's kind (a Redis type code).
    pub kind: u8,
    /// What was kept for it.
    pub group: Group,
}

/// The position ids of one name, left to right: a keyed hash of the name's
/// shape (the separators of every unit, so the unit count), the position
/// and the tokens before it. Ids only, never the literals themselves: what
/// the walk keeps per position is bounded and holds no key-name text.
/// A collision can only merge two positions' counts, so it can only make
/// more positions collapse (fail closed); the per-builder random key keeps
/// a crafted keyspace from aiming one.
struct Positions {
    prefix: std::collections::hash_map::DefaultHasher,
}

impl Positions {
    fn new(state: &RandomState, units: &[Unit]) -> Self {
        let mut prefix = state.build_hasher();
        units.len().hash(&mut prefix);
        for u in units {
            u.sep.hash(&mut prefix);
        }
        Self { prefix }
    }

    /// The id of position `pos`, the tokens before it pushed.
    fn id(&self, pos: usize) -> u64 {
        let mut h = self.prefix.clone();
        pos.hash(&mut h);
        h.finish()
    }

    /// Adds the token of the current position to the prefix.
    fn push(&mut self, tok: &Tok) {
        tok.hash(&mut self.prefix);
    }
}

/// Most position entries (tracked or collapsed) of one walk. Past it, a
/// literal at a position not seen yet becomes `*` (fail closed): the
/// walk's memory stays bounded whatever the keyspace (security review H3).
pub const MAX_POSITIONS: usize = 16 * MAX_TEMPLATES;

/// Builds the patterns of one database walk (see the module
/// documentation). Bounded: at most [`MAX_TEMPLATES`] templates,
/// [`MAX_POSITIONS`] positions and [`MAX_TRACKED_LITERALS`] literal hashes
/// per position.
pub struct PatternBuilder {
    samples: usize,
    state: RandomState,
    templates: HashMap<(Vec<Unit>, u8), Group>,
    /// Keyed hashes of the distinct literals seen per position id (at most
    /// [`MAX_TRACKED_LITERALS`] each).
    literals: HashMap<u64, Vec<u64>>,
    /// Position ids collapsed by cardinality during the walk.
    collapsed: HashSet<u64>,
    /// Keys whose template could not be kept (template bound).
    overflow: u64,
    /// Literals turned into `*` by the position bound.
    position_bound: u64,
}

impl std::fmt::Debug for PatternBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatternBuilder")
            .field("templates", &self.templates.len())
            .field("positions", &self.positions())
            .field("overflow", &self.overflow)
            .field("position_bound", &self.position_bound)
            .finish_non_exhaustive()
    }
}

impl PatternBuilder {
    /// A builder keeping at most `samples` sample keys and name values per
    /// pattern.
    #[must_use]
    pub fn new(samples: usize) -> Self {
        Self {
            samples,
            state: RandomState::new(),
            templates: HashMap::new(),
            literals: HashMap::new(),
            collapsed: HashSet::new(),
            overflow: 0,
            position_bound: 0,
        }
    }

    /// Keys not kept because the template bound was reached.
    #[must_use]
    pub fn overflow(&self) -> u64 {
        self.overflow
    }

    /// Literals turned into `*` because the position bound was reached.
    #[must_use]
    pub fn position_bound_hits(&self) -> u64 {
        self.position_bound
    }

    /// Distinct templates kept so far.
    #[must_use]
    pub fn templates(&self) -> usize {
        self.templates.len()
    }

    /// Position entries kept so far (tracked and collapsed).
    #[must_use]
    pub fn positions(&self) -> usize {
        self.literals.len().saturating_add(self.collapsed.len())
    }

    /// Literal hashes kept so far, over every position.
    #[must_use]
    pub fn tracked_literals(&self) -> usize {
        self.literals.values().map(Vec::len).sum()
    }

    /// Applies the positions already collapsed to `units`, left to right.
    fn apply_collapsed(&self, units: &mut [Unit]) {
        if self.collapsed.is_empty() {
            return;
        }
        let mut ids = Positions::new(&self.state, units);
        for (pos, u) in units.iter_mut().enumerate() {
            if self.collapsed.contains(&ids.id(pos)) {
                u.tok = Tok::Wild;
            }
            ids.push(&u.tok);
        }
    }

    /// Adds one key of the walk, of connector kind `kind`. `raw` is the key
    /// name as the server returned it (kept as a sample key while the
    /// pattern has fewer than `samples`).
    pub fn add(&mut self, raw: &[u8], key: KeyUnits, kind: u8) {
        let KeyUnits {
            mut units,
            name_values,
        } = key;
        self.apply_collapsed(&mut units);
        // A key whose template cannot be kept is not tracked either.
        if self.templates.len() >= MAX_TEMPLATES
            && !self.templates.contains_key(&(units.clone(), kind))
        {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        // Cardinality, tracked while walking (bounded).
        let mut newly = Vec::new();
        {
            let Self {
                state,
                literals,
                collapsed,
                position_bound,
                ..
            } = self;
            let mut ids = Positions::new(state, &units);
            for (pos, u) in units.iter_mut().enumerate() {
                if let Tok::Lit(lit) = &u.tok {
                    let id = ids.id(pos);
                    let lit = state.hash_one(lit.expose());
                    if let Some(set) = literals.get_mut(&id) {
                        if set.len() < MAX_TRACKED_LITERALS && !set.contains(&lit) {
                            set.push(lit);
                        }
                        if set.len() > COLLAPSE_THRESHOLD {
                            newly.push(id);
                        }
                    } else if literals.len().saturating_add(collapsed.len()) >= MAX_POSITIONS {
                        u.tok = Tok::Wild;
                        *position_bound = position_bound.saturating_add(1);
                    } else {
                        literals.insert(id, vec![lit]);
                    }
                }
                ids.push(&u.tok);
            }
        }
        if !newly.is_empty() {
            for id in newly {
                self.literals.remove(&id);
                self.collapsed.insert(id);
            }
            self.apply_collapsed(&mut units);
            self.rebuild();
        }
        let cap = self.samples;
        let slot_key = (units, kind);
        if !self.templates.contains_key(&slot_key) && self.templates.len() >= MAX_TEMPLATES {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        let group = self.templates.entry(slot_key).or_default();
        group.count = group.count.saturating_add(1);
        if group.samples.len() < cap {
            group.samples.push(SecretBytes::new(raw));
        }
        for v in name_values {
            if group.name_values.len() < cap {
                group.name_values.push(v);
            }
        }
    }

    /// Re-keys every template after a collapse, merging the ones that
    /// became equal.
    fn rebuild(&mut self) {
        let old = std::mem::take(&mut self.templates);
        for ((mut units, kind), group) in old {
            self.apply_collapsed(&mut units);
            match self.templates.get_mut(&(units.clone(), kind)) {
                Some(g) => g.merge(group, self.samples),
                None => {
                    self.templates.insert((units, kind), group);
                }
            }
        }
    }

    /// Positions to collapse by the walk's rules over the kept templates:
    /// cardinality, and the record-id rule (2 or more distinct values
    /// before the same suffix, at every position, the first included:
    /// `phone:1` and `addressbook:2` give `*:*`, decision 7 as written;
    /// over-masking is accepted, ADR-0009).
    fn decide(&self) -> Vec<u64> {
        let mut distinct: HashMap<u64, HashSet<u64>> = HashMap::new();
        let mut by_suffix: HashMap<(u64, u64), HashSet<u64>> = HashMap::new();
        for (units, _) in self.templates.keys() {
            // Suffix hashes, right to left.
            let mut suffix = vec![0u64; units.len()];
            let mut h = self.state.hash_one(units.len());
            for (pos, u) in units.iter().enumerate().rev() {
                if let Some(slot) = suffix.get_mut(pos) {
                    *slot = h;
                }
                h = self.state.hash_one((h, &u.sep, &u.tok));
            }
            let mut ids = Positions::new(&self.state, units);
            for (pos, u) in units.iter().enumerate() {
                if let Tok::Lit(lit) = &u.tok {
                    let id = ids.id(pos);
                    let lit = self.state.hash_one(lit.expose());
                    distinct.entry(id).or_default().insert(lit);
                    let suf = suffix.get(pos).copied().unwrap_or_default();
                    by_suffix.entry((id, suf)).or_default().insert(lit);
                }
                ids.push(&u.tok);
            }
        }
        let mut out: HashSet<u64> = distinct
            .into_iter()
            .filter(|(_, values)| values.len() > COLLAPSE_THRESHOLD)
            .map(|(id, _)| id)
            .collect();
        for ((id, _), values) in by_suffix {
            if values.len() >= 2 {
                out.insert(id);
            }
        }
        out.into_iter().collect()
    }

    /// Ends the walk: applies the walk's rules (at most 4 rounds), then
    /// renders each template through the final gate and merges those that
    /// give the same pattern.
    #[must_use]
    pub fn finish(mut self) -> Vec<EmittedPattern> {
        for _ in 0..MAX_ROUNDS {
            let decided = self.decide();
            if decided.is_empty() {
                break;
            }
            self.collapsed.extend(decided);
            self.rebuild();
        }
        let cap = self.samples;
        let mut merged: BTreeMap<(String, u8), Group> = BTreeMap::new();
        for ((units, kind), group) in std::mem::take(&mut self.templates) {
            let pattern = NormalizedName::key_pattern(render(&units));
            match merged.get_mut(&(pattern.as_str().to_owned(), kind)) {
                Some(g) => g.merge(group, cap),
                None => {
                    merged.insert((pattern.as_str().to_owned(), kind), group);
                }
            }
        }
        merged
            .into_iter()
            .map(|((p, kind), group)| EmittedPattern {
                pattern: NormalizedName::key_pattern(p),
                kind,
                group,
            })
            .collect()
    }
}

/// Most patterns kept per learned set (16 databases' worth of
/// [`MAX_TEMPLATES`]); beyond, the rest is not kept (Audit objects only get
/// coarser).
pub const MAX_LEARNED: usize = 16 * MAX_TEMPLATES;
/// Most units of a key name a learned-pattern match looks at.
const MAX_MATCH_UNITS: usize = 4 * MAX_UNITS;

/// One unit of a learned pattern or of a key name met in Audit: the
/// separators before it and its token (`None`: `*`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct LUnit {
    sep: String,
    tok: Option<String>,
}

impl Drop for LUnit {
    fn drop(&mut self) {
        // Units of key names met in Audit are other clients' arguments.
        self.sep.zeroize();
        if let Some(t) = self.tok.as_mut() {
            t.zeroize();
        }
    }
}

/// Splits `s` into units on the segment and token separators. `None` when
/// it has more than `max` units. Trailing separators (no token after
/// them) are returned apart.
fn units_of(s: &str, max: usize, star_is_wild: bool) -> Option<(Vec<LUnit>, String)> {
    let mut units: Vec<LUnit> = Vec::new();
    let mut sep = String::new();
    let mut tok = String::new();
    for c in s.chars() {
        if is_segment_sep(c) || is_token_sep(c) {
            if !tok.is_empty() {
                if units.len() >= max {
                    sep.zeroize();
                    tok.zeroize();
                    return None;
                }
                let t = std::mem::take(&mut tok);
                let wild = star_is_wild && t == "*";
                units.push(LUnit {
                    sep: std::mem::take(&mut sep),
                    tok: (!wild).then_some(t),
                });
            }
            sep.push(c);
        } else {
            tok.push(c);
        }
    }
    if !tok.is_empty() {
        if units.len() >= max {
            sep.zeroize();
            tok.zeroize();
            return None;
        }
        let wild = star_is_wild && tok == "*";
        units.push(LUnit {
            sep: std::mem::take(&mut sep),
            tok: (!wild).then_some(tok),
        });
    }
    Some((units, sep))
}

/// Whether `pattern` matches all of `key`: a literal token equals the
/// key's token, `*` stands for one or more whole units of the key, and
/// every separator run before a pattern unit equals the key's.
fn matches_units(pattern: &[LUnit], key: &[LUnit]) -> bool {
    let (m, n) = (pattern.len(), key.len());
    // ok[i][j]: pattern[i..] matches key[j..].
    let mut ok = vec![vec![false; n + 1]; m + 1];
    if let Some(row) = ok.get_mut(m)
        && let Some(cell) = row.get_mut(n)
    {
        *cell = true;
    }
    for i in (0..m).rev() {
        for j in (0..n).rev() {
            let (Some(p), Some(k)) = (pattern.get(i), key.get(j)) else {
                continue;
            };
            if p.sep != k.sep {
                continue;
            }
            let v = match &p.tok {
                Some(lit) => {
                    k.tok.as_deref() == Some(lit.as_str())
                        && ok
                            .get(i + 1)
                            .and_then(|r| r.get(j + 1))
                            .copied()
                            .unwrap_or(false)
                }
                // `*` takes key[j..j + len] for some len >= 1.
                None => (j + 1..=n).any(|e| {
                    ok.get(i + 1)
                        .and_then(|r| r.get(e))
                        .copied()
                        .unwrap_or(false)
                }),
            };
            if let Some(cell) = ok.get_mut(i).and_then(|r| r.get_mut(j)) {
                *cell = v;
            }
        }
    }
    ok.first().and_then(|r| r.first()).copied().unwrap_or(false)
}

/// The patterns learned by the last completed walk of one database, as
/// Audit uses them (ADR-0052 decision 8, security review H1): a key name
/// read from a log entry is reported under a learned pattern it matches,
/// or under its longest learned **literal** prefix followed by `*`, or as
/// `*`; never under a literal the walk did not emit. Every result then
/// goes through the per-key rules again ([`split_key`], the second gate)
/// and the contract gate ([`is_key_pattern`]).
///
/// Holds only emitted patterns (contract `KeyPattern`s, no key-name
/// text); at most [`MAX_LEARNED`].
#[derive(Debug, Default, Clone)]
pub struct LearnedPatterns {
    /// The patterns, as emitted, sorted and unique.
    texts: Vec<String>,
    /// Their units.
    parsed: Vec<Vec<LUnit>>,
    /// Indices of the patterns by their first token (`None`: `*` first).
    by_first: HashMap<Option<String>, Vec<usize>>,
    /// Every literal prefix (whole units, before the first `*`) of every
    /// pattern, rendered.
    prefixes: HashSet<String>,
}

impl LearnedPatterns {
    /// The learned set of `patterns`; those that are not contract
    /// `KeyPattern`s, and `*`, are ignored.
    #[must_use]
    pub fn new<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Self {
        let mut texts: Vec<String> = patterns
            .into_iter()
            .filter(|p| *p != "*" && is_key_pattern(p))
            .map(str::to_owned)
            .collect();
        texts.sort_unstable();
        texts.dedup();
        texts.truncate(MAX_LEARNED);
        let mut out = Self::default();
        for t in texts {
            let Some((units, tail)) = units_of(&t, MAX_UNITS, true) else {
                continue;
            };
            if !tail.is_empty() || units.is_empty() {
                continue;
            }
            let idx = out.parsed.len();
            let mut prefix = String::new();
            for u in &units {
                let Some(lit) = &u.tok else { break };
                prefix.push_str(&u.sep);
                prefix.push_str(lit);
                out.prefixes.insert(prefix.clone());
            }
            out.by_first
                .entry(units.first().and_then(|u| u.tok.clone()))
                .or_default()
                .push(idx);
            out.parsed.push(units);
            out.texts.push(t);
        }
        out
    }

    /// The patterns, sorted.
    #[must_use]
    pub fn patterns(&self) -> &[String] {
        &self.texts
    }

    /// Number of patterns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.texts.len()
    }

    /// Whether no pattern was learned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.texts.is_empty()
    }

    /// The patterns learned in every one of `sets` (a log entry whose
    /// database is not known); empty when `sets` is.
    #[must_use]
    pub fn intersection(sets: &[&Self]) -> Self {
        let Some((first, rest)) = sets.split_first() else {
            return Self::default();
        };
        Self::new(
            first
                .texts
                .iter()
                .filter(|t| rest.iter().all(|s| s.texts.binary_search(t).is_ok()))
                .map(String::as_str),
        )
    }

    /// The object of a key name `raw` read from a log entry. `cut`: the
    /// server cut the argument (its last unit is incomplete): only the
    /// literal-prefix rule applies, on the complete units.
    #[must_use]
    pub fn object(&self, raw: &[u8], cut: bool) -> NormalizedName {
        if raw.is_empty() || raw.len() > MAX_KEY_BYTES {
            return NormalizedName::wildcard();
        }
        let Ok(text) = std::str::from_utf8(raw) else {
            return NormalizedName::wildcard();
        };
        let mut folded: String = text.nfkc().collect();
        let found = self.find(&folded, cut);
        folded.zeroize();
        match found {
            // The second gate: the per-key rules again, then the contract
            // gate; they only ever turn literals into `*`.
            Some(mut p) => {
                let gated = split_key(p.as_bytes()).pattern();
                p.zeroize();
                gated
            }
            None => NormalizedName::wildcard(),
        }
    }

    fn find(&self, folded: &str, cut: bool) -> Option<String> {
        let (units, tail) = units_of(folded, MAX_MATCH_UNITS, false)?;
        // The best full match: (literal tokens, index).
        let mut full: Option<(usize, usize)> = None;
        if !cut && tail.is_empty() && !units.is_empty() {
            let first = units.first().and_then(|u| u.tok.clone());
            let candidates = self
                .by_first
                .get(&first)
                .into_iter()
                .chain(self.by_first.get(&None))
                .flatten();
            // The most specific match: most literal tokens, then fewest
            // `*`, then the first in order (deterministic).
            let mut best: Option<(usize, usize, usize)> = None;
            for &i in candidates {
                let Some(p) = self.parsed.get(i) else {
                    continue;
                };
                if !matches_units(p, &units) {
                    continue;
                }
                let lits = p.iter().filter(|u| u.tok.is_some()).count();
                let wilds = p.len() - lits;
                let better = best.is_none_or(|(bl, bw, bi)| {
                    (lits, std::cmp::Reverse(wilds), std::cmp::Reverse(i))
                        > (bl, std::cmp::Reverse(bw), std::cmp::Reverse(bi))
                });
                if better {
                    best = Some((lits, wilds, i));
                }
            }
            if let Some((lits, _, i)) = best {
                full = Some((lits, i));
            }
        }
        // The longest learned literal prefix of the key, then `*`: the
        // prefix covers whole units, and at least one unit of the key is
        // left for the `*` (the last, incomplete one of a cut argument is
        // never part of the prefix).
        let complete = if cut {
            units.len().saturating_sub(1)
        } else {
            units.len()
        };
        let mut rendered: Vec<String> = Vec::with_capacity(complete);
        let mut acc = String::new();
        for u in units.iter().take(complete) {
            acc.push_str(&u.sep);
            acc.push_str(u.tok.as_deref().unwrap_or("*"));
            rendered.push(acc.clone());
        }
        acc.zeroize();
        let mut prefixed = None;
        for k in (1..=rendered.len()).rev() {
            let Some(next) = units.get(k) else { continue };
            if let Some(prefix) = rendered.get(k - 1)
                && self.prefixes.contains(prefix)
            {
                prefixed = Some((k, format!("{prefix}{}*", next.sep)));
                break;
            }
        }
        for mut r in rendered {
            r.zeroize();
        }
        // The one naming more learned literals; a full match on a tie.
        match (full, prefixed) {
            (Some((lits, i)), Some((k, _))) if lits >= k => self.texts.get(i).cloned(),
            (_, Some((_, p))) => Some(p),
            (Some((_, i)), None) => self.texts.get(i).cloned(),
            (None, None) => None,
        }
    }
}

/// Fuzz entry point: a learned set from `patterns` (one per line of the
/// first half of `data`), then the object of a key (the second half);
/// the result must always pass the contract gate.
#[doc(hidden)]
#[must_use]
pub fn fuzz_learned(data: &[u8]) -> String {
    let mid = data.len() / 2;
    let (pats, key) = data.split_at(mid);
    let text = String::from_utf8_lossy(pats);
    let learned = LearnedPatterns::new(text.lines());
    let cut = key.first().is_some_and(|b| b & 1 == 1);
    learned.object(key, cut).as_str().to_owned()
}

/// Fuzz entry point: the per-key rules then a walk of one key; the
/// emitted pattern must always pass the final gate (or be `*`).
#[doc(hidden)]
#[must_use]
pub fn fuzz_normalize(raw: &[u8]) -> String {
    let mut b = PatternBuilder::new(1);
    b.add(raw, split_key(raw), 0);
    b.finish()
        .into_iter()
        .map(|p| p.pattern.as_str().to_owned())
        .next()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(key: &str) -> String {
        split_key(key.as_bytes()).pattern().as_str().to_owned()
    }

    fn walk(keys: &[&str]) -> Vec<String> {
        let mut b = PatternBuilder::new(2);
        for k in keys {
            b.add(k.as_bytes(), split_key(k.as_bytes()), 0);
        }
        b.finish()
            .into_iter()
            .map(|p| p.pattern.as_str().to_owned())
            .collect()
    }

    #[test]
    fn per_key_rules() {
        assert_eq!(one("user:42:email"), "user:*:email");
        assert_eq!(one("user:jane.doe@example.com:profile"), "user:*:profile");
        assert_eq!(one("phone:33261917924"), "phone:*");
        assert_eq!(one("session:ced5cce35902394af2b011eb9a6aaead"), "session:*");
        assert_eq!(one("cache:page:about"), "cache:page:about");
        assert_eq!(one("stats:visits:2026-09-03"), "stats:visits:*");
        assert_eq!(one("order_jdupont_2024"), "order_jdupont_*");
        assert_eq!(one("archive_lucas"), "archive_*");
        assert_eq!(one("javascript:alert"), "*:alert");
        assert_eq!(one("host:10.0.0.1"), "host:*.*.*.*");
        assert_eq!(one("user:{42}:x"), "user:{*}:x");
        assert_eq!(one("a::b"), "*");
        assert_eq!(one("trailing:"), "*");
        assert_eq!(one(":leading"), "*");
        assert_eq!(split_key(&[0xff, b':', b'a']).pattern().as_str(), "*");
        assert_eq!(one("x:AbCdEfGhIjKlMnOpQr"), "x:*");
        assert_eq!(one("feature:flags"), "feature:flags");
        assert_eq!(one("ｕｓｅｒ：４２"), "user:*");
    }

    #[test]
    fn values_in_names_are_kept_for_classification() {
        let k = split_key(b"user:jane.doe@example.com:profile");
        let values: Vec<&str> = k.name_values.iter().map(Secret::expose).collect();
        assert_eq!(values, ["jane.doe@example.com"]);
        let k = split_key(b"phone:33261917924");
        assert_eq!(k.name_values.len(), 1);
    }

    #[test]
    fn record_id_and_cardinality_rules() {
        assert_eq!(walk(&["session:jdupont", "session:amartin"]), ["session:*"]);
        assert_eq!(
            walk(&["user:jdupont:email", "user:amartin:email"]),
            ["user:*:email"]
        );
        assert_eq!(
            walk(&["config:prod:url", "config:test:url"]),
            ["config:*:url"]
        );
        // A single-key family keeps its literals (documented residual).
        assert_eq!(walk(&["user:jdupont:email"]), ["user:jdupont:email"]);
        // Different first segments before the same suffix are records too,
        // the first position included (decision 7 as written; security
        // review H1): over-masking is accepted.
        assert_eq!(walk(&["phone:1", "addressbook:2"]), ["*:*"]);
        // The measured leaks of the former first-position exception.
        assert_eq!(walk(&["jdupont:42", "amartin:17"]), ["*:*"]);
        assert_eq!(walk(&["jdupont:42:cart", "amartin:17:cart"]), ["*:*:cart"]);
        assert_eq!(walk(&["jdupont_42", "amartin_17", "lucas_9"]), ["*_*"]);
        assert_eq!(walk(&["jdupont:42", "amartin:x7"]), ["*:*"]);
        // Two one-segment keys are records.
        assert_eq!(walk(&["jdupont", "amartin"]), ["*"]);
        // Token by token.
        assert_eq!(
            walk(&["order_jdupont_2024", "order_amartin_2025"]),
            ["order_*_*"]
        );
        let pages: Vec<String> = (0..17)
            .map(|i| format!("cache:page:p{}", "x".repeat(i + 1)))
            .collect();
        let pages: Vec<&str> = pages.iter().map(String::as_str).collect();
        assert_eq!(walk(&pages), ["cache:page:*"]);
    }

    #[test]
    fn cardinality_bounds_memory_during_the_walk() {
        let mut b = PatternBuilder::new(1);
        for i in 0..5000 {
            let k = format!("cache:{}", word(i));
            b.add(k.as_bytes(), split_key(k.as_bytes()), 0);
        }
        assert!(b.templates() <= 2, "{}", b.templates());
        assert!(b.literals.values().all(|s| s.len() <= MAX_TRACKED_LITERALS));
        assert!(b.positions() <= 4, "{}", b.positions());
        let out = b.finish();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern.as_str(), "cache:*");
        assert_eq!(out[0].group.count, 5000);
    }

    /// Security review H3: 100 000 slug-like keys (each its own template
    /// once the template bound is hit) and 20-token names keep the walk's
    /// state within its bounds, and no key-name text in it.
    #[test]
    fn walk_state_is_bounded_whatever_the_keyspace() {
        let mut b = PatternBuilder::new(1);
        for i in 0..100_000 {
            // Slugs: letters only, which the per-key rules keep (built
            // directly: this test is about the walk, not the per-key rules).
            let t = [word(i), word(i / 3), word(i / 7)];
            let k = t.join(":");
            b.add(k.as_bytes(), literals(&t, ":"), 0);
        }
        assert!(b.templates() <= MAX_TEMPLATES, "{}", b.templates());
        assert!(b.positions() <= MAX_POSITIONS, "{}", b.positions());
        assert!(
            b.tracked_literals() <= MAX_POSITIONS * MAX_TRACKED_LITERALS,
            "{}",
            b.tracked_literals()
        );
        let mut b = PatternBuilder::new(1);
        for i in 0..100_000 {
            let t: Vec<String> = (0..20).map(|t| word(i * 20 + t)).collect();
            let k = t.join("_");
            b.add(k.as_bytes(), literals(&t, "_"), 0);
        }
        assert!(b.templates() <= MAX_TEMPLATES, "{}", b.templates());
        assert!(b.positions() <= MAX_POSITIONS, "{}", b.positions());
        assert!(b.tracked_literals() <= MAX_POSITIONS * MAX_TRACKED_LITERALS);
        // Whatever was kept, the emitted patterns still pass the gate.
        for p in b.finish() {
            assert!(is_key_pattern(p.pattern.as_str()) || p.pattern.as_str() == "*");
        }
    }

    /// Units of literal tokens joined by `sep`.
    fn literals(tokens: &[String], sep: &str) -> KeyUnits {
        KeyUnits {
            units: tokens
                .iter()
                .enumerate()
                .map(|(i, t)| Unit {
                    sep: if i == 0 {
                        String::new()
                    } else {
                        sep.to_owned()
                    },
                    tok: Tok::Lit(Secret(t.clone())),
                })
                .collect(),
            name_values: Vec::new(),
        }
    }

    /// Past the position bound, new positions are `*` (fail closed).
    #[test]
    fn position_bound_masks_new_positions() {
        let mut b = PatternBuilder::new(1);
        // Distinct shapes (unit counts) so that every key opens positions.
        let mut i = 0;
        while b.positions() < MAX_POSITIONS {
            let n = 1 + i % 60;
            let k: Vec<String> = (0..n).map(|t| word(i * 64 + t)).collect();
            let k = k.join("/");
            b.add(k.as_bytes(), split_key(k.as_bytes()), 0);
            i += 1;
            assert!(i < 1_000_000);
        }
        let before = b.position_bound_hits();
        b.add(b"zzzq/www/vvv", split_key(b"zzzq/www/vvv"), 1);
        assert!(b.position_bound_hits() > before);
        assert_eq!(b.positions(), MAX_POSITIONS);
    }

    #[test]
    fn generated_segments_are_values() {
        // Security review M4.
        assert_eq!(one("reset:qzkqfwmxqtrqlvha"), "reset:*");
        assert_eq!(one("api:Hk_QwErTy-ZxCvBnM_PoIuYtRe"), "api:*");
        assert_eq!(one("tok:aZ3_kq9-Lm2pX8_wQ4-vR7nC"), "tok:*");
        assert_eq!(one("x:hjkwqrtz"), "x:*");
        assert_eq!(one("x:bcdfghjklmnpqrstvwxz"), "x:*");
        assert_eq!(one("k:0f9e8d7c6b5a4f3e"), "k:*");
        // Words and ordinary compound names are kept.
        for keep in [
            "integration:aws:secret_access_key",
            "queue:sms_outbox",
            "newsletter:subscribers",
            "loyalty:leaderboard",
            "events:payments",
            "user_profile_settings_backup",
            "customer:internationalization",
            "app:responsibilities",
            "cache:customerprofilesbackup",
        ] {
            assert_eq!(one(keep), keep);
        }
    }

    #[test]
    fn unassigned_code_points_are_values() {
        // Unassigned in this agent's tables, a digit to the console's.
        let k = "\u{11de0}".repeat(9);
        assert!(!is_key_pattern(&k));
        assert_eq!(one(&format!("x:{k}")), "x:*");
        assert_eq!(one("x:a\u{378}b"), "x:*");
    }

    fn word(mut i: usize) -> String {
        let mut s = String::new();
        loop {
            s.push(char::from(b'a' + u8::try_from(i % 26).unwrap_or(0)));
            i /= 26;
            if i == 0 {
                break;
            }
        }
        s
    }

    #[test]
    fn gate_follows_the_contract() {
        for ok in [
            "user:*:email",
            "session:*",
            "order_*_*",
            "db0",
            "*",
            "cafe:babe:dead:beef",
        ] {
            assert!(is_key_pattern(ok), "{ok}");
        }
        for bad in [
            "",
            "a::b",
            "a:",
            "host:10.0.0.1",
            "javascript:x",
            "user:jane%40x",
            "tel:06.12.34.56.78",
            "x@y",
            "device:00:1a:2b:3c:4d:5e",
        ] {
            assert!(!is_key_pattern(bad), "{bad}");
        }
        assert!(!is_key_pattern(&"a".repeat(257)));
    }
    fn learned(p: &[&str]) -> LearnedPatterns {
        LearnedPatterns::new(p.iter().copied())
    }

    fn obj(l: &LearnedPatterns, key: &str) -> String {
        l.object(key.as_bytes(), false).as_str().to_owned()
    }

    #[test]
    fn audit_keys_map_to_learned_patterns_only() {
        let l = learned(&[
            "user:*:email",
            "session:*",
            "cache:page:about",
            "order_*_*",
            "*:*",
        ]);
        assert_eq!(obj(&l, "user:42:email"), "user:*:email");
        assert_eq!(obj(&l, "user:jane.doe@example.com:email"), "user:*:email");
        assert_eq!(obj(&l, "session:jdupont"), "session:*");
        assert_eq!(obj(&l, "cache:page:about"), "cache:page:about");
        // A literal the walk did not emit never reaches the object (H1):
        // the longest learned literal prefix, then `*`.
        assert_eq!(obj(&l, "cache:page:jdupont"), "cache:page:*");
        assert_eq!(obj(&l, "cache:jdupont"), "cache:*");
        assert_eq!(obj(&l, "order_jdupont_2024"), "order_*_*");
        // `*:*` matches any two-unit name; the most specific wins.
        assert_eq!(obj(&l, "jdupont:amartin"), "*:*");
        // No learned prefix: `*`.
        let l = learned(&["session:*"]);
        assert_eq!(obj(&l, "jdupont"), "*");
        assert_eq!(obj(&l, "accounts:jdupont"), "*");
        assert_eq!(obj(&LearnedPatterns::default(), "session:jdupont"), "*");
        // Non-UTF-8 and empty names.
        assert_eq!(l.object(&[0xff, b':', b'x'], false).as_str(), "*");
        assert_eq!(l.object(b"", false).as_str(), "*");
    }

    #[test]
    fn cut_arguments_use_complete_units_only() {
        let l = learned(&["session:*", "cache:page:about"]);
        assert_eq!(
            l.object(b"session:jdupont-and-mo", true).as_str(),
            "session:*"
        );
        // The last unit may be cut: `cache:page:about` is not matched.
        assert_eq!(l.object(b"cache:page:about", true).as_str(), "cache:page:*");
        assert_eq!(l.object(b"cache", true).as_str(), "*");
    }

    #[test]
    fn learned_literals_still_pass_the_second_gate() {
        // A pattern that is not a contract `KeyPattern` is never learned.
        let l = learned(&["user:123456789", "a::b", "*"]);
        assert!(l.is_empty());
        // The intersection keeps what every set learned.
        let a = learned(&["session:*", "user:*:email"]);
        let b = learned(&["session:*", "cart:*"]);
        let i = LearnedPatterns::intersection(&[&a, &b]);
        assert_eq!(i.patterns(), ["session:*"]);
        assert!(LearnedPatterns::intersection(&[]).is_empty());
    }

    proptest::proptest! {
        /// Whatever the key, the object is `*` or a contract `KeyPattern`
        /// made of learned literals only.
        #[test]
        fn audit_objects_hold_learned_literals_only(
            key in "[a-z0-9:_.@-]{0,40}",
            cut in proptest::bool::ANY,
        ) {
            let l = learned(&["user:*:email", "session:*", "cache:page:about", "a_b_*"]);
            let o = l.object(key.as_bytes(), cut);
            let o = o.as_str();
            proptest::prop_assert!(o == "*" || is_key_pattern(o));
            let allowed = ["user", "email", "session", "cache", "page", "about", "a", "b", "*"];
            for tok in o.split(|c: char| is_segment_sep(c) || is_token_sep(c)) {
                proptest::prop_assert!(tok.is_empty() || allowed.contains(&tok), "{} in {}", tok, o);
            }
        }
    }
}
