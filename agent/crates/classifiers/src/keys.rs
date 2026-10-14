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
//!    `user:*:email`), looks generated (hexadecimal or high-entropy, 16
//!    characters or more), holds a character `Identifier` forbids, is a
//!    common first name, or otherwise looks like a value
//!    ([`crate::names::segment_looks_like_value`]); a first segment naming
//!    a URL scheme becomes `*`.
//! 2. **Per walk** ([`PatternBuilder`]): the tokens left are compared
//!    across the keys of one database walk. A position (a token, with the
//!    tokens before it as its prefix and the shape of the name) holding
//!    more than [`COLLAPSE_THRESHOLD`] distinct values becomes `*`
//!    (cardinality), and so does a position where 2 or more distinct values
//!    precede the same suffix (record-id rule: `session:jdupont` and
//!    `session:amartin` give `session:*`). At most 17 distinct literals are
//!    tracked per position and prefix during the walk, in zeroized memory;
//!    patterns are emitted only by [`PatternBuilder::finish`], after the
//!    walk, with at most 4 rounds of collapse and merge.
//!
//! Every emitted pattern passes the final gate [`is_key_pattern`]: the
//! contract `KeyPattern` pattern **and** its `not` rules (digit runs per
//! segment and across separators, IPv4, IPv6, MAC, percent escapes, URL
//! scheme), else it is `*`. Raw key names are never logged and never leave
//! this module but as the sample keys the connector reads, in zeroized
//! buffers.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
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
    pattern.is_match(s) && !not.is_match(s)
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
    if looks_generated(token) {
        return true;
    }
    names::segment_looks_like_value(token)
}

/// Hexadecimal or base64-like tokens of 16 characters or more that look
/// generated: mixed case with many case changes, or a high character
/// entropy.
fn looks_generated(token: &str) -> bool {
    let n = token.chars().count();
    if n < 16 {
        return false;
    }
    if token.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    if !token.chars().all(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    let changes = token
        .chars()
        .zip(token.chars().skip(1))
        .filter(|(a, b)| a.is_ascii_lowercase() && b.is_ascii_uppercase())
        .count();
    if changes >= 3 {
        return true;
    }
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for c in token.chars() {
        *counts.entry(c).or_default() += 1;
    }
    #[allow(clippy::cast_precision_loss, reason = "lengths far below 2^52")]
    let entropy: f64 = counts
        .values()
        .map(|&k| {
            let p = k as f64 / n as f64;
            -p * p.log2()
        })
        .sum();
    entropy >= 3.9
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

/// Position key: the shape (separators of every unit, unit count), the
/// position, and the units before it.
#[derive(Clone, PartialEq, Eq, Hash)]
struct PosKey {
    shape: Vec<String>,
    pos: usize,
    prefix: Vec<Tok>,
}

fn shape_of(units: &[Unit]) -> Vec<String> {
    units.iter().map(|u| u.sep.clone()).collect()
}

/// Builds the patterns of one database walk (see the module
/// documentation). Bounded: at most [`MAX_TEMPLATES`] templates and
/// [`MAX_TRACKED_LITERALS`] literals per position and prefix.
pub struct PatternBuilder {
    samples: usize,
    templates: HashMap<(Vec<Unit>, u8), Group>,
    /// Distinct literals seen per position (up to the tracked bound).
    literals: HashMap<PosKey, BTreeSet<Secret>>,
    /// Positions collapsed by cardinality during the walk.
    collapsed: std::collections::HashSet<PosKey>,
    /// Keys whose template could not be kept (template bound).
    overflow: u64,
}

impl std::fmt::Debug for PatternBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PatternBuilder")
            .field("templates", &self.templates.len())
            .field("overflow", &self.overflow)
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
            templates: HashMap::new(),
            literals: HashMap::new(),
            collapsed: std::collections::HashSet::new(),
            overflow: 0,
        }
    }

    /// Keys not kept because the template bound was reached.
    #[must_use]
    pub fn overflow(&self) -> u64 {
        self.overflow
    }

    /// Distinct templates kept so far.
    #[must_use]
    pub fn templates(&self) -> usize {
        self.templates.len()
    }

    /// Applies the positions already collapsed to `units`, left to right.
    fn apply_collapsed(&self, units: &mut [Unit]) {
        if self.collapsed.is_empty() {
            return;
        }
        let shape = shape_of(units);
        for pos in 0..units.len() {
            let key = PosKey {
                shape: shape.clone(),
                pos,
                prefix: units.iter().take(pos).map(|u| u.tok.clone()).collect(),
            };
            if self.collapsed.contains(&key)
                && let Some(u) = units.get_mut(pos)
            {
                u.tok = Tok::Wild;
            }
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
        // Cardinality, tracked while walking (bounded).
        let shape = shape_of(&units);
        let mut newly = Vec::new();
        for pos in 0..units.len() {
            let Some(Unit {
                tok: Tok::Lit(lit), ..
            }) = units.get(pos)
            else {
                continue;
            };
            let key = PosKey {
                shape: shape.clone(),
                pos,
                prefix: units.iter().take(pos).map(|u| u.tok.clone()).collect(),
            };
            let set = self.literals.entry(key.clone()).or_default();
            if set.len() < MAX_TRACKED_LITERALS {
                set.insert(lit.clone());
            }
            if set.len() > COLLAPSE_THRESHOLD {
                newly.push(key);
            }
        }
        if !newly.is_empty() {
            for key in newly {
                self.literals.remove(&key);
                self.collapsed.insert(key);
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
    /// before the same suffix; at the first position only when the suffix
    /// is empty or holds a literal, so that `phone:*` and `addressbook:*`
    /// keep their prefixes).
    fn decide(&self) -> Vec<PosKey> {
        let mut by_pos: HashMap<PosKey, BTreeMap<Vec<Tok>, BTreeSet<&Secret>>> = HashMap::new();
        let mut distinct: HashMap<PosKey, BTreeSet<&Secret>> = HashMap::new();
        for (units, _) in self.templates.keys() {
            let shape = shape_of(units);
            for (pos, u) in units.iter().enumerate() {
                let Tok::Lit(lit) = &u.tok else { continue };
                let key = PosKey {
                    shape: shape.clone(),
                    pos,
                    prefix: units.iter().take(pos).map(|x| x.tok.clone()).collect(),
                };
                let suffix: Vec<Tok> = units.iter().skip(pos + 1).map(|x| x.tok.clone()).collect();
                distinct.entry(key.clone()).or_default().insert(lit);
                by_pos
                    .entry(key)
                    .or_default()
                    .entry(suffix)
                    .or_default()
                    .insert(lit);
            }
        }
        let mut out = Vec::new();
        for (key, values) in &distinct {
            if values.len() > COLLAPSE_THRESHOLD {
                out.push(key.clone());
            }
        }
        for (key, suffixes) in by_pos {
            if out.contains(&key) {
                continue;
            }
            let record = suffixes.iter().any(|(suffix, values)| {
                values.len() >= 2
                    && (key.pos > 0
                        || suffix.is_empty()
                        || suffix.iter().any(|t| matches!(t, Tok::Lit(_))))
            });
            if record {
                out.push(key);
            }
        }
        out
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
            for key in decided {
                self.collapsed.insert(key);
            }
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
        // Different prefixes with a wildcard suffix keep their names.
        let mut got = walk(&["phone:1", "addressbook:2"]);
        got.sort();
        assert_eq!(got, ["addressbook:*", "phone:*"]);
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
        let out = b.finish();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].pattern.as_str(), "cache:*");
        assert_eq!(out[0].group.count, 5000);
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
}
