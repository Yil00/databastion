//! Document walk: nested fields and arrays to normalized field paths, BSON
//! values to classifier input (ADR-0026 decisions 7 to 9).
//!
//! An embedded document adds a key to the path, an array an index level
//! (`[]`). Each raw path is normalized once per collection with
//! `names::normalize_field_path` (ADR-0009: dynamic keys and keys that
//! look like values become `*`), and the values of every raw path with the
//! same normalized path are pooled. Raw keys and paths stay in this
//! structure (in memory, one collection at a time): they are never logged
//! nor returned, and the key bytes are zeroized on drop.
//!
//! Bounds per document: [`MAX_DEPTH`] levels, the first
//! [`MAX_ARRAY_ELEMENTS`] elements of each array, [`MAX_VALUES_PER_DOC`]
//! values and [`MAX_VISITS_PER_DOC`] elements visited. Per collection:
//! [`MAX_PATHS`] normalized paths, [`MAX_RAW_PATHS`] raw paths, and the
//! per-path value limit given by the job (`sample_rows`). Values are cut to
//! [`MAX_VALUE_BYTES`] on a character boundary.

use std::collections::{HashMap, HashSet};

use databastion_classifiers::masking::RawValue;
use databastion_classifiers::names::{NormalizedName, PathPart, normalize_field_path};
use zeroize::Zeroizing;

use crate::bson::{Doc, Malformed, Value};

/// Deepest nesting walked (the top-level document is level 0).
pub(crate) const MAX_DEPTH: usize = 20;
/// Elements read per array.
pub(crate) const MAX_ARRAY_ELEMENTS: usize = 16;
/// Values kept per document.
pub(crate) const MAX_VALUES_PER_DOC: usize = 512;
/// Elements visited per document (values, skipped kinds, containers).
pub(crate) const MAX_VISITS_PER_DOC: usize = 4096;
/// Normalized paths kept per collection.
pub(crate) const MAX_PATHS: usize = 1024;
/// Raw paths normalized per collection (each is normalized once).
pub(crate) const MAX_RAW_PATHS: usize = 4096;
/// Longest value handed to the classifiers, in bytes.
pub(crate) const MAX_VALUE_BYTES: usize = 4096;
/// An object level with more distinct keys than this across the sample is
/// a map keyed by data (dynamic keys): its keys become `*`.
pub(crate) const MAX_STATIC_KEYS: usize = 16;
/// An object level seen in at least 2 documents, with at least this many
/// distinct keys, each in one document only, is also a map keyed by data.
pub(crate) const MIN_SINGLETON_KEYS: usize = 3;
/// Rounds of the shape pass (a map nested in a map is found in the next
/// round, once its parent is collapsed).
const SHAPE_ROUNDS: usize = 4;
/// Object levels tracked per round.
const MAX_TRACKED_LEVELS: usize = 4096;
/// Distinct keys tracked per object level (past it: dynamic).
const MAX_TRACKED_KEYS: usize = 64;
/// The key a dynamic level's keys are replaced with.
const WILD: &[u8] = b"*";

/// One step of a raw path.
#[derive(Clone, Copy)]
enum Step<'a> {
    Key(&'a [u8]),
    Index,
}

/// What a walk left out (counts only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WalkStats {
    pub(crate) documents: u32,
    pub(crate) too_deep: u64,
    pub(crate) arrays_cut: u64,
    pub(crate) documents_cut: u64,
    pub(crate) paths_dropped: u64,
}

/// Values of one collection, pooled by normalized field path.
#[derive(Default)]
pub(crate) struct Collector {
    per_path: usize,
    paths: Vec<(NormalizedName, Vec<RawValue>)>,
    by_name: HashMap<NormalizedName, usize>,
    /// Raw path encoding -> slot in `paths` (`None`: dropped past
    /// [`MAX_PATHS`]). The keys are zeroized when the collector is dropped.
    raw: HashMap<Vec<u8>, Option<usize>>,
    /// Object levels whose keys are data (see [`Shape`]).
    shape: Shape,
    pub(crate) stats: WalkStats,
}

impl std::fmt::Debug for Collector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Collector")
            .field("paths", &self.paths.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        for (key, _) in self.raw.drain() {
            drop(Zeroizing::new(key));
        }
    }
}

/// Encodes a raw path as a map key: `0x01 key 0x00` per key, `0x02` per
/// index (a BSON key has no NUL).
fn encode(steps: &[Step<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in steps {
        match s {
            Step::Key(k) => {
                out.push(1);
                out.extend_from_slice(k);
                out.push(0);
            }
            Step::Index => out.push(2),
        }
    }
    out
}

/// The normalized name of a raw path. Keys that are not UTF-8 are read
/// lossily (they then carry U+FFFD, and go through the same rules).
pub(crate) fn normalize_steps(steps: &[(bool, &[u8])]) -> NormalizedName {
    let keys: Vec<Option<Zeroizing<String>>> = steps
        .iter()
        .map(|(is_key, k)| is_key.then(|| Zeroizing::new(String::from_utf8_lossy(k).into_owned())))
        .collect();
    let parts: Vec<PathPart<'_>> = keys
        .iter()
        .map(|k| {
            k.as_ref()
                .map_or(PathPart::Index, |k| PathPart::Key(k.as_str()))
        })
        .collect();
    normalize_field_path(&parts)
}

impl Collector {
    /// A collector keeping at most `per_path` values per normalized path,
    /// collapsing the dynamic levels of `shape`.
    pub(crate) fn with_shape(per_path: usize, shape: Shape) -> Self {
        let mut c = Self::new(per_path);
        c.shape = shape;
        c
    }

    /// A collector keeping at most `per_path` values per normalized path.
    pub(crate) fn new(per_path: usize) -> Self {
        let mut c = Self::default();
        c.per_path = per_path;
        c
    }

    /// Walks one document.
    pub(crate) fn add_document(&mut self, doc: Doc<'_>) -> Result<(), Malformed> {
        self.stats.documents = self.stats.documents.saturating_add(1);
        let mut steps: Vec<Step<'_>> = Vec::new();
        let mut budget = Budget {
            values: MAX_VALUES_PER_DOC,
            visits: MAX_VISITS_PER_DOC,
        };
        // The shape is read while values are pushed: move it out for the
        // walk.
        let shape = std::mem::take(&mut self.shape);
        let walked = self.walk(&shape, doc, false, &mut steps, 0, &mut budget);
        self.shape = shape;
        walked?;
        if budget.values == 0 || budget.visits == 0 {
            self.stats.documents_cut += 1;
        }
        Ok(())
    }

    fn walk<'a>(
        &mut self,
        shape: &Shape,
        doc: Doc<'a>,
        is_array: bool,
        steps: &mut Vec<Step<'a>>,
        depth: usize,
        budget: &mut Budget,
    ) -> Result<(), Malformed> {
        let level = if is_array || depth == 0 {
            Level::Keep
        } else {
            shape.level(steps)
        };
        for (i, element) in doc.iter().enumerate() {
            if budget.values == 0 || budget.visits == 0 {
                return Ok(());
            }
            if is_array && i >= MAX_ARRAY_ELEMENTS {
                self.stats.arrays_cut += 1;
                return Ok(());
            }
            let (key, value) = element?;
            budget.visits -= 1;
            steps.push(if is_array {
                Step::Index
            } else if level.keeps(key) {
                Step::Key(key)
            } else {
                Step::Key(WILD)
            });
            match value {
                Value::Doc(d) | Value::Array(d) if depth + 1 > MAX_DEPTH => {
                    let _ = d;
                    self.stats.too_deep += 1;
                }
                Value::Doc(d) => self.walk(shape, d, false, steps, depth + 1, budget)?,
                Value::Array(d) => self.walk(shape, d, true, steps, depth + 1, budget)?,
                leaf => {
                    if let Some(text) = to_text(leaf) {
                        budget.values -= 1;
                        self.push(steps, text);
                    }
                }
            }
            steps.pop();
        }
        Ok(())
    }

    fn push(&mut self, steps: &[Step<'_>], value: RawValue) {
        let key = encode(steps);
        let slot = match self.raw.get(&key) {
            Some(slot) => {
                drop(Zeroizing::new(key));
                *slot
            }
            None => {
                if self.raw.len() >= MAX_RAW_PATHS {
                    drop(Zeroizing::new(key));
                    self.stats.paths_dropped += 1;
                    return;
                }
                let flat: Vec<(bool, &[u8])> = steps
                    .iter()
                    .map(|s| match s {
                        Step::Key(k) => (true, *k),
                        Step::Index => (false, &[][..]),
                    })
                    .collect();
                let name = normalize_steps(&flat);
                let slot = match self.by_name.get(&name) {
                    Some(i) => Some(*i),
                    None if self.paths.len() < MAX_PATHS => {
                        self.paths.push((name.clone(), Vec::new()));
                        self.by_name.insert(name, self.paths.len() - 1);
                        Some(self.paths.len() - 1)
                    }
                    None => {
                        self.stats.paths_dropped += 1;
                        None
                    }
                };
                self.raw.insert(key, slot);
                slot
            }
        };
        if let Some(i) = slot {
            let values = &mut self.paths[i].1;
            if values.len() < self.per_path {
                values.push(value);
            }
        }
    }

    /// The pooled values, by normalized path, in first-seen order.
    pub(crate) fn into_paths(mut self) -> Vec<(NormalizedName, Vec<RawValue>)> {
        std::mem::take(&mut self.paths)
    }
}

/// Object levels whose keys are data rather than field names (dynamic
/// keys that do not look like values: logins, surnames, short ids, codes).
/// Learned from the sampled documents before the values are collected
/// (security review M3): a level with more than [`MAX_STATIC_KEYS`]
/// distinct keys, or seen in at least 2 documents with at least
/// [`MIN_SINGLETON_KEYS`] keys that each appear in one document only, is
/// collapsed to `*`. The top level is never collapsed (a collection's
/// fields). Levels are identified by their raw path (collapsed ancestors
/// as `*`), zeroized on drop.
///
/// Fail closed (end-of-phase-5 review L2): the learner walks the sample in
/// the collector's order and within the same visit budget, and keeps the
/// keys it saw on each static level. A non-top object level the learner
/// never observed (past [`MAX_TRACKED_LEVELS`], or below a level collapsed
/// in the last round) is treated as dynamic, and a key it never saw on a
/// static level becomes `*`.
#[derive(Default)]
pub(crate) struct Shape {
    dynamic: HashSet<Vec<u8>>,
    /// Static levels observed by the learner, with the keys seen there.
    /// `None`: no shape learned (a collector built with
    /// [`Collector::new`], tests only): nothing is collapsed.
    known: Option<HashMap<Vec<u8>, HashSet<Vec<u8>>>>,
}

/// What the collector does with the keys of one object level.
enum Level<'s> {
    /// Keys kept (top level, or no shape learned).
    Keep,
    /// Every key is `*` (a map keyed by data, or a level never observed).
    Wild,
    /// A static level: the keys the learner saw are kept, others are `*`.
    Known(&'s HashSet<Vec<u8>>),
}

impl Level<'_> {
    fn keeps(&self, key: &[u8]) -> bool {
        match self {
            Self::Keep => true,
            Self::Wild => false,
            Self::Known(keys) => keys.contains(key),
        }
    }
}

impl std::fmt::Debug for Shape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shape")
            .field("dynamic_levels", &self.dynamic.len())
            .field("static_levels", &self.known.as_ref().map(HashMap::len))
            .finish()
    }
}

impl Drop for Shape {
    fn drop(&mut self) {
        for key in self.dynamic.drain() {
            drop(Zeroizing::new(key));
        }
        if let Some(known) = self.known.as_mut() {
            for (level, keys) in known.drain() {
                drop(Zeroizing::new(level));
                for key in keys {
                    drop(Zeroizing::new(key));
                }
            }
        }
    }
}

#[derive(Default)]
struct LevelStats {
    documents: u32,
    last_document: Option<usize>,
    /// Key -> (documents holding it, last document).
    keys: HashMap<Vec<u8>, (u32, usize)>,
    overflow: bool,
}

impl LevelStats {
    fn is_dynamic(&self) -> bool {
        self.overflow
            || self.keys.len() > MAX_STATIC_KEYS
            || (self.documents >= 2
                && self.keys.len() >= MIN_SINGLETON_KEYS
                && self.keys.values().all(|(n, _)| *n == 1))
    }
}

impl Drop for LevelStats {
    fn drop(&mut self) {
        for (key, _) in self.keys.drain() {
            drop(Zeroizing::new(key));
        }
    }
}

impl Shape {
    /// Learns the dynamic and the static levels of a sample.
    pub(crate) fn learn(documents: &[Doc<'_>]) -> Self {
        let mut shape = Self {
            dynamic: HashSet::new(),
            known: Some(HashMap::new()),
        };
        for round in 0..SHAPE_ROUNDS {
            let mut levels: HashMap<Vec<u8>, LevelStats> = HashMap::new();
            for (i, d) in documents.iter().enumerate() {
                let mut steps = Vec::new();
                let mut visits = MAX_VISITS_PER_DOC;
                shape.observe(*d, false, &mut steps, 0, i, &mut levels, &mut visits);
            }
            let found: Vec<Vec<u8>> = levels
                .iter()
                .filter(|(level, stats)| !shape.dynamic.contains(*level) && stats.is_dynamic())
                .map(|(level, _)| level.clone())
                .collect();
            let last = found.is_empty() || round + 1 == SHAPE_ROUNDS;
            shape.dynamic.extend(found);
            if last {
                // The levels of the last round that stayed static, with
                // their keys. A level below one collapsed in this round has
                // a new path, never observed: the collector treats it as
                // dynamic.
                let known = shape.known.get_or_insert_with(HashMap::new);
                for (level, mut stats) in levels.drain() {
                    if shape.dynamic.contains(&level) {
                        drop(Zeroizing::new(level));
                        continue;
                    }
                    let keys: HashSet<Vec<u8>> = stats.keys.drain().map(|(k, _)| k).collect();
                    known.insert(level, keys);
                }
                break;
            }
            for (level, _) in levels.drain() {
                drop(Zeroizing::new(level));
            }
        }
        shape
    }

    fn is_dynamic(&self, steps: &[Step<'_>]) -> bool {
        if self.dynamic.is_empty() {
            return false;
        }
        let level = Zeroizing::new(encode(steps));
        self.dynamic.contains(&*level)
    }

    /// How the collector treats the keys of the non-top object level at
    /// `steps`.
    fn level(&self, steps: &[Step<'_>]) -> Level<'_> {
        let Some(known) = &self.known else {
            return Level::Keep;
        };
        let level = Zeroizing::new(encode(steps));
        if self.dynamic.contains(&*level) {
            return Level::Wild;
        }
        known.get(&*level).map_or(Level::Wild, Level::Known)
    }

    /// Records the object levels of one document. Walks in the collector's
    /// order ([`Collector::walk`]: depth first, the same array, depth and
    /// visit bounds), so every level and key the collector reaches has
    /// been seen here (the collector's value budget only stops it
    /// earlier).
    #[allow(clippy::too_many_arguments)]
    fn observe<'a>(
        &self,
        doc: Doc<'a>,
        is_array: bool,
        steps: &mut Vec<Step<'a>>,
        depth: usize,
        document: usize,
        levels: &mut HashMap<Vec<u8>, LevelStats>,
        visits: &mut usize,
    ) {
        let dynamic = !is_array && depth > 0 && self.is_dynamic(steps);
        let mut level: Option<Zeroizing<Vec<u8>>> = None;
        if !is_array && depth > 0 && !dynamic {
            let encoded = Zeroizing::new(encode(steps));
            if levels.len() < MAX_TRACKED_LEVELS || levels.contains_key(&*encoded) {
                let stats = levels.entry(encoded.to_vec()).or_default();
                if stats.last_document != Some(document) {
                    stats.last_document = Some(document);
                    stats.documents = stats.documents.saturating_add(1);
                }
                level = Some(encoded);
            }
        }
        for (i, element) in doc.iter().enumerate() {
            if *visits == 0 || (is_array && i >= MAX_ARRAY_ELEMENTS) {
                return;
            }
            let Ok((key, value)) = element else {
                return;
            };
            *visits -= 1;
            if let Some(stats) = level.as_ref().and_then(|l| levels.get_mut(&***l)) {
                if let Some((n, last)) = stats.keys.get_mut(key) {
                    if *last != document {
                        *last = document;
                        *n = n.saturating_add(1);
                    }
                } else if stats.keys.len() < MAX_TRACKED_KEYS {
                    stats.keys.insert(key.to_vec(), (1, document));
                } else {
                    stats.overflow = true;
                }
            }
            let (Value::Doc(child) | Value::Array(child)) = value else {
                continue;
            };
            if depth + 1 > MAX_DEPTH {
                continue;
            }
            steps.push(if is_array {
                Step::Index
            } else if dynamic {
                Step::Key(WILD)
            } else {
                Step::Key(key)
            });
            let child_is_array = matches!(value, Value::Array(_));
            self.observe(
                child,
                child_is_array,
                steps,
                depth + 1,
                document,
                levels,
                visits,
            );
            steps.pop();
        }
    }
}

struct Budget {
    values: usize,
    visits: usize,
}

/// Cuts a string to [`MAX_VALUE_BYTES`] on a character boundary.
fn cut(s: &str) -> &str {
    let mut end = s.len().min(MAX_VALUE_BYTES);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Text of a UTF-8 string value.
fn utf8(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    Some(cut(s).to_owned())
}

/// A binary read as text: valid UTF-8 without control characters other
/// than tab, line feed and carriage return.
fn binary_text(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.is_empty()
        || s.chars()
            .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return None;
    }
    Some(cut(s).to_owned())
}

/// The classifier input of a leaf value, owned by a [`RawValue`]
/// (zeroized on drop).
pub(crate) fn to_text(value: Value<'_>) -> Option<RawValue> {
    leaf_text(value).map(RawValue::new)
}

/// The text of a leaf value (ADR-0026 decision 9); `None` for the kinds
/// that are never read. Callers wrap it in a [`RawValue`] at once.
pub(crate) fn leaf_text(value: Value<'_>) -> Option<String> {
    match value {
        Value::Str(s) | Value::Symbol(s) => utf8(s),
        Value::Int32(n) => Some(n.to_string()),
        Value::Int64(n) => Some(n.to_string()),
        Value::Double(d) => double_digits(d),
        Value::Decimal128(b) => decimal128(b),
        Value::Date(ms) => date(ms),
        Value::Binary(subtype, data) => match subtype {
            0x00 | 0x80..=0xFF => binary_text(data),
            // Old binary: an inner length, then the bytes.
            0x02 => {
                let inner = data.get(4..)?;
                let len = i32::from_le_bytes(data.get(..4)?.try_into().ok()?);
                (usize::try_from(len).ok()? == inner.len())
                    .then(|| binary_text(inner))
                    .flatten()
            }
            // UUID, MD5, encrypted, compressed column, sensitive, vector,
            // and anything else.
            _ => None,
        },
        Value::Bool(_) | Value::Doc(_) | Value::Array(_) | Value::Other => None,
    }
}

/// An integral double below 2^53 as digits (a phone or card number stored
/// as a number); other doubles are not read.
pub(crate) fn double_digits(d: f64) -> Option<String> {
    const LIMIT: f64 = 9_007_199_254_740_992.0; // 2^53
    if !d.is_finite() || d.fract() != 0.0 || d.abs() >= LIMIT {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)]
    Some((d as i64).to_string())
}

/// A finite decimal128 (BID) as a decimal string; `None` for infinities,
/// NaN and results longer than 80 characters.
pub(crate) fn decimal128(bytes: [u8; 16]) -> Option<String> {
    let bits = u128::from_le_bytes(bytes);
    let negative = bits >> 127 == 1;
    let combination = (bits >> 122) & 0x1F;
    if combination >> 3 == 0b11 {
        // Infinity, NaN, or the second form, whose coefficient is always
        // above the maximum: non-canonical, read as zero.
        if combination == 0b11110 || combination == 0b11111 {
            return None;
        }
        return Some("0".to_owned());
    }
    let exponent = i64::try_from((bits >> 113) & 0x3FFF).ok()? - 6176;
    let mut coefficient = bits & ((1u128 << 113) - 1);
    if coefficient > 9_999_999_999_999_999_999_999_999_999_999_999 {
        coefficient = 0;
    }
    let digits = coefficient.to_string();
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if exponent >= 0 {
        let zeros = usize::try_from(exponent).ok()?;
        if digits.len() + zeros > 80 {
            return None;
        }
        out.push_str(&digits);
        if coefficient != 0 {
            out.extend(std::iter::repeat_n('0', zeros));
        }
    } else {
        let point = usize::try_from(-exponent).ok()?;
        if point > 80 {
            return None;
        }
        if digits.len() > point {
            let (int, frac) = digits.split_at(digits.len() - point);
            out.push_str(int);
            out.push('.');
            out.push_str(frac);
        } else {
            out.push_str("0.");
            out.extend(std::iter::repeat_n('0', point - digits.len()));
            out.push_str(&digits);
        }
    }
    Some(out)
}

/// A date (milliseconds since the Unix epoch) as `YYYY-MM-DD` in UTC;
/// years 1 to 9999 only.
pub(crate) fn date(ms: i64) -> Option<String> {
    let days = ms.div_euclid(86_400_000);
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (1..=9999)
        .contains(&y)
        .then(|| format!("{y:04}-{m:02}-{d:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bson::DocBuf;

    fn text(v: Value<'_>) -> Option<String> {
        leaf_text(v)
    }

    /// Normalized paths and how many values each pooled.
    fn walk(bytes: &[u8], per_path: usize) -> (Vec<(String, usize)>, WalkStats) {
        let mut c = Collector::new(per_path);
        c.add_document(Doc::new(bytes).unwrap()).unwrap();
        let stats = c.stats;
        let out = c
            .into_paths()
            .into_iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.len()))
            .collect();
        (out, stats)
    }

    #[test]
    fn nested_fields_arrays_and_dynamic_keys() {
        let doc = DocBuf::new()
            .str("_id", "u0001")
            .doc(
                "name",
                DocBuf::new().str("first", "Jean").str("last", "Martin"),
            )
            .raw(
                0x04,
                "phones",
                &DocBuf::new()
                    .str("0", "06 12 34 56 78")
                    .str("1", "07 00 00 00 01")
                    .finish(),
            )
            .array(
                "cards",
                vec![DocBuf::new().str("number", "4111 1111 1111 1111")],
            )
            .doc(
                "contacts",
                DocBuf::new()
                    .doc(
                        "jane.doe@example.com",
                        DocBuf::new().str("phone", "0612345678"),
                    )
                    .doc("john@example.org", DocBuf::new().str("phone", "0712345678")),
            )
            .doc(
                "members",
                DocBuf::new().doc("33612345678", DocBuf::new().i32("points", 7)),
            )
            .doc("hourly", DocBuf::new().i32("0", 3).i32("13", 4))
            .bool("verified", true)
            .finish();
        let (paths, _) = walk(&doc, 10);
        let names: Vec<&str> = paths.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "_id",
                "name.first",
                "name.last",
                "phones[]",
                "cards[].number",
                "contacts.*.phone",
                "members.*.points",
                "hourly.*"
            ]
        );
        // Values of every dynamic key are pooled under one path.
        assert_eq!(paths[5].1, 2);
        assert_eq!(paths[3].1, 2);
        assert_eq!(paths[7].1, 2);
        // No raw key survives in a path.
        for (n, _) in &paths {
            assert!(!n.contains('@') && !n.contains("336"), "{n}");
        }
    }

    /// Normalized paths of documents walked with the shape learned from
    /// them.
    fn shaped(docs: &[Vec<u8>]) -> Vec<String> {
        let parsed: Vec<Doc<'_>> = docs.iter().map(|d| Doc::new(d).unwrap()).collect();
        let mut c = Collector::with_shape(10, Shape::learn(&parsed));
        for d in &parsed {
            c.add_document(*d).unwrap();
        }
        c.into_paths()
            .into_iter()
            .map(|(n, _)| n.as_str().to_owned())
            .collect()
    }

    /// Maps keyed by data that do not look like values (logins, surnames,
    /// short ids) collapse to `*` (security review M3).
    #[test]
    fn maps_keyed_by_data_are_collapsed() {
        let logins = ["jdupont", "mmartin", "abernard", "lpetit", "cdurand"];
        let docs: Vec<Vec<u8>> = logins
            .iter()
            .enumerate()
            .map(|(i, login)| {
                DocBuf::new()
                    .doc(
                        "acl",
                        DocBuf::new().doc(login, DocBuf::new().str("role", "admin")),
                    )
                    .doc(
                        "sessions",
                        DocBuf::new().doc(
                            &format!("u{i:04}"),
                            DocBuf::new().str("ip", &format!("10.0.0.{i}")),
                        ),
                    )
                    .doc(
                        "users",
                        DocBuf::new().doc(
                            login,
                            DocBuf::new().doc(
                                &format!("{login}-laptop"),
                                DocBuf::new().str("ip", "10.1.1.1"),
                            ),
                        ),
                    )
                    .doc(
                        "address",
                        DocBuf::new().str("street", "1 rue").str("city", "Nantes"),
                    )
                    .finish()
            })
            .collect();
        let paths = shaped(&docs);
        assert_eq!(
            paths,
            [
                "acl.*.role",
                "sessions.*.ip",
                "users.*.*.ip",
                "address.street",
                "address.city"
            ]
        );
        for p in &paths {
            for login in logins {
                assert!(!p.contains(login), "{p}");
            }
        }
        // More than MAX_STATIC_KEYS keys in one document: a map.
        let mut by_owner = DocBuf::new();
        for i in 0..=MAX_STATIC_KEYS {
            by_owner = by_owner.doc(
                &format!("owner{}", char::from(b'a' + u8::try_from(i).unwrap())),
                DocBuf::new().str("email", "x@example.com"),
            );
        }
        let doc = DocBuf::new().doc("by_owner", by_owner).finish();
        assert_eq!(shaped(&[doc]), ["by_owner.*.email"]);
        // Top-level fields are never collapsed; a few keys in a single
        // document are kept (not enough evidence).
        let doc = DocBuf::new()
            .doc(
                "acl",
                DocBuf::new()
                    .str("dupont", "r")
                    .str("martin", "w")
                    .str("petit", "r"),
            )
            .finish();
        assert_eq!(shaped(&[doc]), ["acl.dupont", "acl.martin", "acl.petit"]);
    }

    /// Levels and keys the learner never observed are collapsed (fail
    /// closed, end-of-phase-5 review L2).
    #[test]
    fn unobserved_levels_and_keys_are_collapsed() {
        let learned = DocBuf::new()
            .doc("name", DocBuf::new().str("first", "Jean"))
            .finish();
        let other = DocBuf::new()
            .doc(
                "name",
                DocBuf::new().str("first", "Jean").str("jdupont", "x"),
            )
            .doc(
                "acl",
                DocBuf::new().doc("mmartin", DocBuf::new().str("role", "r")),
            )
            .finish();
        let shape = Shape::learn(&[Doc::new(&learned).unwrap()]);
        let mut c = Collector::with_shape(10, shape);
        c.add_document(Doc::new(&other).unwrap()).unwrap();
        let paths: Vec<String> = c
            .into_paths()
            .into_iter()
            .map(|(n, _)| n.as_str().to_owned())
            .collect();
        assert_eq!(paths, ["name.first", "name.*", "acl.*.*"]);
    }

    /// The learner walks in the collector's order: a map reached by the
    /// collector before the visit budget runs out is seen whole by the
    /// learner, even when siblings listed later exhaust the budget (the
    /// learner used to list a level's siblings before descending).
    #[test]
    fn learner_sees_what_the_collector_reaches() {
        // One document: the map is a map by its key count alone.
        let docs: Vec<Vec<u8>> = (0..1)
            .map(|d| {
                let mut map = DocBuf::new();
                for k in 0..=MAX_STATIC_KEYS {
                    map = map.str(&format!("owner{}x{}", to_letters(d), to_letters(k)), "v");
                }
                let mut a = DocBuf::new().doc("x", DocBuf::new().doc("m", map));
                for i in 0..MAX_VISITS_PER_DOC - 8 {
                    a = a.i32(&format!("s{}", to_letters(i)), 1);
                }
                DocBuf::new().doc("a", a).finish()
            })
            .collect();
        let paths = shaped(&docs);
        // `a` has more than MAX_STATIC_KEYS keys: a map too.
        assert!(paths.iter().any(|p| p == "a.*.m.*"), "{paths:?}");
        assert!(paths.iter().all(|p| !p.contains("owner")), "{paths:?}");
    }

    #[test]
    fn walk_bounds() {
        // Nesting deeper than MAX_DEPTH is skipped and counted.
        let mut inner = DocBuf::new().str("leaf", "deep value");
        for _ in 0..MAX_DEPTH + 2 {
            inner = DocBuf::new().doc("n", inner);
        }
        let (paths, stats) = walk(&inner.finish(), 10);
        assert!(paths.is_empty());
        assert_eq!(stats.too_deep, 1);
        // Only the first elements of an array are read.
        let mut array = DocBuf::new();
        for i in 0..100 {
            array = array.str(&i.to_string(), &format!("v{i}"));
        }
        let doc = DocBuf::new().raw(0x04, "a", &array.finish()).finish();
        let (paths, stats) = walk(&doc, 1000);
        assert_eq!(paths[0].1, MAX_ARRAY_ELEMENTS);
        assert_eq!(stats.arrays_cut, 1);
        // Values per document.
        let mut many = DocBuf::new();
        for i in 0..MAX_VALUES_PER_DOC + 50 {
            many = many.str(&format!("k{i}"), "x");
        }
        let (paths, stats) = walk(&many.finish(), 10);
        assert_eq!(paths.len(), MAX_VALUES_PER_DOC);
        assert_eq!(stats.documents_cut, 1);
        // Values per path.
        let mut c = Collector::new(2);
        for _ in 0..5 {
            let d = DocBuf::new().str("email", "a@b.example").finish();
            c.add_document(Doc::new(&d).unwrap()).unwrap();
        }
        assert_eq!(c.into_paths()[0].1.len(), 2);
    }

    #[test]
    fn distinct_paths_are_bounded() {
        let mut c = Collector::new(1);
        for i in 0..(MAX_PATHS + 10) {
            let d = DocBuf::new()
                .str(&format!("field_{}", to_letters(i)), "v")
                .finish();
            c.add_document(Doc::new(&d).unwrap()).unwrap();
        }
        let stats = c.stats;
        assert_eq!(c.into_paths().len(), MAX_PATHS);
        assert_eq!(stats.paths_dropped, 10);
    }

    /// A number spelled with letters (field names without long digit runs).
    fn to_letters(mut n: usize) -> String {
        let mut s = String::new();
        loop {
            s.push(char::from(b'a' + u8::try_from(n % 26).unwrap()));
            n /= 26;
            if n == 0 {
                return s;
            }
        }
    }

    #[test]
    fn bson_values_to_classifier_input() {
        assert_eq!(text(Value::Str(b"abc")).as_deref(), Some("abc"));
        assert_eq!(text(Value::Symbol(b"sym")).as_deref(), Some("sym"));
        assert_eq!(text(Value::Str(&[0xFF])), None);
        assert_eq!(text(Value::Int32(-5)).as_deref(), Some("-5"));
        assert_eq!(
            text(Value::Int64(33_612_345_678)).as_deref(),
            Some("33612345678")
        );
        assert_eq!(
            text(Value::Double(4_111_111_111_111_111.0)).as_deref(),
            Some("4111111111111111")
        );
        assert_eq!(text(Value::Double(12.5)), None);
        assert_eq!(text(Value::Double(f64::NAN)), None);
        assert_eq!(text(Value::Double(1e300)), None);
        assert_eq!(text(Value::Date(0)).as_deref(), Some("1970-01-01"));
        assert_eq!(text(Value::Date(-1)).as_deref(), Some("1969-12-31"));
        assert_eq!(
            text(Value::Date(946_684_800_000)).as_deref(),
            Some("2000-01-01")
        );
        assert_eq!(
            text(Value::Date(-2_208_988_800_000)).as_deref(),
            Some("1900-01-01")
        );
        assert_eq!(text(Value::Date(i64::MAX)), None);
        assert_eq!(text(Value::Date(i64::MIN)), None);
        assert_eq!(
            text(Value::Binary(0, b"jane@example.com")).as_deref(),
            Some("jane@example.com")
        );
        assert_eq!(text(Value::Binary(0, b"\x00\x01")), None);
        assert_eq!(text(Value::Binary(0x80, b"text")).as_deref(), Some("text"));
        for subtype in [3, 4, 5, 6, 7, 8, 9] {
            assert_eq!(text(Value::Binary(subtype, b"jane@example.com")), None);
        }
        let mut old = 4i32.to_le_bytes().to_vec();
        old.extend_from_slice(b"abcd");
        assert_eq!(text(Value::Binary(2, &old)).as_deref(), Some("abcd"));
        assert_eq!(text(Value::Binary(2, b"abcd")), None);
        assert_eq!(text(Value::Bool(true)), None);
        assert_eq!(text(Value::Other), None);
        let long = "é".repeat(3000);
        let cut = text(Value::Str(long.as_bytes())).unwrap();
        assert!(cut.len() <= MAX_VALUE_BYTES && cut.chars().all(|c| c == 'é'));
    }

    /// Decimal128 vectors from the BSON corpus (`decimal128-1.json`).
    #[test]
    fn decimal128_vectors() {
        let dec = |hex: &str| {
            let b: Vec<u8> = (0..16)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
                .collect();
            decimal128(b.try_into().unwrap())
        };
        assert_eq!(
            dec("01000000000000000000000000004030").as_deref(),
            Some("1")
        );
        assert_eq!(
            dec("D2040000000000000000000000003430").as_deref(),
            Some("0.001234")
        );
        assert_eq!(
            dec("01000000000000000000000000004630").as_deref(),
            Some("1000")
        );
        assert_eq!(
            dec("010000000000000000000000000040B0").as_deref(),
            Some("-1")
        );
        assert_eq!(
            dec("00000000000000000000000000004030").as_deref(),
            Some("0")
        );
        assert_eq!(dec("0000000000000000000000000000007C"), None); // NaN
        assert_eq!(dec("00000000000000000000000000000078"), None); // Infinity
        // 4111111111111111 as an integral decimal.
        let n: u128 = 4_111_111_111_111_111;
        let bits = (6176u128 << 113) | n;
        assert_eq!(
            decimal128(bits.to_le_bytes()).as_deref(),
            Some("4111111111111111")
        );
    }
}
