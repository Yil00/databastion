//! The `serde::Deserializer` over the events of a pre-scanned document
//! (ADR-0046 decisions 1 to 3), feeding the closed visitor of
//! `definition::parse_with` as `serde_yaml_ng` 0.10 did:
//!
//! - **Values.** Plain scalars resolve as `serde_yaml_ng` resolves untagged
//!   plain scalars (YAML 1.2 core schema: `null` / `~` / empty, booleans,
//!   decimal, `0x`, `0o` and `0b` integers with an optional sign, floats
//!   with `.inf` / `.nan`, a number with a leading zero stays a string);
//!   quoted and block scalars are strings. Keys are read as strings
//!   whatever their style. A collection used as a key, an end of the
//!   events before the visitor is done, or a document libyaml would have
//!   refused ([`super::events`]) is an error, after the visitor (so its
//!   own bound errors come first, as before).
//! - **Buffers.** A scalar is decoded only when the visitor reads it: a
//!   skipped value (`IgnoredAny`: credential fields, structural keys) is
//!   never decoded nor copied. A scalar whose value is its own text (a
//!   single-line plain scalar, a single-line quoted scalar without escape
//!   nor `''`) is borrowed from the zeroizing copy of the file
//!   (`visit_borrowed_str`); any other (line folding, escapes, block
//!   scalars) is built once in a zeroizing buffer allocated at its final
//!   size, which never grows (a push beyond it is an error, not a
//!   reallocation), and wiped when the visitor returns.
//! - **Errors** ([`YamlError`]) carry no text: serde's messages (which can
//!   quote a value) are dropped unformatted.

use std::fmt;
use std::num::ParseIntError;

use serde::de::{self, DeserializeSeed, Visitor};
use zeroize::Zeroizing;

use super::events::{self, Event, Events};
use super::scan::{Chomp, Refusal, Scalar, Style, escape_code, is_blank, is_break};

/// `serde_yaml_ng`'s recursion limit on collections the visitor enters.
const RECURSION_LIMIT: u8 = 128;

/// A YAML document the visitor cannot read, or that libyaml refuses. No
/// text: never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YamlError;

impl fmt::Display for YamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid YAML service definition")
    }
}

impl std::error::Error for YamlError {}

impl de::Error for YamlError {
    // The message is never formatted (it can quote a value).
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self
    }
}

/// A pre-scanned document, as events, ready for the visitor.
pub struct Document<'t> {
    text: &'t str,
    events: Events,
}

impl fmt::Debug for Document<'_> {
    // The text is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Document")
            .field("events", &self.events.events.len())
            .finish_non_exhaustive()
    }
}

impl<'t> Document<'t> {
    /// The events of a pre-scanned text (`Prescanned::text`).
    ///
    /// # Errors
    /// A [`Refusal`] when the text is not UTF-8 or the scanner refuses it
    /// (neither happens after a pre-scan).
    pub fn parse(text: &'t [u8]) -> Result<Self, Refusal> {
        let utf8 = std::str::from_utf8(text).map_err(|_| Refusal::Encoding)?;
        Ok(Self {
            text: utf8,
            events: events::build(text)?,
        })
    }
}

impl<'de> de::Deserializer<'de> for Document<'de> {
    type Error = YamlError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, YamlError> {
        let mut de = De {
            text: self.text,
            events: &self.events.events,
            pos: 0,
            depth: RECURSION_LIMIT,
        };
        let value = (&mut de).deserialize_any(visitor)?;
        // A document libyaml refuses after the events the visitor read
        // (`serde_yaml_ng` checks the parse error, then the end of the
        // stream, once the visitor is done).
        if self.events.failed {
            return Err(YamlError);
        }
        Ok(value)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

/// The deserializer state over the events.
struct De<'a, 'de> {
    text: &'de str,
    events: &'a [Event],
    pos: usize,
    /// Collections the visitor may still enter.
    depth: u8,
}

/// A scalar's value: its own text, or a decoded zeroizing copy.
enum Text<'de> {
    Borrowed(&'de str),
    Owned(Zeroizing<Vec<u8>>),
}

impl<'de> De<'_, 'de> {
    fn peek(&self) -> Result<Event, YamlError> {
        self.events.get(self.pos).copied().ok_or(YamlError)
    }

    fn next(&mut self) -> Result<Event, YamlError> {
        let e = self.peek()?;
        self.pos += 1;
        Ok(e)
    }

    /// Skips one node, decoding nothing (`serde_yaml_ng`'s `ignore_any`).
    fn ignore(&mut self) -> Result<(), YamlError> {
        let mut open = 0usize;
        loop {
            match self.next()? {
                Event::Scalar(_) => {}
                Event::SequenceStart | Event::MappingStart => open += 1,
                Event::SequenceEnd | Event::MappingEnd => {
                    open = open.checked_sub(1).ok_or(YamlError)?;
                }
            }
            if open == 0 {
                return Ok(());
            }
        }
    }

    /// The value of a scalar (see the module documentation).
    fn text(&self, s: Scalar) -> Result<Text<'de>, YamlError> {
        let text = self.text;
        let bytes = text.as_bytes();
        match s.style {
            Style::Plain => {
                let raw = text.get(s.start..s.end).ok_or(YamlError)?;
                if !raw.bytes().any(|c| is_break(Some(c))) {
                    return Ok(Text::Borrowed(raw));
                }
                let mut out = Out::with_capacity(raw.len());
                fold_plain(raw.as_bytes(), &mut out)?;
                Ok(Text::Owned(out.0))
            }
            Style::Single | Style::Double => {
                let single = s.style == Style::Single;
                let inner = s
                    .end
                    .checked_sub(1)
                    .and_then(|end| text.get(s.start + 1..end))
                    .ok_or(YamlError)?;
                let verbatim = !inner.bytes().any(|c| is_break(Some(c)))
                    && if single {
                        !inner.contains("''")
                    } else {
                        !inner.contains('\\')
                    };
                if verbatim {
                    return Ok(Text::Borrowed(inner));
                }
                // `\L` and `\P` grow from two bytes to three.
                let mut out = Out::with_capacity(inner.len() + inner.len() / 2 + 4);
                unquote(inner.as_bytes(), single, &mut out)?;
                Ok(Text::Owned(out.0))
            }
            Style::Block {
                literal,
                indent,
                chomp,
            } => {
                let raw = bytes.get(s.start..s.end).ok_or(YamlError)?;
                let mut out = Out::with_capacity(raw.len() + 1);
                block(raw, literal, indent, chomp, &mut out)?;
                Ok(Text::Owned(out.0))
            }
        }
    }

    fn visit_scalar<V: Visitor<'de>>(&self, s: Scalar, v: V) -> Result<V::Value, YamlError> {
        let resolve = s.style == Style::Plain;
        match self.text(s)? {
            Text::Borrowed(b) => {
                let v = if resolve { untagged(v, b)? } else { Err(v) };
                match v {
                    Ok(value) => Ok(value),
                    Err(v) => v.visit_borrowed_str(b),
                }
            }
            Text::Owned(buf) => {
                let st = std::str::from_utf8(&buf).map_err(|_| YamlError)?;
                let v = if resolve { untagged(v, st)? } else { Err(v) };
                match v {
                    Ok(value) => Ok(value),
                    Err(v) => v.visit_str(st),
                }
            }
        }
    }

    fn visit_sequence<V: Visitor<'de>>(&mut self, v: V) -> Result<V::Value, YamlError> {
        let previous = self.depth;
        self.depth = previous.checked_sub(1).ok_or(YamlError)?;
        let value = v.visit_seq(Seq { de: &mut *self });
        self.depth = previous;
        let value = value?;
        while self.peek()? != Event::SequenceEnd {
            self.ignore()?;
        }
        self.next()?;
        Ok(value)
    }

    fn visit_mapping<V: Visitor<'de>>(&mut self, v: V) -> Result<V::Value, YamlError> {
        let previous = self.depth;
        self.depth = previous.checked_sub(1).ok_or(YamlError)?;
        let value = v.visit_map(Map { de: &mut *self });
        self.depth = previous;
        let value = value?;
        while self.peek()? != Event::MappingEnd {
            self.ignore()?;
            self.ignore()?;
        }
        self.next()?;
        Ok(value)
    }
}

impl<'de> de::Deserializer<'de> for &mut De<'_, 'de> {
    type Error = YamlError;

    fn deserialize_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, YamlError> {
        match self.next()? {
            Event::Scalar(s) => self.visit_scalar(s, v),
            Event::SequenceStart => self.visit_sequence(v),
            Event::MappingStart => self.visit_mapping(v),
            Event::SequenceEnd | Event::MappingEnd => Err(YamlError),
        }
    }

    /// A string whatever the scalar's style (keys); a collection is an
    /// error.
    fn deserialize_str<V: Visitor<'de>>(self, v: V) -> Result<V::Value, YamlError> {
        match self.next()? {
            Event::Scalar(s) => match self.text(s)? {
                Text::Borrowed(b) => v.visit_borrowed_str(b),
                Text::Owned(buf) => v.visit_str(std::str::from_utf8(&buf).map_err(|_| YamlError)?),
            },
            _ => Err(YamlError),
        }
    }

    fn deserialize_string<V: Visitor<'de>>(self, v: V) -> Result<V::Value, YamlError> {
        self.deserialize_str(v)
    }

    /// Skipped without decoding anything.
    fn deserialize_ignored_any<V: Visitor<'de>>(self, v: V) -> Result<V::Value, YamlError> {
        self.ignore()?;
        v.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char bytes
        byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier
    }
}

struct Seq<'r, 'a, 'de> {
    de: &'r mut De<'a, 'de>,
}

impl<'de> de::SeqAccess<'de> for Seq<'_, '_, 'de> {
    type Error = YamlError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, YamlError> {
        if self.de.peek()? == Event::SequenceEnd {
            return Ok(None);
        }
        seed.deserialize(&mut *self.de).map(Some)
    }
}

struct Map<'r, 'a, 'de> {
    de: &'r mut De<'a, 'de>,
}

impl<'de> de::MapAccess<'de> for Map<'_, '_, 'de> {
    type Error = YamlError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, YamlError> {
        if self.de.peek()? == Event::MappingEnd {
            return Ok(None);
        }
        seed.deserialize(&mut *self.de).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, YamlError> {
        seed.deserialize(&mut *self.de)
    }
}

/// A zeroizing buffer allocated once at its final size: a push beyond its
/// capacity is an error, never a reallocation (which would free an
/// unwiped copy).
struct Out(Zeroizing<Vec<u8>>);

impl Out {
    fn with_capacity(n: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(n)))
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), YamlError> {
        if self.0.len() + bytes.len() > self.0.capacity() {
            return Err(YamlError);
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn breaks(&mut self, n: usize) -> Result<(), YamlError> {
        for _ in 0..n {
            self.push(b"\n")?;
        }
        Ok(())
    }
}

/// The length of the line break at `i` (CRLF or LF), 0 if none.
fn break_len(raw: &[u8], i: usize) -> usize {
    match (raw.get(i), raw.get(i + 1)) {
        (Some(b'\r'), Some(b'\n')) => 2,
        (Some(b'\n' | b'\r'), _) => 1,
        _ => 0,
    }
}

/// libyaml's joining of the blanks and line breaks between two runs of
/// content (`scan_plain_scalar`, `scan_flow_scalar`): one line break
/// folds into a space, more keep all but the first; blanks within a line
/// are kept, around a line break they are dropped.
struct Folding {
    /// Blanks after the last content, before any line break.
    ws: Option<(usize, usize)>,
    /// A line break after the last content (libyaml's `leading_blanks`).
    leading_blanks: bool,
    /// libyaml's `leading_break` is `"\n"` (not after an escaped break).
    leading_break: bool,
    /// Line breaks after the first one.
    trailing: usize,
}

impl Folding {
    const fn new() -> Self {
        Self {
            ws: None,
            leading_blanks: false,
            leading_break: false,
            trailing: 0,
        }
    }

    /// Reads blanks and line breaks from `i`; returns the next index.
    fn whitespace(&mut self, raw: &[u8], mut i: usize) -> usize {
        loop {
            match raw.get(i) {
                Some(b' ' | b'\t') => {
                    if !self.leading_blanks {
                        self.ws = Some(match self.ws {
                            Some((from, _)) => (from, i + 1),
                            None => (i, i + 1),
                        });
                    }
                    i += 1;
                }
                Some(b'\n' | b'\r') => {
                    if self.leading_blanks {
                        self.trailing += 1;
                    } else {
                        self.ws = None;
                        self.leading_break = true;
                        self.leading_blanks = true;
                    }
                    i += break_len(raw, i);
                }
                _ => return i,
            }
        }
    }

    /// Writes what the whitespace read so far stands for.
    fn join(&mut self, raw: &[u8], out: &mut Out) -> Result<(), YamlError> {
        if self.leading_blanks {
            if self.leading_break && self.trailing == 0 {
                out.push(b" ")?;
            } else {
                out.breaks(self.trailing)?;
            }
            self.trailing = 0;
            self.leading_break = false;
            self.leading_blanks = false;
        } else if let Some((from, to)) = self.ws.take() {
            out.push(raw.get(from..to).ok_or(YamlError)?)?;
        }
        self.ws = None;
        Ok(())
    }
}

/// The value of a multi-line plain scalar (`raw` from its first to its
/// last content byte: no comment, no indicator inside).
fn fold_plain(raw: &[u8], out: &mut Out) -> Result<(), YamlError> {
    let mut f = Folding::new();
    let mut i = 0;
    loop {
        let from = i;
        while raw
            .get(i)
            .is_some_and(|c| !is_blank(Some(*c)) && !is_break(Some(*c)))
        {
            i += 1;
        }
        if i > from {
            f.join(raw, out)?;
            out.push(raw.get(from..i).ok_or(YamlError)?)?;
        }
        if i >= raw.len() {
            return Ok(());
        }
        i = f.whitespace(raw, i);
    }
}

/// The value of a quoted scalar whose content (between the quotes) is
/// `raw`: `''` pairs, escapes (already checked by the scanner), escaped
/// line breaks and line folding.
fn unquote(raw: &[u8], single: bool, out: &mut Out) -> Result<(), YamlError> {
    let mut f = Folding::new();
    let mut i = 0;
    loop {
        // libyaml clears `leading_blanks` at each run of content.
        f.leading_blanks = false;
        while let Some(&c) = raw.get(i) {
            if is_blank(Some(c)) || is_break(Some(c)) {
                break;
            }
            if single && c == b'\'' && raw.get(i + 1) == Some(&b'\'') {
                out.push(b"'")?;
                i += 2;
            } else if !single && c == b'\\' && is_break(raw.get(i + 1).copied()) {
                i += 1;
                i += break_len(raw, i);
                f.leading_blanks = true;
                break;
            } else if !single && c == b'\\' {
                i = escape(raw, i + 1, out)?;
            } else {
                out.push(&[c])?;
                i += 1;
            }
        }
        if i >= raw.len() {
            return Ok(());
        }
        // libyaml joins at the end of each run of whitespace (an escaped
        // line break adds no space).
        i = f.whitespace(raw, i);
        f.join(raw, out)?;
    }
}

/// Decodes the escape whose letter is at `i` (after its `\`); returns the
/// index after it.
fn escape(raw: &[u8], i: usize, out: &mut Out) -> Result<usize, YamlError> {
    let e = *raw.get(i).ok_or(YamlError)?;
    let simple: &[u8] = match e {
        b'0' => b"\0",
        b'a' => b"\x07",
        b'b' => b"\x08",
        b't' | b'\t' => b"\t",
        b'n' => b"\n",
        b'v' => b"\x0b",
        b'f' => b"\x0c",
        b'r' => b"\r",
        b'e' => b"\x1b",
        b' ' => b" ",
        b'"' => b"\"",
        b'/' => b"/",
        b'\\' => b"\\",
        b'N' => "\u{85}".as_bytes(),
        b'_' => "\u{a0}".as_bytes(),
        b'L' => "\u{2028}".as_bytes(),
        b'P' => "\u{2029}".as_bytes(),
        b'x' | b'u' | b'U' => {
            let digits = match e {
                b'x' => 2,
                b'u' => 4,
                _ => 8,
            };
            let c = raw
                .get(i + 1..i + 1 + digits)
                .and_then(escape_code)
                .ok_or(YamlError)?;
            let mut buf = [0u8; 4];
            out.push(c.encode_utf8(&mut buf).as_bytes())?;
            return Ok(i + 1 + digits);
        }
        _ => return Err(YamlError),
    };
    out.push(simple)?;
    Ok(i + 1)
}

/// The value of a block scalar whose content lines are `raw` (from the
/// line after its header to where the scanner ended it), at `indent`
/// (libyaml's `scan_block_scalar` with a known indentation).
fn block(
    raw: &[u8],
    literal: bool,
    indent: usize,
    chomp: Chomp,
    out: &mut Out,
) -> Result<(), YamlError> {
    let mut i = 0;
    let mut col = 0;
    let mut leading_break = false;
    let mut leading_blank = false;
    let mut trailing = 0usize;
    block_breaks(raw, indent, &mut i, &mut col, &mut trailing);
    while col == indent && i < raw.len() {
        let trailing_blank = is_blank(raw.get(i).copied());
        if !literal && leading_break && !leading_blank && !trailing_blank {
            if trailing == 0 {
                out.push(b" ")?;
            }
        } else if leading_break {
            out.push(b"\n")?;
        }
        leading_break = false;
        out.breaks(trailing)?;
        trailing = 0;
        leading_blank = trailing_blank;
        let from = i;
        while raw.get(i).is_some_and(|c| !is_break(Some(*c))) {
            i += 1;
        }
        out.push(raw.get(from..i).ok_or(YamlError)?)?;
        let n = break_len(raw, i);
        if n > 0 {
            leading_break = true;
            i += n;
            col = 0;
        }
        block_breaks(raw, indent, &mut i, &mut col, &mut trailing);
    }
    if chomp != Chomp::Strip && leading_break {
        out.push(b"\n")?;
    }
    if chomp == Chomp::Keep {
        out.breaks(trailing)?;
    }
    Ok(())
}

/// Indentation spaces and empty lines (libyaml's
/// `scan_block_scalar_breaks` with a known indentation).
fn block_breaks(raw: &[u8], indent: usize, i: &mut usize, col: &mut usize, trailing: &mut usize) {
    loop {
        while *col < indent && raw.get(*i) == Some(&b' ') {
            *i += 1;
            *col += 1;
        }
        let n = break_len(raw, *i);
        if n == 0 {
            return;
        }
        *i += n;
        *col = 0;
        *trailing += 1;
    }
}

/// `serde_yaml_ng`'s `visit_untagged_scalar` up to strings: the resolved
/// value, or the visitor back when the scalar is a string.
fn untagged<'de, V: Visitor<'de>>(v: V, s: &str) -> Result<Result<V::Value, V>, YamlError> {
    if s.is_empty() || matches!(s, "null" | "Null" | "NULL" | "~") {
        return v.visit_unit().map(Ok);
    }
    match s {
        "true" | "True" | "TRUE" => return v.visit_bool(true).map(Ok),
        "false" | "False" | "FALSE" => return v.visit_bool(false).map(Ok),
        _ => {}
    }
    if let Some(i) = unsigned_int(s, u64::from_str_radix) {
        return v.visit_u64(i).map(Ok);
    }
    if let Some(i) = negative_int(s, i64::from_str_radix, negative_i64) {
        return v.visit_i64(i).map(Ok);
    }
    if let Some(i) = unsigned_int(s, u128::from_str_radix) {
        return v.visit_u128(i).map(Ok);
    }
    if let Some(i) = negative_int(s, i128::from_str_radix, negative_i128) {
        return v.visit_i128(i).map(Ok);
    }
    if !digits_but_not_number(s)
        && let Some(f) = float(s)
    {
        return v.visit_f64(f).map(Ok);
    }
    Ok(Err(v))
}

/// A leading zero followed by digits only is a string (YAML 1.2).
fn digits_but_not_number(s: &str) -> bool {
    let t = s.strip_prefix(['-', '+']).unwrap_or(s);
    t.len() > 1 && t.starts_with('0') && t.bytes().skip(1).all(|b| b.is_ascii_digit())
}

/// `serde_yaml_ng`'s `parse_unsigned_int`.
fn unsigned_int<T>(s: &str, from: fn(&str, u32) -> Result<T, ParseIntError>) -> Option<T> {
    let unpositive = s.strip_prefix('+').unwrap_or(s);
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(rest) = unpositive.strip_prefix(prefix) {
            if rest.starts_with(['+', '-']) {
                return None;
            }
            if let Ok(i) = from(rest, radix) {
                return Some(i);
            }
        }
    }
    if unpositive.starts_with(['+', '-']) || digits_but_not_number(s) {
        return None;
    }
    from(unpositive, 10).ok()
}

/// `serde_yaml_ng`'s `parse_negative_int`; `negative(digits, radix)` is its
/// `from_str_radix(&format!("-{digits}"), radix)`, without the copy.
fn negative_int<T>(
    s: &str,
    from: fn(&str, u32) -> Result<T, ParseIntError>,
    negative: fn(&str, u32) -> Option<T>,
) -> Option<T> {
    for (prefix, radix) in [("-0x", 16), ("-0o", 8), ("-0b", 2)] {
        if let Some(rest) = s.strip_prefix(prefix)
            && let Some(i) = negative(rest, radix)
        {
            return Some(i);
        }
    }
    if digits_but_not_number(s) {
        return None;
    }
    from(s, 10).ok()
}

/// The magnitude of `digits` in `radix` (all digits, at least one), as
/// `from_str_radix` reads what follows a `-`.
fn magnitude(digits: &str, radix: u32) -> Option<u128> {
    if digits.is_empty() {
        return None;
    }
    let mut m = 0u128;
    for c in digits.chars() {
        let d = c.to_digit(radix)?;
        m = m
            .checked_mul(u128::from(radix))?
            .checked_add(u128::from(d))?;
    }
    Some(m)
}

fn negative_i64(digits: &str, radix: u32) -> Option<i64> {
    let m = i128::try_from(magnitude(digits, radix)?).ok()?;
    i64::try_from(-m).ok()
}

fn negative_i128(digits: &str, radix: u32) -> Option<i128> {
    let m = magnitude(digits, radix)?;
    if m == 1u128 << 127 {
        return Some(i128::MIN);
    }
    i128::try_from(m).ok().map(|m| -m)
}

/// `serde_yaml_ng`'s `parse_f64`.
fn float(s: &str) -> Option<f64> {
    let unpositive = match s.strip_prefix('+') {
        Some(u) if u.starts_with(['+', '-']) => return None,
        Some(u) => u,
        None => s,
    };
    if matches!(unpositive, ".inf" | ".Inf" | ".INF") {
        return Some(f64::INFINITY);
    }
    if matches!(s, "-.inf" | "-.Inf" | "-.INF") {
        return Some(f64::NEG_INFINITY);
    }
    if matches!(s, ".nan" | ".NaN" | ".NAN") {
        return Some(f64::NAN.copysign(1.0));
    }
    unpositive.parse::<f64>().ok().filter(|f| f.is_finite())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::{Ng, yaml_difference};
    use crate::parse::definition::{Seg, parse_yaml_definition};

    const HEAD: &str = "--- !<org.apereo.cas.services.CasRegisteredService>\nserviceId: x\n";

    /// Whether the crate's parser reads `body` (after [`HEAD`]) without an
    /// error, having checked that `serde_yaml_ng` agrees.
    fn reads(body: &str) -> bool {
        let doc = format!("{HEAD}{body}");
        assert_eq!(yaml_difference(doc.as_bytes(), &Ng), None, "{doc:?}");
        let pre = super::super::prescan(doc.as_bytes()).unwrap();
        let ours = Document::parse(&pre.text)
            .ok()
            .and_then(|d| de::IgnoredAny::deserialize(d).ok());
        let theirs: Result<de::IgnoredAny, _> = serde_yaml_ng::from_slice(&pre.text);
        assert_eq!(ours.is_some(), theirs.is_ok(), "{doc:?}");
        ours.is_some()
    }

    fn value(body: &str, key: &str) -> Option<String> {
        let d = parse_yaml_definition(format!("{HEAD}{body}").as_bytes()).unwrap();
        d.values
            .iter()
            .find(|s| s.path == [Seg::Key(key.to_owned())])
            .map(|s| s.value.to_string())
    }

    use serde::Deserialize;

    #[test]
    fn scalars_decode_as_libyaml_decodes_them() {
        for (body, want) in [
            ("d: plain text\n", "plain text"),
            ("d: multi\n  line\n\n  plain\n", "multi line\nplain"),
            ("d: 'it''s\n  two'\n", "it's two"),
            ("d: \"a\\x41\\u00e9\\\n   b\"\n", "aAéb"),
            ("d: \"x  \n\n\n y\"\n", "x\n\ny"),
            ("d: |\n  lit\n   more\n\n", "lit\n more\n"),
            ("d: |-\n  a\n  b\n\n", "a\nb"),
            ("d: |+\n  a\n\n\n", "a\n\n\n"),
            (
                "d: >\n  folded\n  text\n\n   indented\n  back\n",
                "folded text\n\n indented\nback\n",
            ),
            ("d: \"x\\N\\L\\P\\_y\"\n", "x\u{85}\u{2028}\u{2029}\u{a0}y"),
            ("d: 0612345678\n", "0612345678"),
            ("d: 0x1F\n", "31"),
            ("d: -0x10\n", "-16"),
            ("d: +12\n", "12"),
            ("d: 18446744073709551616\n", "18446744073709551616"),
        ] {
            assert!(reads(body), "{body:?}");
            assert_eq!(value(body, "d").as_deref(), Some(want), "{body:?}");
        }
        // Not strings: floats, booleans and nulls are not sampled.
        for body in ["d: 1e3\n", "d: .inf\n", "d: TRUE\n", "d: ~\n", "d:\n"] {
            assert!(reads(body), "{body:?}");
            assert_eq!(value(body, "d"), None, "{body:?}");
        }
    }

    #[test]
    fn what_libyaml_refuses_is_refused() {
        let long = "k".repeat(1025);
        let fits = "k".repeat(1024);
        // libyaml forgets a simple key more than 1024 bytes back.
        assert!(reads(&format!("{fits}: v\n")));
        assert!(!reads(&format!("{long}: v\n")));
        assert!(!reads(&format!("d: {{{long}: v}}\n")));
        assert!(!reads(&format!("d: [{long}: v]\n")));
        for body in [
            // A key at the mapping's indentation without its `:`.
            "a: 1\nb\n",
            "a: 1\nb",
            "a:\n  b: 1\n  c\n",
            // Indentation libyaml does not accept.
            "a:\n  b: 1\n c: 2\n",
            "a: \"x\" y\n",
            "- a\nb: c\n",
            // A document marker in a quoted scalar.
            "a: \"x\n--- y\"\n",
            "a: 'x\n...\n'\n",
            // Escapes.
            "a: \"\\q\"\n",
            "a: \"\\x4\"\n",
            "a: \"\\uDC00\"\n",
        ] {
            assert!(!reads(body), "{body:?}");
        }
        // A collection as a key (in a flow mapping, where the pre-scan
        // lets it pass): the visitor reads keys as strings.
        assert!(reads("a: {[b], c: d}\n"));
        assert!(parse_yaml_definition(format!("{HEAD}a: {{[b], c: d}}\n").as_bytes()).is_err());
        // Anything after the root node.
        let doc = "--- !<org.apereo.cas.services.CasRegisteredService> {serviceId: x}\nb: c\n";
        assert_eq!(yaml_difference(doc.as_bytes(), &Ng), None);
        assert!(parse_yaml_definition(doc.as_bytes()).is_err());
    }

    /// A search of the process's writable memory (Linux: `/proc/self/maps`
    /// and `/proc/self/mem`, read with safe file I/O). Its buffers are
    /// allocated up front, before what it checks, so that searching
    /// allocates nothing that could reuse (and overwrite) a freed block
    /// before it is read (security review of #187, L1).
    #[cfg(target_os = "linux")]
    struct MemScan {
        maps: String,
        /// Zeroizing (its earlier contents never linger), its own range
        /// skipped.
        buf: Zeroizing<Vec<u8>>,
    }

    #[cfg(target_os = "linux")]
    impl MemScan {
        const CHUNK: usize = 1 << 20;

        fn new() -> Self {
            Self {
                maps: String::with_capacity(1 << 20),
                buf: Zeroizing::new(vec![0u8; Self::CHUNK + 64]),
            }
        }

        /// Occurrences of `needle` (at most 64 bytes) outside the `skip`
        /// address ranges.
        fn occurrences(&mut self, needle: &[u8], skip: &[std::ops::Range<usize>]) -> usize {
            use std::io::{Read, Seek, SeekFrom};
            let cap = self.maps.capacity();
            self.maps.clear();
            std::fs::File::open("/proc/self/maps")
                .unwrap()
                .read_to_string(&mut self.maps)
                .unwrap();
            assert_eq!(self.maps.capacity(), cap, "the maps buffer grew");
            let mut mem = std::fs::File::open("/proc/self/mem").unwrap();
            let buf = &mut self.buf;
            let own = buf.as_ptr() as usize..buf.as_ptr() as usize + buf.len();
            let mut found = 0;
            for line in self.maps.lines() {
                let mut fields = line.split_whitespace();
                let (Some(range), Some(perms)) = (fields.next(), fields.next()) else {
                    continue;
                };
                if !perms.starts_with("rw") {
                    continue;
                }
                let Some((lo, hi)) = range.split_once('-') else {
                    continue;
                };
                let lo = usize::from_str_radix(lo, 16).unwrap();
                let hi = usize::from_str_radix(hi, 16).unwrap();
                let mut at = lo;
                while at < hi {
                    let len = (hi - at).min(Self::CHUNK + needle.len());
                    let ok = mem.seek(SeekFrom::Start(at as u64)).is_ok()
                        && mem.read_exact(&mut buf[..len]).is_ok();
                    if ok {
                        for (i, w) in buf[..len].windows(needle.len()).enumerate() {
                            let addr = at + i;
                            if w == needle
                                && !own.contains(&addr)
                                && !skip.iter().any(|r| r.contains(&addr))
                            {
                                found += 1;
                            }
                        }
                    }
                    at += Self::CHUNK;
                }
            }
            found
        }
    }

    /// The address range of a buffer (skipped by the search).
    #[cfg(target_os = "linux")]
    fn range_of(b: &[u8]) -> std::ops::Range<usize> {
        b.as_ptr() as usize..b.as_ptr() as usize + b.len()
    }

    /// ADR-0046 decision 3: no copy of a credential value outlives the
    /// parse. A counting allocator would need `unsafe impl GlobalAlloc`,
    /// which `unsafe_code = "forbid"` rules out in every target of the
    /// workspace; instead, after parsing a definition whose credential
    /// values hold a marker (made at run time, in every form that reaches
    /// the parser: next-line, multi-line, block, flow and tagged values,
    /// and a top-level `clientSecret` over 1 KiB with escapes, which the
    /// visitor decodes into a large buffer) and dropping everything, the
    /// process's writable memory (heap, stacks, data) is searched for the
    /// marker: a copy freed without being wiped would be found there. The
    /// controls (an unwiped `String` copy of each size, small, medium and
    /// over the allocator's small-block limit, dropped) show the search
    /// finds such a copy, each size on its own.
    #[cfg(target_os = "linux")]
    #[test]
    fn no_unwiped_copy_of_a_credential_value_survives_parsing() {
        // 48 bytes from a run-time seed, never a literal; the needle is the
        // last 32 (an allocator may reuse the first 16 bytes of a freed
        // block for its own links).
        let mut marker = Zeroizing::new(Vec::with_capacity(48));
        let mut x = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
            | 1;
        for _ in 0..48 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            marker.push(b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[(x % 32) as usize]);
        }
        let mut scan = MemScan::new();
        let mut doc = Zeroizing::new(Vec::with_capacity(8192));
        let cap = doc.capacity();
        for (part, secret) in [
            (&b"--- !<org.apereo.cas.support.oauth.services.OAuthRegisteredService>\nserviceId: x\nname: App\nclientSecret: \"F"[..], true),
            (b"\"\napiPassword:\n  ", true),
            (b"\nprivateKey: |\n  ", true),
            (b"\n  second line\ntokens:\n- ", true),
            (b"\n- {a: ", true),
            (b"}\nsigningKey: !<java.lang.String> ", true),
            (b"\nnested:\n  credentials: [", true),
            (b", \"", true),
            (b"\n   folded\"]\n  password: >-\n    ", true),
            (b"\ndescription: kept\n", false),
        ] {
            doc.extend_from_slice(part);
            if secret {
                doc.extend_from_slice(&marker);
            }
            if doc.len() < 200 {
                // The top-level `clientSecret`: over 1 KiB, with escapes.
                for _ in 0..300 {
                    doc.extend_from_slice(b"\\x41");
                }
            }
        }
        assert_eq!(doc.capacity(), cap);
        let d = parse_yaml_definition(&doc).unwrap();
        assert_eq!(d.client_secret, crate::parse::definition::SecretForm::Clear);
        assert_eq!(d.values.len(), 3, "{d:?}");
        drop(d);
        drop(doc);
        let skip = range_of(&marker);
        assert_eq!(
            scan.occurrences(&marker[16..], std::slice::from_ref(&skip)),
            0
        );
        // The controls: an unwiped copy of each size, dropped, is found,
        // each with its own marker.
        for (pad, tag) in [(64, b'a'), (300, b'b'), (2000, b'c')] {
            let mut variant = Zeroizing::new(marker.to_vec());
            if let Some(last) = variant.last_mut() {
                *last = tag;
            }
            let mut leak = String::with_capacity(2 * pad + variant.len());
            leak.push_str(&"-".repeat(pad));
            leak.push_str(std::str::from_utf8(&variant).unwrap());
            leak.push_str(&"-".repeat(pad));
            drop(leak);
            let found = scan.occurrences(&variant[16..], &[skip.clone(), range_of(&variant)]);
            assert!(found > 0, "control of {pad} bytes not found");
        }
    }

    #[test]
    fn errors_hold_no_text() {
        let e = <YamlError as de::Error>::custom("FAKE-SECRET-VALUE");
        assert!(!format!("{e} {e:?}").contains("FAKE"));
    }

    #[test]
    fn decoded_buffers_never_grow() {
        // The worst growth: `\L` (two bytes) is three.
        let raw = "\\L".repeat(100) + "\n x";
        let mut out = Out::with_capacity(raw.len() + raw.len() / 2 + 4);
        let cap = out.0.capacity();
        unquote(raw.as_bytes(), false, &mut out).unwrap();
        assert_eq!(out.0.capacity(), cap);
        assert_eq!(out.0.len(), 302);
        let mut small = Out::with_capacity(1);
        assert_eq!(small.push(b"ab"), Err(YamlError));
    }
}
