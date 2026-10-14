//! A bounded, streaming decoder for the subset of RESP3 the connector
//! reads, and the request encoder (ADR-0052 decision 1).
//!
//! The decoder is a state machine fed with whatever bytes the socket gave
//! ([`Decoder::feed`]): it never buffers more than one header line (at most
//! [`MAX_LINE`] bytes) and the strings the request allows, so a hostile
//! server cannot make the agent allocate what it announces. Every bound is
//! checked on the header, **before** any allocation:
//!
//! - a line (simple string, number, error, double, big number) at most
//!   [`MAX_LINE`] bytes; a blob error (`!`) is capped like a line and its
//!   text discarded but for its first word;
//! - a bulk or verbatim string at most the request's `bulk` cap; above it,
//!   when the request allows it (`skip_oversized`: key names, log
//!   arguments), the string is read and **discarded without buffering** and
//!   decoded as [`Value::Skipped`]; otherwise the reply fails
//!   ([`DecodeError::Limit`]) and the caller closes the connection;
//! - an aggregate at most the request's `items` elements (a map counts
//!   twice its pairs), never preallocated from the announced count, nested
//!   at most [`MAX_DEPTH`] levels;
//! - at most the request's `reply` bytes buffered per reply, strings and
//!   the in-memory size of every element counted (a map pair twice), and
//!   at most [`WIRE_BUDGET`] bytes read per reply, skipped bytes included;
//! - push (`>`) and attribute (`|`) frames, streamed lengths (`$?`, `*?`,
//!   `;` chunks), negative lengths other than `-1` and unknown types are
//!   refused ([`DecodeError::Push`], [`DecodeError::Protocol`]).
//!
//! Error replies keep their first word only, compared with a closed list
//! ([`ErrorWord`]); the rest of the text (a `NOPERM` message names the key)
//! is never kept. Decoded strings live in zeroized buffers.

use zeroize::Zeroize;

/// Longest header line, CRLF excluded.
pub(crate) const MAX_LINE: usize = 512;
/// Deepest nesting of aggregates.
pub(crate) const MAX_DEPTH: usize = 4;
/// Most bytes buffered per reply.
pub(crate) const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;
/// Most bytes read per reply, discarded ones included.
pub(crate) const WIRE_BUDGET: usize = 64 * 1024 * 1024;

/// What one decoded element counts against the reply cap: its in-memory
/// size, whatever its wire size (a null is 3 bytes on the wire).
const ELEMENT_BYTES: usize = std::mem::size_of::<Value>();

/// The bounds of one request's reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Longest bulk or verbatim string.
    pub(crate) bulk: usize,
    /// Most elements of each aggregate (a map counts twice its pairs).
    pub(crate) items: usize,
    /// Oversized bulk strings are read, discarded and decoded as
    /// [`Value::Skipped`] instead of failing the reply.
    pub(crate) skip_oversized: bool,
    /// Most bytes buffered for the reply.
    pub(crate) reply: usize,
}

impl Limits {
    /// A reply of scalars and small aggregates (`OK`, numbers).
    pub(crate) const SIMPLE: Self = Self {
        bulk: MAX_LINE,
        items: 0,
        skip_oversized: false,
        reply: 4096,
    };
}

/// The first word of an error reply, from a closed list; anything else is
/// [`ErrorWord::Err`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorWord {
    Err,
    Noperm,
    Noauth,
    Wrongpass,
    Wrongtype,
    Moved,
    Ask,
    Loading,
    Busy,
    Masterdown,
    Clusterdown,
    Tryagain,
    Readonly,
    Execabort,
    Noreplicas,
    Misconf,
}

impl ErrorWord {
    const ALL: [(Self, &'static str); 16] = [
        (Self::Err, "ERR"),
        (Self::Noperm, "NOPERM"),
        (Self::Noauth, "NOAUTH"),
        (Self::Wrongpass, "WRONGPASS"),
        (Self::Wrongtype, "WRONGTYPE"),
        (Self::Moved, "MOVED"),
        (Self::Ask, "ASK"),
        (Self::Loading, "LOADING"),
        (Self::Busy, "BUSY"),
        (Self::Masterdown, "MASTERDOWN"),
        (Self::Clusterdown, "CLUSTERDOWN"),
        (Self::Tryagain, "TRYAGAIN"),
        (Self::Readonly, "READONLY"),
        (Self::Execabort, "EXECABORT"),
        (Self::Noreplicas, "NOREPLICAS"),
        (Self::Misconf, "MISCONF"),
    ];

    /// The word of an error text (its first space-separated word).
    pub(crate) fn of(text: &[u8]) -> Self {
        let word = text.split(|b| *b == b' ').next().unwrap_or_default();
        Self::ALL
            .iter()
            .find(|(_, w)| w.as_bytes() == word)
            .map_or(Self::Err, |(e, _)| *e)
    }

    /// The contract `EngineCode` of the error.
    pub(crate) fn as_str(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(e, _)| *e == self)
            .map_or("ERR", |(_, w)| w)
    }
}

/// A decoded string, zeroized on drop.
#[derive(Clone, PartialEq, Eq, Default)]
pub(crate) struct Bytes(Vec<u8>);

impl Bytes {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Bytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes({} bytes)", self.0.len())
    }
}

/// A decoded reply.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    /// Simple, bulk or verbatim string (the verbatim format prefix removed).
    Str(Bytes),
    Int(i64),
    /// `_`, `$-1`, `*-1`.
    Null,
    Bool(bool),
    /// A double or a big number: the value is never needed, not kept.
    Number,
    Error(ErrorWord),
    /// Array or set.
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    /// A bulk string over the request's cap, read and discarded.
    Skipped,
}

impl Value {
    pub(crate) fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Str(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub(crate) fn error(&self) -> Option<ErrorWord> {
        match self {
            Self::Error(e) => Some(*e),
            _ => None,
        }
    }
}

/// Why a reply could not be decoded. The connection is unusable after any
/// of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// Not RESP3 as the connector reads it.
    Protocol,
    /// Over a bound of the request.
    Limit,
    /// A push or attribute frame.
    Push,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BulkKind {
    Plain,
    Verbatim,
    BlobError,
}

#[derive(Debug)]
enum State {
    /// Reading a header line.
    Header,
    /// Reading the payload of a bulk string (`buf` `None`: discarding).
    Bulk {
        kind: BulkKind,
        remaining: usize,
        buf: Option<Vec<u8>>,
    },
    /// Expecting the CRLF after a payload (`got` bytes of it seen).
    Crlf {
        kind: BulkKind,
        got: u8,
        buf: Option<Vec<u8>>,
    },
}

#[derive(Debug)]
struct Frame {
    map: bool,
    expected: usize,
    items: Vec<Value>,
}

/// Decodes one reply at a time from a byte stream.
#[derive(Debug)]
pub(crate) struct Decoder {
    limits: Limits,
    state: State,
    line: Vec<u8>,
    stack: Vec<Frame>,
    buffered: usize,
    wire: usize,
}

impl Drop for Decoder {
    fn drop(&mut self) {
        self.line.zeroize();
        match &mut self.state {
            State::Bulk { buf: Some(b), .. } | State::Crlf { buf: Some(b), .. } => b.zeroize(),
            _ => {}
        }
    }
}

fn parse_len(text: &[u8]) -> Result<Option<usize>, DecodeError> {
    if text == b"-1" {
        return Ok(None);
    }
    if text.is_empty() || text.len() > 19 || !text.iter().all(u8::is_ascii_digit) {
        // `?` (streamed), other negative lengths, garbage.
        return Err(DecodeError::Protocol);
    }
    let s = std::str::from_utf8(text).map_err(|_| DecodeError::Protocol)?;
    s.parse::<usize>()
        .map(Some)
        .map_err(|_| DecodeError::Protocol)
}

impl Decoder {
    /// A decoder for the replies of one request.
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: State::Header,
            line: Vec::new(),
            stack: Vec::new(),
            buffered: 0,
            wire: 0,
        }
    }

    /// Starts the next reply with other limits (pipelined replies).
    pub(crate) fn reset(&mut self, limits: Limits) {
        self.line.zeroize();
        self.line.clear();
        self.state = State::Header;
        self.stack.clear();
        self.buffered = 0;
        self.wire = 0;
        self.limits = limits;
    }

    fn account(&mut self, n: usize) -> Result<(), DecodeError> {
        self.buffered = self.buffered.saturating_add(n);
        if self.buffered > self.limits.reply {
            return Err(DecodeError::Limit);
        }
        Ok(())
    }

    /// Feeds bytes. Returns how many were consumed and, when a whole reply
    /// was decoded, that reply (the bytes after it are not consumed).
    ///
    /// # Errors
    /// [`DecodeError`]: the connection must be closed.
    pub(crate) fn feed(&mut self, input: &[u8]) -> Result<(usize, Option<Value>), DecodeError> {
        let mut pos = 0;
        while pos < input.len() {
            let rest = input.get(pos..).unwrap_or_default();
            let (used, done) = self.step(rest)?;
            pos += used;
            self.wire = self.wire.saturating_add(used);
            if self.wire > WIRE_BUDGET {
                return Err(DecodeError::Limit);
            }
            if let Some(v) = done {
                let limits = self.limits;
                self.reset(limits);
                return Ok((pos, Some(v)));
            }
            if used == 0 {
                break;
            }
        }
        Ok((pos, None))
    }

    /// One step: consumes at least one byte of a non-empty input.
    fn step(&mut self, input: &[u8]) -> Result<(usize, Option<Value>), DecodeError> {
        match std::mem::replace(&mut self.state, State::Header) {
            State::Header => {
                let Some(nl) = input.iter().position(|b| *b == b'\n') else {
                    if self.line.len() + input.len() > MAX_LINE + 1 {
                        return Err(DecodeError::Limit);
                    }
                    self.line.extend_from_slice(input);
                    return Ok((input.len(), None));
                };
                let part = input.get(..nl).unwrap_or_default();
                if self.line.len() + part.len() > MAX_LINE + 1 {
                    return Err(DecodeError::Limit);
                }
                self.line.extend_from_slice(part);
                if self.line.pop() != Some(b'\r') {
                    return Err(DecodeError::Protocol);
                }
                let mut line = std::mem::take(&mut self.line);
                let r = self.header(&line);
                line.zeroize();
                Ok((nl + 1, r?))
            }
            State::Bulk {
                kind,
                remaining,
                buf,
            } => {
                let take = remaining.min(input.len());
                let mut buf = buf;
                if let Some(b) = buf.as_mut() {
                    b.extend_from_slice(input.get(..take).unwrap_or_default());
                }
                if take < remaining {
                    self.state = State::Bulk {
                        kind,
                        remaining: remaining - take,
                        buf,
                    };
                } else {
                    self.state = State::Crlf { kind, got: 0, buf };
                }
                Ok((take, None))
            }
            State::Crlf { kind, got, buf } => {
                let expected = if got == 0 { b'\r' } else { b'\n' };
                if input.first() != Some(&expected) {
                    if let Some(mut b) = buf {
                        b.zeroize();
                    }
                    return Err(DecodeError::Protocol);
                }
                if got == 0 {
                    self.state = State::Crlf { kind, got: 1, buf };
                    return Ok((1, None));
                }
                let value = match (kind, buf) {
                    (_, None) => Value::Skipped,
                    (BulkKind::Plain, Some(b)) => Value::Str(Bytes(b)),
                    (BulkKind::Verbatim, Some(mut b)) => {
                        // `txt:` / `mkd:` format prefix.
                        if b.len() < 4 || b.get(3) != Some(&b':') {
                            b.zeroize();
                            return Err(DecodeError::Protocol);
                        }
                        let rest = b.get(4..).unwrap_or_default().to_vec();
                        b.zeroize();
                        Value::Str(Bytes(rest))
                    }
                    (BulkKind::BlobError, Some(mut b)) => {
                        let word = ErrorWord::of(&b);
                        b.zeroize();
                        Value::Error(word)
                    }
                };
                Ok((1, self.complete(value)?))
            }
        }
    }

    fn start_bulk(&mut self, kind: BulkKind, len: usize) -> Result<Option<Value>, DecodeError> {
        let cap = if kind == BulkKind::BlobError {
            MAX_LINE
        } else {
            self.limits.bulk
        };
        let buf = if len > cap {
            if kind == BulkKind::BlobError || !self.limits.skip_oversized {
                return Err(DecodeError::Limit);
            }
            None
        } else {
            self.account(len)?;
            // Sized once: no reallocation leaves a copy behind (L2).
            Some(Vec::with_capacity(len))
        };
        if len == 0 {
            self.state = State::Crlf { kind, got: 0, buf };
        } else {
            self.state = State::Bulk {
                kind,
                remaining: len,
                buf,
            };
        }
        Ok(None)
    }

    fn start_aggregate(&mut self, map: bool, count: usize) -> Result<Option<Value>, DecodeError> {
        let expected = if map {
            count.checked_mul(2).ok_or(DecodeError::Limit)?
        } else {
            count
        };
        if expected > self.limits.items {
            return Err(DecodeError::Limit);
        }
        if self.stack.len() >= MAX_DEPTH {
            return Err(DecodeError::Limit);
        }
        if expected == 0 {
            let v = if map {
                Value::Map(Vec::new())
            } else {
                Value::Array(Vec::new())
            };
            return self.complete(v);
        }
        self.stack.push(Frame {
            map,
            expected,
            items: Vec::new(),
        });
        Ok(None)
    }

    fn header(&mut self, line: &[u8]) -> Result<Option<Value>, DecodeError> {
        let (&ty, rest) = line.split_first().ok_or(DecodeError::Protocol)?;
        match ty {
            b'+' => {
                self.account(rest.len())?;
                self.complete(Value::Str(Bytes(rest.to_vec())))
            }
            b'-' => self.complete(Value::Error(ErrorWord::of(rest))),
            b':' => {
                let s = std::str::from_utf8(rest).map_err(|_| DecodeError::Protocol)?;
                let n = s.parse::<i64>().map_err(|_| DecodeError::Protocol)?;
                self.complete(Value::Int(n))
            }
            b'$' | b'=' | b'!' => {
                let kind = match ty {
                    b'$' => BulkKind::Plain,
                    b'=' => BulkKind::Verbatim,
                    _ => BulkKind::BlobError,
                };
                match parse_len(rest)? {
                    None if kind == BulkKind::Plain => self.complete(Value::Null),
                    None => Err(DecodeError::Protocol),
                    Some(len) => self.start_bulk(kind, len),
                }
            }
            b'*' | b'~' => match parse_len(rest)? {
                None if ty == b'*' => self.complete(Value::Null),
                None => Err(DecodeError::Protocol),
                Some(n) => self.start_aggregate(false, n),
            },
            b'%' => match parse_len(rest)? {
                None => Err(DecodeError::Protocol),
                Some(n) => self.start_aggregate(true, n),
            },
            b'_' if rest.is_empty() => self.complete(Value::Null),
            b'#' => match rest {
                b"t" => self.complete(Value::Bool(true)),
                b"f" => self.complete(Value::Bool(false)),
                _ => Err(DecodeError::Protocol),
            },
            b',' | b'(' if !rest.is_empty() => self.complete(Value::Number),
            b'>' | b'|' => Err(DecodeError::Push),
            _ => Err(DecodeError::Protocol),
        }
    }

    /// A value is complete: into its aggregate, or the reply is done.
    fn complete(&mut self, value: Value) -> Result<Option<Value>, DecodeError> {
        let mut value = value;
        loop {
            if self.stack.is_empty() {
                return Ok(Some(value));
            }
            // Every element counts against the reply cap, strings or not, so
            // nested aggregates of nulls cannot amplify the wire budget
            // (security review M1; a map pair counts twice).
            self.account(ELEMENT_BYTES)?;
            let Some(top) = self.stack.last_mut() else {
                return Ok(Some(value));
            };
            top.items.push(value);
            if top.items.len() < top.expected {
                return Ok(None);
            }
            let Some(frame) = self.stack.pop() else {
                return Err(DecodeError::Protocol);
            };
            value = if frame.map {
                let mut pairs = Vec::new();
                let mut it = frame.items.into_iter();
                while let (Some(k), Some(v)) = (it.next(), it.next()) {
                    pairs.push((k, v));
                }
                Value::Map(pairs)
            } else {
                Value::Array(frame.items)
            };
        }
    }
}

/// Encodes a request: an array of bulk strings. Crate-private, reached only
/// through [`crate::cmd::Cmd`], the closed command set.
pub(crate) fn encode(args: &[&[u8]], out: &mut impl Out) {
    out.put(b"*");
    out.put(args.len().to_string().as_bytes());
    out.put(b"\r\n");
    for a in args {
        out.put(b"$");
        out.put(a.len().to_string().as_bytes());
        out.put(b"\r\n");
        out.put(a);
        out.put(b"\r\n");
    }
}

/// Where a request is encoded: a buffer, or a byte count (so a request
/// buffer is sized once and never reallocated, leaving no copy of an
/// `AUTH` password behind; security review L2).
pub(crate) trait Out {
    fn put(&mut self, bytes: &[u8]);
}

impl Out for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// Counts the bytes of an encoding.
#[derive(Default)]
pub(crate) struct Count(pub(crate) usize);

impl Out for Count {
    fn put(&mut self, bytes: &[u8]) {
        self.0 = self.0.saturating_add(bytes.len());
    }
}

/// Decodes one whole reply from a buffer (tests, fuzzing).
#[cfg(test)]
pub(crate) fn decode_all(input: &[u8], limits: Limits) -> Result<Option<Value>, DecodeError> {
    let mut d = Decoder::new(limits);
    d.feed(input).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: Limits = Limits {
        bulk: 16,
        items: 8,
        skip_oversized: false,
        reply: 1024,
    };

    fn dec(input: &[u8], l: Limits) -> Result<Option<Value>, DecodeError> {
        decode_all(input, l)
    }

    fn s(b: &[u8]) -> Value {
        Value::Str(Bytes(b.to_vec()))
    }

    #[test]
    fn scalars() {
        assert_eq!(dec(b"+OK\r\n", L), Ok(Some(s(b"OK"))));
        assert_eq!(dec(b":-42\r\n", L), Ok(Some(Value::Int(-42))));
        assert_eq!(dec(b"_\r\n", L), Ok(Some(Value::Null)));
        assert_eq!(dec(b"$-1\r\n", L), Ok(Some(Value::Null)));
        assert_eq!(dec(b"#t\r\n", L), Ok(Some(Value::Bool(true))));
        assert_eq!(dec(b",3.14\r\n", L), Ok(Some(Value::Number)));
        assert_eq!(
            dec(b"(12345678901234567890\r\n", L),
            Ok(Some(Value::Number))
        );
        assert_eq!(dec(b"$5\r\nhello\r\n", L), Ok(Some(s(b"hello"))));
        assert_eq!(dec(b"$0\r\n\r\n", L), Ok(Some(s(b""))));
        assert_eq!(dec(b"=8\r\ntxt:abcd\r\n", L), Ok(Some(s(b"abcd"))));
    }

    #[test]
    fn errors_keep_their_first_word_only() {
        assert_eq!(
            dec(
                b"-NOPERM User x has no permissions to access the 'secret' key\r\n",
                L
            ),
            Ok(Some(Value::Error(ErrorWord::Noperm)))
        );
        assert_eq!(
            dec(b"-WEIRD something\r\n", L),
            Ok(Some(Value::Error(ErrorWord::Err)))
        );
        assert_eq!(
            dec(b"!21\r\nSYNTAX invalid syntax\r\n", L),
            Ok(Some(Value::Error(ErrorWord::Err)))
        );
        assert_eq!(ErrorWord::Moved.as_str(), "MOVED");
        // A blob error over a line is refused.
        let long = format!("!600\r\n{}\r\n", "E".repeat(600));
        assert_eq!(dec(long.as_bytes(), L), Err(DecodeError::Limit));
    }

    #[test]
    fn aggregates() {
        assert_eq!(
            dec(b"*2\r\n$1\r\na\r\n:1\r\n", L),
            Ok(Some(Value::Array(vec![s(b"a"), Value::Int(1)])))
        );
        assert_eq!(
            dec(b"%1\r\n+k\r\n~1\r\n+v\r\n", L),
            Ok(Some(Value::Map(vec![(
                s(b"k"),
                Value::Array(vec![s(b"v")])
            )])))
        );
        assert_eq!(dec(b"*0\r\n", L), Ok(Some(Value::Array(vec![]))));
        assert_eq!(dec(b"*-1\r\n", L), Ok(Some(Value::Null)));
    }

    #[test]
    fn refusals() {
        for bad in [&b">2\r\n+a\r\n+b\r\n"[..], b"|1\r\n+a\r\n+b\r\n"] {
            assert_eq!(dec(bad, L), Err(DecodeError::Push));
        }
        for bad in [
            &b"$?\r\n;3\r\nabc\r\n;0\r\n"[..],
            b"*?\r\n",
            b";3\r\nabc\r\n",
            b"$-2\r\n",
            b"*-5\r\n",
            b"~-1\r\n",
            b"%-1\r\n",
            b"+OK\n",
            b"$3\r\nabcX\n",
            b"?x\r\n",
            b"#x\r\n",
            b":12a\r\n",
            b"_x\r\n",
            b"=2\r\nab\r\n",
        ] {
            assert_eq!(dec(bad, L), Err(DecodeError::Protocol), "{bad:?}");
        }
        // Over the bulk, item and reply caps; too deep.
        assert_eq!(dec(b"$17\r\n", L), Err(DecodeError::Limit));
        assert_eq!(dec(b"*9\r\n", L), Err(DecodeError::Limit));
        assert_eq!(dec(b"%5\r\n", L), Err(DecodeError::Limit));
        assert_eq!(dec(b"%9999999999999999999\r\n", L), Err(DecodeError::Limit));
        assert_eq!(
            dec(b"*1\r\n*1\r\n*1\r\n*1\r\n*1\r\n:1\r\n", L),
            Err(DecodeError::Limit)
        );
        let small = Limits { reply: 8, ..L };
        assert_eq!(
            dec(b"*2\r\n$5\r\nhello\r\n$5\r\n", small),
            Err(DecodeError::Limit)
        );
        let line = format!("+{}\r\n", "a".repeat(MAX_LINE + 1));
        assert_eq!(dec(line.as_bytes(), L), Err(DecodeError::Limit));
    }

    #[test]
    fn oversized_strings_are_skipped_without_buffering_when_allowed() {
        let skip = Limits {
            skip_oversized: true,
            ..L
        };
        let input = format!("*2\r\n$32\r\n{}\r\n$1\r\nk\r\n", "x".repeat(32));
        assert_eq!(
            dec(input.as_bytes(), skip),
            Ok(Some(Value::Array(vec![Value::Skipped, s(b"k")])))
        );
        let mut d = Decoder::new(skip);
        let (used, v) = d.feed(b"$100000\r\n").unwrap();
        assert_eq!((used, v), (9, None));
        assert!(matches!(d.state, State::Bulk { buf: None, .. }));
    }

    /// Security review M1: 64 MiB of nested nulls once decoded into
    /// hundreds of MiB; every element now counts against the reply cap.
    #[test]
    fn elements_count_against_the_reply_cap() {
        let limits = Limits {
            bulk: 16,
            items: 1000,
            skip_oversized: false,
            reply: 64 * 1024,
        };
        let mut d = Decoder::new(limits);
        let mut wire = Vec::new();
        for _ in 0..3 {
            wire.extend_from_slice(b"*1000\r\n");
        }
        for _ in 0..1_000_000 {
            wire.extend_from_slice(b"_\r\n");
        }
        let mut fed = 0;
        let err = loop {
            let chunk = wire.get(fed..(fed + 4096).min(wire.len())).unwrap();
            match d.feed(chunk) {
                Ok((used, None)) => fed += used,
                Ok((_, Some(_))) => panic!("decoded"),
                Err(e) => break e,
            }
        };
        assert_eq!(err, DecodeError::Limit);
        // At most the cap's worth of elements was decoded.
        let most = limits.reply / ELEMENT_BYTES;
        assert!(fed <= (most + 1) * 3 + 64, "{fed}");
        assert!(d.buffered <= limits.reply + ELEMENT_BYTES);
        // The HELLO probe's limits: a hostile unauthenticated reply stops
        // within its 64 KiB.
        let hello = crate::cmd::Cmd::HelloProbe.limits();
        let mut d = Decoder::new(hello);
        fn tree(depth: usize, out: &mut Vec<u8>) {
            if depth == 0 {
                out.extend_from_slice(b"_\r\n");
                return;
            }
            out.extend_from_slice(b"*64\r\n");
            for _ in 0..64 {
                tree(depth - 1, out);
            }
        }
        // A map of two pairs whose values are full trees three levels deep
        // (the depth cap): 2 x 64^3 nulls in 1.5 MiB of wire.
        let mut wire = b"%2\r\n".to_vec();
        for _ in 0..2 {
            tree(0, &mut wire);
            tree(3, &mut wire);
        }
        assert_eq!(d.feed(&wire).unwrap_err(), DecodeError::Limit);
        assert!(d.buffered <= hello.reply + ELEMENT_BYTES);
    }

    #[test]
    fn replies_follow_each_other() {
        let mut d = Decoder::new(L);
        let input = b"+OK\r\n:2\r\n";
        let (used, v) = d.feed(input).unwrap();
        assert_eq!((used, v), (5, Some(s(b"OK"))));
        let (used2, v) = d.feed(&input[used..]).unwrap();
        assert_eq!((used2, v), (4, Some(Value::Int(2))));
    }

    #[test]
    fn encoder() {
        let mut out = Vec::new();
        encode(&[b"GETRANGE", b"k", b"0", b"4095"], &mut out);
        assert_eq!(
            out,
            b"*4\r\n$8\r\nGETRANGE\r\n$1\r\nk\r\n$1\r\n0\r\n$4\r\n4095\r\n"
        );
    }
}
