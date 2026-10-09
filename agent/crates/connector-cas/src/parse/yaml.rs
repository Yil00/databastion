//! Pre-scanner of CAS YAML service definitions (ADR-0041 decision 4,
//! security review L8): runs on the raw bytes **before any YAML parsing**
//! and refuses every file outside a small, safe subset of YAML. Only an
//! accepted file reaches the YAML parser, as a copy where the CAS class
//! hints (`!<org.apereo.cas.…>` tags) are blanked out, so the parser never
//! sees an anchor, an alias, a merge key, a tag or a second document.
//!
//! CAS 8.0.2 (`RegisteredServiceYamlSerializer`, Jackson's `YAMLFactory`)
//! loads a file only when its trimmed content starts with `--- !<` and reads
//! one value from it: the class of the definition is the root node's
//! verbatim tag, as in
//!
//! ```yaml
//! --- !<org.apereo.cas.services.CasRegisteredService>
//! serviceId: "^https://app.example.org/.*"
//! name: "App"
//! attributeReleasePolicy: !<org.apereo.cas.services.ReturnAllAttributeReleasePolicy> {}
//! ```
//!
//! The scanner follows libyaml's tokenizer (the parser behind
//! `serde_yaml_ng`) closely enough to know, for every byte, whether it is
//! in a comment, a quoted scalar, a block scalar's content, a plain scalar,
//! or where a token starts; wherever its model could differ from libyaml's
//! it refuses. A file is refused ([`Refusal`]) when:
//!
//! - it does not start with `--- !<class>` ([`Refusal::NotCas`]: CAS would
//!   not load it either); CAS trims the content first, so blank lines
//!   (spaces only) may come before `---`, which must be at column 0;
//! - it is not UTF-8, or holds a control character, a byte order mark, a
//!   lone carriage return or a Unicode line break (`U+0085`, `U+2028`,
//!   `U+2029`, which libyaml counts as line breaks)
//!   ([`Refusal::Encoding`]);
//! - an anchor (`&name`) or an alias (`*name`) starts a token
//!   ([`Refusal::Anchor`], [`Refusal::Alias`]); `&` and `*` inside quoted
//!   or plain scalars, comments and block scalars are text;
//! - a tag starts a token, other than a verbatim Java class name
//!   (`!<[A-Za-z_$][A-Za-z0-9_$.]*>`, at most 256 bytes) right after `:`, a
//!   block sequence `-` or a flow sequence `[` / `,`, and never on a key
//!   ([`Refusal::Tag`]): `!foo`, `!!str`, `!!python/…`, `!<tag:…>` are
//!   refused;
//! - a scalar starts with `<<` (the merge key, quoted or not)
//!   ([`Refusal::MergeKey`]); a key spelled with an escape (`"\x3c<"`)
//!   passes, harmlessly: `serde_yaml_ng` applies merge keys only in
//!   `Value::apply_merge`, which the agent never calls, so `<<` is an
//!   ordinary key to the visitor whatever its spelling;
//! - a directive (`%YAML`, `%TAG`), a second `---` or a `...` appears
//!   ([`Refusal::Directive`], [`Refusal::Documents`]);
//! - an explicit key (`?`), an empty key, or a flow collection or a
//!   multi-line scalar used as a key appears ([`Refusal::ComplexKey`]);
//! - a reserved indicator (`@`, `` ` ``) starts a token, a tab is found
//!   outside quoted scalars, comments and block scalar content
//!   ([`Refusal::Syntax`]);
//! - flow collections nest deeper than [`MAX_FLOW_DEPTH`], block and flow
//!   collections deeper than [`MAX_NESTING`], the file has more than
//!   [`MAX_LINES`] lines, or more than [`MAX_TOKENS`] scalars, flow
//!   collection starts, block entries and values ([`Refusal::Bounds`]):
//!   `serde_yaml_ng` loads every event of the document before the
//!   visitor's node bounds apply, so the token count is what bounds its
//!   memory;
//! - anything else the scanner does not follow (an unterminated quote or
//!   flow collection, an indentation indicator on a block scalar, `:`
//!   followed by a flow indicator or a non-blank inside a flow collection)
//!   ([`Refusal::Syntax`]).
//!
//! The scanner never panics (`get`, no indexing) and runs in linear time.
//!
//! **Credential values are blanked before parsing** (review of #169, L2):
//! `serde_yaml_ng` copies every scalar into plain `String`s (libyaml's
//! buffers, then the event's value), which are freed without being wiped.
//! The copy handed to the parser therefore also has, replaced by spaces
//! (byte positions unchanged), the content of every single-line scalar
//! (plain, single-quoted or double-quoted) that starts on the line of a
//! key's `:` right after it, when the key names a credential
//! ([`super::definition::is_credential_key`], the visitor's rule): a
//! blanked plain scalar reads as `null`, a blanked quoted one as spaces,
//! and the visitor skips the value of such a key either way. The
//! [`SecretForm`] of the top-level `clientSecret` (a key at column 0 in
//! the block context, or in a root flow mapping) is computed here first, from the value before
//! blanking, and given back in [`Prescanned::client_secret`]. Out of
//! scope (left to a future parser change, ROADMAP phase 8 follow-ups):
//! values on the next line, multi-line and block scalars, values after a
//! tag, nested credential subtrees (`password:` followed by a mapping or
//! a sequence), keys written with a double-quoted escape, and a top-level
//! `clientSecret` whose double-quoted value holds an escape. This fails
//! safe: whatever the scanner does not blank is still skipped by the
//! visitor, as before (only the unwiped copies remain).

use zeroize::Zeroizing;

use super::definition::{SecretForm, is_credential_key};

/// Most lines per file.
pub const MAX_LINES: usize = 32_768;
/// Deepest nesting of flow collections (`[…]`, `{…}`).
pub const MAX_FLOW_DEPTH: usize = 4;
/// Deepest nesting of block and flow collections together, as counted by
/// the scanner. A lower bound only: an indentless sequence (`key:` then
/// `- a` at the key's column) adds a level without an indentation and is
/// not counted. The backstops are the visitor's own depth bound
/// (`definition::MAX_DEPTH`, 32) and `serde_yaml_ng`'s recursion limit
/// (128).
pub const MAX_NESTING: usize = 32;
/// Most tokens per file: scalars (keys included), flow collection
/// starts, block sequence entries and value indicators. Each node the
/// visitor counts (at most `definition::MAX_NODES`) costs the scanner at
/// most three tokens (a key, its `:` or a `-`, the node), so no document
/// within the visitor's bounds is refused for it.
pub const MAX_TOKENS: usize = 3 * super::definition::MAX_NODES;
/// Longest class name in a tag, in bytes.
pub const MAX_CLASS_BYTES: usize = 256;

/// Why a YAML file is refused before parsing (kinds only, never content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Does not start with `--- !<class>` (not a CAS YAML definition).
    NotCas,
    /// Not UTF-8, a control character, a BOM, a lone CR or a Unicode
    /// line break.
    Encoding,
    /// An anchor (`&name`).
    Anchor,
    /// An alias (`*name`).
    Alias,
    /// A tag other than a CAS class hint in a value position.
    Tag,
    /// A merge key (`<<`).
    MergeKey,
    /// A directive (`%YAML`, `%TAG`).
    Directive,
    /// More than one document, or a document end marker.
    Documents,
    /// An explicit (`?`), empty, multi-line or collection key.
    ComplexKey,
    /// Beyond [`MAX_LINES`], [`MAX_FLOW_DEPTH`] or [`MAX_NESTING`].
    Bounds,
    /// Anything else the scanner does not follow.
    Syntax,
}

/// An accepted file.
pub struct Prescanned {
    /// The root node's class (the CAS class hint).
    pub class: String,
    /// The file with every tag and every blanked credential value
    /// replaced by spaces (positions unchanged).
    pub text: Zeroizing<Vec<u8>>,
    /// The form of the top-level `clientSecret` value, when the scanner
    /// blanked it (`None`: not present, or left to the visitor).
    pub client_secret: Option<SecretForm>,
}

impl std::fmt::Debug for Prescanned {
    // The text is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prescanned")
            .field("class", &self.class)
            .finish_non_exhaustive()
    }
}

/// Pre-scans one YAML service definition file (see the module
/// documentation).
///
/// # Errors
/// [`Refusal`]; nothing of a refused file is returned.
pub fn prescan(bytes: &[u8]) -> Result<Prescanned, Refusal> {
    check_encoding(bytes)?;
    let mut s = Scanner::new(bytes);
    let class = s.header()?;
    s.run()?;
    let mut text = Zeroizing::new(bytes.to_vec());
    for &(start, end) in s.tags.iter().chain(&s.blanks) {
        if let Some(span) = text.get_mut(start..end) {
            span.fill(b' ');
        }
    }
    Ok(Prescanned {
        class,
        text,
        client_secret: s.client_secret,
    })
}

/// UTF-8, no control character but tab and line feed (CR only before LF),
/// no BOM, no Unicode line break nor non-character, at most [`MAX_LINES`].
fn check_encoding(bytes: &[u8]) -> Result<(), Refusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| Refusal::Encoding)?;
    let mut lines = 1usize;
    let mut prev_cr = false;
    for c in text.chars() {
        if prev_cr && c != '\n' {
            return Err(Refusal::Encoding);
        }
        prev_cr = c == '\r';
        match c {
            '\n' => {
                lines += 1;
                if lines > MAX_LINES {
                    return Err(Refusal::Bounds);
                }
            }
            '\t' | '\r' => {}
            '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{feff}'
            | '\u{fffe}'
            | '\u{ffff}' => return Err(Refusal::Encoding),
            _ => {}
        }
    }
    if prev_cr {
        return Err(Refusal::Encoding);
    }
    Ok(())
}

/// What the last token was (to place tags).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Last {
    Start,
    Value,
    BlockEntry,
    FlowOpen,
    FlowEntry,
    FlowClose,
    Tag,
    Scalar,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    Seq,
    Map,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CandKind {
    Scalar,
    Tagged,
    Collection,
}

/// A possible simple key (libyaml's `simple_key`).
#[derive(Clone, Copy)]
struct Candidate {
    line: usize,
    col: usize,
    /// Byte position of its first byte.
    pos: usize,
    kind: CandKind,
}

/// The extent of the last scalar read (to name keys and blank values).
#[derive(Clone, Copy)]
struct ScalarSpan {
    /// Its first byte (the opening quote of a quoted scalar).
    start: usize,
    /// After its last byte (the closing quote; for a plain scalar, its
    /// last non-blank byte).
    end: usize,
    /// The line it starts on.
    line: usize,
    /// `'`, `"`, or `None` for a plain scalar.
    quote: Option<u8>,
    single_line: bool,
}

/// A credential key whose `:` was just read.
#[derive(Clone, Copy)]
struct CredentialKey {
    /// The line of its `:`.
    line: usize,
    /// It is the top-level `clientSecret`.
    client_secret: bool,
}

struct Scanner<'a> {
    b: &'a [u8],
    pos: usize,
    line: usize,
    /// Column in characters (libyaml counts characters).
    col: usize,
    /// libyaml's block indentation stack (`-1` at the bottom).
    indents: Vec<isize>,
    flow: Vec<Flow>,
    simple_key_allowed: bool,
    /// One possible simple key per flow level (libyaml's `simple_keys`):
    /// the bottom one for the block context.
    candidates: Vec<Option<Candidate>>,
    last: Last,
    /// Byte spans of the tags to blank.
    tags: Vec<(usize, usize)>,
    /// Tokens seen (see [`MAX_TOKENS`]).
    tokens: usize,
    /// The last scalar read.
    last_scalar: Option<ScalarSpan>,
    /// Set by a credential key's `:`, taken by the next token.
    credential_key: Option<CredentialKey>,
    /// Byte spans of the credential values to blank.
    blanks: Vec<(usize, usize)>,
    /// The form of the blanked top-level `clientSecret`.
    client_secret: Option<SecretForm>,
}

fn is_break(c: Option<u8>) -> bool {
    matches!(c, Some(b'\n' | b'\r'))
}

fn is_blank(c: Option<u8>) -> bool {
    matches!(c, Some(b' ' | b'\t'))
}

fn is_blankz(c: Option<u8>) -> bool {
    c.is_none() || is_blank(c) || is_break(c)
}

fn is_flow_indicator(c: Option<u8>) -> bool {
    matches!(c, Some(b',' | b'[' | b']' | b'{' | b'}'))
}

fn is_class_start(c: u8) -> bool {
    c.is_ascii_alphabetic() || c == b'_' || c == b'$'
}

fn is_class_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$' || c == b'.'
}

impl<'a> Scanner<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self {
            b,
            pos: 0,
            line: 0,
            col: 0,
            indents: vec![-1],
            flow: Vec::new(),
            simple_key_allowed: false,
            candidates: vec![None],
            last: Last::Start,
            tags: Vec::new(),
            tokens: 0,
            last_scalar: None,
            credential_key: None,
            blanks: Vec::new(),
            client_secret: None,
        }
    }

    /// Counts one token against [`MAX_TOKENS`].
    fn token(&mut self) -> Result<(), Refusal> {
        self.tokens += 1;
        if self.tokens > MAX_TOKENS {
            return Err(Refusal::Bounds);
        }
        Ok(())
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn at(&self, n: usize) -> Option<u8> {
        self.b.get(self.pos.saturating_add(n)).copied()
    }

    fn starts_with(&self, p: &[u8]) -> bool {
        self.b.get(self.pos..).is_some_and(|r| r.starts_with(p))
    }

    /// Advances one byte (not a line break): columns count characters.
    fn advance(&mut self) {
        if let Some(c) = self.peek() {
            if c & 0xC0 != 0x80 {
                self.col += 1;
            }
            self.pos += 1;
        }
    }

    /// Consumes a line break (LF or CRLF; a lone CR was refused).
    fn eat_break(&mut self) {
        if self.peek() == Some(b'\r') {
            self.pos += 1;
        }
        if self.peek() == Some(b'\n') {
            self.pos += 1;
        }
        self.line += 1;
        self.col = 0;
    }

    fn top(&self) -> isize {
        self.indents.last().copied().unwrap_or(-1)
    }

    fn nesting(&self) -> usize {
        self.indents.len().saturating_sub(1) + self.flow.len()
    }

    fn col_i(&self) -> isize {
        isize::try_from(self.col).unwrap_or(isize::MAX)
    }

    /// libyaml's `roll_indent` (block context only).
    fn roll(&mut self, col: usize) -> Result<(), Refusal> {
        let col = isize::try_from(col).map_err(|_| Refusal::Bounds)?;
        if self.flow.is_empty() && self.top() < col {
            self.indents.push(col);
            if self.nesting() > MAX_NESTING {
                return Err(Refusal::Bounds);
            }
        }
        Ok(())
    }

    /// libyaml's `save_simple_key` (replaces the level's candidate).
    fn save_candidate(&mut self, kind: CandKind) {
        if self.simple_key_allowed {
            let k = Candidate {
                line: self.line,
                col: self.col,
                pos: self.pos,
                kind,
            };
            if let Some(slot) = self.candidates.last_mut() {
                *slot = Some(k);
            }
        }
    }

    /// libyaml's `remove_simple_key` (the current level's candidate).
    fn take_candidate(&mut self) -> Option<Candidate> {
        self.candidates.last_mut().and_then(Option::take)
    }

    /// `--- !<class>`, followed by a blank or a line end. CAS trims the
    /// content before checking its start: blank lines (spaces only) may
    /// come first, so that `---` is still at column 0; a tab, a comment or
    /// spaces before `---` on its own line are refused.
    fn header(&mut self) -> Result<String, Refusal> {
        loop {
            let line_start = self.pos;
            while self.peek() == Some(b' ') {
                self.advance();
            }
            if is_break(self.peek()) {
                self.eat_break();
                continue;
            }
            if self.pos != line_start {
                return Err(Refusal::NotCas);
            }
            break;
        }
        if !self.starts_with(b"--- !<") {
            return Err(Refusal::NotCas);
        }
        for _ in 0..4 {
            self.advance();
        }
        let start = self.pos;
        let class = self.verbatim_tag().ok_or(Refusal::NotCas)?;
        self.tags.push((start, self.pos));
        self.last = Last::Tag;
        self.simple_key_allowed = false;
        Ok(class)
    }

    /// Reads `!<class>` at the cursor; `None` when it is not one, or is not
    /// followed by a blank or a line end.
    fn verbatim_tag(&mut self) -> Option<String> {
        if !self.starts_with(b"!<") {
            return None;
        }
        let rest = self.b.get(self.pos + 2..)?;
        let len = rest.iter().position(|c| *c == b'>')?;
        let name = rest.get(..len)?;
        let ok = !name.is_empty()
            && name.len() <= MAX_CLASS_BYTES
            && name.first().is_some_and(|c| is_class_start(*c))
            && name.iter().all(|c| is_class_byte(*c));
        if !ok || !is_blankz(rest.get(len + 1).copied()) {
            return None;
        }
        let class = String::from_utf8(name.to_vec()).ok()?;
        for _ in 0..len + 3 {
            self.advance();
        }
        Some(class)
    }

    /// libyaml's `scan_to_next_token`: spaces, comments and line breaks.
    fn skip_to_token(&mut self) -> Result<(), Refusal> {
        loop {
            while self.peek() == Some(b' ') {
                self.advance();
            }
            if self.peek() == Some(b'\t') {
                return Err(Refusal::Syntax);
            }
            if self.peek() == Some(b'#') {
                while !is_break(self.peek()) && self.peek().is_some() {
                    self.advance();
                }
            }
            if is_break(self.peek()) {
                self.eat_break();
                if self.flow.is_empty() {
                    self.simple_key_allowed = true;
                }
                continue;
            }
            return Ok(());
        }
    }

    fn run(&mut self) -> Result<(), Refusal> {
        loop {
            self.skip_to_token()?;
            // A possible simple key does not survive a line change.
            let line = self.line;
            for slot in &mut self.candidates {
                if slot.is_some_and(|k| k.line != line) {
                    *slot = None;
                }
            }
            let Some(c) = self.peek() else {
                break;
            };
            if self.flow.is_empty() {
                let col = self.col_i();
                while self.top() > col {
                    self.indents.pop();
                }
            }
            if self.col == 0 && c == b'%' {
                return Err(Refusal::Directive);
            }
            if self.col == 0
                && (self.starts_with(b"---") || self.starts_with(b"..."))
                && is_blankz(self.at(3))
            {
                return Err(Refusal::Documents);
            }
            // Only the token right after a credential key's `:` may be
            // its value.
            let credential_key = self.credential_key.take();
            // Closers, separators and tags (blanked) make no event.
            if !matches!(c, b']' | b'}' | b',' | b'!') {
                self.token()?;
            }
            match c {
                b'[' | b'{' => {
                    self.save_candidate(CandKind::Collection);
                    if self.flow.len() >= MAX_FLOW_DEPTH {
                        return Err(Refusal::Bounds);
                    }
                    self.flow
                        .push(if c == b'[' { Flow::Seq } else { Flow::Map });
                    self.candidates.push(None);
                    if self.nesting() > MAX_NESTING {
                        return Err(Refusal::Bounds);
                    }
                    self.simple_key_allowed = true;
                    self.last = Last::FlowOpen;
                    self.advance();
                }
                b']' | b'}' => {
                    let want = if c == b']' { Flow::Seq } else { Flow::Map };
                    if self.flow.pop() != Some(want) {
                        return Err(Refusal::Syntax);
                    }
                    self.candidates.pop();
                    // The collection itself stays a possible key (refused
                    // as one by `value`).
                    self.simple_key_allowed = false;
                    self.last = Last::FlowClose;
                    self.advance();
                }
                b',' => {
                    if self.flow.is_empty() {
                        return Err(Refusal::Syntax);
                    }
                    let _ = self.take_candidate();
                    self.simple_key_allowed = true;
                    self.last = Last::FlowEntry;
                    self.advance();
                }
                b'-' if is_blankz(self.at(1)) => {
                    if !self.flow.is_empty() || !self.simple_key_allowed {
                        return Err(Refusal::Syntax);
                    }
                    self.roll(self.col)?;
                    let _ = self.take_candidate();
                    self.simple_key_allowed = true;
                    self.last = Last::BlockEntry;
                    self.advance();
                }
                b'?' => return Err(Refusal::ComplexKey),
                b':' if !self.flow.is_empty() || is_blankz(self.at(1)) => self.value()?,
                // `:x` in the block context is a plain scalar for libyaml;
                // not worth following.
                b':' => return Err(Refusal::Syntax),
                b'&' => return Err(Refusal::Anchor),
                b'*' => return Err(Refusal::Alias),
                b'!' => self.tag()?,
                b'|' | b'>' => {
                    if !self.flow.is_empty() {
                        return Err(Refusal::Syntax);
                    }
                    self.block_scalar()?;
                }
                b'\'' | b'"' => {
                    self.quoted(c)?;
                    self.blank_value(credential_key);
                }
                b'%' | b'@' | b'`' | b'\t' => return Err(Refusal::Syntax),
                _ => {
                    self.plain()?;
                    self.blank_value(credential_key);
                }
            }
        }
        if !self.flow.is_empty() {
            return Err(Refusal::Syntax);
        }
        Ok(())
    }

    /// `:`: the value indicator of a simple key.
    fn value(&mut self) -> Result<(), Refusal> {
        match self.take_candidate() {
            Some(k) if k.kind == CandKind::Scalar => {
                self.credential_key = self.credential_key_of(k);
                self.roll(k.col)?;
                // libyaml: no simple key right after a key's `:`.
                self.simple_key_allowed = false;
            }
            Some(k) if k.kind == CandKind::Tagged => return Err(Refusal::Tag),
            _ => return Err(Refusal::ComplexKey),
        }
        self.last = Last::Value;
        self.advance();
        Ok(())
    }

    /// A tag: only a verbatim class name, in a value position.
    fn tag(&mut self) -> Result<(), Refusal> {
        let in_seq = self.flow.last() == Some(&Flow::Seq);
        let placed = match self.last {
            Last::Value | Last::BlockEntry => true,
            Last::FlowOpen | Last::FlowEntry => in_seq,
            _ => false,
        };
        if !placed {
            return Err(Refusal::Tag);
        }
        self.save_candidate(CandKind::Tagged);
        let start = self.pos;
        self.verbatim_tag().ok_or(Refusal::Tag)?;
        self.tags.push((start, self.pos));
        self.simple_key_allowed = false;
        self.last = Last::Tag;
        Ok(())
    }

    /// A single- or double-quoted scalar, to its closing quote.
    fn quoted(&mut self, q: u8) -> Result<(), Refusal> {
        self.save_candidate(CandKind::Scalar);
        let line = self.line;
        let start = self.pos;
        self.advance();
        if self.starts_with(b"<<") {
            return Err(Refusal::MergeKey);
        }
        loop {
            match self.peek() {
                None => return Err(Refusal::Syntax),
                Some(b'\'') if q == b'\'' => {
                    if self.at(1) == Some(b'\'') {
                        self.advance();
                        self.advance();
                    } else {
                        self.advance();
                        break;
                    }
                }
                Some(b'"') if q == b'"' => {
                    self.advance();
                    break;
                }
                Some(b'\\') if q == b'"' => {
                    self.advance();
                    if is_break(self.peek()) {
                        self.eat_break();
                    } else {
                        self.advance();
                    }
                }
                Some(b'\n' | b'\r') => self.eat_break(),
                Some(_) => self.advance(),
            }
        }
        // A multi-line scalar cannot be a key.
        if self.line != line {
            let _ = self.take_candidate();
        }
        self.last_scalar = Some(ScalarSpan {
            start,
            end: self.pos,
            line,
            quote: Some(q),
            single_line: self.line == line,
        });
        self.simple_key_allowed = false;
        self.last = Last::Scalar;
        Ok(())
    }

    /// A plain scalar, as libyaml's `scan_plain_scalar` delimits it.
    fn plain(&mut self) -> Result<(), Refusal> {
        self.save_candidate(CandKind::Scalar);
        if self.starts_with(b"<<") {
            return Err(Refusal::MergeKey);
        }
        let indent = self.top() + 1;
        let mut crossed = false;
        let (start, line) = (self.pos, self.line);
        let (mut end, mut end_line) = (self.pos, self.line);
        loop {
            if self.col == 0
                && (self.starts_with(b"---") || self.starts_with(b"..."))
                && is_blankz(self.at(3))
            {
                break;
            }
            if self.peek() == Some(b'#') {
                break;
            }
            while !is_blankz(self.peek()) {
                let c = self.peek();
                if !self.flow.is_empty() && c == Some(b':') {
                    if is_blankz(self.at(1)) {
                        break;
                    }
                    // `x:y` in a flow collection: libyaml versions differ.
                    return Err(Refusal::Syntax);
                }
                if c == Some(b':') && is_blankz(self.at(1)) {
                    break;
                }
                if !self.flow.is_empty() && is_flow_indicator(c) {
                    break;
                }
                self.advance();
                (end, end_line) = (self.pos, self.line);
            }
            if !(is_blank(self.peek()) || is_break(self.peek())) {
                break;
            }
            while is_blank(self.peek()) || is_break(self.peek()) {
                if self.peek() == Some(b'\t') {
                    return Err(Refusal::Syntax);
                }
                if is_break(self.peek()) {
                    self.eat_break();
                    crossed = true;
                } else {
                    self.advance();
                }
            }
            if self.flow.is_empty() && self.col_i() < indent {
                break;
            }
        }
        self.last_scalar = Some(ScalarSpan {
            start,
            end,
            line,
            quote: None,
            single_line: end_line == line,
        });
        if crossed {
            // libyaml allows a simple key after a plain scalar that ended
            // on a line break (the candidate itself went stale).
            self.simple_key_allowed = true;
        } else {
            self.simple_key_allowed = false;
        }
        self.last = Last::Scalar;
        Ok(())
    }

    /// The text of a single-line scalar key, as the visitor will read it;
    /// `None` when it cannot be known without decoding escapes (a
    /// double-quoted key holding `\\`). A single-quoted key is read with
    /// its `''` pairs, which changes no credential word match (no word
    /// holds a quote) nor the comparison with `clientSecret`.
    fn key_text(&self, s: ScalarSpan) -> Option<&'a str> {
        let b = self.b;
        let raw = match s.quote {
            None => b.get(s.start..s.end)?,
            Some(_) => b.get(s.start + 1..s.end.checked_sub(1)?)?,
        };
        if s.quote == Some(b'"') && raw.contains(&b'\\') {
            return None;
        }
        std::str::from_utf8(raw).ok()
    }

    /// The credential key whose `:` is being read, if the candidate `k`
    /// is one (see the module documentation).
    fn credential_key_of(&self, k: Candidate) -> Option<CredentialKey> {
        let span = self
            .last_scalar
            .filter(|s| s.start == k.pos && s.single_line)?;
        let key = self.key_text(span)?;
        if !is_credential_key(key) {
            return None;
        }
        // A key of the root mapping: at column 0 in the block context, or
        // directly in a root flow mapping (no block indentation yet).
        let top = (self.flow.is_empty() && k.col == 0)
            || (self.flow == [Flow::Map] && self.indents.len() == 1);
        Some(CredentialKey {
            line: self.line,
            client_secret: key == "clientSecret" && top,
        })
    }

    /// Blanks the scalar just read if it is the single-line value of a
    /// credential key on the line of its `:`; for the top-level
    /// `clientSecret`, records its [`SecretForm`] first (or leaves it to
    /// the visitor when it cannot be computed here).
    fn blank_value(&mut self, key: Option<CredentialKey>) {
        let (Some(key), Some(s)) = (key, self.last_scalar) else {
            return;
        };
        if !s.single_line || s.line != key.line {
            return;
        }
        let (from, to) = match s.quote {
            None => (s.start, s.end),
            Some(_) => (s.start + 1, s.end.saturating_sub(1)),
        };
        if from >= to {
            return;
        }
        if key.client_secret {
            let Some(form) = self.form_of(s, from, to) else {
                return;
            };
            self.client_secret = Some(form);
        }
        self.blanks.push((from, to));
    }

    /// The [`SecretForm`] of a scalar value whose content is `from..to`,
    /// as the visitor computes it from the parsed value; `None` for a
    /// double-quoted value with an escape.
    fn form_of(&self, s: ScalarSpan, from: usize, to: usize) -> Option<SecretForm> {
        let raw = std::str::from_utf8(self.b.get(from..to)?).ok()?;
        Some(match s.quote {
            // YAML's null spellings; any other plain scalar (a string, a
            // number, a boolean) is what `SecretForm::of` makes of its
            // text (numbers and booleans are clear either way).
            None if matches!(raw, "~" | "null" | "Null" | "NULL") => SecretForm::Absent,
            None => SecretForm::of(raw),
            Some(b'"') if raw.contains('\\') => return None,
            Some(b'"') => SecretForm::of(raw),
            // `''` is one quote; the copy is zeroizing and never grows.
            Some(_) => {
                let mut text = Zeroizing::new(String::with_capacity(raw.len()));
                let mut rest = raw;
                while let Some((head, tail)) = rest.split_once("''") {
                    text.push_str(head);
                    text.push('\'');
                    rest = tail;
                }
                text.push_str(rest);
                SecretForm::of(&text)
            }
        })
    }

    /// A block scalar (`|` or `>`), as libyaml's `scan_block_scalar`
    /// delimits it; an indentation indicator is refused.
    fn block_scalar(&mut self) -> Result<(), Refusal> {
        let _ = self.take_candidate();
        self.advance();
        if matches!(self.peek(), Some(b'+' | b'-')) {
            self.advance();
        }
        if self.peek().is_some_and(|c| c.is_ascii_digit()) {
            return Err(Refusal::Syntax);
        }
        while self.peek() == Some(b' ') {
            self.advance();
        }
        if self.peek() == Some(b'#') {
            while !is_break(self.peek()) && self.peek().is_some() {
                self.advance();
            }
        }
        if self.peek().is_none() {
            self.simple_key_allowed = true;
            self.last = Last::Scalar;
            return Ok(());
        }
        if !is_break(self.peek()) {
            return Err(Refusal::Syntax);
        }
        self.eat_break();
        // Leading breaks and the indentation (libyaml's
        // `scan_block_scalar_breaks` with an unknown indentation).
        let mut max_indent = 0usize;
        loop {
            while self.peek() == Some(b' ') {
                self.advance();
            }
            if self.peek() == Some(b'\t') {
                return Err(Refusal::Syntax);
            }
            max_indent = max_indent.max(self.col);
            if is_break(self.peek()) {
                self.eat_break();
            } else {
                break;
            }
        }
        let floor = usize::try_from(self.top() + 1).unwrap_or(0).max(1);
        let indent = max_indent.max(floor);
        while self.col == indent && self.peek().is_some() {
            while !is_break(self.peek()) && self.peek().is_some() {
                self.advance();
            }
            if self.peek().is_none() {
                break;
            }
            self.eat_break();
            loop {
                while self.col < indent && self.peek() == Some(b' ') {
                    self.advance();
                }
                if self.col < indent && self.peek() == Some(b'\t') {
                    return Err(Refusal::Syntax);
                }
                if is_break(self.peek()) {
                    self.eat_break();
                } else {
                    break;
                }
            }
        }
        self.simple_key_allowed = true;
        self.last = Last::Scalar;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEAD: &str = "--- !<org.apereo.cas.services.CasRegisteredService>\n";

    fn ok(body: &str) -> Prescanned {
        let doc = format!("{HEAD}{body}");
        match prescan(doc.as_bytes()) {
            Ok(p) => p,
            Err(e) => panic!("{e:?} for {body:?}"),
        }
    }

    fn refused(body: &str) -> Refusal {
        let doc = format!("{HEAD}{body}");
        match prescan(doc.as_bytes()) {
            Ok(_) => panic!("accepted {body:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn the_cas_sample_is_accepted_and_its_tags_blanked() {
        let body = "serviceId: \"testId\"\nname: \"YAML\"\nid: 1000\n\
                    description: \"description\"\n\
                    attributeReleasePolicy: !<org.apereo.cas.services.ReturnAllAttributeReleasePolicy> {}\n\
                    accessStrategy: !<org.apereo.cas.services.DefaultRegisteredServiceAccessStrategy>\n  \
                    enabled: true\n  ssoEnabled: true\n";
        let p = ok(body);
        assert_eq!(p.class, "org.apereo.cas.services.CasRegisteredService");
        let text = std::str::from_utf8(&p.text).unwrap();
        assert!(!text.contains('!') && !text.contains('<'), "{text}");
        assert_eq!(p.text.len(), HEAD.len() + body.len());
        assert!(text.starts_with("---    "));
    }

    #[test]
    fn ampersands_and_stars_in_text_are_not_nodes() {
        ok("description: \"a &b *c\"\n");
        ok("description: 'a &b *c ''&d'''\n");
        ok("description: Tom &Jerry *star\n");
        ok("serviceId: ^https://a\\.org/x\\?a=1&b=2*\n");
        ok("# &anchor *alias !!tag <<: x\nname: a # &x *y\n");
        ok("description: |\n  &anchor\n  *alias\n  <<: x\n  !!python/object\nname: a\n");
        ok("description: >-\n  folded &a\n\n  *b\nname: a\n");
        ok("contacts:\n- name: \"&x\"\n  email: a@b.c\n");
        ok("description: multi\n  line &x plain\nname: a\n");
        ok("description: \"multi\n  line &x\"\nname: a\n");
    }

    #[test]
    fn anchors_and_aliases_in_node_position_are_refused() {
        for (body, want) in [
            ("a: &x 1\nb: *x\n", Refusal::Anchor),
            ("a: *x\n", Refusal::Alias),
            ("&x a: 1\n", Refusal::Anchor),
            ("a:\n  - &x 1\n", Refusal::Anchor),
            ("a: [&x 1]\n", Refusal::Anchor),
            ("a: [1, *x]\n", Refusal::Alias),
            ("a: {b: *x}\n", Refusal::Alias),
            ("a: {*x : 1}\n", Refusal::Alias),
            ("a: b\n*x : 1\n", Refusal::Alias),
            ("a: |\n  t\n&x b: 1\n", Refusal::Anchor),
            ("- a: |\n    t\n  b: &x 1\n", Refusal::Anchor),
            ("a: multi\n  line\nb: &x 1\n", Refusal::Anchor),
            ("a: 'x'\nb: &x 1\n", Refusal::Anchor),
        ] {
            assert_eq!(refused(body), want, "{body:?}");
        }
    }

    #[test]
    fn a_block_scalar_ends_where_libyaml_ends_it() {
        // `b` at the key's column ends the scalar of `- a: |` (the
        // content must be deeper than the key, not than the dash).
        assert_eq!(refused("- a: |\n  b: &x 1\n"), Refusal::Anchor);
        // A first content line less indented than a leading blank line
        // ends the scalar at once.
        assert_eq!(refused("a: |\n    \n  &x\n"), Refusal::Anchor);
        assert_eq!(refused("a: |2\n  t\n"), Refusal::Syntax);
        assert_eq!(refused("a: |\n\t t\n"), Refusal::Syntax);
    }

    #[test]
    fn tags_other_than_class_hints_are_refused() {
        for body in [
            "a: !foo 1\n",
            "a: !!str 1\n",
            "a: !!python/object:os.system x\n",
            "a: !<tag:yaml.org,2002:str> x\n",
            "a: !<java.lang.Runtime>x\n",
            "a: !<> x\n",
            "a: !<9bad> x\n",
            "!<java.util.HashMap> a: 1\n",
            "- !<java.util.HashMap> a: 1\n",
            "a: {!<java.util.HashMap> b: 1}\n",
            "a: !<java.util.HashMap> !<java.util.HashMap> {}\n",
            "a: ! x\n",
        ] {
            assert_eq!(refused(body), Refusal::Tag, "{body:?}");
        }
        ok("a: !<java.util.HashMap> {}\n");
        ok(
            "a: !<java.util.ArrayList>\n- !<org.apereo.cas.services.DefaultRegisteredServiceContact>\n  name: \"J\"\n",
        );
        ok("a: [!<java.lang.String> x, !<java.lang.String> y]\n");
    }

    #[test]
    fn merge_keys_directives_and_documents_are_refused() {
        assert_eq!(refused("<<: {a: 1}\n"), Refusal::MergeKey);
        assert_eq!(refused("\"<<\": {a: 1}\n"), Refusal::MergeKey);
        assert_eq!(refused("a:\n  <<: {b: 1}\n"), Refusal::MergeKey);
        assert_eq!(refused("a: {<<: {b: 1}}\n"), Refusal::MergeKey);
        assert_eq!(refused("a: 1\n%TAG ! tag:x\n"), Refusal::Directive);
        assert_eq!(refused("a: 1\n---\nb: 2\n"), Refusal::Documents);
        assert_eq!(
            refused("a: 1\n--- !<org.apereo.cas.services.CasRegisteredService>\n"),
            Refusal::Documents
        );
        assert_eq!(refused("a: 1\n...\n"), Refusal::Documents);
        assert_eq!(refused("a: multi\n---\n"), Refusal::Documents);
        for doc in [
            "%YAML 1.1\n--- !<org.apereo.cas.services.CasRegisteredService>\na: 1\n",
            " --- !<org.apereo.cas.services.CasRegisteredService>\na: 1\n",
            "a: 1\n",
            "---\na: 1\n",
            "--- !foo\na: 1\n",
            "--- !<org.apereo.cas.services.CasRegisteredService>x\n",
            "\u{feff}--- !<org.apereo.cas.services.CasRegisteredService>\n",
        ] {
            assert!(prescan(doc.as_bytes()).is_err(), "{doc:?}");
        }
    }

    #[test]
    fn complex_keys_and_odd_syntax_are_refused() {
        assert_eq!(refused("? a\n: 1\n"), Refusal::ComplexKey);
        assert_eq!(refused(": 1\n"), Refusal::ComplexKey);
        assert_eq!(refused("[a]: 1\n"), Refusal::ComplexKey);
        assert_eq!(refused("\"a\n b\": 1\n"), Refusal::ComplexKey);
        assert_eq!(refused("a: @x\n"), Refusal::Syntax);
        assert_eq!(refused("a: `x\n"), Refusal::Syntax);
        assert_eq!(refused("a:\tx\n"), Refusal::Syntax);
        assert_eq!(refused("a: \"x\n"), Refusal::Syntax);
        assert_eq!(refused("a: [x\n"), Refusal::Syntax);
        assert_eq!(refused("a: [x}\n"), Refusal::Syntax);
        assert_eq!(refused("a: [b:c]\n"), Refusal::Syntax);
        assert_eq!(refused("a: x\nb: :c\n"), Refusal::Syntax);
    }

    #[test]
    fn encodings_and_bounds_are_enforced() {
        for doc in [
            &b"--- !<a.B>\na: \xff\n"[..],
            b"--- !<a.B>\na: \x00\n",
            b"--- !<a.B>\na: 1\rb: 2\n",
            "--- !<a.B>\na: \u{2028}b\n".as_bytes(),
            "--- !<a.B>\na: \u{85}b\n".as_bytes(),
            "--- !<a.B>\na: \"\u{feff}\"\n".as_bytes(),
        ] {
            assert_eq!(prescan(doc).unwrap_err(), Refusal::Encoding, "{doc:?}");
        }
        ok("a: 1\r\nb: 2\r\n");
        let lines = "a: 1\n".repeat(MAX_LINES);
        assert_eq!(refused(&lines), Refusal::Bounds);
        let flow = format!(
            "a: {}{}\n",
            "[".repeat(MAX_FLOW_DEPTH),
            "]".repeat(MAX_FLOW_DEPTH)
        );
        ok(&flow);
        let flow = format!(
            "a: {}{}\n",
            "[".repeat(MAX_FLOW_DEPTH + 1),
            "]".repeat(MAX_FLOW_DEPTH + 1)
        );
        assert_eq!(refused(&flow), Refusal::Bounds);
        let mut deep = String::new();
        for i in 0..MAX_NESTING + 1 {
            deep.push_str(&" ".repeat(i));
            deep.push_str("k:\n");
        }
        deep.push_str(&" ".repeat(MAX_NESTING + 1));
        deep.push_str("v: 1\n");
        assert_eq!(refused(&deep), Refusal::Bounds);
        let seqs = format!("{}x\n", "- ".repeat(MAX_NESTING + 1));
        assert_eq!(refused(&seqs), Refusal::Bounds);
    }

    #[test]
    fn tokens_are_bounded_before_parsing() {
        // About 1 MiB of a flow sequence and of a flow mapping.
        let seq = format!("a: [{}a]\n", "a,".repeat(512 * 1024));
        assert_eq!(refused(&seq), Refusal::Bounds);
        let map = format!("a: {{{}b: c}}\n", "b: c, ".repeat(170 * 1024));
        assert_eq!(refused(&map), Refusal::Bounds);
        // Within the visitor's node bound: accepted.
        let entries: Vec<String> = (0..60_000).map(|i| format!("k{i}: 1")).collect();
        ok(&format!("a: {{{}}}\n", entries.join(", ")));
    }

    #[test]
    fn blank_lines_may_come_before_the_header() {
        let p = prescan(format!("\n  \r\n\n{HEAD}a: 1\n").as_bytes()).unwrap();
        assert_eq!(p.class, "org.apereo.cas.services.CasRegisteredService");
        for doc in [
            format!("\t\n{HEAD}"),
            format!("# c\n{HEAD}"),
            format!("\n  {HEAD}"),
            "\n\n".to_owned(),
        ] {
            assert_eq!(
                prescan(doc.as_bytes()).unwrap_err(),
                Refusal::NotCas,
                "{doc:?}"
            );
        }
    }
}
