//! The event builder (ADR-0046 decision 1): libyaml's parser
//! (`yaml_parser_parse`, as vendored by `unsafe-libyaml` 0.2.11) over the
//! scanner's tokens, for the pre-scanned subset: no directive, anchor,
//! alias nor tag reaches it. It builds the events of the one document,
//! as `serde_yaml_ng`'s loader did, before the visitor runs (so a bound the
//! visitor hits comes before a syntax error further on, as before).
//!
//! Events hold positions in the blanked text only ([`Scalar`]); no scalar
//! is decoded here. Their number is bounded by the scanner's token bound
//! (each counted token makes at most three events).

use super::scan::{Fail, Refusal, Scalar, Scanner, Tok};

/// A node event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Event {
    Scalar(Scalar),
    SequenceStart,
    SequenceEnd,
    MappingStart,
    MappingEnd,
}

/// The document's events, and whether libyaml would have failed after
/// them (a syntax error, or anything but the end of the stream after the
/// root node).
pub(super) struct Events {
    pub(super) events: Vec<Event>,
    pub(super) failed: bool,
}

/// Builds the events of a pre-scanned text.
///
/// # Errors
/// A [`Refusal`] when the scanner refuses the blanked text (fail safe: the
/// pre-scan accepted the raw text, so this should never happen).
pub(super) fn build(text: &[u8]) -> Result<Events, Refusal> {
    let mut p = Parser {
        s: Scanner::parser(text),
        state: State::StreamStart,
        states: Vec::new(),
    };
    let mut events = Vec::new();
    let mut documents = 0usize;
    let failed = loop {
        match p.next() {
            Err(Fail::Refused(r)) => return Err(r),
            Err(Fail::Yaml) => break true,
            Ok(Ev::StreamStart) => {}
            Ok(Ev::DocumentStart) => {
                documents += 1;
                if documents > 1 {
                    break true;
                }
            }
            // `serde_yaml_ng` reads one document, then requires the end of
            // the stream.
            Ok(Ev::DocumentEnd) => match p.next() {
                Ok(Ev::StreamEnd) => break false,
                Err(Fail::Refused(r)) => return Err(r),
                Ok(_) | Err(Fail::Yaml) => break true,
            },
            // No document at all (cannot happen after a pre-scan).
            Ok(Ev::StreamEnd) => break events.is_empty(),
            Ok(Ev::Node(e)) => events.push(e),
        }
    };
    Ok(Events { events, failed })
}

/// libyaml's events (no alias; tags and anchors never reach here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ev {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Node(Event),
}

/// libyaml's parser states (`yaml_parser_state_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    StreamStart,
    ImplicitDocumentStart,
    DocumentStart,
    DocumentContent,
    DocumentEnd,
    BlockNode,
    BlockSequenceFirstEntry,
    BlockSequenceEntry,
    IndentlessSequenceEntry,
    BlockMappingFirstKey,
    BlockMappingKey,
    BlockMappingValue,
    FlowSequenceFirstEntry,
    FlowSequenceEntry,
    FlowSequenceEntryMappingKey,
    FlowSequenceEntryMappingValue,
    FlowSequenceEntryMappingEnd,
    FlowMappingFirstKey,
    FlowMappingKey,
    FlowMappingValue,
    FlowMappingEmptyValue,
    End,
}

struct Parser<'a> {
    s: Scanner<'a>,
    state: State,
    states: Vec<State>,
}

const EMPTY: Ev = Ev::Node(Event::Scalar(Scalar::EMPTY));

impl Parser<'_> {
    fn peek(&mut self) -> Result<Tok, Fail> {
        self.s.peek_token()
    }

    fn skip(&mut self) {
        self.s.skip_token();
    }

    fn pop(&mut self) -> Result<State, Fail> {
        self.states.pop().ok_or(Fail::Yaml)
    }

    /// The next event (libyaml's `yaml_parser_state_machine`).
    fn next(&mut self) -> Result<Ev, Fail> {
        match self.state {
            State::StreamStart => {
                if self.peek()? != Tok::StreamStart {
                    return Err(Fail::Yaml);
                }
                self.state = State::ImplicitDocumentStart;
                self.skip();
                Ok(Ev::StreamStart)
            }
            State::ImplicitDocumentStart => self.document_start(true),
            State::DocumentStart => self.document_start(false),
            State::DocumentContent => match self.peek()? {
                Tok::DocumentStart | Tok::StreamEnd => {
                    self.state = self.pop()?;
                    Ok(EMPTY)
                }
                _ => self.node(true, false),
            },
            State::DocumentEnd => {
                self.peek()?;
                self.state = State::DocumentStart;
                Ok(Ev::DocumentEnd)
            }
            State::BlockNode => self.node(true, false),
            State::BlockSequenceFirstEntry => self.block_sequence_entry(true),
            State::BlockSequenceEntry => self.block_sequence_entry(false),
            State::IndentlessSequenceEntry => self.indentless_sequence_entry(),
            State::BlockMappingFirstKey => self.block_mapping_key(true),
            State::BlockMappingKey => self.block_mapping_key(false),
            State::BlockMappingValue => self.block_mapping_value(),
            State::FlowSequenceFirstEntry => self.flow_sequence_entry(true),
            State::FlowSequenceEntry => self.flow_sequence_entry(false),
            State::FlowSequenceEntryMappingKey => self.flow_sequence_entry_mapping_key(),
            State::FlowSequenceEntryMappingValue => self.flow_sequence_entry_mapping_value(),
            State::FlowSequenceEntryMappingEnd => {
                self.peek()?;
                self.state = State::FlowSequenceEntry;
                Ok(Ev::Node(Event::MappingEnd))
            }
            State::FlowMappingFirstKey => self.flow_mapping_key(true),
            State::FlowMappingKey => self.flow_mapping_key(false),
            State::FlowMappingValue => self.flow_mapping_value(false),
            State::FlowMappingEmptyValue => self.flow_mapping_value(true),
            State::End => Err(Fail::Yaml),
        }
    }

    fn document_start(&mut self, implicit: bool) -> Result<Ev, Fail> {
        let tok = self.peek()?;
        if implicit && !matches!(tok, Tok::DocumentStart | Tok::StreamEnd) {
            self.states.push(State::DocumentEnd);
            self.state = State::BlockNode;
            return Ok(Ev::DocumentStart);
        }
        if tok == Tok::StreamEnd {
            self.state = State::End;
            self.skip();
            return Ok(Ev::StreamEnd);
        }
        if tok != Tok::DocumentStart {
            return Err(Fail::Yaml);
        }
        self.states.push(State::DocumentEnd);
        self.state = State::DocumentContent;
        self.skip();
        Ok(Ev::DocumentStart)
    }

    /// libyaml's `parse_node` without properties.
    fn node(&mut self, block: bool, indentless_sequence: bool) -> Result<Ev, Fail> {
        match self.peek()? {
            Tok::BlockEntry if indentless_sequence => {
                self.state = State::IndentlessSequenceEntry;
                Ok(Ev::Node(Event::SequenceStart))
            }
            Tok::Scalar(s) => {
                self.state = self.pop()?;
                self.skip();
                Ok(Ev::Node(Event::Scalar(s)))
            }
            Tok::FlowSequenceStart => {
                self.state = State::FlowSequenceFirstEntry;
                Ok(Ev::Node(Event::SequenceStart))
            }
            Tok::FlowMappingStart => {
                self.state = State::FlowMappingFirstKey;
                Ok(Ev::Node(Event::MappingStart))
            }
            Tok::BlockSequenceStart if block => {
                self.state = State::BlockSequenceFirstEntry;
                Ok(Ev::Node(Event::SequenceStart))
            }
            Tok::BlockMappingStart if block => {
                self.state = State::BlockMappingFirstKey;
                Ok(Ev::Node(Event::MappingStart))
            }
            // "did not find expected node content".
            _ => Err(Fail::Yaml),
        }
    }

    fn block_sequence_entry(&mut self, first: bool) -> Result<Ev, Fail> {
        if first {
            self.peek()?;
            self.skip();
        }
        match self.peek()? {
            Tok::BlockEntry => {
                self.skip();
                if matches!(self.peek()?, Tok::BlockEntry | Tok::BlockEnd) {
                    self.state = State::BlockSequenceEntry;
                    Ok(EMPTY)
                } else {
                    self.states.push(State::BlockSequenceEntry);
                    self.node(true, false)
                }
            }
            Tok::BlockEnd => {
                self.state = self.pop()?;
                self.skip();
                Ok(Ev::Node(Event::SequenceEnd))
            }
            // "did not find expected '-' indicator".
            _ => Err(Fail::Yaml),
        }
    }

    fn indentless_sequence_entry(&mut self) -> Result<Ev, Fail> {
        if self.peek()? != Tok::BlockEntry {
            self.state = self.pop()?;
            return Ok(Ev::Node(Event::SequenceEnd));
        }
        self.skip();
        if matches!(
            self.peek()?,
            Tok::BlockEntry | Tok::Key | Tok::Value | Tok::BlockEnd
        ) {
            self.state = State::IndentlessSequenceEntry;
            Ok(EMPTY)
        } else {
            self.states.push(State::IndentlessSequenceEntry);
            self.node(true, false)
        }
    }

    fn block_mapping_key(&mut self, first: bool) -> Result<Ev, Fail> {
        if first {
            self.peek()?;
            self.skip();
        }
        match self.peek()? {
            Tok::Key => {
                self.skip();
                if matches!(self.peek()?, Tok::Key | Tok::Value | Tok::BlockEnd) {
                    self.state = State::BlockMappingValue;
                    Ok(EMPTY)
                } else {
                    self.states.push(State::BlockMappingValue);
                    self.node(true, true)
                }
            }
            Tok::BlockEnd => {
                self.state = self.pop()?;
                self.skip();
                Ok(Ev::Node(Event::MappingEnd))
            }
            // "did not find expected key".
            _ => Err(Fail::Yaml),
        }
    }

    fn block_mapping_value(&mut self) -> Result<Ev, Fail> {
        if self.peek()? != Tok::Value {
            self.state = State::BlockMappingKey;
            return Ok(EMPTY);
        }
        self.skip();
        if matches!(self.peek()?, Tok::Key | Tok::Value | Tok::BlockEnd) {
            self.state = State::BlockMappingKey;
            Ok(EMPTY)
        } else {
            self.states.push(State::BlockMappingKey);
            self.node(true, true)
        }
    }

    fn flow_sequence_entry(&mut self, first: bool) -> Result<Ev, Fail> {
        if first {
            self.peek()?;
            self.skip();
        }
        let mut tok = self.peek()?;
        if tok != Tok::FlowSequenceEnd {
            if !first {
                if tok != Tok::FlowEntry {
                    // "did not find expected ',' or ']'".
                    return Err(Fail::Yaml);
                }
                self.skip();
                tok = self.peek()?;
            }
            if tok == Tok::Key {
                self.state = State::FlowSequenceEntryMappingKey;
                self.skip();
                return Ok(Ev::Node(Event::MappingStart));
            }
            if tok != Tok::FlowSequenceEnd {
                self.states.push(State::FlowSequenceEntry);
                return self.node(false, false);
            }
        }
        self.state = self.pop()?;
        self.skip();
        Ok(Ev::Node(Event::SequenceEnd))
    }

    fn flow_sequence_entry_mapping_key(&mut self) -> Result<Ev, Fail> {
        if matches!(
            self.peek()?,
            Tok::Value | Tok::FlowEntry | Tok::FlowSequenceEnd
        ) {
            // libyaml takes the token here, whichever it is.
            self.skip();
            self.state = State::FlowSequenceEntryMappingValue;
            Ok(EMPTY)
        } else {
            self.states.push(State::FlowSequenceEntryMappingValue);
            self.node(false, false)
        }
    }

    fn flow_sequence_entry_mapping_value(&mut self) -> Result<Ev, Fail> {
        if self.peek()? == Tok::Value {
            self.skip();
            if !matches!(self.peek()?, Tok::FlowEntry | Tok::FlowSequenceEnd) {
                self.states.push(State::FlowSequenceEntryMappingEnd);
                return self.node(false, false);
            }
        }
        self.state = State::FlowSequenceEntryMappingEnd;
        Ok(EMPTY)
    }

    fn flow_mapping_key(&mut self, first: bool) -> Result<Ev, Fail> {
        if first {
            self.peek()?;
            self.skip();
        }
        let mut tok = self.peek()?;
        if tok != Tok::FlowMappingEnd {
            if !first {
                if tok != Tok::FlowEntry {
                    // "did not find expected ',' or '}'".
                    return Err(Fail::Yaml);
                }
                self.skip();
                tok = self.peek()?;
            }
            if tok == Tok::Key {
                self.skip();
                if matches!(
                    self.peek()?,
                    Tok::Value | Tok::FlowEntry | Tok::FlowMappingEnd
                ) {
                    self.state = State::FlowMappingValue;
                    return Ok(EMPTY);
                }
                self.states.push(State::FlowMappingValue);
                return self.node(false, false);
            }
            if tok != Tok::FlowMappingEnd {
                self.states.push(State::FlowMappingEmptyValue);
                return self.node(false, false);
            }
        }
        self.state = self.pop()?;
        self.skip();
        Ok(Ev::Node(Event::MappingEnd))
    }

    fn flow_mapping_value(&mut self, empty: bool) -> Result<Ev, Fail> {
        let tok = self.peek()?;
        if empty {
            self.state = State::FlowMappingKey;
            return Ok(EMPTY);
        }
        if tok == Tok::Value {
            self.skip();
            if !matches!(self.peek()?, Tok::FlowEntry | Tok::FlowMappingEnd) {
                self.states.push(State::FlowMappingKey);
                return self.node(false, false);
            }
        }
        self.state = State::FlowMappingKey;
        Ok(EMPTY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> (Vec<&'static str>, bool) {
        let e = build(text.as_bytes()).unwrap();
        let k = e
            .events
            .iter()
            .map(|e| match e {
                Event::Scalar(s) if s.start == s.end => "~",
                Event::Scalar(_) => "s",
                Event::SequenceStart => "[",
                Event::SequenceEnd => "]",
                Event::MappingStart => "{",
                Event::MappingEnd => "}",
            })
            .collect();
        (k, e.failed)
    }

    #[test]
    fn block_and_flow_collections_make_libyaml_events() {
        let (k, failed) = kinds("---    \na: 1\nb:\n- x\n- y: [p, q: r]\nc: {d: e, f}\n");
        assert!(!failed);
        assert_eq!(k.join(""), "{sss[s{s[s{ss}]}]s{sss~}}", "{k:?}");
        let (k, failed) = kinds("---\n");
        assert_eq!((k.join(""), failed), ("~".to_owned(), false));
    }

    #[test]
    fn what_libyaml_refuses_fails_after_the_events_before_it() {
        for text in [
            // A required key without its `:`.
            "---\na: 1\nb\n",
            "---\na: 1\nb",
            // A node where a key is expected.
            "---\na: \"x\" y\n",
            "---\na:\n  b: 1\n c: 2\n",
            // Anything after the root node.
            "--- {a: b}\nc: d\n",
            "--- [a]\n- b\n",
            // A document marker inside a quoted scalar, a bad escape.
            "---\na: \"x\n--- y\"\n",
            "---\na: \"x\n...\n\"\n",
            "---\na: \"\\q\"\n",
            "---\na: \"\\uD800\"\n",
        ] {
            let e = build(text.as_bytes()).unwrap();
            assert!(e.failed, "{text:?}");
        }
    }
}
