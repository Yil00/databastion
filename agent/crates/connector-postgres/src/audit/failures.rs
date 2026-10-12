//! Failed and cancelled statements (ADR-0037, refinement of 2026-10-12):
//! the classes of the server's `ERROR` and `FATAL` lines by SQLSTATE
//! (item 3), and the per-session state that keeps a line from reporting a
//! read twice (item 4). The event itself is built in [`super::events`],
//! from the statement text, like any other statement.
//!
//! - **Refused** (no event): only `25P02` without a context field (a
//!   statement rejected before parsing, in an aborted transaction),
//!   connection-level `28xxx` / `3D000` lines without a statement text,
//!   and `42601` without a context whose text does not lex and holds no
//!   character a call, a cast or an operator needs. A `25P02` whose text
//!   calls code that is not built in (ADR-0049 decision 8) is not refused
//!   (decided by the caller, [`Base::RefusedUnlessUserCode`]).
//! - **Quiet** (the code says nothing of a value, rows may have been sent
//!   first): every other code of classes `42`, `3F`, `0A`, `25`, and
//!   `57014`, `57P01` to `57P05`, `40001`, `40P01`, `55P03`, classes
//!   `53`, `54`, `08`, `58`.
//! - **Telling**: every other code, and a missing or malformed one (fail
//!   closed).
//!
//! The context field's presence is only ever used to keep a line (a
//! forged `RAISE … USING ERRCODE = '25P02'` has one), never to drop one
//! (item 7).

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;

use super::records::{AuditRecord, ErrorLine, SqlState};

/// The class of a line from its SQLSTATE, context and statement presence,
/// before its text is analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Base {
    /// No event.
    Refused,
    /// `25P02` without a context: refused unless the text calls code that
    /// is not built in, then quiet.
    RefusedUnlessUserCode,
    /// `42601` without a context: refused when the text does not lex and
    /// cannot hold a call, a cast or an operator ([`unlexable_plain`]),
    /// quiet otherwise.
    RefusedIfUnlexable,
    Quiet,
    Telling,
}

/// The final class of a line, once its text is analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Quiet,
    Telling,
}

/// Codes outside the quiet classes that are quiet.
const QUIET_CODES: [&str; 9] = [
    "57014", "57P01", "57P02", "57P03", "57P04", "57P05", "40001", "40P01", "55P03",
];

/// Classes whose every code is quiet (`25P02` and `42601` aside, see
/// [`base_class`]).
const QUIET_CLASSES: [&str; 8] = ["42", "3F", "0A", "25", "53", "54", "08", "58"];

/// Whether a code is quiet (item 3).
pub(crate) fn quiet(code: SqlState) -> bool {
    QUIET_CLASSES.contains(&code.class()) || QUIET_CODES.contains(&code.as_str())
}

/// Item 3: the class by SQLSTATE only (never the message), the context's
/// presence, and whether the line carries a statement text.
pub(crate) fn base_class(code: Option<SqlState>, has_context: bool, statement: bool) -> Base {
    let Some(code) = code else {
        return Base::Telling;
    };
    match code.as_str() {
        "25P02" if !has_context => {
            if statement {
                Base::RefusedUnlessUserCode
            } else {
                Base::Refused
            }
        }
        "42601" if !has_context && statement => Base::RefusedIfUnlexable,
        _ if !statement && (code.class() == "28" || code.as_str() == "3D000") => Base::Refused,
        _ if quiet(code) => Base::Quiet,
        _ => Base::Telling,
    }
}

/// Bytes a call (`(`), a cast (`::`), an operator or a dollar quote needs.
fn code_byte(b: u8) -> bool {
    matches!(
        b,
        b'(' | b':'
            | b'$'
            | b'+'
            | b'-'
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
            | b'['
    )
}

/// The `42601` refusal (item 3, optional): the text did not lex
/// (`lexed`: the analyzer's verdict; without a backslash its reading does
/// not depend on `standard_conforming_strings`, so a text that did not
/// lex failed to lex), and holds no byte a call, a cast or an operator
/// needs, so no code that is not built in can have run from it, whatever
/// a lexer that disagrees with the server's would read.
pub(crate) fn unlexable_plain(text: &str, lexed: bool) -> bool {
    !lexed && !text.contains('\\') && !text.bytes().any(code_byte)
}

/// Sessions followed for item 4 (oldest forgotten first).
const MAX_SESSIONS: usize = 4096;

/// What the last pgaudit record of a session was.
#[derive(Default)]
struct Last {
    /// Statement id of the session's last record, and the keyed hash of
    /// its first text (`pgaudit.log_statement_once`: later records carry
    /// `<previously logged>`).
    statement: Option<(u64, Option<u64>)>,
    /// Keyed hash of the last record's text (resolved), `None` when
    /// unknown.
    text: Option<u64>,
    /// The last record has a row count field (written at the statement's
    /// end).
    rows: bool,
    vxid: String,
}

/// Item 4: per session, the last pgaudit record before a line, in log
/// order. Texts are kept only as hashes keyed per stream (never logged,
/// never sent, and not predictable by a client).
pub(crate) struct SessionTexts {
    hasher: RandomState,
    sessions: HashMap<String, Last>,
    order: VecDeque<String>,
}

impl Default for SessionTexts {
    fn default() -> Self {
        Self {
            hasher: RandomState::new(),
            sessions: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

impl std::fmt::Debug for SessionTexts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTexts")
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

impl SessionTexts {
    fn hash(&self, text: &str) -> u64 {
        self.hasher.hash_one(text)
    }

    /// The keyed hash of a text (a cache key; never logged, never sent).
    pub(crate) fn text_key(&self, text: &str) -> u64 {
        self.hash(text)
    }

    fn entry(&mut self, session: &str) -> &mut Last {
        if !self.sessions.contains_key(session) {
            if self.sessions.len() >= MAX_SESSIONS
                && let Some(old) = self.order.pop_front()
            {
                self.sessions.remove(&old);
            }
            self.order.push_back(session.to_owned());
        }
        self.sessions.entry(session.to_owned()).or_default()
    }

    /// A pgaudit record, in log order (`previously_logged`: the text
    /// `pgaudit.log_statement_once` writes after the first record).
    pub(crate) fn record(&mut self, r: &AuditRecord, previously_logged: &str) {
        let text = r.audit.statement.as_str();
        let own = (text != previously_logged).then(|| self.hash(text));
        let id = r.audit.statement_id;
        let last = self.entry(&r.session);
        let first = match last.statement {
            Some((s, first)) if s == id => first.or(own),
            _ => own,
        };
        last.statement = Some((id, first));
        last.text = own.or(first);
        last.rows = r.audit.rows.is_some();
        last.vxid.clone_from(&r.vxid);
    }

    /// Whether `line` repeats the session's last record (item 4): same
    /// text, same virtual transaction, and that record has no row count
    /// (written when the statement started). A match is used once.
    pub(crate) fn duplicate(&mut self, line: &ErrorLine) -> bool {
        let Some(text) = line.statement.as_deref() else {
            return false;
        };
        if line.vxid.is_empty() {
            return false;
        }
        let h = self.hash(text);
        let Some(last) = self.sessions.get_mut(&line.session) else {
            return false;
        };
        let dup = last.text == Some(h) && !last.rows && last.vxid == line.vxid;
        if dup {
            last.text = None;
        }
        dup
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(s: &str) -> Option<SqlState> {
        SqlState::parse(s)
    }

    #[test]
    fn classes_by_sqlstate() {
        for c in [
            "42P01", "42501", "42883", "42703", "3F000", "0A000", "25001", "25P03", "57014",
            "57P01", "57P05", "40001", "40P01", "55P03", "53100", "53300", "54000", "08006",
            "08P01", "58030",
        ] {
            assert_eq!(base_class(code(c), false, true), Base::Quiet, "{c}");
            assert_eq!(base_class(code(c), true, true), Base::Quiet, "{c}");
        }
        for c in [
            "22P02", "22012", "23505", "23503", "27000", "44000", "P0001", "P0004", "XX000",
            "2F005", "38000", "39001", "55000", "57000", "57P06", "40002", "28000", "28P01",
            "3D000", "ZZ999",
        ] {
            assert_eq!(base_class(code(c), false, true), Base::Telling, "{c}");
        }
        // Unknown or malformed: telling.
        assert_eq!(base_class(None, false, true), Base::Telling);
        assert!(SqlState::parse("22p02").is_none());
        assert!(SqlState::parse("2200").is_none());
        assert!(SqlState::parse("220000").is_none());
    }

    #[test]
    fn refusals_need_no_context() {
        assert_eq!(
            base_class(code("25P02"), false, true),
            Base::RefusedUnlessUserCode
        );
        assert_eq!(base_class(code("25P02"), false, false), Base::Refused);
        // A context: a function raised it (F1), never refused.
        assert_eq!(base_class(code("25P02"), true, true), Base::Quiet);
        assert_eq!(base_class(code("25P02"), true, false), Base::Quiet);
        assert_eq!(
            base_class(code("42601"), false, true),
            Base::RefusedIfUnlexable
        );
        assert_eq!(base_class(code("42601"), true, true), Base::Quiet);
        assert_eq!(base_class(code("42601"), false, false), Base::Quiet);
        // Connection-level lines: refused only without a statement.
        for c in ["28000", "28P01", "3D000"] {
            assert_eq!(base_class(code(c), false, false), Base::Refused, "{c}");
            assert_eq!(base_class(code(c), true, false), Base::Refused, "{c}");
            assert_eq!(base_class(code(c), false, true), Base::Telling, "{c}");
        }
    }

    #[test]
    fn the_42601_refusal_needs_a_plain_unlexable_text() {
        assert!(unlexable_plain("select 'abc", false));
        assert!(unlexable_plain("select \"abc", false));
        assert!(!unlexable_plain("select 'abc'", true));
        for t in [
            "select f() || 'abc",
            "select x::t, 'abc",
            "select 1 + 'abc",
            "select 1 /* abc",
            "select $1, 'abc",
            "select a[1], 'abc",
            "select E'\\' abc",
        ] {
            assert!(!unlexable_plain(t, false), "{t}");
        }
    }

    fn rec(session: &str, id: u64, text: &str, rows: Option<u64>, vxid: &str) -> AuditRecord {
        let mut r = super::super::records::tests_audit_record(session, text, rows);
        r.audit.statement_id = id;
        r.vxid = vxid.to_owned();
        r
    }

    fn line(session: &str, text: Option<&str>, vxid: &str) -> ErrorLine {
        super::super::records::tests_error_line(session, "25001", text, vxid)
    }

    #[test]
    fn a_line_after_its_start_record_is_not_reported_twice() {
        const PREV: &str = "<previously logged>";
        let mut s = SessionTexts::default();
        // `log_rows = off`: the record at the start, then the line.
        s.record(&rec("a", 1, "select x from t", None, "3/1"), PREV);
        assert!(s.duplicate(&line("a", Some("select x from t"), "3/1")));
        // Used once.
        assert!(!s.duplicate(&line("a", Some("select x from t"), "3/1")));
        // Another session, text, or transaction: reported.
        s.record(&rec("a", 2, "select x from t", None, "3/2"), PREV);
        assert!(!s.duplicate(&line("b", Some("select x from t"), "3/2")));
        assert!(!s.duplicate(&line("a", Some("select y from t"), "3/2")));
        assert!(!s.duplicate(&line("a", Some("select x from t"), "3/3")));
        assert!(!s.duplicate(&line("a", None, "3/2")));
        assert!(!s.duplicate(&line("a", Some("select x from t"), "")));
        // A record with a row count was written at the end of an earlier
        // statement.
        s.record(&rec("a", 3, "select x from t", Some(4), "3/4"), PREV);
        assert!(!s.duplicate(&line("a", Some("select x from t"), "3/4")));
        // `log_statement_once`: later records of the statement carry
        // `<previously logged>`.
        s.record(&rec("a", 4, "select x from t, u", None, "3/5"), PREV);
        s.record(&rec("a", 4, PREV, None, "3/5"), PREV);
        assert!(s.duplicate(&line("a", Some("select x from t, u"), "3/5")));
        // A `<previously logged>` without its first record: unknown text.
        s.record(&rec("a", 5, PREV, None, "3/6"), PREV);
        assert!(!s.duplicate(&line("a", Some(PREV), "3/6")));
    }

    #[test]
    fn sessions_are_bounded() {
        let mut s = SessionTexts::default();
        for i in 0..(MAX_SESSIONS + 10) {
            s.record(
                &rec(&format!("s{i}"), 1, "select 1", None, "1/1"),
                "<previously logged>",
            );
        }
        assert_eq!(s.sessions.len(), MAX_SESSIONS);
        assert_eq!(s.order.len(), MAX_SESSIONS);
        assert!(!s.duplicate(&line("s0", Some("select 1"), "1/1")));
        assert!(s.duplicate(&line(
            &format!("s{}", MAX_SESSIONS + 9),
            Some("select 1"),
            "1/1"
        )));
    }
}
