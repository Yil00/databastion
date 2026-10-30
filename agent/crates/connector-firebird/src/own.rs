//! The agent's own attachments and execution credits (ADR-0060 decision
//! 6, "The agent's own statements"; R8 item 4, R13, R20, R22, R35).
//!
//! Every session of the connector records here, per server endpoint and
//! declared `attach`: its attachment (the id from `CURRENT_CONNECTION`, the
//! local port, the server pid, when it opened and closed) and one credit
//! per execution (the exact text, a constant of the closed set or a
//! sampling text built from catalog names, never a value, and the fetch
//! account of R22). The Audit stream consumes a credit for each record it
//! takes as the agent's own; a record of the agent's attachment whose text
//! finds no credit left is ambiguous (loud).
//!
//! In memory only: after a restart, the attachments of the previous
//! process are no longer known, so their records are reported as any
//! client's (fail closed, R39 (a)).
//!
//! A consumed credit is remembered with the record position that consumed
//! it (the log file identity and offset): a stream restarted in the same
//! process re-reads its held-back region (R39 (a)) and finds the credit of
//! the same record at the same position again, so the agent's own records
//! there are not made loud for a credit their first reading consumed. A
//! different position never finds it (one credit per execution).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use crate::conn::{FetchAccount, FetchEnd};

/// Credits kept per ledger (the oldest go first).
const MAX_CREDITS: usize = 65_536;
/// Attachments kept per ledger.
const MAX_ATTACHMENTS: usize = 4096;
/// A credit expires this long after its execution (decision 6: the
/// statement's deadline plus 5 minutes, the outer bound).
const CREDIT_LIFE: Duration = Duration::from_secs(15 * 60);
/// Consumed credits remembered for a re-read (the oldest go first).
const MAX_CONSUMED: usize = 65_536;
/// R22 item 3, L7: a lost attachment lives on for the statement timeout
/// plus 5 s.
const LOST_MARGIN: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct Attachment {
    attach: String,
    id: u64,
    port: u16,
    pid: u32,
    opened: SystemTime,
    closed: Option<SystemTime>,
}

#[derive(Debug, Clone)]
struct Credit {
    attach: String,
    id: u64,
    text: String,
    /// The table a built text (sampling, CAS guard) reads; `None` for a
    /// constant text of the closed set.
    table: Option<String>,
    account: FetchAccount,
    at: SystemTime,
}

/// What the stream's own rule concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The record is the agent's own (a credit consumed).
    Own,
    /// Not the agent's own: reported as any client's record.
    NotOwn,
    /// A text of the agent's set on its attachment, with no credit left
    /// (R8 item 4): ambiguous.
    NoCredit,
}

/// The ledger of one server endpoint.
#[derive(Debug, Default)]
pub(crate) struct Ledger {
    inner: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    attachments: Vec<Attachment>,
    credits: std::collections::VecDeque<Credit>,
    /// Credits consumed, with the record position that consumed them.
    consumed: std::collections::VecDeque<(RecordAt, Credit)>,
}

/// A record's position: the log file's `(st_dev, st_ino)` and the offset
/// of its first byte.
pub(crate) type RecordAt = ((u64, u64), u64);

/// The ledger of an endpoint (one per Firebird target).
pub(crate) fn ledger_for(addr: SocketAddr) -> Arc<Ledger> {
    static LEDGERS: OnceLock<Mutex<HashMap<SocketAddr, Arc<Ledger>>>> = OnceLock::new();
    let map = LEDGERS.get_or_init(Mutex::default);
    let mut m = map
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(m.entry(addr).or_default())
}

impl Ledger {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A session's attachment, after its `CURRENT_CONNECTION` read.
    pub(crate) fn register(&self, attach: &str, id: u64, port: u16, pid: u32) {
        let mut s = self.state();
        if s.attachments.len() >= MAX_ATTACHMENTS {
            s.attachments.remove(0);
        }
        s.attachments.push(Attachment {
            attach: attach.to_owned(),
            id,
            port,
            pid,
            opened: SystemTime::now(),
            closed: None,
        });
    }

    /// One execution of `text` on the attachment; `table`: the table a
    /// built text reads.
    pub(crate) fn credit(
        &self,
        attach: &str,
        id: u64,
        text: &str,
        table: Option<&str>,
        account: FetchAccount,
    ) {
        let mut s = self.state();
        if s.credits.len() >= MAX_CREDITS {
            s.credits.pop_front();
        }
        s.credits.push_back(Credit {
            attach: attach.to_owned(),
            id,
            text: text.to_owned(),
            table: table.map(str::to_owned),
            account,
            at: SystemTime::now(),
        });
    }

    /// Test support: an attachment opened at `opened`.
    #[cfg(test)]
    pub(crate) fn register_at(
        &self,
        attach: &str,
        id: u64,
        port: u16,
        pid: u32,
        opened: SystemTime,
    ) {
        self.register(attach, id, port, pid);
        if let Some(a) = self.state().attachments.last_mut() {
            a.opened = opened;
        }
    }

    /// The session ended: cleanly (`lost` false) or not, after its
    /// statement timeout.
    pub(crate) fn close(&self, attach: &str, id: u64, lost: bool, statement_timeout: Duration) {
        let end = if lost {
            SystemTime::now() + statement_timeout + LOST_MARGIN
        } else {
            SystemTime::now()
        };
        let mut s = self.state();
        if let Some(a) = s
            .attachments
            .iter_mut()
            .find(|a| a.attach == attach && a.id == id && a.closed.is_none())
        {
            a.closed = Some(end);
        }
    }

    /// The stream read the attachment's `DETACH_DATABASE`.
    pub(crate) fn note_detach(&self, attach: &str, id: u64) {
        let mut s = self.state();
        if let Some(a) = s
            .attachments
            .iter_mut()
            .find(|a| a.attach == attach && a.id == id)
        {
            a.closed.get_or_insert(SystemTime::now());
        }
    }

    /// Whether `(id, port)` is an own attachment of the database.
    pub(crate) fn is_own_attach(&self, attach: &str, id: u64, port: u16) -> bool {
        self.state()
            .attachments
            .iter()
            .any(|a| a.attach == attach && a.id == id && a.port == port)
    }

    /// When the attachment opened (the clock offset).
    pub(crate) fn opened(&self, attach: &str, id: u64) -> Option<SystemTime> {
        self.state()
            .attachments
            .iter()
            .find(|a| a.attach == attach && a.id == id)
            .map(|a| a.opened)
    }

    /// The agent's latest own attachment id of the database (R1 rule 5).
    pub(crate) fn latest_id(&self, attach: &str) -> Option<u64> {
        self.state()
            .attachments
            .iter()
            .filter(|a| a.attach == attach)
            .map(|a| a.id)
            .max()
    }

    /// The server pid the agent's attachments saw last (R1 rule 1).
    pub(crate) fn server_pid(&self) -> Option<u32> {
        self.state().attachments.last().map(|a| a.pid)
    }

    /// Consumes the credit of a record of an own attachment at `at`: an
    /// unconsumed credit of the same attachment and text that `accept`
    /// takes (`accept` gets the credit's fetch account and, for a built
    /// text, its table: the own-statement table's row and the R22 bounds,
    /// [`crate::own_table`]). A credit is consumed only by a record that
    /// matches it; a record re-read at the position that consumed a credit
    /// finds that credit again.
    pub(crate) fn consume(
        &self,
        attach: &str,
        id: u64,
        text: &str,
        at: RecordAt,
        accept: impl Fn(&FetchAccount, Option<&str>) -> bool,
    ) -> Verdict {
        let now = SystemTime::now();
        let mut s = self.state();
        let live = |c: &Credit| now.duration_since(c.at).unwrap_or_default() < CREDIT_LIFE;
        s.credits.retain(live);
        s.consumed.retain(|(_, c)| live(c));
        let same = |c: &Credit| c.attach == attach && c.id == id && c.text == text;
        if let Some((_, c)) = s.consumed.iter().find(|(p, c)| *p == at && same(c)) {
            return if accept(&c.account, c.table.as_deref()) {
                Verdict::Own
            } else {
                Verdict::NotOwn
            };
        }
        let any = s.credits.iter().any(same);
        let Some(pos) = s
            .credits
            .iter()
            .position(|c| same(c) && accept(&c.account, c.table.as_deref()))
        else {
            return if !any && crate::sql::checked(text) {
                // A text of the closed set with no credit left (R8 item 4).
                Verdict::NoCredit
            } else {
                Verdict::NotOwn
            };
        };
        let Some(c) = s.credits.remove(pos) else {
            return Verdict::NotOwn;
        };
        if s.consumed.len() >= MAX_CONSUMED {
            s.consumed.pop_front();
        }
        s.consumed.push_back((at, c));
        Verdict::Own
    }
}

/// The R22 / R35 bounds: `requested <= N <= requested + largest` after an
/// early close, `N = counted` after a full read, the last request taken
/// off the lower bound when the attachment was lost, `0 <= N <= Q + M` for
/// a credit the server's statement timeout or the connector's answered
/// cancel ended (only those may be `FAILED`), and no row for an execution
/// that fetched nothing. Any other server error is not the agent's own.
pub(crate) fn within(a: &FetchAccount, n: u64, failed: bool) -> bool {
    let q = a.requested;
    let m = u64::from(a.largest);
    match a.end {
        FetchEnd::End => !failed && n == a.counted,
        FetchEnd::Early => !failed && q <= n && n <= q + m,
        FetchEnd::Lost => !failed && q.saturating_sub(u64::from(a.last)) <= n && n <= q + m,
        FetchEnd::Failed | FetchEnd::Cancelled => failed && n <= q + m,
        FetchEnd::NotRun => !failed && n == 0,
        FetchEnd::Error => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(end: FetchEnd, counted: u64, requested: u64, last: u32, largest: u32) -> FetchAccount {
        FetchAccount {
            counted,
            requested,
            last,
            largest,
            end,
            ..FetchAccount::default()
        }
    }

    /// R35: full reads N = C; early closes Q <= N <= Q + M (M = 64);
    /// failed and cancelled credits 0 <= N <= Q + M, and only they FAILED.
    #[test]
    fn bounds() {
        assert!(within(&acc(FetchEnd::End, 3, 64, 64, 64), 3, false));
        assert!(!within(&acc(FetchEnd::End, 3, 64, 64, 64), 4, false));
        assert!(within(&acc(FetchEnd::Early, 65, 65, 1, 64), 129, false));
        assert!(!within(&acc(FetchEnd::Early, 65, 65, 1, 64), 130, false));
        assert!(!within(&acc(FetchEnd::Early, 65, 65, 1, 64), 64, false));
        assert!(within(&acc(FetchEnd::Lost, 10, 128, 64, 64), 64, false));
        assert!(within(&acc(FetchEnd::Failed, 0, 64, 64, 64), 0, true));
        assert!(!within(&acc(FetchEnd::Failed, 0, 64, 64, 64), 0, false));
        assert!(within(&acc(FetchEnd::Cancelled, 0, 64, 64, 64), 128, true));
        assert!(!within(&acc(FetchEnd::Early, 65, 65, 1, 64), 100, true));
        assert!(!within(&acc(FetchEnd::Error, 0, 0, 0, 0), 0, false));
        assert!(within(&acc(FetchEnd::NotRun, 0, 0, 0, 0), 0, false));
    }

    const AT: RecordAt = ((1, 2), 100);
    const AT2: RecordAt = ((1, 2), 900);

    fn bounded(n: u64) -> impl Fn(&FetchAccount, Option<&str>) -> bool {
        move |a, _| within(a, n, false)
    }

    #[test]
    fn credits_are_consumed_once() {
        let l = Ledger::default();
        l.register("app", 7, 40000, 24);
        assert!(l.is_own_attach("app", 7, 40000));
        assert!(!l.is_own_attach("app", 7, 40001));
        let text = crate::sql::OWN_ATTACHMENT;
        l.credit("app", 7, text, None, acc(FetchEnd::End, 1, 64, 64, 64));
        assert_eq!(l.consume("app", 7, text, AT, bounded(1)), Verdict::Own);
        // A second record of the same text: no credit left, loud.
        assert_eq!(
            l.consume("app", 7, text, AT2, bounded(1)),
            Verdict::NoCredit
        );
        // A text outside the set on the agent's attachment: not own.
        assert_eq!(
            l.consume("app", 7, "SELECT * FROM T", AT2, bounded(1)),
            Verdict::NotOwn
        );
        // Outside the bound: not own, and the credit is not consumed.
        l.credit("app", 7, text, None, acc(FetchEnd::End, 1, 64, 64, 64));
        assert_eq!(l.consume("app", 7, text, AT2, bounded(2)), Verdict::NotOwn);
        assert_eq!(l.consume("app", 7, text, AT2, bounded(1)), Verdict::Own);
        assert_eq!(l.latest_id("app"), Some(7));
        assert_eq!(l.server_pid(), Some(24));
    }

    /// R39 (a): a stream restarted in the same process re-reads the record
    /// that consumed a credit, at the same position, and finds it again;
    /// another file with the same offset, or another attachment, does not.
    #[test]
    fn a_re_read_record_finds_its_credit_again() {
        let l = Ledger::default();
        l.register("app", 7, 40000, 24);
        let text = crate::sql::OWN_ATTACHMENT;
        l.credit("app", 7, text, None, acc(FetchEnd::End, 1, 64, 64, 64));
        assert_eq!(l.consume("app", 7, text, AT, bounded(1)), Verdict::Own);
        assert_eq!(l.consume("app", 7, text, AT, bounded(1)), Verdict::Own);
        assert_eq!(l.consume("app", 7, text, AT, bounded(2)), Verdict::NotOwn);
        assert_eq!(
            l.consume("app", 7, text, ((1, 3), 100), bounded(1)),
            Verdict::NoCredit
        );
        assert_eq!(l.consume("app", 8, text, AT, bounded(1)), Verdict::NoCredit);
    }

    /// A built text's credit carries its table.
    #[test]
    fn a_sampling_credit_names_its_table() {
        let l = Ledger::default();
        l.register("app", 7, 40000, 24);
        let t = "SELECT FIRST 3 X FROM \"T\"";
        l.credit("app", 7, t, Some("T"), acc(FetchEnd::End, 3, 3, 3, 3));
        assert_eq!(
            l.consume("app", 7, t, AT, |_, table| table == Some("U")),
            Verdict::NotOwn
        );
        assert_eq!(
            l.consume("app", 7, t, AT, |_, table| table == Some("T")),
            Verdict::Own
        );
    }
}
