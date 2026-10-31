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
pub(crate) const CREDIT_LIFE: Duration = Duration::from_secs(15 * 60);
/// R42 item 5: the slack on the record-time bounds of attachment
/// lifetimes and credit lives (the printed time is the server's, a whole
/// second; the connector's times are taken around the request).
pub(crate) const LIFETIME_SLACK: Duration = Duration::from_secs(5);
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

    /// Test support: a credit issued at `at` (the record times of the
    /// stream tests are fixed).
    #[cfg(test)]
    pub(crate) fn credit_at(
        &self,
        attach: &str,
        id: u64,
        text: &str,
        account: FetchAccount,
        at: SystemTime,
    ) {
        self.credit(attach, id, text, None, account);
        if let Some(c) = self.state().credits.back_mut() {
            c.at = at;
        }
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

    /// Test support (the engine-matrix own-statement test, R20): the
    /// attachments and the credits, one per line (texts last; the closed
    /// set's texts and built texts hold no tab or line break).
    #[cfg(test)]
    pub(crate) fn dump(&self) -> String {
        let ms = |t: SystemTime| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis())
        };
        let s = self.state();
        let mut out = String::new();
        for a in &s.attachments {
            out.push_str(&format!(
                "A\t{}\t{}\t{}\t{}\t{}\t{}\n",
                a.attach,
                a.id,
                a.port,
                a.pid,
                ms(a.opened),
                a.closed
                    .map_or_else(|| "-".to_owned(), |c| ms(c).to_string())
            ));
        }
        for c in s.credits.iter().chain(s.consumed.iter().map(|(_, c)| c)) {
            let a = &c.account;
            out.push_str(&format!(
                "C\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}\t{}\n",
                ms(c.at),
                c.attach,
                c.id,
                c.table.as_deref().unwrap_or("-"),
                a.counted,
                a.requested,
                a.last,
                a.largest,
                a.end,
                c.text
            ));
        }
        out
    }

    /// Test support: a ledger from [`Self::dump`], with its times.
    #[cfg(test)]
    pub(crate) fn load(dump: &str) -> Self {
        let l = Self::default();
        let time =
            |ms: &str| SystemTime::UNIX_EPOCH + Duration::from_millis(ms.parse::<u64>().unwrap());
        for line in dump.lines() {
            let f: Vec<&str> = line.splitn(11, '\t').collect();
            match f.first() {
                Some(&"A") => {
                    let (attach, id) = (f[1], f[2].parse().unwrap());
                    l.register_at(
                        attach,
                        id,
                        f[3].parse().unwrap(),
                        f[4].parse().unwrap(),
                        time(f[5]),
                    );
                    if f[6] != "-"
                        && let Some(a) = l
                            .state()
                            .attachments
                            .iter_mut()
                            .rev()
                            .find(|a| a.attach == attach && a.id == id)
                    {
                        a.closed = Some(time(f[6]));
                    }
                }
                Some(&"C") => {
                    let at = time(f[1]);
                    let end = match f[9] {
                        "End" => FetchEnd::End,
                        "Early" => FetchEnd::Early,
                        "Lost" => FetchEnd::Lost,
                        "Failed" => FetchEnd::Failed,
                        "Cancelled" => FetchEnd::Cancelled,
                        "NotRun" => FetchEnd::NotRun,
                        _ => FetchEnd::Error,
                    };
                    let account = FetchAccount {
                        counted: f[5].parse().unwrap(),
                        requested: f[6].parse().unwrap(),
                        last: f[7].parse().unwrap(),
                        largest: f[8].parse().unwrap(),
                        end,
                        ..FetchAccount::default()
                    };
                    let table = (f[4] != "-").then_some(f[4]);
                    l.credit(f[2], f[3].parse().unwrap(), f[10], table, account);
                    if let Some(c) = l.state().credits.back_mut() {
                        c.at = at;
                    }
                }
                _ => {}
            }
        }
        l
    }

    /// Test support: the credits not consumed, `(text, end)`.
    #[cfg(test)]
    pub(crate) fn credits_left(&self) -> Vec<(String, FetchEnd)> {
        self.state()
            .credits
            .iter()
            .map(|c| (c.text.clone(), c.account.end))
            .collect()
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
    /// Whether `(id, port)` is an own attachment of the database whose
    /// lifetime holds the record's time `t` (R42 item 5: both bounds,
    /// with [`LIFETIME_SLACK`]; `None`: no time compared).
    pub(crate) fn is_own_attach(
        &self,
        attach: &str,
        id: u64,
        port: u16,
        t: Option<SystemTime>,
    ) -> bool {
        let now = SystemTime::now();
        self.state().attachments.iter().any(|a| {
            a.attach == attach
                && a.id == id
                && a.port == port
                && t.is_none_or(|t| {
                    t + LIFETIME_SLACK >= a.opened && t <= a.closed.unwrap_or(now) + LIFETIME_SLACK
                })
        })
    }

    /// The time of the credit the record at `at` consumed (the connector's
    /// own time of the statement, R42 item 2).
    pub(crate) fn consumed_time(&self, at: RecordAt) -> Option<SystemTime> {
        self.state()
            .consumed
            .iter()
            .rev()
            .find(|(p, _)| *p == at)
            .map(|(_, c)| c.at)
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
        accept: impl Fn(&FetchAccount, Option<&str>, SystemTime) -> bool,
    ) -> Verdict {
        let now = SystemTime::now();
        let mut s = self.state();
        let live = |c: &Credit| now.duration_since(c.at).unwrap_or_default() < CREDIT_LIFE;
        s.credits.retain(live);
        s.consumed.retain(|(_, c)| live(c));
        let same = |c: &Credit| c.attach == attach && c.id == id && c.text == text;
        if let Some((_, c)) = s.consumed.iter().find(|(p, c)| *p == at && same(c)) {
            return if accept(&c.account, c.table.as_deref(), c.at) {
                Verdict::Own
            } else {
                Verdict::NotOwn
            };
        }
        let any = s.credits.iter().any(same);
        let Some(pos) = s
            .credits
            .iter()
            .position(|c| same(c) && accept(&c.account, c.table.as_deref(), c.at))
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

    fn bounded(n: u64) -> impl Fn(&FetchAccount, Option<&str>, SystemTime) -> bool {
        move |a, _, _| within(a, n, false)
    }

    #[test]
    fn credits_are_consumed_once() {
        let l = Ledger::default();
        l.register("app", 7, 40000, 24);
        assert!(l.is_own_attach("app", 7, 40000, None));
        assert!(!l.is_own_attach("app", 7, 40001, None));
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

    /// R42 item 5: an attachment's lifetime bounds the record's time on
    /// both sides.
    #[test]
    fn attachment_lifetimes_bound_record_times() {
        let l = Ledger::default();
        let t0 = SystemTime::now() - Duration::from_secs(3600);
        l.register_at("app", 7, 40000, 24, t0);
        l.close("app", 7, false, Duration::from_secs(1));
        assert!(l.is_own_attach("app", 7, 40000, Some(t0 + Duration::from_secs(10))));
        assert!(!l.is_own_attach("app", 7, 40000, Some(t0 - Duration::from_secs(60))));
        assert!(!l.is_own_attach(
            "app",
            7,
            40000,
            Some(SystemTime::now() + Duration::from_secs(60))
        ));
    }

    /// A built text's credit carries its table.
    #[test]
    fn a_sampling_credit_names_its_table() {
        let l = Ledger::default();
        l.register("app", 7, 40000, 24);
        let t = "SELECT FIRST 3 X FROM \"T\"";
        l.credit("app", 7, t, Some("T"), acc(FetchEnd::End, 3, 3, 3, 3));
        assert_eq!(
            l.consume("app", 7, t, AT, |_, table, _| table == Some("U")),
            Verdict::NotOwn
        );
        assert_eq!(
            l.consume("app", 7, t, AT, |_, table, _| table == Some("T")),
            Verdict::Own
        );
    }
}
