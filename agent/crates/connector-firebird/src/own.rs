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
//! Persisted with the parser checkpoint (R25 item 7, L10: the inputs that
//! do not come from the log): the stream attaches a store
//! ([`Ledger::attach_store`]) and the ledger is written at every
//! checkpoint and at every session's end ([`Ledger::close`]), so a restart
//! right after a check still finds that check's credits. What is written:
//! the attachments (a keyed tag of the declared `attach`, the id, the local
//! port, the server pid, the open and close times) and the credits (a
//! unique id, the tag of the `attach`, the attachment id, a **keyed tag of
//! the text**, never the text, the table a sampling text reads, the fetch
//! account, the time, and the record position that consumed it). A
//! restore ([`Ledger::restore`]) keeps only what holds for the checkpoint
//! it goes with: a credit consumed at or after the checkpoint's position is
//! a credit again (the re-read consumes it again), one consumed before it
//! is dropped, and an `attach` that is no longer declared is dropped.
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

use databastion_classifiers::masking::LocalTagKey;
use databastion_core::audit::CursorStore;

use crate::ckpt::{Bad, Reader, Writer};
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
    /// Unique in the ledger and across agent processes (a restore never
    /// adds a credit twice).
    uid: u64,
    attach: String,
    id: u64,
    text: Text,
    /// The table a built text (sampling, CAS guard) reads; `None` for a
    /// constant text of the closed set.
    table: Option<String>,
    account: FetchAccount,
    at: SystemTime,
}

/// A credit's text: as executed, or, restored from the persisted ledger,
/// its keyed tag (the text is never persisted).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Text {
    Clear(String),
    Tag([u8; 32]),
}

/// The tag purpose of persisted texts and `attach` names.
const TEXT_PURPOSE: &[u8] = b"databastion.firebird.ledger.text.v1";
const ATTACH_PURPOSE: &[u8] = b"databastion.firebird.ledger.attach.v1";
/// The persisted ledger's magic.
pub(crate) const MAGIC: &[u8; 4] = b"FBLG";

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
    /// Where the ledger is persisted, with the key of its tags (set by the
    /// stream, [`Self::attach_store`]); held while writing, so writes are
    /// serialized and the later one holds the later state.
    persist: Mutex<Option<(CursorStore, Arc<LocalTagKey>)>>,
}

#[derive(Debug, Default)]
struct State {
    attachments: Vec<Attachment>,
    credits: std::collections::VecDeque<Credit>,
    /// Credits consumed, with the record position that consumed them.
    consumed: std::collections::VecDeque<(RecordAt, Credit)>,
    /// The key of the tagged texts of restored credits.
    key: Option<Arc<LocalTagKey>>,
    /// The next credit id.
    next_uid: u64,
}

impl State {
    fn uid(&mut self) -> u64 {
        if self.next_uid == 0 {
            // A random start, so credit ids of two agent processes differ.
            let mut b = [0u8; 8];
            let _ = getrandom::fill(&mut b);
            self.next_uid = u64::from_be_bytes(b) | 1;
        }
        let u = self.next_uid;
        self.next_uid = self.next_uid.wrapping_add(1).max(1);
        u
    }
}

/// Whether a credit's text is `text`.
fn same_text(t: &Text, text: &str, key: Option<&LocalTagKey>) -> bool {
    match t {
        Text::Clear(c) => c == text,
        Text::Tag(g) => {
            key.is_some_and(|k| crate::ckpt::tag(k, TEXT_PURPOSE, &[text.as_bytes()]) == *g)
        }
    }
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
        let uid = s.uid();
        s.credits.push_back(Credit {
            uid,
            attach: attach.to_owned(),
            id,
            text: Text::Clear(text.to_owned()),
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
                match &c.text {
                    Text::Clear(t) => t.as_str(),
                    Text::Tag(_) => "<tag>",
                }
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
            .map(|c| {
                let t = match &c.text {
                    Text::Clear(t) => t.clone(),
                    Text::Tag(_) => "<tag>".to_owned(),
                };
                (t, c.account.end)
            })
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
        drop(s);
        // The session's credits are all issued: persisted now, so that an
        // agent stopped right after a check still has them (R25 item 7).
        self.persist();
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
        let key = s.key.clone();
        let same = |c: &Credit| {
            c.attach == attach && c.id == id && same_text(&c.text, text, key.as_deref())
        };
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

/// The largest persisted ledger (the core's counters file): with the
/// checkpoint file, the 16 MiB of R25 item 9's one cap.
const MAX_PERSISTED: usize = 2 * 1024 * 1024;

fn ms(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn from_ms(v: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(v)
}

fn end_code(e: FetchEnd) -> u8 {
    match e {
        FetchEnd::NotRun => 0,
        FetchEnd::End => 1,
        FetchEnd::Early => 2,
        FetchEnd::Lost => 3,
        FetchEnd::Failed => 4,
        FetchEnd::Cancelled => 5,
        FetchEnd::Error => 6,
    }
}

fn end_of(c: u8) -> Result<FetchEnd, Bad> {
    Ok(match c {
        0 => FetchEnd::NotRun,
        1 => FetchEnd::End,
        2 => FetchEnd::Early,
        3 => FetchEnd::Lost,
        4 => FetchEnd::Failed,
        5 => FetchEnd::Cancelled,
        6 => FetchEnd::Error,
        _ => return Err(Bad),
    })
}

/// A persisted attachment, its `attach` as a tag.
struct SavedAttachment {
    attach: [u8; 32],
    id: u64,
    port: u16,
    pid: u32,
    opened: SystemTime,
    closed: Option<SystemTime>,
}

/// A persisted credit.
struct SavedCredit {
    uid: u64,
    attach: [u8; 32],
    id: u64,
    text: [u8; 32],
    table: Option<String>,
    account: FetchAccount,
    at: SystemTime,
    consumed: Option<RecordAt>,
}

/// A persisted ledger, decoded.
pub(crate) struct Saved {
    attachments: Vec<SavedAttachment>,
    credits: Vec<SavedCredit>,
}

impl Saved {
    /// Decodes a persisted ledger body (strict, bounded; the fuzz target).
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Bad> {
        let mut r = Reader::new(body);
        let n = r.len(MAX_ATTACHMENTS, 32 + 8 + 4 + 4 + 8 + 1)?;
        let mut attachments = Vec::with_capacity(n);
        for _ in 0..n {
            let attach = r.bytes32()?;
            let id = r.u64()?;
            let port = u16::try_from(r.u32()?).map_err(|_| Bad)?;
            let pid = r.u32()?;
            let opened = from_ms(r.u64()?);
            let closed = r.opt_u64()?.map(from_ms);
            attachments.push(SavedAttachment {
                attach,
                id,
                port,
                pid,
                opened,
                closed,
            });
        }
        let n = r.len(MAX_CREDITS + MAX_CONSUMED, 8 + 32 + 8 + 32 + 1)?;
        let mut credits = Vec::with_capacity(n);
        for _ in 0..n {
            let uid = r.u64()?;
            let attach = r.bytes32()?;
            let id = r.u64()?;
            let text = r.bytes32()?;
            let table = if r.bool()? { Some(r.str()?) } else { None };
            let account = FetchAccount {
                counted: r.u64()?,
                requested: r.u64()?,
                last: r.u32()?,
                largest: r.u32()?,
                end: end_of(r.u8()?)?,
                stale_cancel_follow_up: r.bool()?,
                session_retired: r.bool()?,
            };
            let at = from_ms(r.u64()?);
            let consumed = if r.bool()? {
                Some(((r.u64()?, r.u64()?), r.u64()?))
            } else {
                None
            };
            credits.push(SavedCredit {
                uid,
                attach,
                id,
                text,
                table,
                account,
                at,
                consumed,
            });
        }
        r.done()?;
        Ok(Self {
            attachments,
            credits,
        })
    }
}

impl Ledger {
    /// The stream's store for the persisted ledger, and the key of its
    /// tags. The first store attached is kept (one stream per endpoint).
    pub(crate) fn attach_store(&self, store: CursorStore, key: Arc<LocalTagKey>) {
        let mut p = self
            .persist
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if p.is_none() {
            *p = Some((store, Arc::clone(&key)));
        }
        drop(p);
        self.state().key.get_or_insert(key);
    }

    /// The persisted body (newest credits first kept within
    /// [`MAX_PERSISTED`]: an older credit left out is lost at a restart,
    /// so its record is reported as any client's, fail closed).
    fn encode(&self, key: &LocalTagKey) -> Vec<u8> {
        let s = self.state();
        let t_attach = |a: &str| crate::ckpt::tag(key, ATTACH_PURPOSE, &[a.as_bytes()]);
        let mut w = Writer::default();
        w.len(s.attachments.len());
        for a in &s.attachments {
            w.bytes32(&t_attach(&a.attach));
            w.u64(a.id);
            w.u32(u32::from(a.port));
            w.u32(a.pid);
            w.u64(ms(a.opened));
            w.opt_u64(a.closed.map(ms));
        }
        let all: Vec<(Option<RecordAt>, &Credit)> = s
            .consumed
            .iter()
            .map(|(p, c)| (Some(*p), c))
            .chain(s.credits.iter().map(|c| (None, c)))
            .collect();
        let mut items: Vec<Vec<u8>> = Vec::new();
        let mut size = w.buf.len() + 4;
        // Newest first (credits are kept in issue order).
        let mut sorted = all;
        sorted.sort_by_key(|(_, c)| std::cmp::Reverse(c.at));
        for (consumed, c) in sorted {
            let mut e = Writer::default();
            e.u64(c.uid);
            e.bytes32(&t_attach(&c.attach));
            e.u64(c.id);
            e.bytes32(&match &c.text {
                Text::Clear(t) => crate::ckpt::tag(key, TEXT_PURPOSE, &[t.as_bytes()]),
                Text::Tag(g) => *g,
            });
            match c
                .table
                .as_deref()
                .filter(|t| t.len() <= crate::ckpt::MAX_NAME)
            {
                Some(t) => {
                    e.bool(true);
                    e.str(t);
                }
                None => e.bool(false),
            }
            let a = &c.account;
            e.u64(a.counted);
            e.u64(a.requested);
            e.u32(a.last);
            e.u32(a.largest);
            e.u8(end_code(a.end));
            e.bool(a.stale_cancel_follow_up);
            e.bool(a.session_retired);
            e.u64(ms(c.at));
            match consumed {
                Some(((dev, ino), off)) => {
                    e.bool(true);
                    e.u64(dev);
                    e.u64(ino);
                    e.u64(off);
                }
                None => e.bool(false),
            }
            if size + e.buf.len() > MAX_PERSISTED - 64 {
                break;
            }
            size += e.buf.len();
            items.push(e.buf);
        }
        drop(s);
        w.len(items.len());
        for i in items {
            w.buf.extend_from_slice(&i);
        }
        w.buf
    }

    /// Writes the ledger to its store, when one is attached. A failed write
    /// keeps the previous file (logged by kind).
    pub(crate) fn persist(&self) {
        let p = self
            .persist
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((store, key)) = p.as_ref() else {
            return;
        };
        let body = self.encode(key);
        match crate::ckpt::seal(key, MAGIC, &body) {
            Some(bytes) => {
                if let Err(e) = store.save(&bytes) {
                    tracing::warn!(error = %e, "Firebird own-statement ledger not saved");
                }
            }
            None => tracing::warn!("Firebird own-statement ledger not saved"),
        }
    }

    /// Restores a persisted ledger with the checkpoint it goes with (the
    /// checkpoint's file and position `at`): attachments and credits whose
    /// `attach` is one of `attaches` (the declared databases); a credit
    /// consumed at or after `at` in that file becomes a credit again, one
    /// consumed elsewhere is dropped; nothing already in the ledger is added
    /// twice. Returns the credits restored.
    pub(crate) fn restore(&self, saved: Saved, attaches: &[String], at: RecordAt) -> usize {
        let mut s = self.state();
        let Some(key) = s.key.clone() else {
            return 0;
        };
        let names: HashMap<[u8; 32], &String> = attaches
            .iter()
            .map(|a| (crate::ckpt::tag(&key, ATTACH_PURPOSE, &[a.as_bytes()]), a))
            .collect();
        for a in saved.attachments {
            let Some(attach) = names.get(&a.attach) else {
                continue;
            };
            if s.attachments.len() >= MAX_ATTACHMENTS
                || s.attachments
                    .iter()
                    .any(|x| &x.attach == *attach && x.id == a.id)
            {
                continue;
            }
            s.attachments.push(Attachment {
                attach: (*attach).clone(),
                id: a.id,
                port: a.port,
                pid: a.pid,
                opened: a.opened,
                closed: a.closed,
            });
        }
        let known: std::collections::HashSet<u64> = s
            .credits
            .iter()
            .map(|c| c.uid)
            .chain(s.consumed.iter().map(|(_, c)| c.uid))
            .collect();
        let mut n = 0;
        for c in saved.credits {
            let Some(attach) = names.get(&c.attach) else {
                continue;
            };
            let again = match c.consumed {
                None => true,
                Some((file, off)) => file == at.0 && off >= at.1,
            };
            if !again || known.contains(&c.uid) || s.credits.len() >= MAX_CREDITS {
                continue;
            }
            s.credits.push_back(Credit {
                uid: c.uid,
                attach: (*attach).clone(),
                id: c.id,
                text: Text::Tag(c.text),
                table: c.table,
                account: c.account,
                at: c.at,
            });
            n += 1;
        }
        s.credits.make_contiguous().sort_by_key(|c| c.at);
        n
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

    /// The persisted ledger (R25 item 7, L10): a restore with its
    /// checkpoint's position makes the credits consumed at or after it
    /// credits again, drops those consumed before it and those of an
    /// `attach` no longer declared, adds nothing twice, and holds no text.
    #[test]
    fn the_persisted_ledger_restores_what_its_checkpoint_needs() {
        let key = std::sync::Arc::new(
            databastion_classifiers::masking::HmacKey::new(&[5; 32])
                .unwrap()
                .local_tag_key("databastion.audit.cursor")
                .unwrap(),
        );
        let dir = std::env::temp_dir().join(format!("fb-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = || CursorStore::counters(&dir, "t", "fblg").unwrap();
        let l = Ledger::default();
        l.attach_store(store(), Arc::clone(&key));
        l.register("app", 7, 40000, 24);
        l.register("gone", 8, 40001, 24);
        let text = crate::sql::OWN_ATTACHMENT;
        let one = acc(FetchEnd::End, 1, 64, 64, 64);
        for _ in 0..3 {
            l.credit("app", 7, text, None, one);
        }
        l.credit("gone", 8, text, None, one);
        // Consumed before the checkpoint's position (100), and after it.
        assert_eq!(
            l.consume("app", 7, text, ((1, 2), 50), bounded(1)),
            Verdict::Own
        );
        assert_eq!(
            l.consume("app", 7, text, ((1, 2), 150), bounded(1)),
            Verdict::Own
        );
        l.persist();
        let bytes = store().load().unwrap().unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("MON$"), "no text");
        assert!(
            !String::from_utf8_lossy(&bytes).contains("app"),
            "no attach"
        );
        let body = crate::ckpt::open(&key, MAGIC, &bytes).unwrap();
        let fresh = Ledger::default();
        fresh.attach_store(store(), Arc::clone(&key));
        let saved = Saved::decode(body).unwrap();
        assert_eq!(fresh.restore(saved, &["app".to_owned()], ((1, 2), 100)), 2);
        // The one consumed after the position and the unconsumed one; not
        // the one consumed before it, nor `gone`'s.
        assert_eq!(fresh.credits_left().len(), 2);
        assert!(fresh.is_own_attach("app", 7, 40000, None));
        assert!(!fresh.is_own_attach("gone", 8, 40001, None));
        // The restored credit matches its text by its tag.
        assert_eq!(
            fresh.consume("app", 7, text, ((1, 2), 150), bounded(1)),
            Verdict::Own
        );
        assert_eq!(
            fresh.consume(
                "app",
                7,
                "SELECT 1 FROM RDB$DATABASE",
                ((1, 2), 160),
                bounded(1)
            ),
            Verdict::NotOwn
        );
        // Restoring again adds nothing twice.
        let saved = Saved::decode(body).unwrap();
        assert_eq!(fresh.restore(saved, &["app".to_owned()], ((1, 2), 100)), 0);
        assert_eq!(fresh.credits_left().len(), 1);
        // Another file: only the unconsumed one.
        let other = Ledger::default();
        other.attach_store(store(), Arc::clone(&key));
        let saved = Saved::decode(body).unwrap();
        assert_eq!(other.restore(saved, &["app".to_owned()], ((9, 9), 0)), 1);
        // Every cut of the body is refused.
        for n in 0..body.len() {
            assert!(Saved::decode(&body[..n]).is_err(), "cut {n}");
        }
        let _ = std::fs::remove_dir_all(&dir);
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
