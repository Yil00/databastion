//! The agent's own sessions and credits (ADR-0051 decision 6, "The
//! agent's own sessions", security review H1, re-review N4 and N6, L5).
//!
//! "Own" is tied to the sessions the agent itself opened, never to a
//! login, application or host name: right after login, every session
//! reads its `@@SPID`, its `login_time` and the client address the server
//! sees (`conn::SESSION_READBACK`) and registers here ([`opened`]). Its
//! lifetime runs from `login_time` to the moment the connector closed it
//! after a clean close (no grace), or, for a lost connection (a network
//! error, a timeout without an `ATTENTION` acknowledgement, a dropped
//! future), to the moment it was lost plus the statement timeout and 5 s.
//! Times are the server's UTC clock: the session's server time at its
//! read-back plus the agent's monotonic time since, so no clock offset
//! between the agent and the server enters the rule.
//!
//! The list is kept per target, bounded by time only (sessions ended more
//! than 48 h ago are dropped, none earlier; a warning above 100 000),
//! and persisted by the Audit stream in its counters file
//! ([`encode`] / [`restore`]), so an agent restart still recognizes the
//! records of its earlier sessions; a session whose end is unknown
//! (crash) is closed at the restart time.
//!
//! **Credits** (L5, and the per-poll credit of decision 6): a sampling
//! statement, a CAS ticket count or an Audit poll is the agent's own only
//! with a credit of the same session for exactly its text whose window
//! holds the record's time, consumed once. Credits are granted only while
//! an Audit stream reads the target ([`stream_started`]). A credit's
//! window runs, on the server's clock, from 1 s before the moment it is
//! granted to the statement timeout plus [`CREDIT_SLACK`] later (at most
//! [`MAX_CREDIT_TTL`]): it is checked against the record's `event_time`
//! (when the statement ran, not when the record is read), so the window
//! only has to cover the statement's run, and a stream that reads late
//! still matches it (security review of P9-A lot 2, L3). A credit covers
//! the records of one execution, by transaction id; a record without one
//! (0) consumes it once. At most [`MAX_CREDITS`] per target (the oldest are dropped: their
//! statements are then reported, fail closed); credits are forgotten an
//! hour after their window. A credit holds a keyed hash of the text
//! (SipHash with a per-process random key), never the text. Poll credits
//! are also persisted (by kind, the poll's text being rebuilt from the
//! catalog), so the last polls before an agent restart are recognized by
//! the next process.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

/// Sessions ended longer ago than this are forgotten (re-review N6).
pub(crate) const KEEP_US: i64 = 48 * 3600 * 1_000_000;
/// Above this many sessions per target, a warning (never a cut).
const WARN_SESSIONS: usize = 100_000;
/// Grace after a lost connection, on top of the statement timeout.
pub(crate) const LOST_GRACE: Duration = Duration::from_secs(5);
/// A persisted session still open at its last save ends this long after
/// that save: the longest statement timeout of the connector (30 s, a
/// Discovery sample) plus [`LOST_GRACE`].
const OPEN_AT_SAVE_GRACE: Duration = Duration::from_secs(35);
/// `login_time` is a `datetime` (3.33 ms steps): the start is moved back
/// this much.
const START_SLACK_US: i64 = 10_000;
/// Shortest and longest lifetime of a credit.
pub(crate) const MAX_CREDIT_TTL: Duration = Duration::from_secs(900);
/// Slack after a credited statement's timeout (clock steps of the
/// server's `event_time`).
pub(crate) const CREDIT_SLACK: Duration = Duration::from_secs(5);
/// Credits held per target at most.
pub(crate) const MAX_CREDITS: usize = 4096;

/// One of the agent's sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OwnSession {
    pub(crate) spid: i64,
    /// Server UTC, µs since 1970.
    pub(crate) start_us: i64,
    /// `None`: still open.
    pub(crate) end_us: Option<i64>,
    /// The client address the server saw (`None`: not an IP literal).
    pub(crate) addr: Option<IpAddr>,
}

impl OwnSession {
    fn within(&self, at_us: i64) -> bool {
        self.start_us <= at_us && self.end_us.is_none_or(|e| at_us <= e)
    }
}

/// Which Audit poll a poll credit is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PollKind {
    /// From the start of the file set.
    Start,
    /// After a position.
    From,
}

#[derive(Debug, Clone, Copy)]
struct Credit {
    spid: i64,
    /// Keyed hash of the text (`None`: a poll credit restored from the
    /// file, matched by its kind).
    hash: Option<u64>,
    poll: Option<PollKind>,
    /// Window on the server's clock (µs).
    from_us: i64,
    until_us: i64,
    /// Consumed by the records of the statement with this transaction id:
    /// further records of that one execution (another object, or a part
    /// read in the next poll) match it again, no other execution does.
    used_tx: Option<i64>,
}

/// A credit's window starts this much before its grant (clock steps).
const CREDIT_SLACK_US: i64 = 1_000_000;
/// Credits are forgotten this long after their window.
const CREDIT_KEEP_US: i64 = 3600 * 1_000_000;

#[derive(Default)]
struct Target {
    sessions: Vec<OwnSession>,
    credits: VecDeque<Credit>,
    streams: usize,
    /// Server time minus agent time (µs), last measured.
    offset_us: i64,
    warned: bool,
}

#[derive(Default)]
struct Registry {
    targets: HashMap<String, Target>,
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(Mutex::default);
static HASHER: LazyLock<RandomState> = LazyLock::new(RandomState::new);

fn lock() -> MutexGuard<'static, Registry> {
    REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn text_hash(text: &str) -> u64 {
    HASHER.hash_one(text)
}

fn agent_now_us() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
}

/// A registered session, held by the connection: its end is recorded when
/// it closes or is dropped.
#[derive(Debug)]
pub(crate) struct Handle {
    target: String,
    spid: i64,
    start_us: i64,
    /// Server time at the read-back, and the agent's instant then.
    server_us: i64,
    at: Instant,
    ended: bool,
}

impl Handle {
    /// The server's UTC time now (µs), from the session's read-back.
    pub(crate) fn server_now(&self) -> i64 {
        self.server_now_us(Duration::ZERO)
    }

    fn server_now_us(&self, extra: Duration) -> i64 {
        let elapsed = self.at.elapsed() + extra;
        self.server_us
            .saturating_add(i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX / 4))
    }

    /// Records the end of the session: `lost` adds `grace` (the statement
    /// timeout plus [`LOST_GRACE`]).
    pub(crate) fn end(&mut self, lost: bool, grace: Duration) {
        if self.ended {
            return;
        }
        self.ended = true;
        let end = self.server_now_us(if lost { grace } else { Duration::ZERO });
        let mut reg = lock();
        if let Some(t) = reg.targets.get_mut(&self.target)
            && let Some(s) = t
                .sessions
                .iter_mut()
                .rev()
                .find(|s| s.spid == self.spid && s.start_us == self.start_us)
        {
            s.end_us = Some(end);
        }
    }

    /// Grants a credit for `text`, sent now on this session, when an Audit
    /// stream reads the target; `poll` for the stream's own polls.
    pub(crate) fn credit(&self, text: &str, statement_timeout: Duration, poll: Option<PollKind>) {
        let now_us = self.server_now();
        let mut reg = lock();
        let Some(t) = reg.targets.get_mut(&self.target) else {
            return;
        };
        if t.streams == 0 {
            return;
        }
        let ttl = (statement_timeout + CREDIT_SLACK).min(MAX_CREDIT_TTL);
        expire(&mut t.credits, now_us);
        while t.credits.len() >= MAX_CREDITS {
            t.credits.pop_front();
        }
        t.credits.push_back(Credit {
            spid: self.spid,
            hash: Some(text_hash(text)),
            poll,
            from_us: now_us.saturating_sub(CREDIT_SLACK_US),
            until_us: now_us.saturating_add(i64::try_from(ttl.as_micros()).unwrap_or(i64::MAX / 4)),
            used_tx: None,
        });
    }
}

impl Drop for Handle {
    /// A session dropped without a clean close is lost (decision 6): the
    /// server may still finish a statement; the default grace applies.
    fn drop(&mut self) {
        self.end(true, Duration::from_secs(30) + LOST_GRACE);
    }
}

fn expire(credits: &mut VecDeque<Credit>, now_us: i64) {
    credits.retain(|c| now_us.saturating_sub(c.until_us) <= CREDIT_KEEP_US);
}

fn prune(t: &mut Target, now_us: i64) {
    t.sessions
        .retain(|s| s.end_us.is_none_or(|e| now_us.saturating_sub(e) <= KEEP_US));
    if t.sessions.len() > WARN_SESSIONS && !t.warned {
        t.warned = true;
        tracing::warn!(
            sessions = t.sessions.len(),
            "SQL Server: more than 100000 own sessions in 48 h for one target"
        );
    }
}

/// Registers a session opened on `target_id`: its `spid`, the server's UTC
/// time at the read-back (`server_us`), the time since its login
/// (`since_login_us`), the client address the server saw, and `at`, the
/// agent's instant **before** the read-back was sent: the session's end is
/// the read-back's server time plus the agent's time since `at`, which
/// can only be later than the server's time at the close (measured on
/// 2022: with the instant taken after the answer, the last statement's
/// records could fall up to a few milliseconds after the computed end).
pub(crate) fn opened(
    target_id: &str,
    spid: i64,
    server_us: i64,
    since_login_us: i64,
    addr: Option<IpAddr>,
    at: Instant,
) -> Handle {
    let start_us = server_us
        .saturating_sub(since_login_us.max(0))
        .saturating_sub(START_SLACK_US);
    let mut reg = lock();
    let t = reg.targets.entry(target_id.to_owned()).or_default();
    t.offset_us = server_us.saturating_sub(agent_now_us());
    prune(t, server_us);
    t.sessions.push(OwnSession {
        spid,
        start_us,
        end_us: None,
        addr,
    });
    Handle {
        target: target_id.to_owned(),
        spid,
        start_us,
        server_us,
        at,
        ended: false,
    }
}

/// The agent's session `spid` of `target_id` whose lifetime holds
/// `at_us`, if any.
pub(crate) fn session_at(target_id: &str, spid: i64, at_us: i64) -> Option<OwnSession> {
    let reg = lock();
    reg.targets
        .get(target_id)?
        .sessions
        .iter()
        .rev()
        .find(|s| s.spid == spid && s.within(at_us))
        .copied()
}

/// Consumes the oldest credit of session `spid` for exactly `text` whose
/// window holds `at_us` (the record's time), for the execution with the
/// transaction id `tx`; a credit already consumed by that execution
/// matches again (its other records). `poll`: the text is the stream's
/// current poll text of that kind (restored poll credits carry no hash and
/// match by kind).
pub(crate) fn take_credit(
    target_id: &str,
    spid: i64,
    text: &str,
    poll: Option<PollKind>,
    at_us: i64,
    tx: i64,
) -> bool {
    let mut reg = lock();
    let Some(t) = reg.targets.get_mut(target_id) else {
        return false;
    };
    let h = text_hash(text);
    let same = |c: &Credit| {
        c.spid == spid
            && c.from_us <= at_us
            && at_us <= c.until_us
            && match c.hash {
                Some(ch) => ch == h,
                None => poll.is_some() && c.poll == poll,
            }
    };
    // Another record of the same execution; a record without a
    // transaction id (0) never shares a credit (review L3).
    if tx != 0 && t.credits.iter().any(|c| same(c) && c.used_tx == Some(tx)) {
        return true;
    }
    match t
        .credits
        .iter_mut()
        .find(|c| same(c) && c.used_tx.is_none())
    {
        Some(c) => {
            c.used_tx = Some(tx);
            true
        }
        None => false,
    }
}

/// An Audit stream reading `target_id`; credits are granted while one
/// runs. Unregistered on drop.
pub(crate) struct Streaming {
    target: String,
}

impl Drop for Streaming {
    fn drop(&mut self) {
        let mut reg = lock();
        if let Some(t) = reg.targets.get_mut(&self.target) {
            // Credits already granted stay valid for their window: a
            // restarted stream still matches the last polls of this one.
            t.streams = t.streams.saturating_sub(1);
        }
    }
}

/// Registers a running stream (credits are granted while one runs).
pub(crate) fn stream_started(target_id: &str) -> Streaming {
    let mut reg = lock();
    let t = reg.targets.entry(target_id.to_owned()).or_default();
    t.streams += 1;
    Streaming {
        target: target_id.to_owned(),
    }
}

/// The persisted form of a target's sessions: `v1`, `offset <µs>`, then
/// one line per session `<spid> <start> <end|-> <ip|->` (numbers and IP
/// literals only), newest last, cut at `max_bytes` from the oldest.
pub(crate) fn encode(target_id: &str, max_bytes: usize) -> Vec<u8> {
    let mut reg = lock();
    let Some(t) = reg.targets.get_mut(target_id) else {
        return b"v1\noffset 0\n".to_vec();
    };
    prune(t, agent_now_us().saturating_add(t.offset_us));
    let saved_us = agent_now_us().saturating_add(t.offset_us);
    let head = format!("v1\noffset {}\nsaved {saved_us}\n", t.offset_us);
    let lines: Vec<String> = t
        .sessions
        .iter()
        .map(|s| {
            format!(
                "{} {} {} {}\n",
                s.spid,
                s.start_us,
                s.end_us.map_or("-".to_owned(), |e| e.to_string()),
                s.addr.map_or("-".to_owned(), |a| a.to_string())
            )
        })
        .collect();
    let mut total = head.len();
    let mut keep = 0;
    for l in lines.iter().rev() {
        if total + l.len() > max_bytes {
            break;
        }
        total += l.len();
        keep += 1;
    }
    if keep < lines.len() {
        tracing::warn!(
            dropped = lines.len() - keep,
            "SQL Server: own sessions file full, the oldest sessions are not persisted"
        );
    }
    let mut out = head.into_bytes();
    for c in t
        .credits
        .iter()
        .filter(|c| c.poll.is_some() && c.used_tx.is_none())
        .rev()
        .take(16)
    {
        let kind = if c.poll == Some(PollKind::Start) {
            "start"
        } else {
            "from"
        };
        out.extend_from_slice(
            format!("p {} {} {} {kind}\n", c.spid, c.from_us, c.until_us).as_bytes(),
        );
    }
    for l in &lines[lines.len() - keep..] {
        out.extend_from_slice(l.as_bytes());
    }
    out
}

/// What a persisted file holds.
#[derive(Debug, Default)]
pub(crate) struct Persisted {
    pub(crate) offset_us: i64,
    /// The server time of the save.
    pub(crate) saved_us: Option<i64>,
    pub(crate) sessions: Vec<OwnSession>,
    polls: Vec<Credit>,
}

/// The sessions and poll credits of a persisted file (`None` when not
/// understood).
pub(crate) fn decode(bytes: &[u8]) -> Option<Persisted> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "v1" {
        return None;
    }
    let offset_us = lines.next()?.strip_prefix("offset ")?.parse().ok()?;
    let mut out = Vec::new();
    let mut polls = Vec::new();
    let mut saved_us = None;
    for l in lines {
        if let Some(v) = l.strip_prefix("saved ") {
            saved_us = Some(v.parse().ok()?);
            continue;
        }
        if let Some(rest) = l.strip_prefix("p ") {
            let mut p = rest.split(' ');
            let spid = p.next()?.parse().ok()?;
            let from_us = p.next()?.parse().ok()?;
            let until_us = p.next()?.parse().ok()?;
            let poll = match p.next()? {
                "start" => PollKind::Start,
                "from" => PollKind::From,
                _ => return None,
            };
            if polls.len() < 16 {
                polls.push(Credit {
                    spid,
                    hash: None,
                    poll: Some(poll),
                    from_us,
                    until_us,
                    used_tx: None,
                });
            }
            continue;
        }
        let mut p = l.split(' ');
        let spid = p.next()?.parse().ok()?;
        let start_us = p.next()?.parse().ok()?;
        let end_us = match p.next()? {
            "-" => None,
            e => Some(e.parse().ok()?),
        };
        let addr = match p.next()? {
            "-" => None,
            a => Some(a.parse().ok()?),
        };
        if p.next().is_some() {
            return None;
        }
        out.push(OwnSession {
            spid,
            start_us,
            end_us,
            addr,
        });
    }
    Some(Persisted {
        offset_us,
        saved_us,
        sessions: out,
        polls,
    })
}

/// Restores persisted sessions at a stream's start: a session still open
/// in the file belongs to an earlier agent process, closed at the restart
/// time (decision 6). Sessions already known are kept as they are.
pub(crate) fn restore(target_id: &str, persisted: Persisted) {
    let Persisted {
        offset_us,
        saved_us,
        sessions,
        polls,
    } = persisted;
    let restart_us = agent_now_us().saturating_add(offset_us);
    // A session open at the last save ends at that save plus the grace of
    // a lost connection, not at the restart (review L4): what it did after
    // the save is reported.
    let open_end = saved_us.map_or(restart_us, |s| {
        s.saturating_add(i64::try_from((OPEN_AT_SAVE_GRACE).as_micros()).unwrap_or(0))
            .min(restart_us)
    });
    let mut reg = lock();
    let t = reg.targets.entry(target_id.to_owned()).or_default();
    for c in polls {
        if !t
            .credits
            .iter()
            .any(|k| k.spid == c.spid && k.from_us == c.from_us)
        {
            t.credits.push_front(c);
        }
    }
    let mut restored: Vec<OwnSession> = sessions
        .into_iter()
        .filter(|s| {
            !t.sessions
                .iter()
                .any(|k| k.spid == s.spid && k.start_us == s.start_us)
        })
        .map(|mut s| {
            if s.end_us.is_none() {
                s.end_us = Some(open_end);
            }
            s
        })
        .collect();
    restored.append(&mut t.sessions);
    t.sessions = restored;
    prune(t, restart_us);
}

#[cfg(test)]
pub(crate) fn reset(target_id: &str) {
    lock().targets.remove(target_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetime_and_clean_close() {
        let t = "own-test-lifetime";
        reset(t);
        let mut h = opened(
            t,
            61,
            1_000_000_000,
            500_000,
            "10.0.0.1".parse().ok(),
            Instant::now(),
        );
        let s = session_at(t, 61, 999_600_000).unwrap();
        assert_eq!(s.addr, "10.0.0.1".parse().ok());
        assert!(session_at(t, 61, 999_400_000).is_none(), "before the login");
        assert!(session_at(t, 62, 999_600_000).is_none(), "another spid");
        h.end(false, Duration::from_secs(30));
        let end = session_at(t, 61, 999_600_000).unwrap().end_us.unwrap();
        assert!((1_000_000_000..1_001_000_000).contains(&end), "{end}");
        assert!(
            session_at(t, 61, end + 1).is_none(),
            "no grace after a clean close"
        );
        drop(h);
        assert_eq!(session_at(t, 61, 999_600_000).unwrap().end_us, Some(end));
    }

    #[test]
    fn lost_sessions_get_the_grace() {
        let t = "own-test-lost";
        reset(t);
        let h = opened(t, 70, 2_000_000_000, 0, None, Instant::now());
        drop(h);
        let end = session_at(t, 70, 2_000_000_000).unwrap().end_us.unwrap();
        assert!(end >= 2_000_000_000 + 35_000_000);
    }

    #[test]
    fn credits_need_a_stream_the_session_the_text_and_the_window() {
        let t = "own-test-credits";
        reset(t);
        let now = agent_now_us();
        let h = opened(t, 80, now, 0, None, Instant::now());
        let q = "SELECT TOP (10) x FROM [d].[s].[t]";
        h.credit(q, Duration::from_secs(5), None);
        assert!(!take_credit(t, 80, q, None, now, 1), "no stream");
        let s = stream_started(t);
        h.credit(q, Duration::from_secs(5), None);
        assert!(!take_credit(t, 81, q, None, now, 1), "another session");
        assert!(
            !take_credit(t, 80, "SELECT TOP (11) x FROM [d].[s].[t]", None, now, 1),
            "another text"
        );
        assert!(
            !take_credit(t, 80, q, None, now - 60_000_000, 1),
            "before the window"
        );
        assert!(
            !take_credit(t, 80, q, None, now + 3_600_000_000, 1),
            "after the window"
        );
        assert!(take_credit(t, 80, q, None, now + 1_000_000, 7));
        assert!(
            take_credit(t, 80, q, None, now + 1_000_500, 7),
            "the same execution's other records"
        );
        assert!(
            !take_credit(t, 80, q, None, now + 1_000_000, 8),
            "consumed once"
        );
        // Without a transaction id, a credit is consumed once (review L3).
        h.credit(q, Duration::from_secs(5), None);
        assert!(take_credit(t, 80, q, None, now + 1, 0));
        assert!(!take_credit(t, 80, q, None, now + 1, 0));
        // The window covers the statement's run, not a late read.
        h.credit(q, Duration::from_secs(5), None);
        assert!(!take_credit(t, 80, q, None, now + 60_000_000, 9));
        for _ in 0..MAX_CREDITS + 5 {
            h.credit("x", Duration::from_secs(5), None);
        }
        assert!(lock().targets[t].credits.len() <= MAX_CREDITS);
        // A poll credit outlives its stream (a restarted stream reads it),
        // and is persisted by kind.
        h.credit("poll text", Duration::from_secs(5), Some(PollKind::From));
        drop(s);
        let bytes = encode(t, 64 * 1024);
        let other = "own-test-credits-2";
        reset(other);
        restore(other, decode(&bytes).unwrap());
        assert!(
            !take_credit(other, 80, "any", Some(PollKind::Start), now, 1),
            "another kind"
        );
        assert!(take_credit(
            other,
            80,
            "any",
            Some(PollKind::From),
            now + 1,
            1
        ));
        assert!(take_credit(
            t,
            80,
            "poll text",
            Some(PollKind::From),
            now + 1,
            2
        ));
    }

    #[test]
    fn persisted_sessions_round_trip_and_close_at_restart() {
        let t = "own-test-persist";
        reset(t);
        let mut h = opened(
            t,
            90,
            agent_now_us(),
            1_000,
            "::1".parse().ok(),
            Instant::now(),
        );
        let _open = opened(t, 91, agent_now_us(), 1_000, None, Instant::now());
        h.end(false, Duration::ZERO);
        let bytes = encode(t, 64 * 1024);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("v1\noffset "));
        let p = decode(&bytes).unwrap();
        assert_eq!(p.sessions.len(), 2);
        let p_saved = p.saved_us;
        let other = "own-test-persist-2";
        reset(other);
        restore(other, p);
        let s91 = lock().targets[other]
            .sessions
            .iter()
            .find(|s| s.spid == 91)
            .copied()
            .unwrap();
        let end = s91.end_us.unwrap();
        let saved = p_saved.unwrap();
        assert!(
            end <= saved + 35_000_000,
            "an open session ends at its last save plus the grace (review L4)"
        );
        assert!(decode(b"v2\n").is_none());
        assert!(decode(b"v1\noffset 0\n1 2 - x\n").is_none());
        assert!(decode(b"v1\noffset 0\nsaved x\n").is_none());
        // Cut from the oldest.
        let small = encode(t, 40);
        assert!(decode(&small).unwrap().sessions.len() <= 1);
    }

    #[test]
    fn ended_sessions_are_pruned_after_48_hours() {
        let t = "own-test-prune";
        reset(t);
        restore(
            t,
            Persisted {
                offset_us: 0,
                saved_us: None,
                sessions: vec![OwnSession {
                    spid: 1,
                    start_us: 0,
                    end_us: Some(1),
                    addr: None,
                }],
                polls: Vec::new(),
            },
        );
        assert!(lock().targets[t].sessions.is_empty());
    }
}
