//! The agent's own sessions as `performance_schema` shows them after they
//! ended (phase 8 follow-ups: security reviews of #186, L1, and of #197,
//! M3).
//!
//! A `performance_schema` poll reads the statement history, where a
//! statement keeps its `THREAD_ID` but loses its account, host and
//! `program_name` once its session has ended (`threads` no longer has a
//! row for it). Two kinds of the agent's own sessions end before a poll
//! reads all of their statements:
//!
//! - **Poll sessions** ([`PollThreads`], per connector, so per server): a
//!   poll leaves its own session out by `CONNECTION_ID()`, but a stream
//!   that reconnected (a stale or failed session, a restarted stream) or
//!   a sibling stream (another target on the same server) sees the ended
//!   session's probes and polls with no account: reads of statement-text
//!   tables by an unidentified principal, always reported. Each poll
//!   session reads its own thread id when it attaches (`sql::PS_OWN_THREAD`)
//!   and notes it here; every stream on that server run then drops the
//!   rows of that thread, as the poll text drops its own. A row whose
//!   thread is still connected under another account is never dropped.
//! - **Discovery sessions** ([`DiscoveryPins`], per target): the scan's
//!   session has usually ended when the next poll reads its samples. When
//!   the target's Audit stream polls `performance_schema`, each Discovery
//!   session reads its thread id at its start (by a random nonce in a
//!   session user variable, `sql::PS_OWN_PIN`: exactly one thread must
//!   hold it) and pins it for the
//!   target's stream until the scan ends plus two poll intervals
//!   ([`MIN_PIN_TTL`] to [`MAX_PIN_TTL`]). A row of a pinned thread with
//!   no account is attributed to the agent's identity (its account, its
//!   address as the server sees it, its `program_name`) and takes the
//!   usual own-account path: reads are charged to the own-read budget;
//!   writes, DDL and DCL, statement-text and statistics reads stay always
//!   reported.
//!
//! **Fail closed.** A thread id is matched only together with the server
//! run it was read on ([`ServerRun`]): the server's identity (`@@hostname`,
//! `@@port`, `@@server_id`, read in the same statement as the thread id
//! on the same session)
//! and its start time (`Uptime` against the agent's clock, within
//! [`RUN_TOLERANCE_S`]); `performance_schema` thread ids are not reused
//! within a server run, but a restarted server counts them from 1 again.
//! Nothing is noted on a server that started less than [`MIN_UPTIME_S`]
//! ago, so that a restart after the note never gives a start time within
//! the tolerance. Unknown identity or start time: nothing is noted nor
//! matched. Both sets are bounded (the oldest are dropped: their rows are
//! then reported, as before) and kept in memory only: after an agent
//! restart, the statements of its earlier sessions that the persisted
//! cursor reads again are reported as before.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Two start times (Unix seconds, each `now - Uptime` read at another
/// time) this close are the same server run.
pub(crate) const RUN_TOLERANCE_S: u64 = 2;
/// Nothing is noted on a server up for less than this: a restart after
/// the note gives a start time at least the uptime of then later.
pub(crate) const MIN_UPTIME_S: u64 = 10;
/// Server runs whose poll threads are kept at most.
const MAX_RUNS: usize = 64;
/// Poll threads kept per server run at most.
const MAX_POLL_THREADS: usize = 1024;
/// Discovery pins kept at most (every target of the connector).
pub(crate) const MAX_PINS: usize = 4096;
/// Shortest and longest life of a pin after its scan ended.
pub(crate) const MIN_PIN_TTL: Duration = Duration::from_secs(30);
pub(crate) const MAX_PIN_TTL: Duration = Duration::from_secs(900);
/// Longest life of a pin whose scan never reported its end.
const MAX_OPEN_PIN: Duration = Duration::from_secs(25 * 3600);

/// One run of one server: its identity and its start time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerRun {
    ident: String,
    boot: u64,
}

impl ServerRun {
    /// The run from the identity columns of `sql::PS_OWN_THREAD`
    /// (`@@hostname`, `@@port`, `@@server_id`) and the start time. `None`
    /// when a column is missing or empty.
    pub(crate) fn new(ident: &[Option<String>], boot: u64) -> Option<Self> {
        if ident.is_empty() || ident.iter().any(|c| c.as_deref().is_none_or(str::is_empty)) {
            return None;
        }
        let ident = ident
            .iter()
            .map(|c| c.as_deref().unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\u{0}");
        Some(Self { ident, boot })
    }

    /// Whether `other` is the same server run.
    pub(crate) fn same(&self, other: &Self) -> bool {
        self.ident == other.ident && self.boot.abs_diff(other.boot) <= RUN_TOLERANCE_S
    }
}

/// The agent's poll sessions' threads, per server run (see the module
/// documentation). One per connector: every stream on a server shares it.
#[derive(Default)]
pub(crate) struct PollThreads {
    runs: VecDeque<(ServerRun, VecDeque<u64>)>,
}

pub(crate) type SharedPollThreads = Arc<Mutex<PollThreads>>;

impl PollThreads {
    /// Notes `thread` as a poll session of `run`, up `uptime` seconds.
    pub(crate) fn note(&mut self, run: &ServerRun, uptime: u64, thread: u64) {
        if uptime < MIN_UPTIME_S {
            return;
        }
        // Another run of the same server: its threads mean nothing now.
        self.runs
            .retain(|(r, _)| r.ident != run.ident || r.same(run));
        if let Some((_, threads)) = self.runs.iter_mut().find(|(r, _)| r.same(run)) {
            if !threads.contains(&thread) {
                if threads.len() >= MAX_POLL_THREADS {
                    threads.pop_front();
                }
                threads.push_back(thread);
            }
            return;
        }
        if self.runs.len() >= MAX_RUNS {
            self.runs.pop_front();
        }
        self.runs.push_back((run.clone(), VecDeque::from([thread])));
    }

    /// Whether `thread` of `run` is one of the agent's poll sessions.
    pub(crate) fn contains(&self, run: &ServerRun, thread: u64) -> bool {
        self.runs
            .iter()
            .any(|(r, threads)| r.same(run) && threads.contains(&thread))
    }
}

struct Pin {
    run: ServerRun,
    thread: u64,
    /// The account the pinning target's Discovery connects with.
    account: String,
    /// `None` while its scan runs (bounded by [`MAX_OPEN_PIN`]).
    until: Option<Instant>,
    pinned: Instant,
}

impl Pin {
    fn live(&self, now: Instant) -> bool {
        match self.until {
            Some(until) => now < until,
            None => now.saturating_duration_since(self.pinned) < MAX_OPEN_PIN,
        }
    }
}

/// The threads of the agent's Discovery sessions (see the module
/// documentation), per server run: shared by the connector's scans and
/// streams, so that every stream on the server (a sibling target's too)
/// knows them.
#[derive(Default)]
pub(crate) struct DiscoveryPins {
    pins: VecDeque<Pin>,
    /// Per target: its `performance_schema` streams running, and the poll
    /// interval of the last one started.
    streams: HashMap<String, (usize, Duration)>,
}

pub(crate) type SharedPins = Arc<Mutex<DiscoveryPins>>;

impl DiscoveryPins {
    /// A `performance_schema` stream of `target` starts.
    pub(crate) fn stream_started(&mut self, target: &str, poll: Duration) {
        let e = self.streams.entry(target.to_owned()).or_insert((0, poll));
        *e = (e.0.saturating_add(1), poll);
    }

    /// A `performance_schema` stream of `target` ends.
    pub(crate) fn stream_ended(&mut self, target: &str) {
        if let Some(e) = self.streams.get_mut(target) {
            e.0 = e.0.saturating_sub(1);
            if e.0 == 0 {
                self.streams.remove(target);
            }
        }
    }

    /// Whether Discovery of `target` pins its sessions: only while a
    /// `performance_schema` stream of the target runs (the thread id is
    /// read from `performance_schema`, which the file sources do not
    /// need).
    pub(crate) fn accepting(&self, target: &str) -> bool {
        self.streams.contains_key(target)
    }

    /// Life of a pin of `target` after its scan ended: two poll intervals
    /// of the target's stream.
    pub(crate) fn ttl(&self, target: &str) -> Duration {
        (self
            .streams
            .get(target)
            .map_or(Duration::from_secs(60), |e| e.1)
            * 2)
        .clamp(MIN_PIN_TTL, MAX_PIN_TTL)
    }

    fn expire(&mut self, now: Instant) {
        self.pins.retain(|p| p.live(now));
    }

    /// Pins `thread` of `run`, a Discovery session of `target` under
    /// `account`, on a server up `uptime` seconds. `false` when not
    /// pinned.
    pub(crate) fn pin(
        &mut self,
        target: &str,
        account: &str,
        run: &ServerRun,
        uptime: u64,
        thread: u64,
        now: Instant,
    ) -> bool {
        if !self.accepting(target) || uptime < MIN_UPTIME_S {
            return false;
        }
        self.expire(now);
        while self.pins.len() >= MAX_PINS {
            self.pins.pop_front();
        }
        self.pins.push_back(Pin {
            run: run.clone(),
            thread,
            account: account.to_owned(),
            until: None,
            pinned: now,
        });
        true
    }

    /// The scan of `target` that pinned `threads` ended at `now`: they
    /// expire after [`Self::ttl`].
    pub(crate) fn release(&mut self, target: &str, threads: &[(ServerRun, u64)], now: Instant) {
        let until = now + self.ttl(target);
        for p in &mut self.pins {
            if p.until.is_none()
                && threads
                    .iter()
                    .any(|(run, thread)| *thread == p.thread && run.same(&p.run))
            {
                p.until = Some(until);
            }
        }
    }

    /// The account of the live pin of `thread` of `run`, if any.
    pub(crate) fn matches(&mut self, run: &ServerRun, thread: u64, now: Instant) -> Option<String> {
        self.expire(now);
        self.pins
            .iter()
            .find(|p| p.thread == thread && p.run.same(run))
            .map(|p| p.account.clone())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.pins.len()
    }
}

fn lock(pins: &SharedPins) -> std::sync::MutexGuard<'_, DiscoveryPins> {
    pins.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Marks a `performance_schema` stream of a target as running while it
/// lives (see [`DiscoveryPins::accepting`]).
pub(crate) struct PsStreamMark {
    pins: SharedPins,
    target: String,
}

impl PsStreamMark {
    pub(crate) fn new(pins: SharedPins, target: &str, poll: Duration) -> Self {
        lock(&pins).stream_started(target, poll);
        Self {
            pins,
            target: target.to_owned(),
        }
    }
}

impl Drop for PsStreamMark {
    fn drop(&mut self) {
        lock(&self.pins).stream_ended(&self.target);
    }
}

/// The pins of one Discovery scan: each of its sessions is pinned at its
/// start ([`Self::pin`]); they expire two poll intervals after the scan
/// ends (when this is dropped, whatever the outcome).
pub(crate) struct ScanPins {
    shared: SharedPins,
    target: String,
    account: String,
    pinned: Vec<(ServerRun, u64)>,
}

impl ScanPins {
    pub(crate) fn new(shared: SharedPins, target: &str, account: &str) -> Self {
        Self {
            shared,
            target: target.to_owned(),
            account: account.to_owned(),
            pinned: Vec::new(),
        }
    }

    /// Pins `session`'s thread when the target's Audit stream polls
    /// `performance_schema`. Nothing when it does not, or when the thread
    /// or the server run cannot be read (its rows then have no account, as
    /// before); a fatal error leaves the session poisoned for its next
    /// statement.
    pub(crate) async fn pin(&mut self, session: &mut crate::conn::Session) {
        if !lock(&self.shared).accepting(&self.target) {
            return;
        }
        let own = match super::pfs::pinned_session(session, crate::error::Stage::Sample).await {
            Ok(Some(own)) => own,
            Ok(None) | Err(_) => {
                tracing::debug!(
                    target_id = %self.target,
                    "discovery session not pinned: its thread is not readable"
                );
                return;
            }
        };
        let Some(run) = own.run else {
            tracing::debug!(
                target_id = %self.target,
                "discovery session not pinned: server identity or start unknown"
            );
            return;
        };
        let pinned = lock(&self.shared).pin(
            &self.target,
            &self.account,
            &run,
            own.uptime,
            own.thread,
            Instant::now(),
        );
        if pinned && self.pinned.len() < MAX_PINS {
            self.pinned.push((run, own.thread));
        }
    }
}

impl Drop for ScanPins {
    fn drop(&mut self) {
        if !self.pinned.is_empty() {
            lock(&self.shared).release(&self.target, &self.pinned, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(host: &str, boot: u64) -> ServerRun {
        ServerRun::new(
            &[
                Some(host.to_owned()),
                Some("3306".to_owned()),
                Some("1".to_owned()),
            ],
            boot,
        )
        .unwrap()
    }

    #[test]
    fn a_server_run_is_its_identity_and_start_time() {
        let a = run("db1", 1_000_000);
        assert!(a.same(&run("db1", 1_000_000 + RUN_TOLERANCE_S)));
        assert!(a.same(&run("db1", 1_000_000 - RUN_TOLERANCE_S)));
        assert!(!a.same(&run("db1", 1_000_000 + RUN_TOLERANCE_S + 1)));
        assert!(!a.same(&run("db2", 1_000_000)));
        // The columns are joined unambiguously.
        let x = ServerRun::new(&[Some("a".into()), Some("b c".into())], 1).unwrap();
        let y = ServerRun::new(&[Some("a b".into()), Some("c".into())], 1).unwrap();
        assert!(!x.same(&y));
        // Missing or empty identity: no run.
        assert!(ServerRun::new(&[Some("db".into()), None], 1).is_none());
        assert!(ServerRun::new(&[Some("db".into()), Some(String::new())], 1).is_none());
        assert!(ServerRun::new(&[], 1).is_none());
    }

    #[test]
    fn poll_threads_are_per_server_run_and_bounded() {
        let mut p = PollThreads::default();
        let r = run("db1", 1_000_000);
        p.note(&r, 3600, 42);
        assert!(p.contains(&r, 42));
        assert!(p.contains(&run("db1", 1_000_001), 42));
        assert!(!p.contains(&r, 43));
        // Another server, or the same server restarted: not matched.
        assert!(!p.contains(&run("db2", 1_000_000), 42));
        assert!(!p.contains(&run("db1", 1_003_600), 42));
        // A server that just started: nothing noted.
        p.note(&run("db3", 2_000_000), MIN_UPTIME_S - 1, 7);
        assert!(!p.contains(&run("db3", 2_000_000), 7));
        // A restart of db1 seen by a new note forgets the old run.
        p.note(&run("db1", 1_003_600), 60, 5);
        assert!(!p.contains(&r, 42));
        assert!(p.contains(&run("db1", 1_003_600), 5));
        // Bounded: the oldest threads, then the oldest runs, are dropped.
        let r = run("db4", 5_000_000);
        for t in 0..(MAX_POLL_THREADS as u64 + 5) {
            p.note(&r, 3600, t);
        }
        assert!(!p.contains(&r, 0));
        assert!(p.contains(&r, MAX_POLL_THREADS as u64 + 4));
        for i in 0..(MAX_RUNS as u64 + 1) {
            p.note(&run(&format!("h{i}"), 9_000_000), 3600, 1);
        }
        assert!(p.runs.len() <= MAX_RUNS);
        assert!(!p.contains(&r, MAX_POLL_THREADS as u64 + 4));
    }

    #[test]
    fn discovery_pins_need_a_stream_and_expire_after_the_scan() {
        let now = Instant::now();
        let mut d = DiscoveryPins::default();
        let r = run("db1", 1_000_000);
        let pin = |d: &mut DiscoveryPins, uptime: u64, thread: u64| {
            d.pin("t1", "databastion", &r, uptime, thread, now)
        };
        // No performance_schema stream of the target: no pin.
        assert!(!pin(&mut d, 3600, 9));
        d.stream_started("t2", Duration::from_secs(60));
        assert!(!pin(&mut d, 3600, 9));
        d.stream_started("t1", Duration::from_secs(60));
        assert!(d.accepting("t1"));
        assert!(!pin(&mut d, MIN_UPTIME_S - 1, 9));
        assert!(pin(&mut d, 3600, 9));
        // While the scan runs: matched, for this run only, with the
        // account (every stream of the connector on that server).
        assert_eq!(
            d.matches(&r, 9, now + Duration::from_secs(7200)).as_deref(),
            Some("databastion")
        );
        assert!(d.matches(&r, 10, now).is_none());
        assert!(d.matches(&run("db1", 1_000_100), 9, now).is_none());
        assert!(d.matches(&run("db2", 1_000_000), 9, now).is_none());
        // An open pin still has a bound.
        assert!(!d.clone_matches(&r, 9, now + MAX_OPEN_PIN));
        // The scan ends: two polls of the target's stream later, the pin
        // is gone.
        d.release("t1", &[(r.clone(), 9)], now);
        assert_eq!(d.ttl("t1"), Duration::from_secs(120));
        assert!(d.matches(&r, 9, now + Duration::from_secs(119)).is_some());
        assert!(d.matches(&r, 9, now + Duration::from_secs(120)).is_none());
        assert_eq!(d.len(), 0);
        // The TTL is bounded.
        d.stream_started("t1", Duration::from_secs(1));
        assert_eq!(d.ttl("t1"), MIN_PIN_TTL);
        d.stream_started("t1", Duration::from_secs(3600));
        assert_eq!(d.ttl("t1"), MAX_PIN_TTL);
        for _ in 0..3 {
            d.stream_ended("t1");
        }
        assert!(!d.accepting("t1"));
        assert!(d.accepting("t2"));
        // Bounded count: the oldest dropped.
        d.stream_started("t1", Duration::from_secs(60));
        for t in 0..(MAX_PINS as u64 + 3) {
            assert!(pin(&mut d, 3600, t));
        }
        assert_eq!(d.len(), MAX_PINS);
        assert!(d.matches(&r, 0, now).is_none());
        assert!(d.matches(&r, MAX_PINS as u64 + 2, now).is_some());
    }

    impl DiscoveryPins {
        /// `matches` without expiring the others (test helper).
        fn clone_matches(&self, run: &ServerRun, thread: u64, now: Instant) -> bool {
            self.pins
                .iter()
                .any(|p| p.thread == thread && p.run.same(run) && p.live(now))
        }
    }
}
