//! The agent's own activity in an audit source (engine-agnostic).
//!
//! The agent's Discovery scans read the monitored tables with the agent's
//! own account. Those reads are left out of the access events only when
//! all of these hold ([`OwnAccount::routine`]): the event is a read (or a
//! connection; writes, DDL and DCL are always reported), the account is the agent's,
//! the application name (when the source logs one) is the agent's, the
//! client address (when the source logs one) is the agent's own address as
//! the server sees it, the event carries no signal, and the agent's reads
//! of each object stay within one Discovery scan's row budget over a
//! rolling 24 h. With stolen agent credentials, reads from elsewhere, reads
//! that look like exports, and reading more of a table than one Discovery
//! scan per day are still reported.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use databastion_classifiers::masking::{ClientAddr, EventAction, MaskedEvent};
use serde::{Deserialize, Serialize};

use crate::AuditConfig;
use crate::audit::CursorStore;

/// Period over which the agent's own reads of one object are budgeted.
const OWN_PERIOD_HOURS: u64 = 24;
/// Objects budgeted at most; beyond, the agent's own reads of a new
/// object are reported.
const OWN_MAX_OBJECTS: usize = 10_000;
/// Name of the counters file (`<target_id>.own_usage.counters`).
const OWN_COUNTERS: &str = "own_usage";

/// Where the client address of an event comes from.
#[derive(Debug, Clone, Copy)]
pub enum ClientSeen {
    /// The source logs it; `None`: not logged for this event.
    Logged(Option<ClientAddr>),
    /// The source never shows it (`pg_stat_statements`); the agent's own
    /// address must still be known (read from the server) for anything to
    /// be left out.
    NotVisible,
    /// The source records no client address at all, for anyone (OpenLDAP
    /// `cn=accesslog`), and the engine cannot tell the agent its own
    /// address: the address rule does not apply, and only the identity,
    /// signal and row-budget rules remain (ADR-0029 decision 9).
    NotRecorded,
}

/// Rows the agent's own account read per object, per hour, over the last
/// 24 hours. Kept per target by the connector, so it outlives streams: a
/// restarted stream (failure, source switch, the agent's sessions
/// terminated on purpose) does not get a fresh budget. Persisted across
/// agent restarts once a stream attaches its counters file
/// ([`OwnAccount::persisted`]): object names (normalized, as sent in the
/// events) and row counts per hour only, never a value.
#[derive(Debug)]
pub struct OwnUsage {
    start: Instant,
    /// Wall-clock seconds at `start`: hours are absolute (Unix hours), so
    /// the counters mean the same after a restart.
    start_unix_s: u64,
    usage: HashMap<String, VecDeque<(u64, u64)>>,
    /// Where the counters are persisted (`None`: in memory only).
    store: Option<CursorStore>,
    /// Charges not saved yet.
    dirty: bool,
    /// Last save attempt.
    saved: Option<Instant>,
}

impl Default for OwnUsage {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            start_unix_s: std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            usage: HashMap::new(),
            store: None,
            dirty: false,
            saved: None,
        }
    }
}

/// Least time between two saves of the counters (a restart loses at most
/// the charges of this period, besides those of a stream that ended).
const OWN_SAVE_EVERY: Duration = Duration::from_secs(30);
/// Version tag of the counters file.
const OWN_FILE_VERSION: u32 = 1;

/// The persisted form: per object, its hourly charges.
#[derive(Debug, Serialize, Deserialize)]
struct OwnFile {
    v: u32,
    /// (object key, [(Unix hour, rows)]).
    o: Vec<(String, Vec<(u64, u64)>)>,
}

impl OwnUsage {
    /// Keys of the objects with a charge (`database NUL schema NUL
    /// object`), in no order: what the budget currently tracks.
    #[must_use]
    pub fn budgeted_objects(&self) -> Vec<String> {
        self.usage.keys().cloned().collect()
    }

    /// The absolute hour of `now`.
    fn hour(&self, now: Instant) -> u64 {
        self.start_unix_s
            .saturating_add(now.saturating_duration_since(self.start).as_secs())
            / 3600
    }

    /// Persists the counters to `store` from now on. The first store
    /// attached is loaded and merged into the counters (added to what was
    /// charged in memory before); later calls change nothing. A file that
    /// cannot be read or parsed is ignored (counted from zero, as before
    /// persistence) and logged by kind only.
    pub fn attach(&mut self, store: CursorStore, now: Instant) {
        if self.store.is_some() {
            return;
        }
        let current = self.hour(now);
        match store.load() {
            Ok(None) => {}
            Ok(Some(bytes)) => match serde_json::from_slice::<OwnFile>(&bytes) {
                Ok(file) if file.v == OWN_FILE_VERSION => {
                    self.merge(file, current);
                }
                _ => tracing::warn!("own-account counters file not understood: counting from zero"),
            },
            Err(e) => tracing::warn!(error = %e, "own-account counters not readable"),
        }
        self.store = Some(store);
    }

    /// Adds the persisted charges of the last 24 hours. Hours in the
    /// future (the clock went back) count as the current hour, so a charge
    /// is never lost to a clock change; at most [`OWN_MAX_OBJECTS`]
    /// objects are taken.
    fn merge(&mut self, file: OwnFile, current: u64) {
        for (key, hours) in file.o {
            if !self.usage.contains_key(&key) && self.usage.len() >= OWN_MAX_OBJECTS {
                break;
            }
            let mut merged: std::collections::BTreeMap<u64, u64> =
                std::collections::BTreeMap::new();
            for (h, n) in self.usage.remove(&key).unwrap_or_default() {
                let e = merged.entry(h).or_default();
                *e = e.saturating_add(n);
            }
            for (h, n) in hours.into_iter().take(2 * OWN_PERIOD_HOURS as usize) {
                let h = h.min(current);
                if current.saturating_sub(h) >= OWN_PERIOD_HOURS {
                    continue;
                }
                let e = merged.entry(h).or_default();
                *e = e.saturating_add(n);
            }
            if !merged.is_empty() {
                self.usage.insert(key, merged.into_iter().collect());
            }
        }
    }

    /// Saves the counters when due (`force`: whenever something changed).
    fn persist(&mut self, now: Instant, force: bool) {
        if !self.dirty || self.store.is_none() {
            return;
        }
        if !force
            && self
                .saved
                .is_some_and(|t| now.saturating_duration_since(t) < OWN_SAVE_EVERY)
        {
            return;
        }
        self.saved = Some(now);
        let current = self.hour(now);
        // Objects with the latest charges first: when the file would be
        // too large, the objects left out are those read longest ago.
        let mut objects: Vec<(String, Vec<(u64, u64)>)> = self
            .usage
            .iter()
            .filter_map(|(k, v)| {
                let hours: Vec<(u64, u64)> = v
                    .iter()
                    .copied()
                    .filter(|(h, _)| current.saturating_sub(*h) < OWN_PERIOD_HOURS)
                    .collect();
                (!hours.is_empty()).then(|| (k.clone(), hours))
            })
            .collect();
        objects.sort_by(|a, b| {
            let last = |o: &(String, Vec<(u64, u64)>)| o.1.last().map_or(0, |(h, _)| *h);
            last(b).cmp(&last(a)).then_with(|| a.0.cmp(&b.0))
        });
        let mut file = OwnFile {
            v: OWN_FILE_VERSION,
            o: objects,
        };
        let bytes = loop {
            let Ok(bytes) = serde_json::to_vec(&file) else {
                return;
            };
            if bytes.len() <= crate::audit::MAX_COUNTERS_BYTES || file.o.is_empty() {
                break bytes;
            }
            // Too large: drop the least recent quarter and retry.
            let keep = file.o.len() - file.o.len().div_ceil(4);
            tracing::warn!(
                left_out = file.o.len() - keep,
                "own-account counters too large to persist in full: the objects read longest \
                 ago are left out"
            );
            file.o.truncate(keep);
        };
        if let Some(store) = &self.store {
            match store.save(&bytes) {
                Ok(()) => self.dirty = false,
                Err(e) => tracing::warn!(error = %e, "own-account counters not saved"),
            }
        }
    }
}

/// Shared handle on a target's [`OwnUsage`].
pub type SharedOwnUsage = std::sync::Arc<std::sync::Mutex<OwnUsage>>;

/// Attaches `store` to the shared counters ([`OwnUsage::attach`]) and, on
/// the first attachment, starts a task that saves the counters every
/// `every` when a charge is not saved yet (phase-7 security review: a
/// charge shortly after a save, followed by no activity, stayed unsaved
/// until a later charge or the end of the stream, and was lost on a crash
/// or a kill). Without a Tokio runtime (synchronous callers), no task is
/// started.
///
/// Lifetime: the task holds a weak handle and ends once the counters are
/// dropped. The connectors keep one [`SharedOwnUsage`] per target id for
/// the life of the process (it outlives streams, by design), so in
/// practice there is one task per target id with a counters file, ending
/// with the runtime; a reconfigured target keeps its task. Each save runs
/// on the blocking pool (`spawn_blocking`), not on a runtime worker.
fn attach_and_flush(usage: &SharedOwnUsage, store: CursorStore, every: Duration) {
    let first = {
        let mut guard = usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let first = guard.store.is_none();
        guard.attach(store, Instant::now());
        first
    };
    if !first {
        return;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let weak = std::sync::Arc::downgrade(usage);
    handle.spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate.
        tick.tick().await;
        loop {
            tick.tick().await;
            let Some(usage) = weak.upgrade() else {
                break;
            };
            let saved = tokio::task::spawn_blocking(move || {
                usage
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .persist(Instant::now(), true);
            })
            .await;
            if saved.is_err() {
                tracing::warn!("own-account counters not saved (flush task failed)");
            }
        }
    });
}

/// The agent's own activity, which may be left out of the events.
#[derive(Debug)]
pub struct OwnAccount {
    account: String,
    /// Application name the agent's sessions carry, when the engine lets
    /// the client declare one.
    application: Option<String>,
    /// Client address the server sees for the agent (`None`: could not be
    /// read; then nothing is left out).
    addr: Option<ClientAddr>,
    /// Rows per object over [`OWN_PERIOD_HOURS`] above which the agent's
    /// own reads are reported anyway (`limits.max_sample_rows`: one
    /// Discovery scan never reads more per object).
    budget: u64,
    /// Per object: rows per hour (hour index, rows), last 24 hours.
    usage: SharedOwnUsage,
}

impl OwnAccount {
    /// The agent's account `account`, whose sessions carry `application`
    /// (when the engine has such a name) and come from `addr` as the
    /// server sees it.
    #[must_use]
    pub fn new(
        account: &str,
        application: Option<&str>,
        addr: Option<ClientAddr>,
        budget: u64,
        usage: SharedOwnUsage,
    ) -> Self {
        Self {
            account: account.to_owned(),
            application: application.map(str::to_owned),
            addr,
            budget,
            usage,
        }
    }

    /// Persists the shared counters in `cfg`'s counters file `own_usage`
    /// (under `<state_dir>/audit/`), so an agent restart keeps the
    /// budget spent in the last 24 hours. The first stream of the target
    /// loads them; without a state directory they stay in memory.
    ///
    /// The first attachment also starts a periodic flush
    /// ([`attach_and_flush`]): charges made within [`OWN_SAVE_EVERY`] of
    /// the last save and followed by no activity are saved at the next
    /// tick, not only when a later charge or the end of a stream saves
    /// them.
    #[must_use]
    pub fn persisted(self, cfg: &AuditConfig) -> Self {
        if let Some(store) = cfg.counters(OWN_COUNTERS) {
            attach_and_flush(&self.usage, store, OWN_SAVE_EVERY);
        }
        self
    }

    fn lock_usage(&self) -> std::sync::MutexGuard<'_, OwnUsage> {
        self.usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Replaces the agent's own address (re-read by the connector at each
    /// re-probe of its source).
    pub fn set_addr(&mut self, addr: Option<ClientAddr>) {
        self.addr = addr;
    }

    /// Charges `rows` to an object; `true` when its 24 h total exceeds the
    /// budget (or it cannot be tracked).
    fn charge(&mut self, key: String, rows: u64, now: Instant) -> bool {
        let mut guard = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hour = guard.hour(now);
        guard.dirty = true;
        let usage = &mut guard.usage;
        if !usage.contains_key(&key) && usage.len() >= OWN_MAX_OBJECTS {
            // Drop objects with no use in the period, then fail open to
            // reporting.
            usage.retain(|_, v| {
                v.back()
                    .is_some_and(|(h, _)| hour.saturating_sub(*h) < OWN_PERIOD_HOURS)
            });
            if usage.len() >= OWN_MAX_OBJECTS {
                return true;
            }
        }
        let buckets = usage.entry(key).or_default();
        while buckets
            .front()
            .is_some_and(|(h, _)| hour.saturating_sub(*h) >= OWN_PERIOD_HOURS)
        {
            buckets.pop_front();
        }
        match buckets.back_mut() {
            Some((h, n)) if *h == hour => *n = n.saturating_add(rows),
            _ => buckets.push_back((hour, rows)),
        }
        let total = buckets
            .iter()
            .fold(0u64, |acc, (_, n)| acc.saturating_add(*n));
        total > self.budget
    }

    /// Whether an event may be left out: the agent's account, its
    /// application name (when the source logs one: `application` is the
    /// logged value), its own client address (when the source logs
    /// addresses; the agent's address must be known), no signal, and at
    /// most `budget` rows per object over 24 hours (unknown rows are
    /// charged the whole budget). The rows are charged whenever the account
    /// is the agent's. When the agent's own address is unknown, nothing is
    /// left out.
    pub fn routine(
        &mut self,
        user: &str,
        application: Option<&str>,
        client: ClientSeen,
        e: &MaskedEvent,
        now: Instant,
    ) -> bool {
        // The agent only reads (I4): a write, DDL or DCL with its identity
        // is someone else using it, and is always reported.
        if user != self.account || !matches!(e.action(), EventAction::Read | EventAction::Connect) {
            return false;
        }
        let rows = e.rows().unwrap_or(self.budget);
        let identity = self.identity(application, client);
        let mut over = false;
        for o in e.objects() {
            let key = format!(
                "{}\u{0}{}\u{0}{}",
                o.database().as_str(),
                o.schema().map_or("", |s| s.as_str()),
                o.object().as_str()
            );
            over |= self.charge(key, rows, now);
        }
        if !e.objects().is_empty() {
            self.lock_usage().persist(now, false);
        }
        identity && e.signals().is_empty() && !over
    }

    /// Like [`OwnAccount::routine`] (account, application, address, no
    /// signal) but without the row budget: nothing is charged. Only for
    /// statements a connector recognizes as its own by their whole, exact
    /// text: catalog queries and `performance_schema` probes and polls,
    /// which read no application row, and the extra batches of a sampling
    /// statement whose first batch was charged (a credit). A connector
    /// that has no such list never calls it.
    #[must_use]
    pub fn routine_unbudgeted(
        &self,
        user: &str,
        application: Option<&str>,
        client: ClientSeen,
        e: &MaskedEvent,
    ) -> bool {
        user == self.account
            && matches!(e.action(), EventAction::Read | EventAction::Connect)
            && self.identity(application, client)
            && e.signals().is_empty()
    }

    /// The application (when logged) and the client address are the
    /// agent's; the agent's own address must be known.
    fn identity(&self, application: Option<&str>, client: ClientSeen) -> bool {
        let addr_ok = match (self.addr, client) {
            (_, ClientSeen::NotRecorded) => true,
            (None, _) => false,
            (Some(own), ClientSeen::Logged(Some(c))) => own == c,
            (Some(_), ClientSeen::Logged(None)) => false,
            (Some(_), ClientSeen::NotVisible) => true,
        };
        let app_ok = match application {
            None => true,
            Some(a) => self.application.as_deref() == Some(a),
        };
        app_ok && addr_ok
    }
}

impl Drop for OwnAccount {
    /// A stream that ends (failure, source switch, reconfiguration,
    /// shutdown) saves the charges not saved yet.
    fn drop(&mut self) {
        self.lock_usage().persist(Instant::now(), true);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::time::{Duration, SystemTime};

    use databastion_classifiers::masking::{
        EventAction, EventObject, EventPrincipal, EventSource, Signal,
    };
    use databastion_classifiers::names::normalize_path;

    use super::*;

    fn own(addr: Option<&str>) -> OwnAccount {
        OwnAccount::new(
            "databastion",
            Some("databastion-agent"),
            addr.and_then(ClientAddr::parse),
            1000,
            SharedOwnUsage::default(),
        )
    }

    fn ev(rows: Option<u64>) -> MaskedEvent {
        MaskedEvent::new(
            EventSource::Pgaudit,
            EventAction::Read,
            EventPrincipal::account("databastion"),
            SystemTime::UNIX_EPOCH,
        )
        .with_object(EventObject::new(
            normalize_path("shop"),
            Some(normalize_path("crm")),
            normalize_path("t"),
        ))
        .with_rows(rows)
    }

    #[test]
    fn unbudgeted_routine_is_for_reads_and_connections_only() {
        let o = own(Some("192.0.2.14"));
        let logged = ClientSeen::Logged(ClientAddr::parse("192.0.2.14"));
        for (action, expected) in [
            (EventAction::Read, true),
            (EventAction::Connect, true),
            (EventAction::Write, false),
            (EventAction::Ddl, false),
            (EventAction::Dcl, false),
        ] {
            let e = MaskedEvent::new(
                EventSource::Pgaudit,
                action,
                EventPrincipal::account("databastion"),
                SystemTime::UNIX_EPOCH,
            );
            assert_eq!(
                o.routine_unbudgeted("databastion", Some("databastion-agent"), logged, &e),
                expected,
                "{action:?}"
            );
        }
    }

    #[test]
    fn sources_without_addresses_rely_on_identity_signal_and_budget() {
        let now = Instant::now();
        // No address known for the agent, none recorded by the source.
        let mut o = OwnAccount::new(
            "cn=databastion,ou=services,dc=example,dc=org",
            None,
            None,
            1000,
            SharedOwnUsage::default(),
        );
        let user = "cn=databastion,ou=services,dc=example,dc=org";
        let seen = ClientSeen::NotRecorded;
        assert!(o.routine(user, None, seen, &ev(Some(600)), now));
        assert!(o.routine_unbudgeted(user, None, seen, &ev(Some(5000))));
        // Over the budget, with a signal, another identity, or a write:
        // reported.
        assert!(!o.routine(user, None, seen, &ev(Some(600)), now));
        assert!(!o.routine("cn=other", None, seen, &ev(Some(1)), now));
        let signalled = ev(Some(1)).with_signal(Signal::LargeResult);
        assert!(!o.routine_unbudgeted(user, None, seen, &signalled));
        let write = MaskedEvent::new(
            EventSource::OpenldapAccesslog,
            EventAction::Write,
            EventPrincipal::account(user),
            SystemTime::UNIX_EPOCH,
        );
        assert!(!o.routine_unbudgeted(user, None, seen, &write));
        // `NotVisible` still needs the agent's own address.
        assert!(!o.routine_unbudgeted(user, None, ClientSeen::NotVisible, &ev(Some(1))));
    }

    #[test]
    fn own_writes_ddl_and_dcl_are_never_routine() {
        let now = Instant::now();
        let logged = ClientSeen::Logged(ClientAddr::parse("192.0.2.14"));
        for action in [EventAction::Write, EventAction::Ddl, EventAction::Dcl] {
            let e = MaskedEvent::new(
                EventSource::Pgaudit,
                action,
                EventPrincipal::account("databastion"),
                SystemTime::UNIX_EPOCH,
            );
            assert!(!own(Some("192.0.2.14")).routine(
                "databastion",
                Some("databastion-agent"),
                logged,
                &e,
                now
            ));
        }
        let connect = MaskedEvent::new(
            EventSource::Pgaudit,
            EventAction::Connect,
            EventPrincipal::account("databastion"),
            SystemTime::UNIX_EPOCH,
        );
        assert!(own(Some("192.0.2.14")).routine(
            "databastion",
            Some("databastion-agent"),
            logged,
            &connect,
            now
        ));
    }

    #[test]
    fn own_budget_spans_a_day_not_a_window() {
        let mut o = own(Some("192.0.2.14"));
        let t0 = Instant::now();
        let key = || "shop\u{0}crm\u{0}t".to_owned();
        assert!(!o.charge(key(), 600, t0));
        // An hour later (past any aggregation window): still counted.
        assert!(o.charge(key(), 600, t0 + Duration::from_secs(3600)));
        // A day later: the first charges have aged out.
        let mut o = own(Some("192.0.2.14"));
        assert!(!o.charge(key(), 600, t0));
        assert!(!o.charge(key(), 600, t0 + Duration::from_secs(25 * 3600)));
    }

    #[test]
    fn unbudgeted_routine_has_the_same_identity_rules_and_charges_nothing() {
        let addr = ClientAddr::parse("192.0.2.14");
        let logged = ClientSeen::Logged(addr);
        let usage = SharedOwnUsage::default();
        let o = OwnAccount::new(
            "databastion",
            Some("databastion-agent"),
            addr,
            1,
            std::sync::Arc::clone(&usage),
        );
        for _ in 0..3 {
            assert!(o.routine_unbudgeted(
                "databastion",
                Some("databastion-agent"),
                logged,
                &ev(None)
            ));
        }
        assert!(usage.lock().unwrap().budgeted_objects().is_empty());
        assert!(!o.routine_unbudgeted("other", None, logged, &ev(None)));
        assert!(!o.routine_unbudgeted("databastion", Some("psql"), logged, &ev(None)));
        assert!(!o.routine_unbudgeted(
            "databastion",
            None,
            ClientSeen::Logged(ClientAddr::parse("198.51.100.7")),
            &ev(None)
        ));
        assert!(!o.routine_unbudgeted(
            "databastion",
            None,
            logged,
            &ev(None).with_signal(Signal::LargeResult)
        ));
        assert!(!own(None).routine_unbudgeted(
            "databastion",
            None,
            ClientSeen::NotVisible,
            &ev(None)
        ));
    }

    #[test]
    fn routine_needs_account_application_address_and_no_signal() {
        let now = Instant::now();
        let addr = ClientAddr::parse("192.0.2.14");
        let logged = ClientSeen::Logged(addr);
        assert!(own(Some("192.0.2.14")).routine(
            "databastion",
            Some("databastion-agent"),
            logged,
            &ev(Some(10)),
            now
        ));
        // Application not logged by the source: not held against it.
        assert!(own(Some("192.0.2.14")).routine("databastion", None, logged, &ev(Some(10)), now));
        assert!(!own(Some("192.0.2.14")).routine(
            "databastion",
            Some("mysqldump"),
            logged,
            &ev(Some(10)),
            now
        ));
        assert!(!own(Some("192.0.2.14")).routine("other", None, logged, &ev(Some(10)), now));
        assert!(!own(Some("192.0.2.14")).routine(
            "databastion",
            None,
            ClientSeen::Logged(ClientAddr::parse("198.51.100.7")),
            &ev(Some(10)),
            now
        ));
        assert!(!own(Some("192.0.2.14")).routine(
            "databastion",
            None,
            ClientSeen::Logged(None),
            &ev(Some(10)),
            now
        ));
        // The agent's address is unknown: nothing is left out.
        assert!(!own(None).routine("databastion", None, logged, &ev(Some(10)), now));
        assert!(!own(None).routine(
            "databastion",
            None,
            ClientSeen::NotVisible,
            &ev(Some(10)),
            now
        ));
        assert!(!own(Some("192.0.2.14")).routine(
            "databastion",
            None,
            logged,
            &ev(Some(10)).with_signal(Signal::FullTableRead),
            now
        ));
        // Unknown rows are charged the whole budget.
        let mut o = own(Some("192.0.2.14"));
        assert!(o.routine("databastion", None, logged, &ev(None), now));
        assert!(!o.routine("databastion", None, logged, &ev(None), now));
    }

    fn counters_store(dir: &std::path::Path) -> CursorStore {
        crate::fsutil::ensure_private_dir(dir).unwrap();
        CursorStore::counters(dir, "pg", "own_usage").unwrap()
    }

    fn own_on(usage: &SharedOwnUsage, budget: u64) -> OwnAccount {
        OwnAccount::new(
            "databastion",
            Some("databastion-agent"),
            ClientAddr::parse("192.0.2.14"),
            budget,
            std::sync::Arc::clone(usage),
        )
    }

    /// Phase 7: the budget spent before an agent restart is still spent
    /// after it (the counters are persisted, object names and row counts
    /// only).
    #[test]
    fn own_budget_survives_an_agent_restart() {
        let dir = crate::fsutil::test_dir::TempDir::new();
        let logged = ClientSeen::Logged(ClientAddr::parse("192.0.2.14"));
        let now = Instant::now();
        {
            let usage = SharedOwnUsage::default();
            usage
                .lock()
                .unwrap()
                .attach(counters_store(dir.path()), now);
            let mut o = own_on(&usage, 1000);
            assert!(o.routine("databastion", None, logged, &ev(Some(600)), now));
            // The stream ends: its charges are saved.
        }
        let path = dir.path().join("pg.own_usage.counters");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let text = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
        assert!(text.contains("shop\\u0000crm\\u0000t"), "{text}");
        // A new agent process: fresh counters, loaded from the file.
        let usage = SharedOwnUsage::default();
        usage
            .lock()
            .unwrap()
            .attach(counters_store(dir.path()), Instant::now());
        let mut o = own_on(&usage, 1000);
        assert!(
            !o.routine("databastion", None, logged, &ev(Some(600)), Instant::now()),
            "600 + 600 rows exceed the budget of 1000 across the restart"
        );
        // Attaching again (another stream of the target) loads nothing
        // twice.
        usage
            .lock()
            .unwrap()
            .attach(counters_store(dir.path()), Instant::now());
        assert_eq!(usage.lock().unwrap().usage.len(), 1);
    }

    #[test]
    fn persisted_counters_age_out_and_bad_files_are_ignored() {
        let dir = crate::fsutil::test_dir::TempDir::new();
        let store = counters_store(dir.path());
        let usage = OwnUsage::default();
        let current = usage.hour(Instant::now());
        let file = serde_json::json!({"v": 1, "o": [
            ["old", [[current - 30, 900]]],
            ["recent", [[current - 2, 300], [current, 100]]],
            // The clock went back: counted as the current hour.
            ["future", [[current + 5, 50]]],
        ]});
        store.save(file.to_string().as_bytes()).unwrap();
        let mut usage = OwnUsage::default();
        usage.attach(store, Instant::now());
        let mut keys = usage.budgeted_objects();
        keys.sort();
        assert_eq!(keys, ["future", "recent"]);
        assert_eq!(usage.usage["future"], [(current, 50)]);
        assert_eq!(
            usage.usage["recent"].iter().map(|(_, n)| n).sum::<u64>(),
            400
        );
        // Not understood (another version, garbage): counted from zero.
        for bad in [&b"{\"v\": 2, \"o\": []}"[..], b"not json"] {
            let store = counters_store(dir.path());
            store.save(bad).unwrap();
            let mut usage = OwnUsage::default();
            usage.attach(store, Instant::now());
            assert!(usage.budgeted_objects().is_empty());
        }
    }

    /// Phase-7 security review (Low): a charge made within the save
    /// period after a save, followed by no activity, is saved by the
    /// periodic flush without waiting for another charge or the end of
    /// the stream.
    #[tokio::test]
    async fn a_lone_charge_after_a_save_is_flushed_periodically() {
        let dir = crate::fsutil::test_dir::TempDir::new();
        let path = dir.path().join("pg.own_usage.counters");
        let usage = SharedOwnUsage::default();
        let every = Duration::from_millis(50);
        attach_and_flush(&usage, counters_store(dir.path()), every);
        // A second attachment starts no second task.
        attach_and_flush(&usage, counters_store(dir.path()), every);
        let logged = ClientSeen::Logged(ClientAddr::parse("192.0.2.14"));
        let mut o = own_on(&usage, 1_000_000);
        let t0 = Instant::now();
        o.routine("databastion", None, logged, &ev(Some(1)), t0);
        let first = std::fs::read(&path).unwrap();
        // Within the save period: not saved by the charge itself.
        let other = MaskedEvent::new(
            EventSource::Pgaudit,
            EventAction::Read,
            EventPrincipal::account("databastion"),
            SystemTime::UNIX_EPOCH,
        )
        .with_rows(Some(7))
        .with_object(EventObject::new(
            normalize_path("shop"),
            Some(normalize_path("crm")),
            normalize_path("lonely"),
        ));
        o.routine(
            "databastion",
            None,
            logged,
            &other,
            t0 + Duration::from_secs(1),
        );
        assert_eq!(std::fs::read(&path).unwrap(), first, "not due yet");
        // No further activity, the stream still running (`o` alive).
        let mut saved = false;
        for _ in 0..100 {
            tokio::time::sleep(every).await;
            let text = String::from_utf8(std::fs::read(&path).unwrap()).unwrap();
            if text.contains("lonely") {
                saved = true;
                break;
            }
        }
        assert!(saved, "the lone charge was flushed");
        assert!(!usage.lock().unwrap().dirty);
        drop(o);
        // The task ends with the counters.
        drop(usage);
    }

    #[test]
    fn counters_are_saved_at_most_every_period_while_charging() {
        let dir = crate::fsutil::test_dir::TempDir::new();
        let path = dir.path().join("pg.own_usage.counters");
        let usage = SharedOwnUsage::default();
        let t0 = Instant::now();
        usage.lock().unwrap().attach(counters_store(dir.path()), t0);
        let logged = ClientSeen::Logged(ClientAddr::parse("192.0.2.14"));
        let mut o = own_on(&usage, 1_000_000);
        o.routine("databastion", None, logged, &ev(Some(1)), t0);
        let first = std::fs::read(&path).unwrap();
        o.routine(
            "databastion",
            None,
            logged,
            &ev(Some(1)),
            t0 + Duration::from_secs(1),
        );
        assert_eq!(std::fs::read(&path).unwrap(), first, "not due yet");
        o.routine(
            "databastion",
            None,
            logged,
            &ev(Some(1)),
            t0 + OWN_SAVE_EVERY,
        );
        assert_ne!(std::fs::read(&path).unwrap(), first);
    }
}
