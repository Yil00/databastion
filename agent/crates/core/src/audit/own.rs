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
use std::time::Instant;

use databastion_classifiers::masking::{ClientAddr, EventAction, MaskedEvent};

/// Period over which the agent's own reads of one object are budgeted.
const OWN_PERIOD_HOURS: u64 = 24;
/// Objects budgeted at most; beyond, the agent's own reads of a new
/// object are reported.
const OWN_MAX_OBJECTS: usize = 10_000;

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
/// terminated on purpose) does not get a fresh budget. Not persisted: an
/// agent restart resets it.
#[derive(Debug)]
pub struct OwnUsage {
    start: Instant,
    usage: HashMap<String, VecDeque<(u64, u64)>>,
}

impl Default for OwnUsage {
    fn default() -> Self {
        Self {
            start: Instant::now(),
            usage: HashMap::new(),
        }
    }
}

impl OwnUsage {
    /// Keys of the objects with a charge (`database NUL schema NUL
    /// object`), in no order: what the budget currently tracks.
    #[must_use]
    pub fn budgeted_objects(&self) -> Vec<String> {
        self.usage.keys().cloned().collect()
    }
}

/// Shared handle on a target's [`OwnUsage`].
pub type SharedOwnUsage = std::sync::Arc<std::sync::Mutex<OwnUsage>>;

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
        let hour = now.saturating_duration_since(guard.start).as_secs() / 3600;
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
        identity && e.signals().is_empty() && !over
    }

    /// Like [`OwnAccount::routine`] (account, application, address, no
    /// signal) but without the row budget: nothing is charged. Only for
    /// events a connector has established read no row of any relation
    /// (a closed list of its own statements); a connector that has no
    /// such list never calls it.
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
}
