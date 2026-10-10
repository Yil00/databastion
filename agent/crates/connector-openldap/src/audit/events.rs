//! Log records to masked access events (ADR-0029 decisions 7 to 9).
//!
//! - Principal: the authorization DN (`anonymous` when empty), the bind DN
//!   for a bind (fingerprinted by the core when it fails), unidentified for
//!   a SASL bind. No client address and no application name: the log has
//!   none.
//! - Objects: the naming context of `reqDN` and the console's
//!   `sensitive_objects` the operation could reach (by scope), else `*`
//!   with the container as `schema`. Never an entry DN.
//! - Signals: `shape.bulk_search` (unselective filter, scope beyond base),
//!   `volume.large_result` (entries of one search, or of the pages of one
//!   paged search: same connection, base and scope).
//! - The agent's own reads, connections and exact probe shapes are left
//!   out through `databastion_core::audit::own` (identity, no signal, row
//!   budget; the log records no address: `ClientSeen::NotRecorded`).

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::time::{Duration, Instant};

use databastion_classifiers::masking::{
    EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::names::{NormalizedName, normalize_ldap_dn};
use databastion_core::audit::own::{ClientSeen, OwnAccount};
use databastion_core::job::SensitiveObject;
use zeroize::Zeroizing;

use super::filter::OwnFilter;
use super::records::{LogScope, Op, Record};
use crate::check::PASSWORD_PROBE_ENTRIES;
use crate::dn;

/// Entries above which a search (or a paged search) is a large result.
pub(crate) const LARGE_ENTRIES: u64 = 10_000;
/// Paged-search totals kept at most.
const MAX_SESSIONS: usize = 4096;
/// A paged-search total unused for this long is forgotten.
const SESSION_IDLE: Duration = Duration::from_secs(3600);
/// Principal of an operation without authorization identity.
pub(crate) const ANONYMOUS: &str = "anonymous";

/// A naming context: canonical DN and normalized name.
#[derive(Debug, Clone)]
pub(crate) struct Context {
    pub(crate) canon: String,
    pub(crate) name: NormalizedName,
}

/// Builds events from records, keeping the paged-search totals and the
/// agent's own-read budget across polls.
pub(crate) struct EventBuilder {
    own: OwnAccount,
    /// The agent's authorization DN (canonical).
    identity: String,
    budget: u64,
    contexts: Vec<Context>,
    sensitive: Vec<SensitiveObject>,
    /// (connection, hashed base and scope) -> (entries, last use).
    totals: HashMap<(u64, u64), (u64, Instant)>,
    keys: std::collections::hash_map::RandomState,
    /// Canonical DNs sent by name besides the agent's own.
    clear: std::collections::HashSet<String>,
}

impl std::fmt::Debug for EventBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBuilder")
            .field("contexts", &self.contexts.len())
            .field("totals", &self.totals.len())
            .finish_non_exhaustive()
    }
}

/// Whether a container name `c` (normalized) is `base` or below it,
/// without case.
fn under(c: &str, base: &str) -> bool {
    match (dn::canon(c), dn::canon(base)) {
        (Some(c), Some(base)) => dn::is_within(&c, &base),
        _ => false,
    }
}

impl EventBuilder {
    pub(crate) fn new(
        own: OwnAccount,
        identity: String,
        budget: u64,
        sensitive: Vec<SensitiveObject>,
    ) -> Self {
        Self {
            own,
            identity,
            budget,
            contexts: Vec::new(),
            sensitive,
            totals: HashMap::new(),
            keys: std::collections::hash_map::RandomState::new(),
            clear: std::collections::HashSet::new(),
        }
    }

    /// The principal of a canonical DN (security review M2 of #79): entry
    /// DNs name people, so only the agent's own identity, `anonymous` and
    /// the DNs listed in `openldap.clear_principals` are sent by name;
    /// every other DN is sent as its keyed fingerprint (`db_user_fingerprint`).
    fn principal(&self, user: &str) -> EventPrincipal {
        if user == ANONYMOUS || user == self.identity || self.clear.contains(user) {
            EventPrincipal::account(user)
        } else {
            EventPrincipal::failed_account(user)
        }
    }

    /// DNs sent by name (canonical forms of `openldap.clear_principals`).
    pub(crate) fn set_clear_principals(&mut self, dns: &[String]) {
        self.clear = dns.iter().filter_map(|d| dn::canon(d)).collect();
    }

    /// The naming contexts (re-read at each re-probe).
    pub(crate) fn set_contexts(&mut self, contexts: Vec<Context>) {
        self.contexts = contexts;
    }

    /// The naming context of a canonical DN.
    pub(crate) fn context_of(&self, canon: &str) -> Option<&Context> {
        self.contexts
            .iter()
            .filter(|c| dn::is_within(canon, &c.canon))
            .max_by_key(|c| c.canon.len())
    }

    fn is_context(&self, canon: &str) -> bool {
        self.contexts.iter().any(|c| c.canon == canon)
    }

    /// The objects an operation on `r` could reach (at most 16).
    fn objects(&self, r: &Record, database: &NormalizedName) -> Vec<EventObject> {
        let parent = dn::parent(&r.target);
        // The container named for the operation, and the rule selecting
        // Discovery objects.
        let (container, subtree) = match (r.op, r.scope) {
            (Op::Search, Some(LogScope::One)) => (normalize_ldap_dn(&r.target), false),
            (Op::Search, Some(LogScope::Sub | LogScope::Subord)) => {
                (normalize_ldap_dn(&r.target), true)
            }
            _ => (
                parent.map_or_else(|| normalize_ldap_dn(&r.target), normalize_ldap_dn),
                false,
            ),
        };
        let mut out: Vec<EventObject> = Vec::new();
        if container.as_str() != "*" {
            for o in &self.sensitive {
                if !o.database.eq_ignore_ascii_case(database.as_str()) {
                    continue;
                }
                let Some(schema) = &o.schema else {
                    continue;
                };
                let hit = if subtree {
                    under(schema, container.as_str())
                } else {
                    schema.eq_ignore_ascii_case(container.as_str())
                };
                if hit {
                    // The console's names are normalized (contract
                    // `Identifier`), and are sent back as they came.
                    out.push(EventObject::new(
                        database.clone(),
                        Some(databastion_classifiers::names::normalize_ldap_dn(schema)),
                        databastion_classifiers::names::normalize_path(&o.object),
                    ));
                }
                if out.len() >= 16 {
                    break;
                }
            }
        }
        if out.is_empty() {
            out.push(EventObject::new(
                database.clone(),
                Some(container),
                NormalizedName::wildcard(),
            ));
        }
        out
    }

    /// Adds `entries` to the paged-search total of `r`; the new total.
    fn total(&mut self, r: &Record, entries: u64, now: Instant) -> u64 {
        let Some(session) = r.session else {
            return entries;
        };
        let mut h = self.keys.build_hasher();
        r.target_canon.as_str().hash(&mut h);
        std::mem::discriminant(&r.scope).hash(&mut h);
        if let Some(s) = r.scope {
            (s as u8).hash(&mut h);
        }
        let key = (session, h.finish());
        if !self.totals.contains_key(&key) && self.totals.len() >= MAX_SESSIONS {
            self.totals
                .retain(|_, (_, t)| now.saturating_duration_since(*t) < SESSION_IDLE);
            if self.totals.len() >= MAX_SESSIONS
                && let Some(oldest) = self
                    .totals
                    .iter()
                    .min_by_key(|(_, (_, t))| *t)
                    .map(|(k, _)| *k)
            {
                self.totals.remove(&oldest);
            }
        }
        let e = self.totals.entry(key).or_insert((0, now));
        e.0 = e.0.saturating_add(entries);
        e.1 = now;
        e.0
    }

    fn forget_session(&mut self, session: Option<u64>) {
        if let Some(s) = session {
            self.totals.retain(|(k, _), _| *k != s);
        }
    }

    /// Which of the agent's exact shapes a search of its identity has.
    fn own_shape(&self, r: &Record) -> Option<OwnShape> {
        if r.op != Op::Search || !self.is_context(&r.target_canon) {
            // Sampling reads containers, which may not be contexts.
            return (r.op == Op::Search
                && r.scope == Some(LogScope::One)
                && r.filter.own == Some(OwnFilter::Everything)
                && sampling_attributes(r)
                && r.size_limit
                    .is_some_and(|l| l >= 1 && l.unsigned_abs() <= self.budget))
            .then_some(OwnShape::Sampling);
        }
        let q = &r.requested;
        match (r.scope, r.filter.own) {
            (Some(LogScope::Sub), Some(OwnFilter::Containers)) if q.none && !r.attrs_only => {
                Some(OwnShape::Probe)
            }
            (Some(LogScope::Base), Some(OwnFilter::Everything)) if q.none && !r.attrs_only => {
                Some(OwnShape::Probe)
            }
            (Some(LogScope::Sub), Some(OwnFilter::Everything))
                if r.attrs_only
                    && q.listed == 2
                    && q.only_credential
                    && r.size_limit
                        .is_some_and(|l| (1..=i64::from(PASSWORD_PROBE_ENTRIES)).contains(&l)) =>
            {
                Some(OwnShape::Probe)
            }
            (Some(LogScope::One), Some(OwnFilter::Everything))
                if sampling_attributes(r)
                    && r.size_limit
                        .is_some_and(|l| l >= 1 && l.unsigned_abs() <= self.budget) =>
            {
                Some(OwnShape::Sampling)
            }
            _ => None,
        }
    }

    /// Events of `records` (in log order). The agent's routine activity is
    /// left out.
    pub(crate) fn convert(&mut self, records: Vec<Record>, now: Instant) -> Vec<MaskedEvent> {
        let mut out = Vec::new();
        for r in records {
            if let Some(e) = self.event(&r, now) {
                out.push(e);
            }
        }
        out
    }

    fn event(&mut self, r: &Record, now: Instant) -> Option<MaskedEvent> {
        let source = EventSource::OpenldapAccesslog;
        let (action, principal, user): (EventAction, EventPrincipal, Option<Zeroizing<String>>) =
            match r.op {
                Op::Unbind => {
                    self.forget_session(r.session);
                    return None;
                }
                Op::Other => return None,
                Op::Bind { sasl } => {
                    // A bind DN that is not a DN (a password typed as the user
                    // name, review L3): fingerprinted, never an identity.
                    let malformed = r.target_canon.is_empty() && !r.target.trim().is_empty();
                    let user = if r.target_canon.is_empty() {
                        None
                    } else {
                        Some(Zeroizing::new(r.target_canon.to_string()))
                    };
                    match (r.result, sasl, user) {
                        (14, _, _) => return None,
                        (0, _, _) if malformed => (
                            EventAction::Connect,
                            EventPrincipal::failed_account(&r.target),
                            None,
                        ),
                        (0, true, None) => {
                            (EventAction::Connect, EventPrincipal::unidentified(), None)
                        }
                        (0, false, None) => (
                            EventAction::Connect,
                            EventPrincipal::account(ANONYMOUS),
                            Some(Zeroizing::new(ANONYMOUS.to_owned())),
                        ),
                        (0, _, Some(u)) => (EventAction::Connect, self.principal(&u), Some(u)),
                        (_, _, u) => (
                            EventAction::AuthFailure,
                            EventPrincipal::failed_account(u.as_deref().unwrap_or(&r.target)),
                            None,
                        ),
                    }
                }
                Op::Search | Op::Compare | Op::Write => {
                    let reported = match r.op {
                        // A search that failed but returned entries is kept.
                        Op::Search => r.result == 0 || r.entries.is_some_and(|n| n > 0),
                        // compareFalse, compareTrue.
                        Op::Compare => matches!(r.result, 5 | 6),
                        _ => r.result == 0,
                    };
                    if !reported {
                        return None;
                    }
                    let action = if r.op == Op::Write {
                        EventAction::Write
                    } else {
                        EventAction::Read
                    };
                    let user = r
                        .authz
                        .clone()
                        .unwrap_or_else(|| Zeroizing::new(ANONYMOUS.to_owned()));
                    (action, self.principal(&user), Some(user))
                }
            };
        let mut e = MaskedEvent::new(source, action, principal, r.start);
        if matches!(r.op, Op::Search | Op::Compare | Op::Write) {
            let database = self
                .context_of(&r.target_canon)
                .map_or_else(NormalizedName::wildcard, |c| c.name.clone());
            for o in self.objects(r, &database) {
                e = e.with_object(o);
            }
        }
        let mut bulk = false;
        match r.op {
            Op::Search => {
                let entries = r.entries.unwrap_or(0);
                e = e.with_rows(Some(entries));
                bulk = r.filter.unselective && r.scope != Some(LogScope::Base);
                let total = self.total(r, entries, now);
                if entries > LARGE_ENTRIES || total > LARGE_ENTRIES {
                    e = e.with_signal(Signal::LargeResult);
                }
            }
            Op::Write => e = e.with_rows(Some(1)),
            _ => {}
        }
        let own = user.as_ref().map(|u| u.as_str()) == Some(self.identity.as_str());
        if own {
            let user = self.identity.clone();
            match self.own_shape(r) {
                Some(OwnShape::Probe) => {
                    if self
                        .own
                        .routine_unbudgeted(&user, None, ClientSeen::NotRecorded, &e)
                    {
                        return None;
                    }
                }
                Some(OwnShape::Sampling) => {
                    if self
                        .own
                        .routine(&user, None, ClientSeen::NotRecorded, &e, now)
                    {
                        return None;
                    }
                }
                None => {
                    let e2 = if bulk {
                        e.clone().with_signal(Signal::BulkSearch)
                    } else {
                        e.clone()
                    };
                    if self
                        .own
                        .routine(&user, None, ClientSeen::NotRecorded, &e2, now)
                    {
                        return None;
                    }
                }
            }
        }
        if bulk {
            e = e.with_signal(Signal::BulkSearch);
        }
        Some(e)
    }

    /// The budget per object (for the tests).
    #[cfg(test)]
    pub(crate) fn budget(&self) -> u64 {
        self.budget
    }
}

/// The agent's shapes (decision 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnShape {
    /// Container listing and check probes: never charged.
    Probe,
    /// Entry sampling: charged to the budget.
    Sampling,
}

/// The sampling attribute list: explicit names, no wildcard, no
/// credential, not attributes-only.
fn sampling_attributes(r: &Record) -> bool {
    let q = &r.requested;
    !r.attrs_only && q.listed > 0 && !q.none && !q.all_user && !q.operational && !q.credential
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::records::parse;
    use crate::audit::records::tests::{CSN, log_entry};
    use databastion_classifiers::names::normalize_path;
    use databastion_core::audit::own::SharedOwnUsage;

    const AGENT: &str = "cn=databastion,ou=services,dc=example,dc=org";

    fn builder(sensitive: Vec<SensitiveObject>) -> EventBuilder {
        let mut b = EventBuilder::new(
            OwnAccount::new(AGENT, None, None, 1000, SharedOwnUsage::default()),
            AGENT.to_owned(),
            1000,
            sensitive,
        );
        b.set_contexts(vec![Context {
            canon: "dc=example,dc=org".to_owned(),
            name: normalize_ldap_dn("dc=example,dc=org"),
        }]);
        b
    }

    fn people() -> SensitiveObject {
        SensitiveObject {
            database: "dc=example,dc=org".to_owned(),
            schema: Some("ou=people,dc=example,dc=org".to_owned()),
            object: "inetOrgPerson".to_owned(),
            classifiers: Vec::new(),
        }
    }

    fn teams() -> SensitiveObject {
        SensitiveObject {
            database: "dc=example,dc=org".to_owned(),
            schema: Some("ou=*,ou=teams,dc=example,dc=org".to_owned()),
            object: "inetOrgPerson".to_owned(),
            classifiers: Vec::new(),
        }
    }

    struct S<'a> {
        who: &'a str,
        base: &'a str,
        scope: &'a str,
        filter: &'a str,
        attrs: &'a [&'a str],
        entries: &'a str,
        size: &'a str,
        session: &'a str,
        only: &'a str,
    }

    const DEFAULT: S<'static> = S {
        who: "uid=app,ou=services,dc=example,dc=org",
        base: "ou=people,dc=example,dc=org",
        scope: "sub",
        filter: "(uid=jdoe)",
        attrs: &["mail"],
        entries: "1",
        size: "500",
        session: "1000",
        only: "FALSE",
    };

    fn search(s: &S<'_>) -> Record {
        parse(&log_entry(&[
            ("reqStart", &["20260929202642.000003Z"]),
            ("reqType", &["search"]),
            ("reqSession", &[s.session]),
            ("reqAuthzID", &[s.who]),
            ("reqDN", &[s.base]),
            ("reqResult", &["0"]),
            ("reqScope", &[s.scope]),
            ("reqFilter", &[s.filter]),
            ("reqAttr", s.attrs),
            ("reqAttrsOnly", &[s.only]),
            ("reqEntries", &[s.entries]),
            ("reqSizeLimit", &[s.size]),
            ("entryCSN", &[CSN]),
        ]))
        .unwrap()
    }

    fn names(e: &MaskedEvent) -> Vec<(String, Option<String>, String)> {
        e.objects()
            .iter()
            .map(|o| {
                (
                    o.database().as_str().to_owned(),
                    o.schema().map(|s| s.as_str().to_owned()),
                    o.object().as_str().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn a_selective_search_names_the_objects_below_its_base() {
        let mut b = builder(vec![people(), teams()]);
        let e = b
            .convert(vec![search(&DEFAULT)], Instant::now())
            .pop()
            .unwrap();
        assert_eq!(e.action(), EventAction::Read);
        assert_eq!(e.rows(), Some(1));
        assert!(e.signals().is_empty());
        assert_eq!(
            e.principal().account_name(),
            "uid=app,ou=services,dc=example,dc=org"
        );
        // Entry DNs are sent as fingerprints (security review M2).
        assert!(!e.principal().send_name());
        assert_eq!(e.principal().client(), None);
        assert_eq!(
            names(&e),
            vec![(
                "dc=example,dc=org".to_owned(),
                Some("ou=people,dc=example,dc=org".to_owned()),
                "inetOrgPerson".to_owned()
            )]
        );
        // A subtree search from the context reaches both containers.
        let root = S {
            base: "dc=Example,dc=org",
            ..DEFAULT
        };
        let e = b
            .convert(vec![search(&root)], Instant::now())
            .pop()
            .unwrap();
        // The console's names come back exactly, so `sensitive_objects` and
        // the console's per-object sensitivity match them.
        assert_eq!(
            names(&e),
            vec![
                (
                    "dc=example,dc=org".to_owned(),
                    Some("ou=*,ou=teams,dc=example,dc=org".to_owned()),
                    "inetOrgPerson".to_owned()
                ),
                (
                    "dc=example,dc=org".to_owned(),
                    Some("ou=people,dc=example,dc=org".to_owned()),
                    "inetOrgPerson".to_owned()
                ),
            ]
        );
        // Nothing sensitive below: `*` with the container.
        let groups = S {
            base: "ou=groups,dc=example,dc=org",
            ..DEFAULT
        };
        let e = b
            .convert(vec![search(&groups)], Instant::now())
            .pop()
            .unwrap();
        assert_eq!(
            names(&e),
            vec![(
                "dc=example,dc=org".to_owned(),
                Some("ou=groups,dc=example,dc=org".to_owned()),
                "*".to_owned()
            )]
        );
        // A base read of an entry: its container's objects; the DN never.
        let entry = S {
            base: "uid=jdoe,ou=people,dc=example,dc=org",
            scope: "base",
            ..DEFAULT
        };
        let e = b
            .convert(vec![search(&entry)], Instant::now())
            .pop()
            .unwrap();
        assert_eq!(
            names(&e)[0].1.as_deref(),
            Some("ou=people,dc=example,dc=org")
        );
        assert!(!format!("{e:?}").contains("jdoe"));
    }

    #[test]
    fn bulk_searches_and_paged_volume() {
        let mut b = builder(vec![people()]);
        let dump = S {
            filter: "(objectClass=*)",
            attrs: &["*"],
            entries: "6000",
            ..DEFAULT
        };
        let now = Instant::now();
        let first = b.convert(vec![search(&dump)], now).pop().unwrap();
        assert_eq!(first.signals(), &[Signal::BulkSearch]);
        // The second page of the same connection, base and scope crosses
        // 10 000 entries.
        let second = b.convert(vec![search(&dump)], now).pop().unwrap();
        assert_eq!(second.signals(), &[Signal::LargeResult, Signal::BulkSearch]);
        // Another connection starts from zero; an unbind forgets it.
        let other = S {
            session: "1001",
            ..dump
        };
        assert_eq!(
            b.convert(vec![search(&other)], now)
                .pop()
                .unwrap()
                .signals(),
            &[Signal::BulkSearch]
        );
        // One search above the threshold on its own; base scope is never
        // bulk.
        let big = S {
            entries: "10001",
            scope: "base",
            session: "2000",
            ..dump
        };
        assert_eq!(
            b.convert(vec![search(&big)], now).pop().unwrap().signals(),
            &[Signal::LargeResult]
        );
    }

    #[test]
    fn the_agents_own_shapes_are_left_out_within_the_budget() {
        let mut b = builder(vec![people()]);
        let now = Instant::now();
        let sampling = S {
            who: AGENT,
            scope: "one",
            filter: "(objectClass=*)",
            attrs: &["cn", "mail", "objectClass", "structuralObjectClass"],
            entries: "200",
            size: "200",
            ..DEFAULT
        };
        assert!(b.convert(vec![search(&sampling)], now).is_empty());
        let listing = S {
            who: AGENT,
            base: "dc=example,dc=org",
            filter: "(|(objectClass=organizationalUnit)(objectClass=organization)\
                     (objectClass=dcObject)(objectClass=domain)(objectClass=country)\
                     (objectClass=locality))",
            attrs: &["1.1"],
            entries: "900",
            size: "1024",
            ..DEFAULT
        };
        for _ in 0..10 {
            assert!(b.convert(vec![search(&listing)], now).is_empty());
        }
        let probe = S {
            who: AGENT,
            base: "dc=example,dc=org",
            filter: "(objectClass=*)",
            attrs: &["userPassword", "authPassword"],
            only: "TRUE",
            entries: "64",
            size: "64",
            ..DEFAULT
        };
        assert!(b.convert(vec![search(&probe)], now).is_empty());
        // Over the budget, the sampling shape is reported, with its shape.
        let big = S {
            entries: "900",
            size: "1000",
            ..sampling
        };
        let e = b.convert(vec![search(&big)], now).pop().unwrap();
        assert_eq!(e.signals(), &[Signal::BulkSearch]);
        // Any other shape of the agent's identity is judged as usual: a
        // dump with every attribute carries the signal and is reported.
        let dump = S {
            who: AGENT,
            filter: "(objectClass=*)",
            attrs: &["*"],
            ..DEFAULT
        };
        assert_eq!(
            b.convert(vec![search(&dump)], now).pop().unwrap().signals(),
            &[Signal::BulkSearch]
        );
        assert_eq!(b.budget(), 1000);
    }

    /// A search of the agent's identity that returns no entry is charged
    /// one (security review of #196, Low): a filter walk (`(mail=a*)`,
    /// `(mail=b*)`…, each answering by its emptiness) is left out for at
    /// most the per-object budget of searches, then reported; so are the
    /// agent's sampling searches of empty containers.
    #[test]
    fn own_searches_without_entries_are_charged_one_each() {
        let now = Instant::now();
        let mut b = EventBuilder::new(
            OwnAccount::new(AGENT, None, None, 3, SharedOwnUsage::default()),
            AGENT.to_owned(),
            3,
            vec![people()],
        );
        b.set_contexts(vec![Context {
            canon: "dc=example,dc=org".to_owned(),
            name: normalize_ldap_dn("dc=example,dc=org"),
        }]);
        let filters = ["(mail=a*)", "(mail=b*)", "(mail=c*)", "(mail=d*)"];
        let reported: Vec<bool> = filters
            .iter()
            .map(|f| {
                let walk = S {
                    who: AGENT,
                    scope: "one",
                    filter: f,
                    entries: "0",
                    ..DEFAULT
                };
                !b.convert(vec![search(&walk)], now).is_empty()
            })
            .collect();
        assert_eq!(reported, [false, false, false, true]);
        // The sampling shape of an empty container: one each as well.
        let empty = S {
            who: AGENT,
            base: "ou=empty,dc=example,dc=org",
            scope: "one",
            filter: "(objectClass=*)",
            attrs: &["cn", "mail", "objectClass", "structuralObjectClass"],
            entries: "0",
            size: "3",
            ..DEFAULT
        };
        let reported: Vec<bool> = (0..4)
            .map(|_| !b.convert(vec![search(&empty)], now).is_empty())
            .collect();
        assert_eq!(reported, [false, false, false, true]);
    }

    #[test]
    fn binds_writes_and_other_records() {
        let mut b = builder(Vec::new());
        let now = Instant::now();
        let rec = |kind: &str, dn: &str, result: &str, method: &str| {
            parse(&log_entry(&[
                ("reqStart", &["20260929202642.000001Z"]),
                ("reqType", &[kind]),
                ("reqAuthzID", &["uid=admin,dc=example,dc=org"]),
                ("reqDN", &[dn]),
                ("reqResult", &[result]),
                ("reqMethod", &[method]),
                ("entryCSN", &[CSN]),
            ]))
            .unwrap()
        };
        let failed = b
            .convert(
                vec![rec("bind", "uid=Jane,dc=example,dc=org", "49", "SIMPLE")],
                now,
            )
            .pop()
            .unwrap();
        assert_eq!(failed.action(), EventAction::AuthFailure);
        assert!(!failed.principal().send_name());
        let ok = b
            .convert(
                vec![rec("bind", "uid=Jane, dc=example,dc=org", "0", "SIMPLE")],
                now,
            )
            .pop()
            .unwrap();
        assert_eq!(ok.action(), EventAction::Connect);
        assert_eq!(ok.principal().account_name(), "uid=jane,dc=example,dc=org");
        assert!(ok.objects().is_empty());
        let sasl = b
            .convert(vec![rec("bind", "", "0", "SASL(EXTERNAL)")], now)
            .pop()
            .unwrap();
        assert!(!sasl.principal().send_name());
        // The agent's own bind is a routine connection.
        assert!(
            b.convert(vec![rec("bind", AGENT, "0", "SIMPLE")], now)
                .is_empty()
        );
        let write = b
            .convert(
                vec![rec(
                    "modify",
                    "uid=jdoe,ou=people,dc=example,dc=org",
                    "0",
                    "",
                )],
                now,
            )
            .pop()
            .unwrap();
        assert_eq!(write.action(), EventAction::Write);
        assert_eq!(write.rows(), Some(1));
        // Failed writes, unbinds and extended operations: no event.
        assert!(
            b.convert(
                vec![rec("modify", "uid=x,dc=example,dc=org", "50", "")],
                now
            )
            .is_empty()
        );
        assert!(b.convert(vec![rec("unbind", "", "0", "")], now).is_empty());
        assert!(
            b.convert(vec![rec("extended1.2.3", "", "0", "")], now)
                .is_empty()
        );
        let _ = normalize_path("x");
    }

    #[test]
    fn only_listed_dns_the_agent_and_anonymous_are_sent_by_name() {
        let mut b = builder(Vec::new());
        b.set_clear_principals(&["UID=App, ou=services,dc=example,dc=org".to_owned()]);
        let now = Instant::now();
        let listed = b.convert(vec![search(&DEFAULT)], now).pop().unwrap();
        assert!(listed.principal().send_name());
        let person = S {
            who: "uid=jdoe,ou=people,dc=example,dc=org",
            ..DEFAULT
        };
        let e = b.convert(vec![search(&person)], now).pop().unwrap();
        assert!(!e.principal().send_name());
        let anonymous = S { who: "", ..DEFAULT };
        let e = b.convert(vec![search(&anonymous)], now).pop().unwrap();
        assert!(e.principal().send_name());
        assert_eq!(e.principal().account_name(), ANONYMOUS);
        // A bind whose DN is not a DN (a password typed as the user name,
        // review L3): fingerprinted, even when it succeeds.
        let bind = parse(&log_entry(&[
            ("reqStart", &["20260929202642.000001Z"]),
            ("reqType", &["bind"]),
            ("reqDN", &["hunter2-typed-as-user"]),
            ("reqResult", &["0"]),
            ("reqMethod", &["SIMPLE"]),
            ("entryCSN", &[CSN]),
        ]))
        .unwrap();
        let e = b.convert(vec![bind], now).pop().unwrap();
        assert_eq!(e.action(), EventAction::Connect);
        assert!(!e.principal().send_name());
    }

    #[test]
    fn failed_searches_without_entries_are_not_events() {
        // The check's read of a missing entry (noSuchObject), by anyone.
        let mut b = builder(Vec::new());
        let r = parse(&log_entry(&[
            ("reqStart", &["20260929202642.000001Z"]),
            ("reqType", &["search"]),
            ("reqAuthzID", &[AGENT]),
            ("reqDN", &["cn=databastion-absent-probe,dc=example,dc=org"]),
            ("reqResult", &["32"]),
            ("reqScope", &["base"]),
            ("reqFilter", &["(objectClass=*)"]),
            ("reqAttr", &["1.1"]),
            ("reqEntries", &["0"]),
            ("entryCSN", &[CSN]),
        ]))
        .unwrap();
        assert!(b.convert(vec![r], Instant::now()).is_empty());
    }

    #[test]
    fn writes_by_the_agents_identity_are_always_reported() {
        let mut b = builder(Vec::new());
        let r = parse(&log_entry(&[
            ("reqStart", &["20260929202642.000001Z"]),
            ("reqType", &["delete"]),
            ("reqAuthzID", &[AGENT]),
            ("reqDN", &["uid=jdoe,ou=people,dc=example,dc=org"]),
            ("reqResult", &["0"]),
            ("entryCSN", &[CSN]),
        ]))
        .unwrap();
        assert_eq!(b.convert(vec![r], Instant::now()).len(), 1);
    }
}
