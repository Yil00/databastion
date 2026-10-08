//! From parsed audit records to access events (ADR-0041 decisions 7 and 8).
//!
//! | CAS action | Event |
//! |---|---|
//! | `AUTHENTICATION_SUCCESS` | `connect` |
//! | `AUTHENTICATION_FAILED` | `auth_failure` (flood rules below) |
//! | `SERVICE_TICKET_CREATED` | `read`, object = the service (or `*`), rows 1 |
//! | `SAVE_SERVICE_SUCCESS`, `DELETE_SERVICE_SUCCESS` | `dcl` on `service_registry` |
//! | anything else | no event, counted per action base (at most 64 bases) |
//!
//! - **Principals**: every `who` is sent as its `db_user` fingerprint
//!   (`EventPrincipal::failed_account`) except the `clear_principals`; a
//!   failed authentication's name always is. A credential object's string
//!   form (`…Credentials@6cd7c975`), `audit:unknown` or a missing `who` is
//!   reported as the fixed `unidentified` token, never parsed further.
//! - **Client addresses**: signals are computed on the full address, then
//!   it is reduced per `client_addr` (`truncated`: IPv4 /24, IPv6 /56).
//! - **Failed-login floods**: per client address, the first
//!   [`MANY_ACCOUNTS`] distinct principals failing within [`WINDOW`] give
//!   their own events (the last of them with
//!   `volume.failed_logins_many_accounts`); beyond that, failures from that
//!   address are aggregated into one event per address and minute with the
//!   principal `*` ([`CasPrincipal::ManyAccounts`]) and that signal. One
//!   principal failing at least [`ONE_ACCOUNT_FAILURES`] times within
//!   [`WINDOW`] gets `volume.failed_logins_one_account`.
//! - **Bounded state** (security review M7): the per-address and
//!   per-principal windows hold at most [`MAX_WINDOW_ENTRIES`] entries
//!   each, keyed by the address and by a keyed tag of the principal (never
//!   the raw `who`), not persisted. A failure that would need a new entry
//!   in a full window is aggregated into one event per minute without a
//!   client address, principal `*`, and counted ([`Builder::overflow`]).
//!
//! [`CasEvent::into_masked`] gives the `MaskedEvent` the core accepts
//! (source `cas_audit_log`, the signals as `masking::Signal`, the `*`
//! aggregate as `EventPrincipal::many_accounts`).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use databastion_classifiers::masking::{
    ClientAddr, EventAction, EventObject, EventPrincipal, EventSource, LocalTagKey, MaskedEvent,
};
use databastion_classifiers::names::{NormalizedName, normalize_path};

use crate::config::ClientAddrMode;
use crate::notes::CasSignal;
use crate::parse::record::{Action, AuditRecord};
use crate::registry::ServiceIndex;

/// Window of the failed-login signals.
pub const WINDOW: Duration = Duration::from_secs(600);
/// Distinct principals failing from one address that make a flood.
pub const MANY_ACCOUNTS: usize = 16;
/// Failures of one principal that make online guessing.
pub const ONE_ACCOUNT_FAILURES: usize = 20;
/// Most entries of each window.
pub const MAX_WINDOW_ENTRIES: usize = 4096;
/// Most action bases counted.
pub const MAX_ACTION_BASES: usize = 64;
/// Token reported for principals that cannot be named.
pub const UNIDENTIFIED: &str = "unidentified";
/// Purpose of the agent key's sub-key for the window tags.
pub const TAG_PURPOSE: &str = "cas-failed-login-windows";

/// Who an event is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasPrincipal {
    /// One principal (named only when in `clear_principals`).
    Account(EventPrincipal),
    /// Several accounts (`db_user` `*`): a failed-login aggregate.
    ManyAccounts,
}

/// An access event of a `cas` target (closed facts only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasEvent {
    /// First occurrence (clamped to the agent clock).
    pub ts: SystemTime,
    /// Last occurrence, when aggregated.
    pub ts_last: Option<SystemTime>,
    /// Action.
    pub action: EventAction,
    /// Who.
    pub principal: CasPrincipal,
    /// Client address, reduced per `client_addr`.
    pub client: Option<ClientAddr>,
    /// First product token of the user agent.
    pub application: Option<String>,
    /// Object reached.
    pub object: Option<EventObject>,
    /// Rows (1 for a service ticket).
    pub rows: Option<u64>,
    /// Signals (sorted, unique).
    pub signals: Vec<CasSignal>,
    /// Records merged into this event.
    pub count: u64,
}

impl CasEvent {
    fn add_signal(&mut self, s: CasSignal) {
        if let Err(i) = self.signals.binary_search(&s) {
            self.signals.insert(i, s);
        }
    }

    /// The masked event the core accepts: source `cas_audit_log`, the
    /// principal with its (already reduced) client address and the
    /// application through the contract `Principal.application`
    /// sanitization, the object, rows and signals, and the aggregate count
    /// and last time when records were merged.
    #[must_use]
    pub fn into_masked(self) -> MaskedEvent {
        let principal = match self.principal {
            CasPrincipal::Account(p) => p,
            CasPrincipal::ManyAccounts => EventPrincipal::many_accounts(),
        }
        .with_client(self.client);
        let principal = match self.application.as_deref() {
            Some(app) => principal.with_application(app),
            None => principal,
        };
        let mut e = MaskedEvent::new(EventSource::CasAuditLog, self.action, principal, self.ts)
            .with_rows(self.rows);
        if let Some(o) = self.object {
            e = e.with_object(o);
        }
        for s in self.signals {
            e = e.with_signal(s.signal());
        }
        if self.count > 1 || self.ts_last.is_some() {
            e = e.with_aggregate(self.count, self.ts_last.unwrap_or(self.ts));
        }
        e
    }
}

/// The address a failure counts for, in the windows and the aggregates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum AddrKey {
    /// A parsed client address (canonical, before reduction).
    Known(IpAddr),
    /// No parseable client address: one shared key (review of #138 L4),
    /// so failures without an address still reach the many-accounts
    /// signal.
    Unknown,
}

/// The aggregate a failure is merged into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AggAddr {
    Addr(AddrKey),
    /// A window was full.
    Overflow,
}

type AggKey = (AggAddr, u64);

/// Per-address window: distinct principals and when each last failed.
#[derive(Default)]
struct AddrWindow {
    principals: HashMap<[u8; 16], SystemTime>,
}

fn within(t: SystemTime, now: SystemTime) -> bool {
    now.duration_since(t).map_or(true, |age| age < WINDOW)
}

fn minute(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() / 60)
}

/// Whether `who` cannot name a principal (see the module documentation).
#[must_use]
pub fn is_unidentified(who: &str) -> bool {
    let w = who.trim();
    if w.is_empty() || w.eq_ignore_ascii_case("audit:unknown") {
        return true;
    }
    // `org.apereo.cas.authentication.credential.UsernamePasswordCredential@6cd7c975`
    w.rsplit_once('@').is_some_and(|(class, hash)| {
        class.contains("Credential")
            && (1..=16).contains(&hash.len())
            && hash.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// The canonical form of a logged address (review of #138 L3): an
/// IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`, not `::`
/// nor `::1`) IPv6 address is its IPv4 address, so the windows and the
/// reduction see one address per client.
#[must_use]
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let bits = u128::from(v6);
            if bits >> 32 == 0 && bits > 1 {
                return IpAddr::V4(std::net::Ipv4Addr::from(u32::try_from(bits).unwrap_or(0)));
            }
            ip
        }
    }
}

/// Reduces a client address per `mode`. `truncated`: IPv4 to its /24,
/// IPv6 to its /56, except 6to4 (`2002::/16`), whose embedded IPv4 address
/// is cut to its /24 (the /40 prefix is kept, the rest zeroed); Teredo
/// (`2001::/32`) keeps its prefix and part of the server address, its
/// obfuscated client address and port are zeroed by the /56. Mapped and
/// compatible addresses are IPv4 first ([`canonical`]); `::` and `::1` are
/// sent as is.
#[must_use]
pub fn reduce(ip: IpAddr, mode: ClientAddrMode) -> Option<ClientAddr> {
    let ip = canonical(ip);
    match mode {
        ClientAddrMode::Omitted => None,
        ClientAddrMode::Clear => Some(ClientAddr::Ip(ip)),
        ClientAddrMode::Truncated => Some(ClientAddr::Ip(match ip {
            IpAddr::V4(v4) => IpAddr::V4((u32::from(v4) & 0xffff_ff00).into()),
            // `::` and `::1` carry no client: sent as is.
            IpAddr::V6(v6) if u128::from(v6) <= 1 => ip,
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let keep = if bits >> 112 == 0x2002 { 40 } else { 56 };
                IpAddr::V6((bits & !(u128::MAX >> keep)).into())
            }
        })),
    }
}

/// Builds events from records (see the module documentation).
pub struct Builder {
    key: LocalTagKey,
    clear: HashSet<String>,
    mode: ClientAddrMode,
    services: Option<Arc<ServiceIndex>>,
    registry_db: NormalizedName,
    addrs: HashMap<AddrKey, AddrWindow>,
    principals: HashMap<[u8; 16], VecDeque<SystemTime>>,
    aggregates: BTreeMap<AggKey, CasEvent>,
    /// Failures aggregated because a window was full (heartbeat metric
    /// `audit_window_overflow_total` once wired).
    pub overflow: u64,
    /// Records of other actions, per action base (at most
    /// [`MAX_ACTION_BASES`]; the rest under `""`).
    pub ignored: BTreeMap<String, u64>,
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder")
            .field("addresses", &self.addrs.len())
            .field("principals", &self.principals.len())
            .field("overflow", &self.overflow)
            .finish_non_exhaustive()
    }
}

impl Builder {
    /// A builder whose window tags are made with `key` (a sub-key of the
    /// agent key, [`TAG_PURPOSE`]).
    #[must_use]
    pub fn new(
        key: LocalTagKey,
        clear_principals: &[String],
        mode: ClientAddrMode,
        services: Option<Arc<ServiceIndex>>,
    ) -> Self {
        Self {
            key,
            clear: clear_principals.iter().cloned().collect(),
            mode,
            services,
            registry_db: normalize_path("service_registry"),
            addrs: HashMap::new(),
            principals: HashMap::new(),
            aggregates: BTreeMap::new(),
            overflow: 0,
            ignored: BTreeMap::new(),
        }
    }

    /// Replaces the service index (after a registry reload).
    pub fn set_services(&mut self, services: Option<Arc<ServiceIndex>>) {
        self.services = services;
    }

    fn tag(&self, who: &str) -> [u8; 16] {
        let t = self.key.tag(&[b"cas/principal\0", who.as_bytes()]);
        let mut out = [0u8; 16];
        for (o, b) in out.iter_mut().zip(t.iter()) {
            *o = *b;
        }
        out
    }

    fn principal(&self, who: &str, failed: bool) -> EventPrincipal {
        if who == UNIDENTIFIED {
            return EventPrincipal::failed_account(UNIDENTIFIED);
        }
        if !failed && self.clear.contains(who) {
            EventPrincipal::account(who)
        } else {
            EventPrincipal::failed_account(who)
        }
    }

    fn event(&self, r: &AuditRecord, ts: SystemTime, action: EventAction, who: &str) -> CasEvent {
        CasEvent {
            ts,
            ts_last: None,
            action,
            principal: CasPrincipal::Account(
                self.principal(who, action == EventAction::AuthFailure),
            ),
            client: r.client.and_then(|ip| reduce(ip, self.mode)),
            application: r.user_agent.clone(),
            object: None,
            rows: None,
            signals: Vec::new(),
            count: 1,
        }
    }

    /// Converts one record; events are appended to `out` (aggregates are
    /// emitted by [`Self::flush`]). `now` is the agent clock: record times
    /// after it are clamped.
    pub fn push(&mut self, r: &AuditRecord, now: SystemTime, out: &mut Vec<CasEvent>) {
        let ts = r.when.min(now);
        let who = match r.who.as_deref() {
            Some(w) if !is_unidentified(w) => w.as_str(),
            _ => UNIDENTIFIED,
        };
        match &r.action {
            Action::AuthSuccess => out.push(self.event(r, ts, EventAction::Connect, who)),
            Action::AuthFailed => self.failure(r, ts, who, out),
            Action::ServiceTicketCreated | Action::TokenIssued => {
                let found = r
                    .service
                    .as_ref()
                    .zip(self.services.as_ref())
                    .and_then(|(h, idx)| idx.lookup(h));
                let object = match found {
                    Some((t, name)) => EventObject::new(
                        self.registry_db.clone(),
                        Some(normalize_path(t.as_str())),
                        name.clone(),
                    ),
                    None => {
                        EventObject::new(self.registry_db.clone(), None, NormalizedName::wildcard())
                    }
                };
                let mut e = self.event(r, ts, EventAction::Read, who);
                e.object = Some(object);
                e.rows = Some(1);
                out.push(e);
            }
            Action::SaveService | Action::DeleteService => {
                let mut e = self.event(r, ts, EventAction::Dcl, who);
                e.object = Some(EventObject::new(
                    self.registry_db.clone(),
                    None,
                    NormalizedName::wildcard(),
                ));
                out.push(e);
            }
            Action::Other(base) => {
                let key =
                    if self.ignored.contains_key(base) || self.ignored.len() < MAX_ACTION_BASES {
                        base.clone()
                    } else {
                        String::new()
                    };
                let n = self.ignored.entry(key).or_insert(0);
                *n = n.saturating_add(1);
            }
        }
    }

    /// Removes window entries older than [`WINDOW`] at `now`.
    fn prune(&mut self, now: SystemTime) {
        self.addrs.retain(|_, w| {
            w.principals.retain(|_, t| within(*t, now));
            !w.principals.is_empty()
        });
        self.principals.retain(|_, q| {
            q.retain(|t| within(*t, now));
            !q.is_empty()
        });
    }

    /// Notes a failure of `tag` in the per-principal window: `Some(true)`
    /// at [`ONE_ACCOUNT_FAILURES`] or more, `None` when the window is full.
    fn note_principal(&mut self, tag: [u8; 16], ts: SystemTime) -> Option<bool> {
        if !self.principals.contains_key(&tag) && self.principals.len() >= MAX_WINDOW_ENTRIES {
            self.prune(ts);
            if self.principals.len() >= MAX_WINDOW_ENTRIES {
                return None;
            }
        }
        let q = self.principals.entry(tag).or_default();
        q.retain(|t| within(*t, ts));
        q.push_back(ts);
        while q.len() > ONE_ACCOUNT_FAILURES {
            q.pop_front();
        }
        Some(q.len() >= ONE_ACCOUNT_FAILURES)
    }

    /// Notes a failure of `tag` from `ip`: `Some(Own(many))` for an event of
    /// its own (`many`: this principal is the [`MANY_ACCOUNTS`]th),
    /// `Some(Flood)` to aggregate, `None` when the window is full.
    fn note_addr(&mut self, ip: AddrKey, tag: [u8; 16], ts: SystemTime) -> Option<AddrOutcome> {
        if !self.addrs.contains_key(&ip) && self.addrs.len() >= MAX_WINDOW_ENTRIES {
            self.prune(ts);
            if self.addrs.len() >= MAX_WINDOW_ENTRIES {
                return None;
            }
        }
        let w = self.addrs.entry(ip).or_default();
        w.principals.retain(|_, t| within(*t, ts));
        if w.principals.len() >= MANY_ACCOUNTS {
            if let Some(t) = w.principals.get_mut(&tag) {
                *t = (*t).max(ts);
            }
            return Some(AddrOutcome::Flood);
        }
        let new = w.principals.insert(tag, ts).is_none();
        Some(AddrOutcome::Own(new && w.principals.len() == MANY_ACCOUNTS))
    }

    fn failure(&mut self, r: &AuditRecord, ts: SystemTime, who: &str, out: &mut Vec<CasEvent>) {
        let tag = self.tag(who);
        let one = self.note_principal(tag, ts);
        let key = r
            .client
            .map_or(AddrKey::Unknown, |ip| AddrKey::Known(canonical(ip)));
        let addr = match one {
            None => None,
            Some(_) => self.note_addr(key, tag, ts),
        };
        let one = one == Some(true);
        match addr {
            Some(AddrOutcome::Own(many)) => {
                let mut e = self.event(r, ts, EventAction::AuthFailure, who);
                if many {
                    e.add_signal(CasSignal::FailedLoginsManyAccounts);
                }
                if one {
                    e.add_signal(CasSignal::FailedLoginsOneAccount);
                }
                out.push(e);
            }
            Some(AddrOutcome::Flood) => self.aggregate(AggAddr::Addr(key), ts, one),
            None => {
                self.overflow = self.overflow.saturating_add(1);
                self.aggregate(AggAddr::Overflow, ts, one);
            }
        }
    }

    fn aggregate(&mut self, addr: AggAddr, ts: SystemTime, one: bool) {
        let client = match addr {
            AggAddr::Addr(AddrKey::Known(ip)) => reduce(ip, self.mode),
            AggAddr::Addr(AddrKey::Unknown) | AggAddr::Overflow => None,
        };
        let e = self
            .aggregates
            .entry((addr, minute(ts)))
            .or_insert_with(|| CasEvent {
                ts,
                ts_last: None,
                action: EventAction::AuthFailure,
                principal: CasPrincipal::ManyAccounts,
                client,
                application: None,
                object: None,
                rows: None,
                signals: vec![CasSignal::FailedLoginsManyAccounts],
                count: 0,
            });
        e.count = e.count.saturating_add(1);
        if ts < e.ts {
            e.ts_last = Some(e.ts_last.unwrap_or(e.ts));
            e.ts = ts;
        } else if ts > e.ts {
            e.ts_last = Some(e.ts_last.map_or(ts, |l| l.max(ts)));
        }
        if one {
            e.add_signal(CasSignal::FailedLoginsOneAccount);
        }
    }

    /// Emits the aggregates of minutes that ended before `now` (all of them
    /// with `all`, when the stream ends).
    pub fn flush(&mut self, now: SystemTime, all: bool, out: &mut Vec<CasEvent>) {
        let current = minute(now);
        let due: Vec<AggKey> = self
            .aggregates
            .keys()
            .filter(|(_, m)| all || *m < current)
            .copied()
            .collect();
        for k in due {
            if let Some(e) = self.aggregates.remove(&k) {
                out.push(e);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddrOutcome {
    Own(bool),
    Flood,
}

#[cfg(test)]
pub(crate) mod tests_support {
    use databastion_classifiers::masking::{HmacKey, LocalTagKey};

    /// A window tag key for tests.
    pub(crate) fn key() -> LocalTagKey {
        HmacKey::new(&[7u8; 32])
            .unwrap()
            .local_tag_key(super::TAG_PURPOSE)
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::key;
    use super::*;
    use crate::config::UtcOffset;
    use crate::parse::definition::parse_definition;
    use crate::parse::record::parse_record;

    const T0: u64 = 1_800_000_000;

    fn at(s: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(T0 + s)
    }

    fn rec(action: &str, who: &str, ip: &str, s: u64) -> AuditRecord {
        parse_record(
            format!(
                r#"{{"action": "{action}", "who": "{who}", "clientIpAddress": "{ip}",
                   "when": {}, "userAgent": "curl/8.5.0 extra",
                   "what": "ST-1-FAKEfake-cas01 for https://hr.example.org/x?ticket=ST-1"}}"#,
                (T0 + s) * 1000
            )
            .as_bytes(),
            UtcOffset(0),
        )
        .unwrap()
    }

    fn builder(mode: ClientAddrMode) -> Builder {
        Builder::new(key(), &["svc-monitoring".to_owned()], mode, None)
    }

    fn run(b: &mut Builder, recs: &[AuditRecord], now: SystemTime) -> Vec<CasEvent> {
        let mut out = Vec::new();
        for r in recs {
            b.push(r, now, &mut out);
        }
        out
    }

    #[test]
    fn principals_are_fingerprinted_except_clear_ones() {
        let mut b = builder(ClientAddrMode::Clear);
        let now = at(1000);
        let out = run(
            &mut b,
            &[
                rec(
                    "AUTHENTICATION_SUCCESS",
                    "jane.doe@example.org",
                    "192.0.2.1",
                    1,
                ),
                rec("AUTHENTICATION_SUCCESS", "svc-monitoring", "192.0.2.1", 2),
                rec("AUTHENTICATION_FAILED", "svc-monitoring", "192.0.2.1", 3),
                rec(
                    "AUTHENTICATION_SUCCESS",
                    "org.apereo.cas.authentication.credential.UsernamePasswordCredential@6cd7c975",
                    "192.0.2.1",
                    4,
                ),
                rec("AUTHENTICATION_SUCCESS", "audit:unknown", "192.0.2.1", 5),
            ],
            now,
        );
        let p: Vec<(bool, String)> = out
            .iter()
            .map(|e| match &e.principal {
                CasPrincipal::Account(p) => (p.send_name(), p.account_name().to_owned()),
                CasPrincipal::ManyAccounts => (true, "*".to_owned()),
            })
            .collect();
        assert_eq!(
            p,
            [
                (false, "jane.doe@example.org".to_owned()),
                (true, "svc-monitoring".to_owned()),
                (false, "svc-monitoring".to_owned()),
                (false, UNIDENTIFIED.to_owned()),
                (false, UNIDENTIFIED.to_owned()),
            ]
        );
        assert_eq!(out[0].action, EventAction::Connect);
        assert_eq!(out[2].action, EventAction::AuthFailure);
        assert_eq!(out[0].application.as_deref(), Some("curl/8.5.0"));
        assert_eq!(out[0].client, ClientAddr::parse("192.0.2.1"));
    }

    #[test]
    fn service_tickets_name_the_service_only() {
        let def = parse_definition(
            br#"{"@class": "org.apereo.cas.services.CasRegisteredService", "name": "HR-Portal",
                "serviceId": "^https://hr\\.example\\.org/.*"}"#,
        )
        .unwrap();
        let idx = Arc::new(ServiceIndex::new([&def]));
        let mut b = builder(ClientAddrMode::Truncated);
        let r = rec("SERVICE_TICKET_CREATED", "jdoe", "192.0.2.77", 1);
        let out = run(&mut b, std::slice::from_ref(&r), at(10));
        let o = out[0].object.as_ref().unwrap();
        assert_eq!(o.database().as_str(), "service_registry");
        assert_eq!(o.object().as_str(), "*", "no index: unknown service");
        b.set_services(Some(idx));
        let out = run(&mut b, &[r], at(10));
        let e = &out[0];
        assert_eq!(e.action, EventAction::Read);
        assert_eq!(e.rows, Some(1));
        let o = e.object.as_ref().unwrap();
        assert_eq!(o.schema().map(NormalizedName::as_str), Some("cas"));
        assert_eq!(o.object().as_str(), "HR-Portal");
        assert_eq!(e.client, ClientAddr::parse("192.0.2.0"));
        let dbg = format!("{out:?}");
        for leak in ["ST-1", "ticket", "hr.example", "jdoe"] {
            assert!(!dbg.contains(leak), "{leak}");
        }
    }

    #[test]
    fn object_form_service_tickets_name_the_service_only() {
        // CAS 8.0.2 shape: `what` is an object; a clear ticket id, a
        // principal and a credential next to `service` never reach events.
        let def = parse_definition(
            br#"{"@class": "org.apereo.cas.services.CasRegisteredService", "name": "Intranet",
                "serviceId": "^https://intranet\\.example\\.org/.*"}"#,
        )
        .unwrap();
        let mut b = builder(ClientAddrMode::Truncated);
        b.set_services(Some(Arc::new(ServiceIndex::new([&def]))));
        let r = parse_record(
            br#"{"who": "jdoe", "what": {"service": "https://intranet.example.org/login",
                 "ticketId": "ST-1-FAKEclearTICKET-cas01", "principal": "MRKprincipal",
                 "credential": {"password": "MRKpassword"}},
                 "action": "SERVICE_TICKET_CREATED", "when": "2026-10-04T12:00:00Z",
                 "clientIpAddress": "192.0.2.77"}"#,
            UtcOffset(0),
        )
        .unwrap();
        let out = run(&mut b, std::slice::from_ref(&r), at(10));
        let o = out[0].object.as_ref().unwrap();
        assert_eq!(o.object().as_str(), "Intranet");
        let dbg = format!("{out:?} {r:?} {b:?}");
        for leak in ["ST-1", "FAKE", "cas01", "MRK", "intranet.example", "jdoe"] {
            assert!(!dbg.contains(leak), "{leak}");
        }
    }

    /// Real CAS 8.0.2 OAuth 2.0 / OIDC records (dev CAS: authorization
    /// code, `refresh_token`, `client_credentials` on `/oidc/token` and
    /// `/oauth2.0/accessToken`, `password`, implicit; token values
    /// redacted, `fixtures/README.md` of this crate).
    #[test]
    fn cas_802_oauth_records_map_issuance_only() {
        let def = parse_definition(
            br#"{"@class": "org.apereo.cas.services.OidcRegisteredService", "name": "M2M",
                "serviceId": "^https://m2m\\.example\\.org(/.*)?$", "clientId": "scratch-m2m"}"#,
        )
        .unwrap();
        let mut b = builder(ClientAddrMode::Truncated);
        b.set_services(Some(Arc::new(ServiceIndex::new([&def]))));
        let recs: Vec<AuditRecord> =
            include_str!("../../fixtures/cas-8.0.2-oauth-oidc-audit.jsonl")
                .lines()
                .map(|l| parse_record(l.as_bytes(), UtcOffset(0)).unwrap())
                .collect();
        assert_eq!(recs.len(), 26);
        let mut out = Vec::new();
        for r in &recs {
            b.push(r, at(10), &mut out);
        }
        let reads = |object: &str| {
            out.iter()
                .filter(|e| {
                    e.action == EventAction::Read
                        && e.rows == Some(1)
                        && e.object.as_ref().map(|o| o.object().as_str()) == Some(object)
                })
                .count()
        };
        // Service tickets (authorization code and implicit logins: `service`
        // is the redirect URI) name the client's registry entry (a pattern
        // that matches `scheme://host/`); token responses (every grant)
        // name no service (`*`).
        assert_eq!(reads("M2M"), 2);
        assert_eq!(reads("*"), 5);
        assert_eq!(
            out.iter()
                .filter(|e| e.action == EventAction::Connect)
                .count(),
            3
        );
        assert_eq!(out.len(), 10);
        let dbg = format!("{out:?} {recs:?} {b:?}");
        for leak in [
            "FAKEredacted",
            "REDACTED",
            "eyJ",
            "Basic",
            "camille",
            "scratch-m2m",
            "m2m.example",
            "N/A",
        ] {
            assert!(!dbg.contains(leak), "{leak}");
        }
        // The other OAuth / OIDC actions are counted per base.
        for base in [
            "OAUTH2_ACCESS_TOKEN_REQUEST",
            "OIDC_ID_TOKEN",
            "OAUTH2_AUTHORIZATION_RESPONSE",
            "OAUTH2_USER_PROFILE",
        ] {
            assert!(b.ignored.contains_key(base), "{base}");
        }
    }

    #[test]
    fn registry_changes_are_dcl_and_others_counted() {
        let mut b = builder(ClientAddrMode::Omitted);
        let out = run(
            &mut b,
            &[
                rec("SAVE_SERVICE_SUCCESS", "admin", "192.0.2.1", 1),
                rec("DELETE_SERVICE_SUCCESS", "admin", "192.0.2.1", 2),
                rec("TICKET_GRANTING_TICKET_CREATED", "jdoe", "192.0.2.1", 3),
                rec("SERVICE_TICKET_VALIDATE_SUCCESS", "jdoe", "192.0.2.1", 4),
                rec("LOGOUT_SUCCESS", "jdoe", "192.0.2.1", 5),
            ],
            at(10),
        );
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|e| e.action == EventAction::Dcl && e.client.is_none())
        );
        assert_eq!(
            b.ignored.keys().cloned().collect::<Vec<_>>(),
            [
                "LOGOUT",
                "SERVICE_TICKET_VALIDATE",
                "TICKET_GRANTING_TICKET"
            ]
        );
        for i in 0..100 {
            let r = rec(&format!("CUSTOM{i}_SUCCESS"), "x", "192.0.2.1", 6);
            run(&mut b, &[r], at(10));
        }
        assert_eq!(b.ignored.len(), MAX_ACTION_BASES + 1);
        assert_eq!(b.ignored.get(""), Some(&39));
    }

    #[test]
    fn a_stuffing_burst_from_one_address_is_aggregated() {
        let mut b = builder(ClientAddrMode::Truncated);
        let now = at(10_000);
        let recs: Vec<AuditRecord> = (0..40u64)
            .map(|i| {
                rec(
                    "AUTHENTICATION_FAILED",
                    &format!("user{i}"),
                    "203.0.113.9",
                    i,
                )
            })
            .collect();
        let mut out = run(&mut b, &recs, now);
        assert_eq!(out.len(), MANY_ACCOUNTS);
        assert!(
            out[..MANY_ACCOUNTS - 1]
                .iter()
                .all(|e| e.signals.is_empty())
        );
        assert_eq!(
            out[MANY_ACCOUNTS - 1].signals,
            [CasSignal::FailedLoginsManyAccounts]
        );
        b.flush(now, false, &mut out);
        let agg = &out[MANY_ACCOUNTS];
        assert_eq!(agg.principal, CasPrincipal::ManyAccounts);
        assert_eq!(agg.count, 24);
        assert_eq!(agg.signals, [CasSignal::FailedLoginsManyAccounts]);
        assert_eq!(agg.client, ClientAddr::parse("203.0.113.0"));
        assert_eq!(agg.ts, at(16));
        assert_eq!(agg.ts_last, Some(at(39)));
        assert_eq!(out.len(), MANY_ACCOUNTS + 1);
        // Another address is not affected.
        let out = run(
            &mut b,
            &[rec("AUTHENTICATION_FAILED", "user1", "198.51.100.1", 41)],
            now,
        );
        assert_eq!(out.len(), 1);
        // After the window, the address gets events of its own again.
        let out = run(
            &mut b,
            &[rec(
                "AUTHENTICATION_FAILED",
                "user99",
                "203.0.113.9",
                41 + 601,
            )],
            now,
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn failures_without_an_address_share_one_window() {
        let mut b = builder(ClientAddrMode::Truncated);
        let now = at(10_000);
        let recs: Vec<AuditRecord> = (0..20u64)
            .map(|i| {
                rec(
                    "AUTHENTICATION_FAILED",
                    &format!("user{i}"),
                    "not-an-address",
                    i,
                )
            })
            .collect();
        let mut out = run(&mut b, &recs, now);
        assert_eq!(out.len(), MANY_ACCOUNTS);
        assert_eq!(
            out[MANY_ACCOUNTS - 1].signals,
            [CasSignal::FailedLoginsManyAccounts]
        );
        b.flush(now, true, &mut out);
        let agg = out.last().unwrap();
        assert_eq!(agg.principal, CasPrincipal::ManyAccounts);
        assert_eq!((agg.count, agg.client), (4, None));
        assert_eq!(b.overflow, 0);
    }

    #[test]
    fn mapped_addresses_share_the_ipv4_window() {
        let mut b = builder(ClientAddrMode::Clear);
        let recs: Vec<AuditRecord> = (0..16u64)
            .map(|i| {
                let ip = if i % 2 == 0 {
                    "192.0.2.9"
                } else {
                    "::ffff:192.0.2.9"
                };
                rec("AUTHENTICATION_FAILED", &format!("user{i}"), ip, i)
            })
            .collect();
        let out = run(&mut b, &recs, at(10_000));
        assert_eq!(out[15].signals, [CasSignal::FailedLoginsManyAccounts]);
        assert!(
            out.iter()
                .all(|e| e.client == ClientAddr::parse("192.0.2.9"))
        );
    }

    #[test]
    fn guessing_one_account_is_signalled_from_any_address() {
        let mut b = builder(ClientAddrMode::Clear);
        let recs: Vec<AuditRecord> = (0..21u64)
            .map(|i| {
                rec(
                    "AUTHENTICATION_FAILED",
                    "jdoe",
                    &format!("192.0.2.{i}"),
                    i * 20,
                )
            })
            .collect();
        let out = run(&mut b, &recs, at(10_000));
        assert_eq!(out.len(), 21);
        assert!(out[..19].iter().all(|e| e.signals.is_empty()));
        assert!(
            out[19..]
                .iter()
                .all(|e| e.signals == [CasSignal::FailedLoginsOneAccount])
        );
        // Spread over more than the window: no signal.
        let mut b = builder(ClientAddrMode::Clear);
        let recs: Vec<AuditRecord> = (0..30u64)
            .map(|i| rec("AUTHENTICATION_FAILED", "jdoe", "192.0.2.1", i * 40))
            .collect();
        assert!(
            run(&mut b, &recs, at(10_000))
                .iter()
                .all(|e| e.signals.is_empty())
        );
    }

    #[test]
    fn full_windows_overflow_into_an_anonymous_aggregate() {
        let mut b = builder(ClientAddrMode::Clear);
        let now = at(100_000);
        let mut out = Vec::new();
        for i in 0..(MAX_WINDOW_ENTRIES as u64 + 10) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(
                u32::try_from(0x0a00_0000 + i).unwrap(),
            ));
            let r = rec(
                "AUTHENTICATION_FAILED",
                &format!("u{i}"),
                &ip.to_string(),
                0,
            );
            b.push(&r, now, &mut out);
        }
        assert_eq!(out.len(), MAX_WINDOW_ENTRIES);
        assert_eq!(b.overflow, 10);
        assert!(b.principals.len() <= MAX_WINDOW_ENTRIES && b.addrs.len() <= MAX_WINDOW_ENTRIES);
        let mut agg = Vec::new();
        b.flush(now, true, &mut agg);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].count, 10);
        assert_eq!(agg[0].client, None);
        assert_eq!(agg[0].principal, CasPrincipal::ManyAccounts);
        // Old entries are pruned when a window is full.
        let r = rec("AUTHENTICATION_FAILED", "late", "192.0.2.1", 1000);
        let mut out = Vec::new();
        b.push(&r, now, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(b.overflow, 10);
    }

    #[test]
    fn addresses_are_reduced() {
        let v4: IpAddr = "192.0.2.77".parse().unwrap();
        let v6: IpAddr = "2001:db8:1234:5678:9abc::1".parse().unwrap();
        assert_eq!(reduce(v4, ClientAddrMode::Omitted), None);
        assert_eq!(reduce(v4, ClientAddrMode::Clear), Some(ClientAddr::Ip(v4)));
        assert_eq!(
            reduce(v4, ClientAddrMode::Truncated),
            ClientAddr::parse("192.0.2.0")
        );
        assert_eq!(
            reduce(v6, ClientAddrMode::Truncated),
            ClientAddr::parse("2001:db8:1234:5600::")
        );
        let r = |s: &str| reduce(s.parse().unwrap(), ClientAddrMode::Truncated);
        // Mapped and compatible: IPv4 /24.
        assert_eq!(r("::ffff:192.0.2.77"), ClientAddr::parse("192.0.2.0"));
        assert_eq!(r("::192.0.2.77"), ClientAddr::parse("192.0.2.0"));
        assert_eq!(
            reduce("::ffff:192.0.2.77".parse().unwrap(), ClientAddrMode::Clear),
            ClientAddr::parse("192.0.2.77")
        );
        assert_eq!(r("::1"), ClientAddr::parse("::1"));
        assert_eq!(r("::"), ClientAddr::parse("::"));
        // 6to4: the embedded IPv4 cut to its /24.
        assert_eq!(
            r("2002:c000:024d:1234::1"),
            ClientAddr::parse("2002:c000:200::")
        );
        // Teredo: the obfuscated client address and port are zeroed.
        assert_eq!(
            r("2001:0:4136:e378:8000:63bf:3fff:fdd2"),
            ClientAddr::parse("2001:0:4136:e300::")
        );
    }

    /// The bodies the console would receive for `events` (the core's own
    /// masked -> contract conversion), parsed.
    fn contract(events: Vec<CasEvent>) -> Vec<serde_json::Value> {
        let masked: Vec<MaskedEvent> = events.into_iter().map(CasEvent::into_masked).collect();
        let key = databastion_classifiers::masking::HmacKey::new(&[9u8; 32]).unwrap();
        let json = databastion_core::test_support::contract_events_json(&masked, &key);
        json.lines()
            .flat_map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                v["events"].as_array().unwrap().clone()
            })
            .collect()
    }

    #[test]
    fn client_addresses_are_reduced_end_to_end() {
        let cases = [
            ("198.51.100.77", "198.51.100.0"),
            ("::ffff:192.0.2.77", "192.0.2.0"),
            ("::192.0.2.77", "192.0.2.0"),
            ("2002:c000:024d:1234::1", "2002:c000:200::"),
            ("2001:db8:1234:5678:9abc::1", "2001:db8:1234:5600::"),
            ("2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:0:4136:e300::"),
            ("::", "::"),
            ("::1", "::1"),
        ];
        let mut b = builder(ClientAddrMode::Truncated);
        let recs: Vec<AuditRecord> = cases
            .iter()
            .enumerate()
            .map(|(i, (ip, _))| {
                rec(
                    "AUTHENTICATION_SUCCESS",
                    "jane.doe@example.org",
                    ip,
                    i as u64,
                )
            })
            .collect();
        let sent = contract(run(&mut b, &recs, at(1000)));
        assert_eq!(sent.len(), cases.len());
        for (e, (ip, want)) in sent.iter().zip(cases) {
            assert_eq!(e["source"], "cas_audit_log");
            assert_eq!(e["action"], "connect");
            assert_eq!(e["principal"]["client_addr"], want, "{ip}");
            assert!(e["principal"]["db_user_fingerprint"].is_string());
            assert_eq!(e["principal"]["application"], "curl/8.5.0");
        }
        // `clear` keeps the address (mapped ones as IPv4), `omitted` drops it.
        let mut clear = builder(ClientAddrMode::Clear);
        let sent = contract(run(
            &mut clear,
            &[
                rec(
                    "AUTHENTICATION_SUCCESS",
                    "svc-monitoring",
                    "::ffff:192.0.2.77",
                    1,
                ),
                rec("AUTHENTICATION_SUCCESS", "svc-monitoring", "2001:db8::1", 2),
            ],
            at(1000),
        ));
        assert_eq!(sent[0]["principal"]["client_addr"], "192.0.2.77");
        assert_eq!(sent[1]["principal"]["client_addr"], "2001:db8::1");
        assert_eq!(sent[0]["principal"]["db_user"], "svc-monitoring");
        let mut omitted = builder(ClientAddrMode::Omitted);
        let sent = contract(run(
            &mut omitted,
            &[rec("AUTHENTICATION_SUCCESS", "x", "192.0.2.1", 1)],
            at(1000),
        ));
        assert!(sent[0]["principal"].get("client_addr").is_none());
    }

    #[test]
    fn a_flood_reaches_the_contract_as_the_star_aggregate() {
        let mut b = builder(ClientAddrMode::Truncated);
        let now = at(10_000);
        let recs: Vec<AuditRecord> = (0..40u64)
            .map(|i| {
                rec(
                    "AUTHENTICATION_FAILED",
                    &format!("user{i}@example.org"),
                    "203.0.113.9",
                    i,
                )
            })
            .collect();
        let mut out = run(&mut b, &recs, now);
        b.flush(now, true, &mut out);
        let sent = contract(out);
        assert_eq!(sent.len(), MANY_ACCOUNTS + 1);
        let agg = sent.last().unwrap();
        assert_eq!(agg["action"], "auth_failure");
        assert_eq!(agg["principal"]["db_user"], "*");
        assert_eq!(agg["principal"]["client_addr"], "203.0.113.0");
        assert_eq!(agg["aggregated_count"], 24);
        assert_eq!(
            agg["signals"],
            serde_json::json!(["volume.failed_logins_many_accounts"])
        );
        // Every other failure is a fingerprint, never a name.
        for e in &sent[..MANY_ACCOUNTS] {
            assert!(e["principal"].get("db_user").is_none(), "{e}");
        }
        let all = serde_json::to_string(&sent).unwrap();
        for leak in ["user1", "example.org", "ST-1", "hr.example", "203.0.113.9"] {
            assert!(!all.contains(leak), "{leak} in {all}");
        }
    }

    #[test]
    fn unidentified_forms() {
        for w in [
            "",
            "  ",
            "audit:unknown",
            "x.UsernamePasswordCredential@6cd7c975",
        ] {
            assert!(is_unidentified(w), "{w}");
        }
        for w in ["jdoe", "jane.doe@example.org", "Credential@example.org"] {
            assert!(!is_unidentified(w), "{w}");
        }
    }
}
