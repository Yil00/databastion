//! From audit records to masked access events (ADR-0007, ADR-0027
//! decisions 4, 6, 7 and 9): who (`name@authdb`, client address,
//! application name), which collection (normalized names), which action,
//! how many documents, and the signals computed here from the record's
//! closed-shape facts.
//!
//! Signals (vocabulary: `classifiers::masking::Signal`):
//! - `signature.mongodump` / `signature.mongoexport`: a read of a
//!   collection (`find`, `aggregate`, `getMore`) by a client whose
//!   application name is the tool's (alone, or followed by a space, `/`,
//!   `-` or a version);
//! - `shape.full_table_read`: a `find` whose filter has no key, without a
//!   limit or with a limit above [`LARGE_LIMIT`]; an `aggregate` made of
//!   pass-through stages only; a `getMore` of such a cursor when the source
//!   shows the command that opened it;
//! - `volume.large_result`: more than [`LARGE_ROWS`] documents returned or
//!   written by one operation.
//!
//! Connections are followed per source: the server log ties a slow-query
//! line to its connection's user, address and application name through
//! `ctx`; the `auditLog` ties a record to the application name of a
//! `clientMetadata` record of the same address and port. Both maps are
//! bounded ([`MAX_CONNECTIONS`], oldest forgotten first).
//!
//! An `auditLog` endpoint (address and port) can be reused by a later
//! connection, so its application name is forgotten on a `logout` record
//! (explicit, or the implicit one MongoDB 5.0+ writes when the client
//! disconnects), and on a successful `authenticate` that no
//! `clientMetadata` record of the endpoint preceded since the previous one
//! (a driver sends its metadata in `hello`, before authenticating): a new
//! connection never inherits a previous one's name, the agent's own
//! included (end-of-phase-5 review L4).

use std::collections::{HashMap, VecDeque};
use std::time::{Instant, SystemTime};

use databastion_classifiers::masking::{
    ClientAddr, EventAction, EventObject, EventPrincipal, EventSource, MaskedEvent, Signal,
};
use databastion_classifiers::names::NormalizedName;
use databastion_core::audit::own::{ClientSeen, OwnAccount};
use zeroize::Zeroizing;

use super::records::{Cmd, ConnId, Kind, Record, Shape};
use crate::discover::{normalize_collection, normalize_database};

/// A limit above this many documents reads a whole collection.
pub(crate) const LARGE_LIMIT: u64 = 10_000;
/// Documents above which `volume.large_result` is set. Both thresholds
/// sit just above the agent's own maximum sample (`limits.max_sample_rows`
/// is at most 10 000), so its Discovery reads never carry these signals.
pub(crate) const LARGE_ROWS: u64 = 10_000;
/// Connections (or client addresses) followed.
pub(crate) const MAX_CONNECTIONS: usize = 4096;

/// What the source told about a connection.
#[derive(Default, Clone)]
struct ConnInfo {
    client: Option<ClientAddr>,
    user: Option<String>,
    app: Option<String>,
    /// `auditLog`: a `clientMetadata` record was seen since the last
    /// successful `authenticate` of the endpoint.
    fresh_meta: bool,
}

/// Bounded map of followed connections (insertion order evicts).
#[derive(Default)]
struct Conns {
    map: HashMap<ConnId, ConnInfo>,
    order: VecDeque<ConnId>,
}

impl Conns {
    fn entry(&mut self, id: ConnId) -> &mut ConnInfo {
        if !self.map.contains_key(&id) {
            while self.map.len() >= MAX_CONNECTIONS {
                match self.order.pop_front() {
                    Some(old) => {
                        self.map.remove(&old);
                    }
                    None => break,
                }
            }
            self.order.push_back(id);
        }
        self.map.entry(id).or_default()
    }

    fn get(&self, id: &ConnId) -> Option<&ConnInfo> {
        self.map.get(id)
    }

    fn remove(&mut self, id: &ConnId) {
        if self.map.remove(id).is_some() {
            self.order.retain(|c| c != id);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// The dump tool an application name declares.
pub(crate) fn dump_tool(app: &str) -> Option<Signal> {
    let b = app.as_bytes();
    let tool = |name: &str| {
        let n = name.len();
        b.len() >= n
            && b[..n].eq_ignore_ascii_case(name.as_bytes())
            && b.get(n)
                .is_none_or(|c| matches!(c, b' ' | b'/' | b'-') || c.is_ascii_digit())
    };
    if tool("mongodump") {
        Some(Signal::Mongodump)
    } else if tool("mongoexport") {
        Some(Signal::Mongoexport)
    } else {
        None
    }
}

/// Whether a `find` shape reads a whole collection.
fn whole_find(s: &Shape) -> bool {
    s.filter.is_empty()
        && s.limit
            .is_none_or(|l| l == 0 || l.unsigned_abs() > LARGE_LIMIT)
}

/// Whether an operation reads a whole collection (`shape.full_table_read`).
fn whole_read(cmd: Cmd, shape: &Shape, origin: Option<&Shape>) -> bool {
    match cmd {
        Cmd::Find => whole_find(shape),
        Cmd::Aggregate => shape.pipeline.is_some_and(|p| p.pass_through && !p.writes),
        Cmd::GetMore => origin.is_some_and(|o| match o.pipeline {
            Some(p) => p.pass_through && !p.writes,
            None => whole_find(o),
        }),
        _ => false,
    }
}

/// The action of an operation, `None` for metadata commands.
fn action(cmd: Cmd, shape: &Shape) -> Option<EventAction> {
    Some(match cmd {
        Cmd::Aggregate if shape.pipeline.is_some_and(|p| p.writes) => EventAction::Write,
        Cmd::Find | Cmd::Aggregate | Cmd::GetMore | Cmd::Count | Cmd::Distinct | Cmd::MapReduce => {
            EventAction::Read
        }
        Cmd::Insert | Cmd::Update | Cmd::Delete | Cmd::FindAndModify | Cmd::BulkWrite => {
            EventAction::Write
        }
        Cmd::Ddl => EventAction::Ddl,
        Cmd::Dcl => EventAction::Dcl,
        Cmd::Other => return None,
    })
}

/// Turns records into events.
pub(crate) struct EventBuilder {
    own: OwnAccount,
    /// The agent's account as the sources name it (`account@auth_source`).
    own_user: String,
    /// Documents per collection and day the agent's own reads may take
    /// (`limits.max_sample_rows`).
    budget: u64,
    conns: Conns,
    /// Per database: profiler polls the stream sent whose own profiler
    /// entry was not seen yet (at most [`MAX_POLL_CREDITS`]). Only that
    /// many poll-shaped reads of `system.profile` are left out uncharged.
    poll_credits: HashMap<String, u32>,
    /// Records dropped because their conversion panicked.
    pub(crate) panicked: u64,
}

/// Unused poll credits kept per database: polls whose own entry is never
/// seen (not profiled, overwritten) do not add up.
pub(crate) const MAX_POLL_CREDITS: u32 = 64;

/// The agent's own profiler polls (`audit::profiler`): a `find` on
/// `system.profile` with a one-key filter on `ts` and the batch limit, or
/// the newest-entry probe (no filter, limit 1). Only these are left out
/// without being charged, and only on the profiler source.
fn own_profiler_poll(cmd: Cmd, r: &Record) -> bool {
    use super::records::Filter;
    cmd == Cmd::Find
        && r.ns
            .as_ref()
            .is_some_and(|(_, c)| c.as_deref() == Some("system.profile"))
        && matches!(
            (r.shape.filter, r.shape.limit),
            (Filter::Keys(1), Some(super::profiler::BATCH)) | (Filter::Keys(0), Some(1))
        )
}

impl EventBuilder {
    pub(crate) fn new(own: OwnAccount, own_user: String, budget: u64) -> Self {
        Self {
            own,
            own_user,
            budget,
            conns: Conns::default(),
            poll_credits: HashMap::new(),
            panicked: 0,
        }
    }

    /// The profiler stream is about to send one poll (or newest-entry
    /// probe) to `db`: one poll-shaped read of its `system.profile` may be
    /// left out uncharged.
    pub(crate) fn grant_poll(&mut self, db: &str) {
        if self.poll_credits.len() >= MAX_CONNECTIONS && !self.poll_credits.contains_key(db) {
            return;
        }
        let c = self.poll_credits.entry(db.to_owned()).or_default();
        *c = (*c + 1).min(MAX_POLL_CREDITS);
    }

    /// Uses one poll credit of the record's database.
    fn take_poll_credit(&mut self, r: &Record) -> bool {
        let Some((db, _)) = &r.ns else {
            return false;
        };
        match self.poll_credits.get_mut(db) {
            Some(c) if *c > 0 => {
                *c -= 1;
                true
            }
            _ => false,
        }
    }

    /// Refreshes the agent's own address (re-read at each re-probe).
    pub(crate) fn set_own_addr(&mut self, addr: Option<ClientAddr>) {
        self.own.set_addr(addr);
    }

    /// Converts records in source order.
    pub(crate) fn convert(
        &mut self,
        records: Vec<Record>,
        source: EventSource,
        now: SystemTime,
    ) -> Vec<MaskedEvent> {
        let mut out = Vec::new();
        for r in records {
            // Each record in isolation: one whose conversion panics is
            // dropped alone, counted (PR #83 re-review M-A).
            match databastion_core::isolate(|| self.one(r, source, now)) {
                Some(Some(e)) => out.push(e),
                Some(None) => {}
                None => self.panicked = self.panicked.saturating_add(1),
            }
        }
        out
    }

    fn one(&mut self, mut r: Record, source: EventSource, now: SystemTime) -> Option<MaskedEvent> {
        if r.system {
            return None;
        }
        let ts = r.ts.unwrap_or(now);
        match r.kind {
            Kind::Accepted => {
                let id = r.conn?;
                let entry = self.conns.entry(id);
                *entry = ConnInfo {
                    client: r.client,
                    ..ConnInfo::default()
                };
                None
            }
            Kind::Ended => {
                if let Some(id) = r.conn {
                    self.conns.remove(&id);
                }
                None
            }
            Kind::ClientMeta => {
                let id = r.conn?;
                let entry = self.conns.entry(id);
                entry.app = r.app;
                entry.fresh_meta = true;
                if r.client.is_some() {
                    entry.client = r.client;
                }
                None
            }
            Kind::Auth { ok } => {
                let user = r.user.take()?;
                let client = r
                    .client
                    .or_else(|| self.known(r.conn).and_then(|c| c.client));
                if !ok {
                    return Some(MaskedEvent::new(
                        source,
                        EventAction::AuthFailure,
                        EventPrincipal::failed_account(&user).with_client(client),
                        ts,
                    ));
                }
                if let Some(id @ ConnId::Remote(..)) = r.conn {
                    // A new authentication on the endpoint without a new
                    // `clientMetadata`: another connection, or one that
                    // declared no name; the previous name is not its own.
                    if let Some(entry) = self.conns.map.get_mut(&id) {
                        if !entry.fresh_meta {
                            entry.app = None;
                        }
                        entry.fresh_meta = false;
                    }
                }
                let app = self.known(r.conn).and_then(|c| c.app.clone());
                if let Some(ConnId::Log(_)) = r.conn {
                    let entry = self.conns.entry(r.conn?);
                    entry.user = Some(user.to_string());
                    if client.is_some() {
                        entry.client = client;
                    }
                }
                let mut principal = EventPrincipal::account(&user).with_client(client);
                if let Some(a) = &app {
                    principal = principal.with_application(a);
                }
                let e = MaskedEvent::new(source, EventAction::Connect, principal, ts);
                let routine = self.own.routine(
                    &user,
                    app.as_deref(),
                    ClientSeen::Logged(client),
                    &e,
                    Instant::now(),
                );
                (!routine).then_some(e)
            }
            Kind::Op(cmd) => {
                // What the connection told earlier.
                if let Some(c) = self.known(r.conn).cloned() {
                    if r.user.is_none() {
                        r.user = c.user.map(Zeroizing::new);
                    }
                    if r.client.is_none() {
                        r.client = c.client;
                    }
                    if r.app.is_none() {
                        r.app = c.app;
                    }
                }
                self.operation(cmd, &r, source, ts)
            }
        }
    }

    fn known(&self, id: Option<ConnId>) -> Option<&ConnInfo> {
        self.conns.get(&id?)
    }

    fn operation(
        &mut self,
        cmd: Cmd,
        r: &Record,
        source: EventSource,
        ts: SystemTime,
    ) -> Option<MaskedEvent> {
        let action = action(cmd, &r.shape)?;
        // A failed operation is reported only when it returned documents.
        if r.failed && r.rows.unwrap_or(0) == 0 {
            return None;
        }
        let mut principal = match &r.user {
            Some(u) => EventPrincipal::account(u.as_str()),
            None => EventPrincipal::unidentified(),
        }
        .with_client(r.client);
        if let Some(a) = &r.app {
            principal = principal.with_application(a);
        }
        let mut e = MaskedEvent::new(source, action, principal, ts);
        let collection = r.ns.as_ref().and_then(|(_, c)| c.as_deref());
        if action != EventAction::Dcl {
            if let Some((db, coll)) = &r.ns {
                let object = coll
                    .as_deref()
                    .map_or_else(NormalizedName::wildcard, normalize_collection);
                e = e.with_object(EventObject::new(normalize_database(db), None, object));
            }
        }
        if matches!(action, EventAction::Read | EventAction::Write) {
            e = e.with_rows(r.rows);
        }
        if action == EventAction::Read && collection.is_some() {
            if cmd.returns_documents() {
                if let Some(tool) = r.app.as_deref().and_then(dump_tool) {
                    e = e.with_signal(tool);
                }
            }
            if whole_read(cmd, &r.shape, r.origin.as_ref()) {
                e = e.with_signal(Signal::FullTableRead);
            }
        }
        if matches!(action, EventAction::Read | EventAction::Write)
            && r.rows.is_some_and(|n| n > LARGE_ROWS)
        {
            e = e.with_signal(Signal::LargeResult);
        }
        let user = r.user.as_ref().map_or("", |u| u.as_str());
        // Writes, DDL and DCL by the agent's account are always reported:
        // the agent only reads (I4).
        if user != self.own_user || action != EventAction::Read {
            return Some(e);
        }
        let client = ClientSeen::Logged(r.client);
        let app = r.app.as_deref();
        // The agent's own reads that return no document of a collection:
        // its `count` without a filter, and its polls of the profiler (on
        // the profiler source, with their exact shape, and no more of them
        // than the stream sent: any excess is charged like any read).
        let own_poll = source == EventSource::MongodbProfiler
            && own_profiler_poll(cmd, r)
            && self.own.routine_unbudgeted(user, app, client, &e)
            && self.take_poll_credit(r);
        let routine = if own_poll {
            true
        } else if cmd == Cmd::Count && r.shape.filter.is_empty() {
            self.own.routine_unbudgeted(user, app, client, &e)
        } else if r.rows.is_some() {
            self.own.routine(user, app, client, &e, Instant::now())
        } else {
            // No count (auditLog): only a `find` with a limit within the
            // budget, charged that limit; anything else is reported.
            match (cmd, r.shape.limit) {
                (Cmd::Find, Some(l)) if l > 0 && l.unsigned_abs() <= self.budget => {
                    let charged = e.clone().with_rows(Some(l.unsigned_abs()));
                    self.own
                        .routine(user, app, client, &charged, Instant::now())
                }
                _ => false,
            }
        };
        (!routine).then_some(e)
    }

    #[cfg(test)]
    pub(crate) fn followed(&self) -> usize {
        self.conns.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use databastion_core::audit::own::SharedOwnUsage;

    use super::super::records::{Filter, Pipeline, parse_audit_log, parse_server_log};
    use super::*;

    const AGENT: &str = "172.18.0.1";

    fn builder() -> EventBuilder {
        EventBuilder::new(
            OwnAccount::new(
                "databastion@admin",
                Some("databastion-agent"),
                ClientAddr::parse(AGENT),
                200,
                SharedOwnUsage::default(),
            ),
            "databastion@admin".to_owned(),
            200,
        )
    }

    fn log(lines: &[String]) -> Vec<Record> {
        lines
            .iter()
            .filter_map(|l| parse_server_log(l.as_bytes()).unwrap())
            .collect()
    }

    fn line(id: u64, ctx: &str, attr: &str) -> String {
        format!(
            r#"{{"t":{{"$date":"2026-09-29T10:00:00.000+00:00"}},"s":"I","c":"X","id":{id},"ctx":"{ctx}","msg":"m","attr":{attr}}}"#
        )
    }

    fn accepted(conn: u64, remote: &str) -> String {
        line(
            22943,
            "listener",
            &format!(r#"{{"remote":"{remote}:5000","connectionId":{conn},"connectionCount":1}}"#),
        )
    }

    fn meta(conn: u64, app: &str) -> String {
        line(
            51800,
            &format!("conn{conn}"),
            &format!(
                r#"{{"remote":"x","client":"conn{conn}","doc":{{"application":{{"name":"{app}"}}}}}}"#
            ),
        )
    }

    fn auth(conn: u64, user: &str, ok: bool) -> String {
        line(
            if ok { 5_286_306 } else { 5_286_307 },
            &format!("conn{conn}"),
            &format!(
                r#"{{"client":"10.0.0.9:5000","mechanism":"SCRAM-SHA-256","user":"{user}","db":"admin","result":0}}"#
            ),
        )
    }

    fn slow(conn: u64, command: &str, n: u64) -> String {
        line(
            51803,
            &format!("conn{conn}"),
            &format!(
                r#"{{"type":"command","ns":"app.customers","command":{command},"nreturned":{n}}}"#
            ),
        )
    }

    #[test]
    fn dump_tools_by_application_name() {
        assert_eq!(dump_tool("mongodump"), Some(Signal::Mongodump));
        assert_eq!(dump_tool("MongoDump 100.9.4"), Some(Signal::Mongodump));
        assert_eq!(dump_tool("mongoexport/100.9"), Some(Signal::Mongoexport));
        assert_eq!(dump_tool("mongodumper"), None);
        assert_eq!(dump_tool("mongosh 2.3"), None);
        assert_eq!(dump_tool("mongo"), None);
        assert_eq!(dump_tool("é"), None);
        assert_eq!(dump_tool("mongodumpé"), None);
    }

    #[test]
    fn server_log_connections_give_the_user_and_the_tool() {
        let mut b = builder();
        let records = log(&[
            accepted(7, "10.0.0.9"),
            meta(7, "mongodump"),
            auth(7, "alice", true),
            slow(7, r#"{"find":"customers","filter":{},"$db":"app"}"#, 20_000),
            slow(
                7,
                r#"{"find":"customers","filter":{"email":"x@example.com"},"$db":"app"}"#,
                1,
            ),
            slow(7, r#"{"listCollections":1,"$db":"app"}"#, 0),
            line(
                22944,
                "conn7",
                r#"{"remote":"10.0.0.9:5000","connectionId":7}"#,
            ),
            slow(7, r#"{"find":"customers","$db":"app"}"#, 1),
        ]);
        let ev = b.convert(records, EventSource::MongodbLog, SystemTime::now());
        assert_eq!(ev.len(), 4, "{ev:?}");
        assert_eq!(ev[0].action(), EventAction::Connect);
        assert_eq!(ev[0].principal().account_name(), "alice@admin");
        assert_eq!(ev[0].principal().application(), Some("mongodump"));
        let dump = &ev[1];
        assert_eq!(dump.action(), EventAction::Read);
        assert_eq!(dump.rows(), Some(20_000));
        assert_eq!(dump.objects()[0].object().as_str(), "customers");
        assert_eq!(
            dump.signals(),
            [
                Signal::FullTableRead,
                Signal::LargeResult,
                Signal::Mongodump
            ]
        );
        assert_eq!(dump.principal().client(), ClientAddr::parse("10.0.0.9"));
        // A filtered read by the tool: the signature, not the shape.
        assert_eq!(ev[2].signals(), [Signal::Mongodump]);
        // After the connection ended, the user is unknown.
        assert!(!ev[3].principal().send_name());
        assert_eq!(ev[3].principal().account_name(), "");
        assert_eq!(b.followed(), 0);
    }

    #[test]
    fn auth_failures_are_fingerprinted() {
        let mut b = builder();
        let ev = b.convert(
            log(&[auth(3, "hunter2", false)]),
            EventSource::MongodbLog,
            SystemTime::now(),
        );
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].action(), EventAction::AuthFailure);
        assert!(!ev[0].principal().send_name());
    }

    /// A driver closing a pooled connection in its handshake (the e2e
    /// `mongodump` does, intermittently): mongod logs "Failed to
    /// authenticate" with `AuthenticationAbandoned` (337). Not a failed
    /// login: no `auth_failure` event, whereas a refused proof on the next
    /// connection still is one.
    #[test]
    fn abandoned_authentications_are_not_auth_failures() {
        let abandoned = |conn: u64| {
            line(
                5_286_307,
                &format!("conn{conn}"),
                r#"{"client":"10.0.0.9:5000","isSpeculative":true,"mechanism":"SCRAM-SHA-256","user":"e2e_exporter","db":"admin","error":"AuthenticationAbandoned: Authentication session abandoned, client has likely disconnected","result":337}"#,
            )
        };
        let refused = line(
            5_286_307,
            "conn5",
            r#"{"client":"10.0.0.9:5000","isSpeculative":false,"mechanism":"SCRAM-SHA-256","user":"e2e_exporter","db":"admin","error":"AuthenticationFailed: SCRAM authentication failed, storedKey mismatch","result":18}"#,
        );
        let mut b = builder();
        let ev = b.convert(
            log(&[
                accepted(3, "10.0.0.9"),
                meta(3, "mongodump"),
                abandoned(3),
                accepted(4, "10.0.0.9"),
                abandoned(4),
            ]),
            EventSource::MongodbLog,
            SystemTime::now(),
        );
        assert!(ev.is_empty(), "{ev:?}");
        let ev = b.convert(
            log(&[accepted(5, "10.0.0.9"), refused]),
            EventSource::MongodbLog,
            SystemTime::now(),
        );
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].action(), EventAction::AuthFailure);
        assert!(!ev[0].principal().send_name());
    }

    #[test]
    fn get_more_carries_the_shape_of_its_cursor() {
        let mut b = builder();
        let getmore = line(
            51803,
            "conn8",
            r#"{"type":"command","ns":"app.customers","appName":"mongoexport","command":{"getMore":42,"collection":"customers","$db":"app"},"originatingCommand":{"find":"customers","filter":{},"$db":"app"},"nreturned":500}"#,
        );
        let ev = b.convert(log(&[getmore]), EventSource::MongodbLog, SystemTime::now());
        assert_eq!(
            ev[0].signals(),
            [Signal::FullTableRead, Signal::Mongoexport]
        );
    }

    #[test]
    fn actions_and_objects() {
        let mut b = builder();
        let ev = b.convert(
            log(&[
                slow(
                    1,
                    r#"{"insert":"customers","documents":[{"a":1}],"$db":"app"}"#,
                    0,
                ),
                slow(
                    1,
                    r#"{"aggregate":"customers","pipeline":[{"$out":"copy"}],"$db":"app"}"#,
                    0,
                ),
                slow(1, r#"{"drop":"customers","$db":"app"}"#, 0),
                slow(
                    1,
                    r#"{"createUser":"bob","pwd":"xxx","roles":[],"$db":"app"}"#,
                    0,
                ),
            ]),
            EventSource::MongodbLog,
            SystemTime::now(),
        );
        let actions: Vec<EventAction> = ev.iter().map(MaskedEvent::action).collect();
        assert_eq!(
            actions,
            [
                EventAction::Write,
                EventAction::Write,
                EventAction::Ddl,
                EventAction::Dcl
            ]
        );
        assert!(ev[3].objects().is_empty());
        assert_eq!(ev[2].objects()[0].database().as_str(), "app");
    }

    #[test]
    fn failed_operations_without_documents_are_skipped() {
        let mut b = builder();
        let failed = line(
            51803,
            "conn1",
            r#"{"type":"command","ns":"app.customers","command":{"find":"customers","$db":"app"},"ok":0,"errMsg":"x@example.com","errName":"Unauthorized","errCode":13,"nreturned":0}"#,
        );
        assert!(
            b.convert(log(&[failed]), EventSource::MongodbLog, SystemTime::now())
                .is_empty()
        );
    }

    fn own_record(cmd: Cmd, coll: &str, rows: Option<u64>, app: Option<&str>) -> Record {
        let mut r = Record::new(Kind::Op(cmd));
        r.user = Some(Zeroizing::new("databastion@admin".to_owned()));
        r.client = ClientAddr::parse(AGENT);
        r.app = app.map(str::to_owned);
        r.ns = Some(("app".to_owned(), Some(coll.to_owned())));
        r.rows = rows;
        r.shape.limit = Some(200);
        r.shape.filter = Filter::Absent;
        r
    }

    #[test]
    fn own_reads_are_left_out_within_the_budget() {
        let mut b = builder();
        let app = Some("databastion-agent");
        let poll = |filter, limit| {
            let mut r = own_record(Cmd::Find, "system.profile", Some(1000), app);
            r.shape.filter = filter;
            r.shape.limit = Some(limit);
            r
        };
        for _ in 0..3 {
            b.grant_poll("app");
        }
        let own = vec![
            own_record(Cmd::Count, "customers", None, app),
            own_record(Cmd::Find, "customers", Some(200), app),
            poll(Filter::Keys(1), crate::audit::profiler::BATCH),
            poll(Filter::Keys(1), crate::audit::profiler::BATCH),
            poll(Filter::Keys(0), 1),
        ];
        assert!(
            b.convert(own, EventSource::MongodbProfiler, SystemTime::now())
                .is_empty()
        );
        // Over the budget: reported.
        let again = vec![own_record(Cmd::Find, "customers", Some(200), app)];
        assert_eq!(
            b.convert(again, EventSource::MongodbProfiler, SystemTime::now())
                .len(),
            1
        );
        // Another application name: reported.
        let mut b = builder();
        let other = vec![own_record(Cmd::Find, "customers", Some(1), Some("mongosh"))];
        assert_eq!(
            b.convert(other, EventSource::MongodbProfiler, SystemTime::now())
                .len(),
            1
        );
        // Another account reading system.profile: reported.
        let mut r = own_record(Cmd::Find, "system.profile", Some(1), None);
        r.user = Some(Zeroizing::new("alice@admin".to_owned()));
        assert_eq!(
            b.convert(vec![r], EventSource::MongodbProfiler, SystemTime::now())
                .len(),
            1
        );
        // The tool's name on the agent's account: never left out.
        let mut b = builder();
        let dump = vec![own_record(
            Cmd::Find,
            "customers",
            Some(1),
            Some("mongodump"),
        )];
        assert_eq!(
            b.convert(dump, EventSource::MongodbProfiler, SystemTime::now())
                .len(),
            1
        );
    }

    /// Security review M1: only the agent's exact profiler polls, on the
    /// profiler source, are free; any other read of `system.profile` with
    /// the agent's identity is charged (and reported past the budget).
    #[test]
    fn system_profile_reads_are_free_only_as_the_agents_own_polls() {
        let app = Some("databastion-agent");
        let shaped = |filter, limit| {
            let mut r = own_record(Cmd::Find, "system.profile", Some(150), app);
            r.shape.filter = filter;
            r.shape.limit = limit;
            r
        };
        // Not the poll shape: charged, so reported past the budget (200).
        let mut b = builder();
        let reads = vec![
            shaped(Filter::Keys(2), Some(5)),
            shaped(Filter::Keys(2), Some(5)),
        ];
        assert_eq!(
            b.convert(reads, EventSource::MongodbProfiler, SystemTime::now())
                .len(),
            1
        );
        // The poll shape on a file source: charged too.
        let mut b = builder();
        let reads = vec![
            shaped(Filter::Keys(1), Some(crate::audit::profiler::BATCH)),
            shaped(Filter::Keys(1), Some(crate::audit::profiler::BATCH)),
        ];
        assert_eq!(
            b.convert(reads, EventSource::MongodbLog, SystemTime::now())
                .len(),
            1
        );
        // An aggregate on system.profile: charged.
        let mut b = builder();
        let mut agg = shaped(Filter::Keys(1), Some(crate::audit::profiler::BATCH));
        agg.kind = Kind::Op(Cmd::Aggregate);
        let reads = vec![agg.clone(), agg];
        assert_eq!(
            b.convert(reads, EventSource::MongodbProfiler, SystemTime::now())
                .len(),
            1
        );
    }

    /// Security review L3: no more uncharged poll-shaped reads of a
    /// database's `system.profile` than polls the stream sent; the excess
    /// is charged (and reported past the budget).
    #[test]
    fn uncharged_profiler_polls_are_limited_to_the_polls_sent() {
        let app = Some("databastion-agent");
        let poll = || {
            let mut r = own_record(Cmd::Find, "system.profile", Some(1000), app);
            r.shape.filter = Filter::Keys(1);
            r.shape.limit = Some(crate::audit::profiler::BATCH);
            r
        };
        let mut b = builder();
        b.grant_poll("app");
        b.grant_poll("app");
        b.grant_poll("other");
        let ev = b.convert(
            vec![poll(), poll(), poll()],
            EventSource::MongodbProfiler,
            SystemTime::now(),
        );
        // Two credits for `app`: the third read is charged 1000 > 200.
        assert_eq!(ev.len(), 1);
        // Another identity never uses a credit.
        let mut b = builder();
        b.grant_poll("app");
        let mut stolen = poll();
        stolen.client = ClientAddr::parse("10.9.9.9");
        assert_eq!(
            b.convert(
                vec![stolen, poll()],
                EventSource::MongodbProfiler,
                SystemTime::now()
            )
            .len(),
            1
        );
        // Credits do not pile up.
        let mut b = builder();
        for _ in 0..1000 {
            b.grant_poll("app");
        }
        let polls: Vec<Record> = (0..=MAX_POLL_CREDITS).map(|_| poll()).collect();
        assert_eq!(
            b.convert(polls, EventSource::MongodbProfiler, SystemTime::now())
                .len(),
            1
        );
    }

    /// Security review M2: writes, DDL and DCL by the agent's account are
    /// always reported, whatever its identity and budget.
    #[test]
    fn own_writes_ddl_and_dcl_are_always_reported() {
        let mut b = builder();
        let app = Some("databastion-agent");
        let records = vec![
            own_record(Cmd::Insert, "customers", Some(1), app),
            own_record(Cmd::Ddl, "customers", None, app),
            own_record(Cmd::Dcl, "customers", None, app),
        ];
        let ev = b.convert(records, EventSource::MongodbLog, SystemTime::now());
        let actions: Vec<EventAction> = ev.iter().map(MaskedEvent::action).collect();
        assert_eq!(
            actions,
            [EventAction::Write, EventAction::Ddl, EventAction::Dcl]
        );
    }

    /// Security review L1: without counts (`auditLog`), only a `find` with
    /// a limit within the budget is left out, charged that limit.
    #[test]
    fn own_reads_without_counts_need_a_bounded_find() {
        let app = Some("databastion-agent");
        let find = |limit| {
            let mut r = own_record(Cmd::Find, "customers", None, app);
            r.shape.limit = limit;
            r
        };
        let mut b = builder();
        let ev = b.convert(
            vec![find(Some(150)), find(None), find(Some(201)), find(Some(0))],
            EventSource::MongodbAuditLog,
            SystemTime::now(),
        );
        // The first is left out; no limit, over the budget, `0`: reported.
        assert_eq!(ev.len(), 3);
        // Charged 150 of 200: a second one goes over.
        assert_eq!(
            b.convert(
                vec![find(Some(100))],
                EventSource::MongodbAuditLog,
                SystemTime::now()
            )
            .len(),
            1
        );
        let mut agg = own_record(Cmd::Aggregate, "customers", None, app);
        agg.shape.limit = None;
        let mut b = builder();
        assert_eq!(
            b.convert(vec![agg], EventSource::MongodbAuditLog, SystemTime::now())
                .len(),
            1
        );
    }

    #[test]
    fn audit_log_uses_client_metadata_of_the_same_endpoint() {
        let mut b = builder();
        let meta = r#"{"atype":"clientMetadata","ts":{"$date":"2026-09-29T10:00:00.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[],"param":{"clientMetadata":{"application":{"name":"mongodump"}}},"result":0}"#;
        let find = r#"{"atype":"authCheck","ts":{"$date":"2026-09-29T10:00:01.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[{"user":"alice","db":"admin"}],"param":{"command":"find","ns":"app.customers","args":{"find":"customers","$db":"app"}},"result":0}"#;
        let other_port = find.replace("51000", "51001");
        let records: Vec<Record> = [meta, find, other_port.as_str()]
            .iter()
            .filter_map(|l| parse_audit_log(l.as_bytes()).unwrap())
            .collect();
        let ev = b.convert(records, EventSource::MongodbAuditLog, SystemTime::now());
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].signals(), [Signal::FullTableRead, Signal::Mongodump]);
        assert!(ev[0].rows().is_none());
        assert_eq!(ev[1].signals(), [Signal::FullTableRead]);
    }

    /// End-of-phase-5 review L4: an endpoint's application name is
    /// forgotten on `logout`, and on a new `authenticate` without its own
    /// `clientMetadata`.
    #[test]
    fn audit_log_forgets_a_reused_endpoint_application_name() {
        let meta = r#"{"atype":"clientMetadata","ts":{"$date":"2026-09-29T10:00:00.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[],"param":{"clientMetadata":{"application":{"name":"mongodump"}}},"result":0}"#;
        let auth = r#"{"atype":"authenticate","ts":{"$date":"2026-09-29T10:00:00.500Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[{"user":"alice","db":"admin"}],"param":{"user":"alice","db":"admin","mechanism":"SCRAM-SHA-256"},"result":0}"#;
        let find = r#"{"atype":"authCheck","ts":{"$date":"2026-09-29T10:00:01.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[{"user":"alice","db":"admin"}],"param":{"command":"find","ns":"app.customers","args":{"find":"customers","filter":{"a":1},"$db":"app"}},"result":0}"#;
        let logout = r#"{"atype":"logout","ts":{"$date":"2026-09-29T10:00:02.000Z"},"remote":{"ip":"10.0.0.9","port":51000},"users":[],"param":{"reason":"Client has disconnected","initialUsers":[{"user":"alice","db":"admin"}],"updatedUsers":[]},"result":0}"#;
        let convert = |lines: &[&str]| {
            let records: Vec<Record> = lines
                .iter()
                .filter_map(|l| parse_audit_log(l.as_bytes()).unwrap())
                .collect();
            builder().convert(records, EventSource::MongodbAuditLog, SystemTime::now())
        };
        let apps = |ev: &[MaskedEvent]| -> Vec<Option<String>> {
            ev.iter()
                .map(|e| e.principal().application().map(str::to_owned))
                .collect()
        };
        // The metadata, then the authentication, of the same connection.
        let ev = convert(&[meta, auth, find]);
        assert_eq!(
            apps(&ev),
            [Some("mongodump".to_owned()), Some("mongodump".to_owned())]
        );
        assert_eq!(ev[1].signals(), [Signal::Mongodump]);
        // Logged out: the next connection on the same port has no name.
        let ev = convert(&[meta, auth, logout, auth, find]);
        assert_eq!(apps(&ev), [Some("mongodump".to_owned()), None, None]);
        assert!(ev[2].signals().is_empty());
        // No logout record, but a new authentication without metadata.
        let ev = convert(&[meta, auth, find, auth, find]);
        assert_eq!(
            apps(&ev),
            [
                Some("mongodump".to_owned()),
                Some("mongodump".to_owned()),
                None,
                None
            ]
        );
        assert!(ev[3].signals().is_empty());
        // A new connection with its own metadata keeps its name.
        let ev = convert(&[meta, auth, logout, meta, auth, find]);
        assert_eq!(ev[2].signals(), [Signal::Mongodump]);
        // A logout record parses and yields no event.
        assert!(convert(&[logout]).is_empty());
    }

    #[test]
    fn connection_maps_are_bounded() {
        let mut b = builder();
        let lines: Vec<String> = (0..(MAX_CONNECTIONS as u64 + 10))
            .map(|i| accepted(i, "10.0.0.9"))
            .collect();
        b.convert(log(&lines), EventSource::MongodbLog, SystemTime::now());
        assert_eq!(b.followed(), MAX_CONNECTIONS);
    }

    #[test]
    fn shapes() {
        let find = |filter, limit| Shape {
            filter,
            limit,
            pipeline: None,
        };
        assert!(whole_read(Cmd::Find, &find(Filter::Absent, None), None));
        assert!(whole_read(Cmd::Find, &find(Filter::Keys(0), Some(0)), None));
        assert!(whole_read(
            Cmd::Find,
            &find(Filter::Keys(0), Some(-20_000)),
            None
        ));
        assert!(!whole_read(
            Cmd::Find,
            &find(Filter::Keys(0), Some(10_000)),
            None
        ));
        assert!(!whole_read(Cmd::Find, &find(Filter::Keys(1), None), None));
        assert!(!whole_read(Cmd::Find, &find(Filter::Unknown, None), None));
        assert!(!whole_read(Cmd::Count, &find(Filter::Absent, None), None));
        let agg = Shape {
            pipeline: Some(Pipeline {
                pass_through: true,
                writes: false,
            }),
            ..Shape::default()
        };
        assert!(whole_read(Cmd::Aggregate, &agg, None));
        assert!(whole_read(Cmd::GetMore, &Shape::default(), Some(&agg)));
        assert!(!whole_read(Cmd::GetMore, &Shape::default(), None));
    }
}
