//! Degraded Audit (level Limited) through `pg_stat_statements`: the
//! counters are polled, and the deltas between two polls become events.
//!
//! What it can attribute: the role (`userid`) and database of a statement,
//! how many times it ran and how many rows it returned or affected in the
//! poll interval, and the relations named by its (normalized) text.
//! What it cannot: the client address or application, the time of each
//! execution (only the poll interval), per-execution row counts, statements
//! evicted before a poll (`pg_stat_statements.max`), utility statements
//! when `pg_stat_statements.track_utility` is off, and anything on
//! unqualified names beyond the name itself (no schema: the search path is
//! unknown). The `pg_dump` application name is invisible; only the pattern
//! (several whole relations copied to the client by one role in one poll)
//! is detected. The level reported by `check()` stays Limited.
//!
//! Queries follow ADR-0012: read-only transactions with `SET LOCAL`
//! timeouts, extension objects qualified with the schema of their
//! extension and checked as members (`pg_depend`), counters read without
//! text (`showtext => false`), texts read only for new statements, cut at
//! [`sql::PSS_MAX_TEXT_CHARS`] and analyzed by the query normalizer only.

use std::collections::HashMap;
use std::time::SystemTime;

use databastion_classifiers::masking::MaskedEvent;
use databastion_classifiers::query::QueryAnalysis;
use databastion_core::config::TargetConfig;
use databastion_core::{EventSink, FailureCode};
use tokio_postgres::types::Type;

use super::events::{
    Catalogs, PgOwn, StatementDelta, analyze_pss, pss_events_counted, pss_unanalyzed_event,
};
use crate::check::audit_probe;
use crate::conn::{Session, Timeouts};
use crate::error::{PgError, Stage};
use crate::sql;
use crate::wire::catalog_text;

/// Texts fetched per poll at most (new statements only).
const MAX_TEXTS_PER_POLL: usize = 500;
/// Analyses cached (cleared when full).
const MAX_CACHED: usize = 20_000;

type Key = (u32, u32, i64, bool);

#[derive(Clone, Copy)]
struct Counters {
    calls: i64,
    rows: i64,
}

/// Poller state kept across polls of one session.
pub(crate) struct PssPoller {
    /// Database of the session the poller reads through.
    database: String,
    schema: String,
    toplevel: bool,
    own: PgOwn,
    catalogs: Catalogs,
    snapshot: Option<HashMap<Key, Counters>>,
    /// `None`: the analysis panicked; the statement is dropped (counted
    /// once) and not analyzed again while cached.
    analyses: HashMap<Key, Option<Analyzed>>,
    /// The `queryid` pinned for each of the connector's own statements.
    own_keys: OwnKeys,
    last_poll: SystemTime,
    /// Statements dropped because their analysis or conversion panicked.
    pub(crate) panicked: u64,
}

/// Where the connector's own table-less statements may be recognized on
/// `pg_stat_statements`, and the `queryid` pinned for each (PR #90 review
/// Low-1). An entry whose text is exactly an own statement
/// (`PgOwn::own_pss_form`) is the connector's only when all hold:
/// - its `userid` is the agent's role (its oid, read once per connection);
/// - it is a top-level entry (the connector never runs them nested);
/// - the connector runs that statement in that database: the session and
///   transaction statements (`sql::OWN_TABLELESS`) in the declared
///   databases, the text query only in the poller's database;
/// - its `queryid` is the one first seen in that slot. A client can
///   prepare the exact stored text with every constant bound as a
///   parameter: another `queryid`, same text. The connector's statements
///   have one `queryid` per database and role, so a legitimate second key
///   does not occur; if such a client's entry was seen first, the
///   connector's own executions are the ones reported: loud, not hidden.
///
/// Anything else with an own text is reported. The slots are closed (at
/// most 16 databases x 3 statements, plus one), so other roles cannot
/// exhaust them. Not persisted: pinned again after an agent restart.
#[derive(Default)]
struct OwnKeys {
    /// The agent role's oid (`None`: unknown, nothing is own).
    role: Option<u32>,
    /// The declared databases' oids.
    databases: Vec<u32>,
    /// The poller's database oid.
    poller_database: Option<u32>,
    /// The text query the poller sends (as sent).
    texts_sql: String,
    pinned: HashMap<(u32, String), i64>,
}

impl OwnKeys {
    /// Whether the entry `key`, whose text is the own statement `sent` (as
    /// sent), is the connector's (pinning it when it is the first seen in
    /// its slot).
    fn admit(&mut self, key: Key, sent: &str) -> bool {
        let (userid, dbid, queryid, toplevel) = key;
        if self.role != Some(userid) || !toplevel {
            return false;
        }
        let runs_here = if sql::OWN_TABLELESS.contains(&sent) {
            self.databases.contains(&dbid)
        } else {
            sent == self.texts_sql && self.poller_database == Some(dbid)
        };
        if !runs_here {
            return false;
        }
        *self
            .pinned
            .entry((dbid, sent.to_owned()))
            .or_insert(queryid)
            == queryid
    }
}

/// A statement text's analysis, and whether the entry is one of the
/// connector's own table-less statements (exact text,
/// `PgOwn::own_pss_form`, and pinned `queryid`, [`OwnKeys`]; decided on
/// the text, which is not kept).
struct Analyzed {
    analysis: QueryAnalysis,
    own_text: bool,
}

/// Tests: a text holding this marker makes its analysis panic (a bug on
/// one statement).
#[cfg(test)]
const TEST_POISON: &str = "TEST-ANALYZER-PANIC";

/// One text's analysis in isolation (`databastion_core::isolate`, as the
/// file sources do; security review of #85): `None` when it panicked.
fn analyze_isolated(text: &str, cut: bool) -> Option<QueryAnalysis> {
    databastion_core::isolate(|| {
        #[cfg(test)]
        #[allow(clippy::panic)]
        if text.contains(TEST_POISON) {
            panic!("analysis bug on a statement");
        }
        analyze_pss(text, cut)
    })
}

/// Finds a database of the target where `pg_stat_statements` is usable
/// (installed, loaded, other users visible) and its function schema.
pub(crate) async fn connect(
    target: &TargetConfig,
    timeouts: Timeouts,
    own: PgOwn,
) -> Result<(Session, PssPoller), PgError> {
    let mut own = Some(own);
    let settings = target.postgres_settings();
    let mut last = PgError::new(FailureCode::Unsupported, Stage::Audit);
    for database in &settings.databases {
        let session = match Session::connect(target, database, timeouts).await {
            Ok(s) => s,
            Err(e) => {
                last = e;
                continue;
            }
        };
        let probe = audit_probe(&session, timeouts).await?;
        if !(probe.pss_installed && probe.pss_loaded && probe.stats_visible) {
            continue;
        }
        let tx = session.begin(timeouts).await?;
        let rows = tx.query(Stage::Audit, sql::PSS_FUNCTION_SCHEMA, &[]).await;
        let schema = match rows {
            Ok(rows) => {
                tx.commit().await?;
                rows.first()
                    .map(|r| catalog_text(r, 0))
                    .transpose()
                    .map_err(|e| PgError::from_driver(&e, Stage::Audit))?
                    .flatten()
            }
            Err(e) => {
                tx.rollback().await;
                return Err(e);
            }
        };
        let Some(schema) = schema else {
            continue;
        };
        let toplevel = session.server_version_num() >= 140_000;
        let mut own = own
            .take()
            .ok_or(PgError::new(FailureCode::Internal, Stage::Audit))?;
        // The text query reads `pg_stat_statements` through the
        // extension's function (no relation named): one of the
        // connector's own statements, like the view `pg_stat_statements*`
        // skipped as statistics for every role.
        let texts_sql = sql::pss_texts(&schema, toplevel)
            .ok_or(PgError::new(FailureCode::Internal, Stage::Audit))?;
        own.allow_statement(&texts_sql);
        let (role, databases, poller_database) =
            own_oids(&session, timeouts, &settings.databases).await?;
        return Ok((
            session,
            PssPoller {
                database: database.clone(),
                schema,
                toplevel,
                own,
                catalogs: Catalogs::default(),
                snapshot: None,
                analyses: HashMap::new(),
                own_keys: OwnKeys {
                    role,
                    databases,
                    poller_database,
                    texts_sql,
                    pinned: HashMap::new(),
                },
                last_poll: SystemTime::now(),
                panicked: 0,
            },
        ));
    }
    Err(last)
}

/// The agent role's oid, the declared databases' oids and this session's
/// database oid ([`sql::OWN_OIDS`], in a transaction with the timeouts).
async fn own_oids(
    session: &Session,
    timeouts: Timeouts,
    databases: &[String],
) -> Result<(Option<u32>, Vec<u32>, Option<u32>), PgError> {
    let names: Vec<String> = databases.to_vec();
    let tx = session.begin(timeouts).await?;
    let rows = match tx
        .query(Stage::Audit, sql::OWN_OIDS, &[(&names, Type::TEXT_ARRAY)])
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tx.rollback().await;
            return Err(e);
        }
    };
    tx.commit().await?;
    let get = |e: tokio_postgres::Error| PgError::from_driver(&e, Stage::Audit);
    let Some(r) = rows.first() else {
        return Ok((None, Vec::new(), None));
    };
    Ok((
        r.try_get::<_, Option<u32>>(0).map_err(get)?,
        r.try_get::<_, Option<Vec<u32>>>(1)
            .map_err(get)?
            .unwrap_or_default(),
        r.try_get::<_, Option<u32>>(2).map_err(get)?,
    ))
}

fn delta(now: Counters, prev: Option<Counters>, first: bool) -> Option<(u64, u64)> {
    let (calls, rows) = match prev {
        // Reset or eviction and reuse: the counters restarted.
        Some(p) if now.calls < p.calls || now.rows < p.rows => (now.calls, now.rows),
        Some(p) => (now.calls - p.calls, now.rows - p.rows),
        // First poll: a baseline only.
        None if first => (0, 0),
        // New since the last poll.
        None => (now.calls, now.rows),
    };
    let calls = u64::try_from(calls).ok().filter(|c| *c > 0)?;
    Some((calls, u64::try_from(rows).unwrap_or(0)))
}

/// A new session on the poller's database (the held one was closed for a
/// re-probe of the other databases, phase 7).
pub(crate) async fn reopen(
    target: &TargetConfig,
    timeouts: Timeouts,
    poller: &PssPoller,
) -> Result<Session, PgError> {
    Session::connect(target, &poller.database, timeouts).await
}

impl PssPoller {
    /// Analyzes one statement text read from `pg_stat_statements` and
    /// caches the result for its entry: whether it is one of the
    /// connector's own statements (exact text and pinned `queryid`), and
    /// `None` when the analysis panicked (counted once).
    fn record_text(&mut self, key: Key, text: &str, cut: bool) {
        let own_text = !cut
            && self
                .own
                .own_pss_form(text)
                .is_some_and(|sent| self.own_keys.admit(key, sent));
        let analysis = analyze_isolated(text, cut).map(|analysis| Analyzed { analysis, own_text });
        if analysis.is_none() {
            self.panicked = self.panicked.saturating_add(1);
        }
        self.analyses.insert(key, analysis);
    }

    /// The events of one poll's changed statements, between the last poll
    /// and `now`.
    fn events_of(
        &mut self,
        changed: &[(Key, String, String, u64, u64)],
        now: SystemTime,
    ) -> Vec<MaskedEvent> {
        let (deltas, keys, unanalyzed) = split_deltas(changed, &self.analyses);
        let (mut events, panicked) =
            pss_events_counted(&deltas, &mut self.own, &self.catalogs, self.last_poll, now);
        self.panicked = self.panicked.saturating_add(panicked.len() as u64);
        // A statement whose conversion panicked is marked poisoned, like
        // one whose analysis panicked: its later deltas go straight to the
        // `*` fallback, without converting (and counting) it again.
        let poisoned: Vec<Key> = panicked
            .iter()
            .filter_map(|i| keys.get(*i).copied())
            .collect();
        drop(deltas);
        // A statement whose analysis panicked stays cached as such (never
        // analyzed again, counted once), but each of its deltas is still
        // reported against `*`: `queryid` ignores constants and comments,
        // so dropping them would hide every later execution of that shape
        // (phase-7 security review).
        for (user, database, calls, n) in unanalyzed {
            events.push(pss_unanalyzed_event(
                user,
                database,
                calls,
                n,
                self.last_poll,
                now,
            ));
        }
        for k in poisoned {
            self.analyses.insert(k, None);
        }
        events
    }

    /// Database of the session the poller reads through.
    pub(crate) fn database(&self) -> &str {
        &self.database
    }

    /// Sets the per-database catalog facts (re-probed with the source).
    pub(crate) fn set_catalogs(&mut self, catalogs: Catalogs) {
        self.catalogs = catalogs;
    }

    /// One poll: reads the counters, fetches the texts of new statements,
    /// submits the events of the deltas.
    pub(crate) async fn poll(
        &mut self,
        session: &Session,
        timeouts: Timeouts,
        sink: &EventSink,
    ) -> Result<(), PollError> {
        let now = SystemTime::now();
        let counters_sql =
            sql::pss_counters(&self.schema, self.toplevel).ok_or(PollError::Internal)?;
        let tx = session.begin(timeouts).await?;
        let rows = match tx.query(Stage::Audit, &counters_sql, &[]).await {
            Ok(r) => r,
            Err(e) => {
                tx.rollback().await;
                return Err(e.into());
            }
        };
        let first = self.snapshot.is_none();
        let prev = self.snapshot.take().unwrap_or_default();
        let mut snapshot = HashMap::with_capacity(rows.len());
        // (key, user, database, calls, rows)
        let mut changed: Vec<(Key, String, String, u64, u64)> = Vec::new();
        for r in &rows {
            let get = |e: tokio_postgres::Error| PgError::from_driver(&e, Stage::Audit);
            let key: Key = (
                r.try_get::<_, u32>(0).map_err(get)?,
                r.try_get::<_, u32>(1).map_err(get)?,
                r.try_get::<_, i64>(2).map_err(get)?,
                r.try_get::<_, bool>(3).map_err(get)?,
            );
            let c = Counters {
                calls: r.try_get::<_, i64>(4).map_err(get)?,
                rows: r.try_get::<_, i64>(5).map_err(get)?,
            };
            snapshot.insert(key, c);
            let Some((calls, n)) = delta(c, prev.get(&key).copied(), first) else {
                continue;
            };
            let user = catalog_text(r, 6).map_err(get)?.unwrap_or_default();
            if user.is_empty() {
                continue;
            }
            let database = catalog_text(r, 7).map_err(get)?.unwrap_or_default();
            changed.push((key, user, database, calls, n));
        }
        // Texts of statements not analyzed yet.
        let missing: Vec<i64> = changed
            .iter()
            .filter(|(k, ..)| !self.analyses.contains_key(k))
            .map(|(k, ..)| k.2)
            .take(MAX_TEXTS_PER_POLL)
            .collect();
        if !missing.is_empty() {
            if self.analyses.len() + missing.len() > MAX_CACHED {
                self.analyses.clear();
            }
            let texts_sql =
                sql::pss_texts(&self.schema, self.toplevel).ok_or(PollError::Internal)?;
            let texts = match tx
                .query(Stage::Audit, &texts_sql, &[(&missing, Type::INT8_ARRAY)])
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tx.rollback().await;
                    return Err(e.into());
                }
            };
            for r in &texts {
                let get = |e: tokio_postgres::Error| PgError::from_driver(&e, Stage::Audit);
                let key: Key = (
                    r.try_get::<_, u32>(0).map_err(get)?,
                    r.try_get::<_, u32>(1).map_err(get)?,
                    r.try_get::<_, i64>(2).map_err(get)?,
                    r.try_get::<_, bool>(3).map_err(get)?,
                );
                // Zeroized after the analysis; never logged.
                let text =
                    zeroize::Zeroizing::new(catalog_text(r, 4).map_err(get)?.unwrap_or_default());
                let cut = r
                    .try_get::<_, Option<bool>>(5)
                    .map_err(get)?
                    .unwrap_or(true);
                self.record_text(key, &text, cut);
            }
        }
        tx.commit().await?;
        // A delta without an analysis (text limit per poll, cache cleared)
        // is carried over: the previous counters stay the baseline, so the
        // next poll reports it in full.
        carry_over(&mut snapshot, &prev, &changed, &self.analyses);
        let events = self.events_of(&changed, now);
        self.snapshot = Some(snapshot);
        self.last_poll = now;
        for e in events {
            sink.submit(e).await.map_err(|_| PollError::SinkClosed)?;
        }
        Ok(())
    }
}

/// Changed statements with an analysis, as deltas (with their keys, in
/// the same order); and those whose analysis or conversion panicked, as
/// (user, database, calls, rows). Statements not
/// analyzed yet (text limit per poll, cache cleared) are in neither: they
/// are carried over ([`carry_over`]).
#[allow(clippy::type_complexity)]
fn split_deltas<'a>(
    changed: &'a [(Key, String, String, u64, u64)],
    analyses: &'a HashMap<Key, Option<Analyzed>>,
) -> (
    Vec<StatementDelta<'a>>,
    Vec<Key>,
    Vec<(&'a str, &'a str, u64, u64)>,
) {
    let mut deltas = Vec::new();
    let mut keys = Vec::new();
    let mut unanalyzed = Vec::new();
    for (k, user, database, calls, n) in changed {
        match analyses.get(k) {
            Some(Some(a)) => {
                deltas.push(StatementDelta {
                    user,
                    database,
                    analysis: &a.analysis,
                    own_text: a.own_text,
                    calls: *calls,
                    rows: *n,
                });
                keys.push(*k);
            }
            Some(None) => unanalyzed.push((user.as_str(), database.as_str(), *calls, *n)),
            None => {}
        }
    }
    (deltas, keys, unanalyzed)
}

fn carry_over<V>(
    snapshot: &mut HashMap<Key, Counters>,
    prev: &HashMap<Key, Counters>,
    changed: &[(Key, String, String, u64, u64)],
    analyses: &HashMap<Key, V>,
) {
    for (k, ..) in changed {
        if analyses.contains_key(k) {
            continue;
        }
        match prev.get(k) {
            Some(p) => {
                snapshot.insert(*k, *p);
            }
            None => {
                snapshot.remove(k);
            }
        }
    }
}

/// A poll failed.
pub(crate) enum PollError {
    Db(PgError),
    SinkClosed,
    Internal,
}

impl From<PgError> for PollError {
    fn from(e: PgError) -> Self {
        Self::Db(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deltas_without_analysis_carry_over() {
        let c = |calls, rows| Counters { calls, rows };
        let (k1, k2, k3) = ((1, 1, 1, true), (1, 1, 2, true), (1, 1, 3, true));
        let prev: HashMap<Key, Counters> = [(k1, c(5, 5)), (k2, c(1, 1))].into();
        let mut snapshot: HashMap<Key, Counters> =
            [(k1, c(9, 9)), (k2, c(4, 4)), (k3, c(2, 2))].into();
        let changed = vec![
            (k1, String::new(), String::new(), 4, 4),
            (k2, String::new(), String::new(), 3, 3),
            (k3, String::new(), String::new(), 2, 2),
        ];
        // Only k1 was analyzed this poll.
        let analyses: HashMap<Key, ()> = [(k1, ())].into();
        carry_over(&mut snapshot, &prev, &changed, &analyses);
        assert_eq!(snapshot[&k1].calls, 9);
        assert_eq!(
            snapshot[&k2].calls, 1,
            "baseline kept: the next delta includes this one"
        );
        assert!(
            !snapshot.contains_key(&k3),
            "new entry: seen as new next time"
        );
        assert_eq!(
            delta(c(4, 4), snapshot.get(&k2).copied(), false),
            Some((3, 3))
        );
        assert_eq!(
            delta(c(2, 2), snapshot.get(&k3).copied(), false),
            Some((2, 2))
        );
    }

    #[test]
    fn deltas_handle_baseline_resets_and_new_entries() {
        let c = |calls, rows| Counters { calls, rows };
        assert_eq!(delta(c(5, 50), None, true), None, "first poll: baseline");
        assert_eq!(delta(c(5, 50), None, false), Some((5, 50)), "new entry");
        assert_eq!(delta(c(7, 70), Some(c(5, 50)), false), Some((2, 20)));
        assert_eq!(delta(c(5, 50), Some(c(5, 50)), false), None, "unchanged");
        assert_eq!(delta(c(2, 3), Some(c(5, 50)), false), Some((2, 3)), "reset");
    }

    /// Security review of #85: a statement whose analysis panics is
    /// dropped alone; the others are analyzed.
    #[test]
    fn a_panicking_analysis_drops_one_statement() {
        assert!(analyze_isolated(&format!("SELECT 1 /* {TEST_POISON} */"), false).is_none());
        let ok = analyze_isolated("SELECT * FROM shop.customers", false).unwrap();
        assert!(!ok.parts().is_empty());
        // A statement whose analysis panicked stays cached as such: its
        // counters move on (not analyzed again every poll).
        let c = |calls, rows| Counters { calls, rows };
        let k = (1, 1, 1, true);
        let prev: HashMap<Key, Counters> = [(k, c(1, 1))].into();
        let mut snapshot: HashMap<Key, Counters> = [(k, c(5, 5))].into();
        let changed = vec![(k, String::new(), String::new(), 4, 4)];
        let analyses: HashMap<Key, Option<Analyzed>> = [(k, None)].into();
        carry_over(&mut snapshot, &prev, &changed, &analyses);
        assert_eq!(snapshot[&k].calls, 5);
    }

    /// Phase-7 security review: the later deltas of a statement whose
    /// analysis panicked are still reported, against `*`, with their
    /// counts; the others are analyzed as usual.
    #[test]
    fn a_poisoned_statement_still_reports_its_later_deltas() {
        let poisoned = (10, 1, 7, true);
        let fine = (10, 1, 8, true);
        let not_yet = (10, 1, 9, true);
        let analyses: HashMap<Key, Option<Analyzed>> = [
            (
                poisoned,
                analyze_isolated(&format!("SELECT 1 /* {TEST_POISON} */"), false).map(|analysis| {
                    Analyzed {
                        analysis,
                        own_text: false,
                    }
                }),
            ),
            (
                fine,
                analyze_isolated("SELECT id FROM crm.customers WHERE id = $1", false).map(
                    |analysis| Analyzed {
                        analysis,
                        own_text: false,
                    },
                ),
            ),
        ]
        .into();
        assert!(analyses[&poisoned].is_none());
        let t0 = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        let own = || {
            PgOwn::new(
                databastion_core::audit::own::OwnAccount::new(
                    "databastion",
                    Some(crate::conn::APPLICATION_NAME),
                    None,
                    1000,
                    databastion_core::audit::own::SharedOwnUsage::default(),
                ),
                super::super::events::SharedOwnStatements::default(),
            )
        };
        let mut own = own();
        // Two later polls of the poisoned statement, run by another role
        // and by the agent's own account.
        for (user, calls, rows) in [("mallory", 3u64, 12_000u64), ("databastion", 1, 2)] {
            let changed = vec![
                (poisoned, user.to_owned(), "shop".to_owned(), calls, rows),
                (fine, "alice".to_owned(), "shop".to_owned(), 1, 1),
                (not_yet, "bob".to_owned(), "shop".to_owned(), 1, 1),
            ];
            let (deltas, keys, unanalyzed) = split_deltas(&changed, &analyses);
            assert_eq!(deltas.len(), 1);
            assert_eq!(keys, [fine]);
            assert_eq!(unanalyzed, [(user, "shop", calls, rows)]);
            let (mut events, panicked) =
                pss_events_counted(&deltas, &mut own, &Catalogs::default(), t0, t0);
            assert!(panicked.is_empty(), "never analyzed again");
            for (u, d, c, r) in unanalyzed {
                events.push(pss_unanalyzed_event(u, d, c, r, t0, t0));
            }
            assert_eq!(events.len(), 2);
            let e = &events[1];
            assert_eq!(e.principal().account_name(), user);
            assert_eq!(e.objects().len(), 1);
            assert_eq!(e.objects()[0].database().as_str(), "shop");
            assert_eq!(e.objects()[0].object().as_str(), "*");
            assert_eq!(e.aggregated_count(), calls);
            assert_eq!(e.rows(), Some(rows));
        }
    }

    /// The agent's role oid in the tests.
    const AGENT_ROLE: u32 = 10;
    /// Declared databases (`1`: the poller's, `2`), and a non-target one.
    const POLLER_DB: u32 = 1;
    const OTHER_TARGET_DB: u32 = 2;
    const NON_TARGET_DB: u32 = 3;

    fn poller() -> PssPoller {
        let texts_sql = sql::pss_texts("public", true).unwrap();
        let mut own = PgOwn::new(
            databastion_core::audit::own::OwnAccount::new(
                "databastion",
                Some(crate::conn::APPLICATION_NAME),
                databastion_classifiers::masking::ClientAddr::parse("192.0.2.14"),
                1000,
                databastion_core::audit::own::SharedOwnUsage::default(),
            ),
            super::super::events::SharedOwnStatements::default(),
        );
        own.allow_statement(&texts_sql);
        PssPoller {
            database: "shop".to_owned(),
            schema: "public".to_owned(),
            toplevel: true,
            own,
            catalogs: Catalogs::default(),
            snapshot: None,
            analyses: HashMap::new(),
            own_keys: OwnKeys {
                role: Some(AGENT_ROLE),
                databases: vec![POLLER_DB, OTHER_TARGET_DB],
                poller_database: Some(POLLER_DB),
                texts_sql,
                pinned: HashMap::new(),
            },
            last_poll: SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000),
            panicked: 0,
        }
    }

    fn own_pss_text(sql_text: &str) -> String {
        super::super::events::tests_pss_form(sql_text)
    }

    /// PR #90 review Low-1: an own statement's exact stored text is the
    /// connector's only for the agent's role, at top level, in a database
    /// where the connector runs it, and under the first `queryid` seen
    /// there; anything else with the same text is reported.
    #[test]
    fn own_texts_count_only_in_the_connectors_own_slots() {
        let mut p = poller();
        let set_local = own_pss_text(sql::SET_LOCAL_TIMEOUTS);
        let setup = own_pss_text(sql::SESSION_SETUP);
        let texts = own_pss_text(&sql::pss_texts("public", true).unwrap());
        let own = |p: &PssPoller, k: &Key| p.analyses[k].as_ref().unwrap().own_text;
        // The agent's own entries in their own slots: excluded.
        let agent = (AGENT_ROLE, POLLER_DB, 100, true);
        let agent_other_db = (AGENT_ROLE, OTHER_TARGET_DB, 100, true);
        let agent_texts = (AGENT_ROLE, POLLER_DB, 200, true);
        p.record_text(agent, &set_local, false);
        p.record_text(agent_other_db, &set_local, false);
        p.record_text(agent_texts, &texts, false);
        p.record_text((AGENT_ROLE, POLLER_DB, 101, true), &setup, false);
        for k in [
            agent,
            agent_other_db,
            agent_texts,
            (AGENT_ROLE, POLLER_DB, 101, true),
        ] {
            assert!(own(&p, &k), "{k:?}");
        }
        // Slots the connector never uses: reported, never pinned.
        let cases = [
            (
                "non-target database",
                (AGENT_ROLE, NON_TARGET_DB, 300, true),
                &set_local,
            ),
            (
                "texts query outside the poller's database",
                (AGENT_ROLE, OTHER_TARGET_DB, 301, true),
                &texts,
            ),
            (
                "nested entry",
                (AGENT_ROLE, POLLER_DB, 302, false),
                &set_local,
            ),
            ("another role", (11, POLLER_DB, 303, true), &set_local),
            // Same slot, another queryid (every constant bound).
            (
                "another queryid",
                (AGENT_ROLE, POLLER_DB, 999, true),
                &set_local,
            ),
        ];
        for (what, k, text) in cases {
            p.record_text(k, text, false);
            assert!(!own(&p, &k), "{what}");
        }
        assert_eq!(p.own_keys.pinned.len(), 4, "only the connector's slots");
        // The pin survives the cache being cleared (texts read again).
        p.analyses.clear();
        p.record_text((AGENT_ROLE, POLLER_DB, 999, true), &set_local, false);
        p.record_text(agent, &set_local, false);
        assert!(!own(&p, &(AGENT_ROLE, POLLER_DB, 999, true)));
        assert!(own(&p, &agent));
        // A cut text is never own, and does not pin.
        let cut = (AGENT_ROLE, OTHER_TARGET_DB, 7, true);
        p.record_text(cut, &setup, true);
        assert!(!own(&p, &cut));
        p.record_text((AGENT_ROLE, OTHER_TARGET_DB, 8, true), &setup, false);
        assert!(own(&p, &(AGENT_ROLE, OTHER_TARGET_DB, 8, true)));
        // Unknown agent role: nothing is own.
        let mut q = poller();
        q.own_keys.role = None;
        q.record_text(agent, &set_local, false);
        assert!(!own(&q, &agent));
        for (_, k, text) in &cases {
            p.record_text(*k, text, false);
        }
        // Events: the agent's own entry is left out; the same text in a
        // non-target database, nested, or under another queryid, run by the
        // agent's account, is reported against `*`.
        let changed = vec![
            (agent, "databastion".to_owned(), "shop".to_owned(), 90, 90),
            (
                (AGENT_ROLE, NON_TARGET_DB, 300, true),
                "databastion".to_owned(),
                "other".to_owned(),
                3,
                3,
            ),
            (
                (AGENT_ROLE, POLLER_DB, 302, false),
                "databastion".to_owned(),
                "shop".to_owned(),
                4,
                4,
            ),
            (
                (AGENT_ROLE, OTHER_TARGET_DB, 301, true),
                "databastion".to_owned(),
                "crm".to_owned(),
                5,
                5,
            ),
            (
                (AGENT_ROLE, POLLER_DB, 999, true),
                "databastion".to_owned(),
                "shop".to_owned(),
                6,
                6,
            ),
        ];
        let events = p.events_of(
            &changed,
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2000),
        );
        let mut counts: Vec<u64> = events.iter().map(MaskedEvent::aggregated_count).collect();
        counts.sort_unstable();
        assert_eq!(counts, [3, 4, 5, 6], "{events:?}");
        assert!(
            events
                .iter()
                .all(|e| e.objects()[0].object().as_str() == "*")
        );
    }

    /// PR #90 review Low-2: a statement whose conversion panics is marked
    /// poisoned: counted once, and its later deltas go straight to the
    /// `*` fallback.
    #[test]
    fn a_conversion_panic_poisons_the_statement() {
        let mut p = poller();
        let k = (20, 1, 42, true);
        p.record_text(k, "SELECT * FROM crm.customers", false);
        let changed = vec![(
            k,
            super::super::events::TEST_POISON_USER.to_owned(),
            "shop".to_owned(),
            2,
            5,
        )];
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2000);
        for poll in 0..3 {
            let events = p.events_of(&changed, now);
            assert_eq!(events.len(), 1, "poll {poll}");
            assert_eq!(events[0].objects()[0].object().as_str(), "*");
            assert_eq!(events[0].aggregated_count(), 2);
            assert!(p.analyses[&k].is_none(), "poisoned");
            assert_eq!(p.panicked, 1, "counted once (poll {poll})");
        }
    }
}
