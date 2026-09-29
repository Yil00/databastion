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

use databastion_classifiers::query::QueryAnalysis;
use databastion_core::config::TargetConfig;
use databastion_core::{EventSink, FailureCode};
use tokio_postgres::types::Type;

use super::events::{Catalogs, PgOwn, StatementDelta, analyze_pss, pss_events};
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
    schema: String,
    toplevel: bool,
    own: PgOwn,
    catalogs: Catalogs,
    snapshot: Option<HashMap<Key, Counters>>,
    analyses: HashMap<Key, QueryAnalysis>,
    last_poll: SystemTime,
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
        return Ok((
            session,
            PssPoller {
                schema,
                toplevel,
                own,
                catalogs: Catalogs::default(),
                snapshot: None,
                analyses: HashMap::new(),
                last_poll: SystemTime::now(),
            },
        ));
    }
    Err(last)
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

impl PssPoller {
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
                self.analyses.insert(key, analyze_pss(&text, cut));
            }
        }
        tx.commit().await?;
        // A delta without an analysis (text limit per poll, cache cleared)
        // is carried over: the previous counters stay the baseline, so the
        // next poll reports it in full.
        carry_over(&mut snapshot, &prev, &changed, &self.analyses);
        let deltas: Vec<StatementDelta<'_>> = changed
            .iter()
            .filter_map(|(k, user, database, calls, n)| {
                Some(StatementDelta {
                    user,
                    database,
                    analysis: self.analyses.get(k)?,
                    calls: *calls,
                    rows: *n,
                })
            })
            .collect();
        let events = pss_events(&deltas, &mut self.own, &self.catalogs, self.last_poll, now);
        drop(deltas);
        self.snapshot = Some(snapshot);
        self.last_poll = now;
        for e in events {
            sink.submit(e).await.map_err(|_| PollError::SinkClosed)?;
        }
        Ok(())
    }
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
}
