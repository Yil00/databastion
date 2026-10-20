//! Local census of the access events the agent spools, for the
//! measurement that ADR-0053 decision 6 requires before acceptance (the
//! rate of overflowed events) and its open question 1 (the rate of
//! unknown-object `*` events).
//!
//! Counts only, per target engine: no name, no value, no text (I2). Not in
//! the protocol (I6): nothing here reaches the console. Exposed as one
//! structured `tracing` info line per engine (message
//! [`CENSUS_MESSAGE`]), written by the heartbeat loop when the counts
//! changed since the previous line and once when the audit worker stops.
//! The counts are cumulative since the agent started.
//!
//! The counts are taken when the aggregator is flushed, after the
//! `audit.configure` filter and **before** `spool_events`: an event that
//! is then dropped as invalid while built into batches (per-item
//! sanitization, ADR-0009), part of a batch that cannot be serialized, or
//! lost on a spool error is still counted here. Those losses are reported
//! by the spool's `dropped_items`, `batches_serialization_failed_total`
//! and `events_lost_total` counters and their log lines.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use databastion_classifiers::masking::MaskedEvent;

use crate::config::TargetEngine;

/// Message of the census line (greppable by the load and e2e harnesses).
pub const CENSUS_MESSAGE: &str = "audit event census";

/// Every target engine, in the order of the counters.
const ENGINES: [TargetEngine; 9] = [
    TargetEngine::Postgres,
    TargetEngine::Mysql,
    TargetEngine::Mariadb,
    TargetEngine::Mongodb,
    TargetEngine::Openldap,
    TargetEngine::Cas,
    TargetEngine::Redis,
    TargetEngine::Valkey,
    TargetEngine::Sqlserver,
];

const fn index(engine: TargetEngine) -> usize {
    match engine {
        TargetEngine::Postgres => 0,
        TargetEngine::Mysql => 1,
        TargetEngine::Mariadb => 2,
        TargetEngine::Mongodb => 3,
        TargetEngine::Openldap => 4,
        TargetEngine::Cas => 5,
        TargetEngine::Redis => 6,
        TargetEngine::Valkey => 7,
        TargetEngine::Sqlserver => 8,
    }
}

const fn name(engine: TargetEngine) -> &'static str {
    match engine {
        TargetEngine::Postgres => "postgres",
        TargetEngine::Mysql => "mysql",
        TargetEngine::Mariadb => "mariadb",
        TargetEngine::Mongodb => "mongodb",
        TargetEngine::Openldap => "openldap",
        TargetEngine::Cas => "cas",
        TargetEngine::Redis => "redis",
        TargetEngine::Valkey => "valkey",
        TargetEngine::Sqlserver => "sqlserver",
    }
}

/// Counters of one engine.
struct Counts {
    /// Events spooled (after aggregation and the `audit.configure` filter).
    events: AtomicU64,
    /// Raw statements those events stand for (sum of `aggregated_count`).
    statements: AtomicU64,
    /// Spooled events whose objects overflowed a bound
    /// (`MaskedEvent::objects_overflowed`).
    overflowed: AtomicU64,
    /// Raw statements of the overflowed events.
    overflowed_statements: AtomicU64,
    /// Spooled events that name an object `*` without having overflowed
    /// (an unknown object: dynamic SQL, user code, a text the connector
    /// could not analyse; on Redis / Valkey also a real `*` key pattern).
    unknown_star: AtomicU64,
    /// Raw statements of the unknown-`*` events.
    unknown_star_statements: AtomicU64,
    /// Events dropped by the `audit.configure` filter.
    filtered: AtomicU64,
}

impl Counts {
    const fn new() -> Self {
        Self {
            events: AtomicU64::new(0),
            statements: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
            overflowed_statements: AtomicU64::new(0),
            unknown_star: AtomicU64::new(0),
            unknown_star_statements: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> [u64; 7] {
        [
            self.events.load(Ordering::Relaxed),
            self.statements.load(Ordering::Relaxed),
            self.overflowed.load(Ordering::Relaxed),
            self.overflowed_statements.load(Ordering::Relaxed),
            self.unknown_star.load(Ordering::Relaxed),
            self.unknown_star_statements.load(Ordering::Relaxed),
            self.filtered.load(Ordering::Relaxed),
        ]
    }
}

static COUNTS: [Counts; 9] = [
    Counts::new(),
    Counts::new(),
    Counts::new(),
    Counts::new(),
    Counts::new(),
    Counts::new(),
    Counts::new(),
    Counts::new(),
    Counts::new(),
];

/// Snapshots last written, per engine.
static LOGGED: Mutex<[[u64; 7]; 9]> = Mutex::new([[0; 7]; 9]);

/// The kind of a spooled event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Objects overflowed a bound.
    Overflowed,
    /// Names an object `*` without having overflowed.
    UnknownStar,
    /// Every object named.
    Named,
}

pub(crate) fn kind(e: &MaskedEvent) -> Kind {
    if e.objects_overflowed() {
        Kind::Overflowed
    } else if e.objects().iter().any(|o| o.object().as_str() == "*") {
        Kind::UnknownStar
    } else {
        Kind::Named
    }
}

/// Counts the events of a target of `engine` about to be spooled, and the
/// number the `audit.configure` filter dropped.
pub(crate) fn record(engine: TargetEngine, spooled: &[MaskedEvent], filtered: usize) {
    let c = &COUNTS[index(engine)];
    let n = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
    c.filtered.fetch_add(n(filtered), Ordering::Relaxed);
    for e in spooled {
        let raw = e.aggregated_count();
        c.events.fetch_add(1, Ordering::Relaxed);
        c.statements.fetch_add(raw, Ordering::Relaxed);
        match kind(e) {
            Kind::Overflowed => {
                c.overflowed.fetch_add(1, Ordering::Relaxed);
                c.overflowed_statements.fetch_add(raw, Ordering::Relaxed);
            }
            Kind::UnknownStar => {
                c.unknown_star.fetch_add(1, Ordering::Relaxed);
                c.unknown_star_statements.fetch_add(raw, Ordering::Relaxed);
            }
            Kind::Named => {}
        }
    }
}

/// Writes one census line per engine whose counts changed since the last
/// line (at most nine lines, counts only).
pub(crate) fn log_changed() {
    let mut logged = LOGGED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for engine in ENGINES {
        let i = index(engine);
        let now = COUNTS[i].snapshot();
        if now == logged[i] {
            continue;
        }
        logged[i] = now;
        let [
            events,
            statements,
            overflowed,
            overflowed_statements,
            unknown_star,
            unknown_star_statements,
            filtered,
        ] = now;
        tracing::info!(
            engine = name(engine),
            events,
            statements,
            overflowed,
            overflowed_statements,
            unknown_star,
            unknown_star_statements,
            filtered,
            "{CENSUS_MESSAGE}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use databastion_classifiers::masking::{EventAction, EventObject, EventPrincipal, EventSource};
    use databastion_classifiers::names::{NormalizedName, normalize_path};

    fn obj(object: NormalizedName) -> EventObject {
        EventObject::new(normalize_path("shop"), None, object)
    }

    fn ev() -> MaskedEvent {
        MaskedEvent::new(
            EventSource::Pgaudit,
            EventAction::Read,
            EventPrincipal::account("app"),
            std::time::SystemTime::UNIX_EPOCH,
        )
    }

    #[test]
    fn kinds_follow_the_flag_then_the_star() {
        let named = ev().with_object(obj(normalize_path("orders")));
        assert_eq!(kind(&named), Kind::Named);
        let star = ev().with_object(obj(NormalizedName::wildcard()));
        assert_eq!(kind(&star), Kind::UnknownStar);
        let mut over = ev();
        for i in 0..20u8 {
            over = over.with_object(obj(normalize_path(&format!(
                "table_{}",
                char::from(b'a' + i)
            ))));
        }
        assert_eq!(kind(&over), Kind::Overflowed);
        let unlisted = named.with_unlisted_objects(normalize_path("shop"));
        assert_eq!(kind(&unlisted), Kind::Overflowed);
    }

    #[test]
    fn record_counts_per_engine() {
        // Valkey only, so that other tests' counts do not interfere.
        let before = COUNTS[index(TargetEngine::Valkey)].snapshot();
        let star = ev().with_object(obj(NormalizedName::wildcard()));
        let over = ev().with_unlisted_objects(normalize_path("shop"));
        let named = ev()
            .with_object(obj(normalize_path("orders")))
            .with_aggregate(3, std::time::SystemTime::UNIX_EPOCH);
        record(TargetEngine::Valkey, &[star, over, named], 2);
        let after = COUNTS[index(TargetEngine::Valkey)].snapshot();
        let d: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
        assert_eq!(d, [3, 5, 1, 1, 1, 1, 2]);
        log_changed();
        log_changed();
    }
}
