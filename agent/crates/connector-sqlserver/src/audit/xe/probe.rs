//! The Extended Events source's proofs and level (ADR-0051 decision 6,
//! "Levels and proofs", Extended Events): one rule shared by `check()` and
//! the stream.
//!
//! Grant: `VIEW SERVER STATE` on SQL Server 2019, `VIEW SERVER PERFORMANCE
//! STATE` on 2022 and later (decision 4); the session is the operator's,
//! the agent never creates, alters, starts or stops it (I4).
//!
//! **Partial** when all hold, else **Limited** (a record read in the last
//! 24 h) or **None**; never Full:
//! 1. the named session exists, is running, with an `event_file` target
//!    whose current file the agent can name; otherwise
//!    `audit.source_not_configured` and no source;
//! 2. `sql_statement_completed`, `sp_statement_completed` and
//!    `rpc_completed`, each with the actions `server_principal_name`,
//!    `session_server_principal_name`, `client_app_name`, `database_name`
//!    and `session_id`, and statement collection on
//!    (`audit.xe_events_missing` with the count of what is missing);
//!    `TRACK_CAUSALITY` off is a note only (`audit.xe_causality_off`);
//! 3. no predicate on those events (`audit.xe_session_filtered`);
//! 4. the drop counters have not grown and the session was not restarted
//!    (`create_time`), and no file was lost to rollover, in the last 24 h
//!    (`audit.records_dropped`); the retention mode
//!    (`ALLOW_SINGLE_EVENT_LOSS`, the default, `ALLOW_MULTIPLE_EVENT_LOSS`
//!    or `NO_EVENT_LOSS`) goes to the local detail: a lossy mode is why
//!    Full is never reported, and a loss that happens shows in the
//!    counters;
//! 5. a record parsed in the last 24 h (`audit.partial_pending_first_record`).
//!
//! Failed logins are seen only when the session has `error_reported`
//! (error 18456); without it, a local detail says so (the
//! `audit.failed_logins_not_audited` text names SQL Server Audit's group:
//! not sent for this source).

use std::collections::BTreeSet;
use std::time::Duration;

use databastion_core::config::sqlserver::{SqlserverAuditConfig, SqlserverAuditSource};
use databastion_core::{AuditLevel, NoteCode, TargetNote};

use crate::audit::probe::{Level, StreamFacts};
use crate::conn::{Session, Shape};
use crate::error::{SsError, Stage};
use crate::sql;
use crate::token::Value;

/// The Extended Events grant on SQL Server 2019.
pub(crate) const GRANT_2019: &str = "VIEW SERVER STATE";
/// The Extended Events grant on SQL Server 2022 and later.
pub(crate) const GRANT_2022: &str = "VIEW SERVER PERFORMANCE STATE";

/// The grant the source needs on `major`.
pub(crate) fn grant(major: i64) -> &'static str {
    if major >= 16 { GRANT_2022 } else { GRANT_2019 }
}

/// The events the Partial proof needs (decision 6, proof 2; re-review N2:
/// not `sql_batch_completed`).
pub(crate) const REQUIRED_EVENTS: &[&str] = &[
    "sql_statement_completed",
    "sp_statement_completed",
    "rpc_completed",
];
/// The actions each of them needs.
pub(crate) const REQUIRED_ACTIONS: i64 = 5;

/// Jitter of `sys.dm_xe_sessions.create_time` between two reads of the
/// same running session: measured up to 10 ms (three `datetime` ticks,
/// back and forth) on 2019 and 2025; the tolerance keeps a wide margin. A
/// restart moves the value by the time the session had run since its
/// previous start, which the agent observed: a restart of a session that
/// had run less than this long is not told from jitter (a residual; the
/// first restart is a gap all the same).
pub(crate) const CREATE_TIME_JITTER_US: i64 = 500_000;

/// Whether two `create_time` reads are the same start of the session: a
/// restart moves it by the time the session had run (at least the time
/// between two reads), far above the jitter.
pub(crate) fn same_start(a: i64, b: i64) -> bool {
    a.abs_diff(b) <= CREATE_TIME_JITTER_US.unsigned_abs()
}

/// The session named in `agent.yaml` for the Extended Events source, if
/// that source applies.
pub(crate) fn session_name(cfg: Option<&SqlserverAuditConfig>) -> Option<&str> {
    let cfg = cfg?;
    match cfg.source {
        SqlserverAuditSource::Auto | SqlserverAuditSource::SqlserverXevents => {
            cfg.xe_session.as_deref()
        }
        SqlserverAuditSource::SqlserverAudit => None,
    }
}

/// What the session's catalogs say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Probe {
    /// Running, with an `event_file` target and a current file.
    pub(crate) running: bool,
    /// `create_time` (server µs).
    pub(crate) create_us: i64,
    pub(crate) dropped_events: i64,
    pub(crate) dropped_buffers: i64,
    /// `buffer_policy_desc`.
    pub(crate) retention: String,
    pub(crate) causality: bool,
    /// The current file of the `event_file` target.
    pub(crate) current_file: String,
    /// `MAX_DISPATCH_LATENCY`, when stated and finite.
    pub(crate) dispatch_latency: Option<Duration>,
    /// Required events or actions missing, statement collection off.
    pub(crate) missing: u64,
    /// A predicate on a required event.
    pub(crate) filtered: bool,
    /// `error_reported` is in the session (failed logins).
    pub(crate) failed_logins: bool,
    /// A catalog read failed or was cut.
    pub(crate) incomplete: bool,
}

impl Probe {
    /// The quoted file pattern of the poll (`sql::xe_pattern`).
    pub(crate) fn pattern(&self) -> Option<String> {
        sql::xe_pattern(&self.current_file)
    }

    /// The counters a restart or a loss changes.
    pub(crate) fn counters(&self) -> (i64, i64, i64) {
        (self.create_us, self.dropped_events, self.dropped_buffers)
    }

    /// The retention mode, in the words of `CREATE EVENT SESSION`.
    pub(crate) fn retention_mode(&self) -> &'static str {
        match self.retention.as_str() {
            "drop_event" => "ALLOW_SINGLE_EVENT_LOSS",
            "drop_full_buffer" => "ALLOW_MULTIPLE_EVENT_LOSS",
            "block" | "do_not_drop_event" => "NO_EVENT_LOSS",
            _ => "unknown",
        }
    }
}

/// Reads the session's proofs on `s` (constant texts with the session's
/// name as a literal, decision 6 "Exact text").
pub(crate) async fn probe(s: &mut Session, name: &str, stage: Stage) -> Result<Probe, SsError> {
    let mut p = Probe::default();
    let session = sql::quote_literal(name)
        .ok_or(SsError::new(databastion_core::FailureCode::Internal, stage))?;
    let text = sql::render(sql::XE_SESSION, &[("session", &session)])
        .ok_or(SsError::new(databastion_core::FailureCode::Internal, stage))?;
    let rows = match s.rows(&text, stage, Shape::rows(7, 2)).await {
        Ok(r) => r,
        Err(e) if !e.fatal => {
            p.incomplete = true;
            return Ok(p);
        }
        Err(e) => return Err(e),
    };
    let Some(row) = rows.first() else {
        return Ok(p);
    };
    let int = |i: usize| row.get(i).and_then(Value::as_int);
    let text = |i: usize| row.get(i).and_then(Value::as_text).unwrap_or_default();
    p.create_us = int(0).unwrap_or(0);
    p.dropped_events = int(1).unwrap_or(0);
    p.dropped_buffers = int(2).unwrap_or(0);
    p.retention = text(3).trim().to_owned();
    p.causality = int(4) == Some(1);
    p.current_file = text(5).trim().to_owned();
    p.dispatch_latency = int(6)
        .filter(|ms| *ms > 0)
        .and_then(|ms| u64::try_from(ms).ok())
        .map(Duration::from_millis);
    p.running = !p.current_file.is_empty() && int(0).is_some();
    let events = sql::render(sql::XE_EVENTS, &[("session", &session)])
        .ok_or(SsError::new(databastion_core::FailureCode::Internal, stage))?;
    match s.rows(&events, stage, Shape::rows(4, 257)).await {
        Ok(rows) => {
            if rows.len() > 256 {
                p.incomplete = true;
            }
            let mut seen = BTreeSet::new();
            for r in rows.iter().take(256) {
                let name = r
                    .first()
                    .and_then(Value::as_text)
                    .unwrap_or_default()
                    .trim();
                let no_predicate = r.get(1).and_then(Value::as_int) == Some(1);
                let actions = r.get(2).and_then(Value::as_int).unwrap_or(0);
                let no_statement = r.get(3).and_then(Value::as_int).unwrap_or(0) > 0;
                if name == "error_reported" {
                    p.failed_logins = true;
                }
                if !REQUIRED_EVENTS.contains(&name) {
                    continue;
                }
                seen.insert(name.to_owned());
                if !no_predicate {
                    p.filtered = true;
                }
                p.missing += u64::try_from((REQUIRED_ACTIONS - actions).max(0)).unwrap_or(0);
                if no_statement && name != "rpc_completed" {
                    p.missing += 1;
                }
            }
            p.missing += REQUIRED_EVENTS
                .iter()
                .filter(|e| !seen.contains(**e))
                .count() as u64;
        }
        Err(e) if !e.fatal => p.incomplete = true,
        Err(e) => return Err(e),
    }
    Ok(p)
}

/// Everything the level depends on.
pub(crate) struct Inputs<'a> {
    pub(crate) cfg: Option<&'a SqlserverAuditConfig>,
    pub(crate) major: i64,
    pub(crate) perms: &'a BTreeSet<String>,
    pub(crate) blocks: bool,
    pub(crate) probe: Option<&'a Probe>,
    pub(crate) stream: StreamFacts,
}

/// The level rule (see the module documentation). `source` is `false`
/// when no session is named (the rule does not apply).
pub(crate) fn level(i: &Inputs<'_>) -> Level {
    let mut out = Level {
        level: AuditLevel::None,
        notes: Vec::new(),
        details: Vec::new(),
        source: false,
    };
    if i.blocks || session_name(i.cfg).is_none() {
        return out;
    }
    let none = |mut out: Level, detail: &'static str| {
        out.notes
            .push(TargetNote::new(NoteCode::AuditSourceNotConfigured));
        out.details.push(detail);
        out
    };
    if !i.perms.contains(grant(i.major)) {
        return none(
            out,
            if i.major >= 16 {
                "Extended Events: GRANT VIEW SERVER PERFORMANCE STATE is missing"
            } else {
                "Extended Events: GRANT VIEW SERVER STATE is missing"
            },
        );
    }
    let Some(p) = i.probe else {
        return none(
            out,
            "Extended Events: the session's catalogs could not be read",
        );
    };
    if !p.running {
        return none(
            out,
            "Extended Events: the named session is not running, or has no event_file target",
        );
    }
    if p.pattern().is_none() {
        return none(
            out,
            "Extended Events: the session's file name cannot be used in a file pattern",
        );
    }
    out.source = true;
    // Decision 6 measurement obligation (M2): what this source cannot see.
    out.details.push(crate::audit::probe::XE_INVISIBLE_DETAIL);
    if !crate::audit::probe::invisible_measured(i.major) {
        out.details
            .push(crate::audit::probe::INVISIBLE_NOT_MEASURED);
    }
    let mut proofs = !p.incomplete;
    if p.missing > 0 {
        proofs = false;
        out.notes
            .push(TargetNote::new(NoteCode::AuditXeEventsMissing).with_count(p.missing));
    }
    if p.filtered {
        proofs = false;
        out.notes
            .push(TargetNote::new(NoteCode::AuditXeSessionFiltered));
    }
    if !p.causality {
        out.notes
            .push(TargetNote::new(NoteCode::AuditXeCausalityOff));
    }
    if !p.failed_logins {
        out.details.push(
            "Extended Events: the session has no error_reported event (error 18456): failed \
             logins are not seen",
        );
    }
    out.details.push(match p.retention_mode() {
        "ALLOW_SINGLE_EVENT_LOSS" => {
            "Extended Events: EVENT_RETENTION_MODE = ALLOW_SINGLE_EVENT_LOSS (events can be \
             dropped under load; drops are counted and lower the level)"
        }
        "ALLOW_MULTIPLE_EVENT_LOSS" => {
            "Extended Events: EVENT_RETENTION_MODE = ALLOW_MULTIPLE_EVENT_LOSS (buffers of \
             events can be dropped under load; drops are counted and lower the level)"
        }
        "NO_EVENT_LOSS" => "Extended Events: EVENT_RETENTION_MODE = NO_EVENT_LOSS",
        _ => "Extended Events: the session's retention mode is unknown",
    });
    if p.incomplete {
        out.details
            .push("Extended Events: a session catalog read failed or was cut");
    }
    if i.stream.gap {
        proofs = false;
    }
    if i.stream.dropped > 0 {
        out.notes
            .push(TargetNote::new(NoteCode::AuditRecordsDropped).with_count(i.stream.dropped));
    }
    out.level = if proofs && i.stream.fresh && i.stream.running {
        AuditLevel::Partial
    } else if proofs {
        if !i.stream.fresh {
            out.notes
                .push(TargetNote::new(NoteCode::AuditPartialPendingFirstRecord));
        }
        AuditLevel::Limited
    } else if i.stream.fresh {
        AuditLevel::Limited
    } else {
        AuditLevel::None
    };
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SqlserverAuditConfig {
        SqlserverAuditConfig {
            source: SqlserverAuditSource::SqlserverXevents,
            audit_name: None,
            xe_session: Some("databastion_xe".into()),
        }
    }

    fn full_probe() -> Probe {
        Probe {
            running: true,
            create_us: 1,
            dropped_events: 0,
            dropped_buffers: 0,
            retention: "drop_event".into(),
            causality: true,
            current_file: "/var/opt/mssql/xe/databastion_xe_0_134365650237540000.xel".into(),
            dispatch_latency: Some(Duration::from_secs(5)),
            missing: 0,
            filtered: false,
            failed_logins: true,
            incomplete: false,
        }
    }

    fn codes(l: &Level) -> Vec<&'static str> {
        l.notes.iter().map(|n| n.code().as_str()).collect()
    }

    fn at(p: &Probe, major: i64, perms: &[&str], stream: StreamFacts) -> Level {
        let c = cfg();
        let pm: BTreeSet<String> = perms.iter().map(|s| (*s).to_owned()).collect();
        level(&Inputs {
            cfg: Some(&c),
            major,
            perms: &pm,
            blocks: false,
            probe: Some(p),
            stream,
        })
    }

    const LIVE: StreamFacts = StreamFacts {
        running: true,
        fresh: true,
        gap: false,
        dropped: 0,
    };

    #[test]
    fn partial_needs_every_proof() {
        let p = full_probe();
        let l = at(&p, 15, &[GRANT_2019], LIVE);
        assert_eq!(l.level, AuditLevel::Partial, "{:?}", codes(&l));
        assert!(l.source);
        // Review of #276, L1: 2019 is not measured yet; 2022 is.
        assert!(
            l.details
                .contains(&crate::audit::probe::INVISIBLE_NOT_MEASURED)
        );
        assert!(
            !at(&p, 16, &[GRANT_2022], LIVE)
                .details
                .contains(&crate::audit::probe::INVISIBLE_NOT_MEASURED)
        );
        // Decision 6 measurement obligation (M2): the reads this source
        // cannot see are named in the local detail.
        assert!(
            l.details
                .contains(&crate::audit::probe::XE_INVISIBLE_DETAIL),
            "{:?}",
            l.details
        );
        assert!(!codes(&l).contains(&"audit.log_without_row_counts"));
        // 2022 needs VIEW SERVER PERFORMANCE STATE.
        assert_eq!(at(&p, 16, &[GRANT_2019], LIVE).level, AuditLevel::None);
        assert_eq!(at(&p, 16, &[GRANT_2022], LIVE).level, AuditLevel::Partial);
        // A pending first record, no stream.
        let l = at(
            &p,
            15,
            &[GRANT_2019],
            StreamFacts {
                fresh: false,
                ..LIVE
            },
        );
        assert_eq!(l.level, AuditLevel::Limited);
        assert!(codes(&l).contains(&"audit.partial_pending_first_record"));
        assert_eq!(
            at(
                &p,
                15,
                &[GRANT_2019],
                StreamFacts {
                    running: false,
                    ..LIVE
                }
            )
            .level,
            AuditLevel::Limited
        );
        // A gap.
        let l = at(
            &p,
            15,
            &[GRANT_2019],
            StreamFacts {
                gap: true,
                dropped: 2,
                ..LIVE
            },
        );
        assert_eq!(l.level, AuditLevel::Limited);
        assert!(codes(&l).contains(&"audit.records_dropped"));
        for (f, note) in [
            (
                (|p: &mut Probe| p.missing = 2) as fn(&mut Probe),
                "audit.xe_events_missing",
            ),
            (
                |p: &mut Probe| p.filtered = true,
                "audit.xe_session_filtered",
            ),
        ] {
            let mut q = full_probe();
            f(&mut q);
            let l = at(&q, 15, &[GRANT_2019], LIVE);
            assert_eq!(l.level, AuditLevel::Limited, "{note}");
            assert!(codes(&l).contains(&note), "{note}");
            let l = at(
                &q,
                15,
                &[GRANT_2019],
                StreamFacts {
                    fresh: false,
                    ..LIVE
                },
            );
            assert_eq!(l.level, AuditLevel::None, "{note}");
        }
        // Causality off: a note, no effect on the level.
        let mut q = full_probe();
        q.causality = false;
        let l = at(&q, 15, &[GRANT_2019], LIVE);
        assert_eq!(l.level, AuditLevel::Partial);
        assert!(codes(&l).contains(&"audit.xe_causality_off"));
    }

    #[test]
    fn create_time_jitter_is_not_a_restart() {
        assert!(same_start(1_792_091_423_743_333, 1_792_091_423_746_666));
        assert!(same_start(1_792_094_790_483_333, 1_792_094_790_493_333));
        assert!(!same_start(1_792_091_423_743_333, 1_792_091_424_743_333));
    }

    #[test]
    fn no_session_is_none() {
        let mut p = full_probe();
        p.running = false;
        let l = at(&p, 15, &[GRANT_2019], LIVE);
        assert_eq!(l.level, AuditLevel::None);
        assert!(!l.source);
        assert!(codes(&l).contains(&"audit.source_not_configured"));
        let l = at(&full_probe(), 15, &[], LIVE);
        assert_eq!(l.level, AuditLevel::None);
        // Not named: the rule does not apply.
        let pm = BTreeSet::new();
        let l = level(&Inputs {
            cfg: None,
            major: 15,
            perms: &pm,
            blocks: false,
            probe: None,
            stream: LIVE,
        });
        assert!(!l.source && l.notes.is_empty());
    }
}
