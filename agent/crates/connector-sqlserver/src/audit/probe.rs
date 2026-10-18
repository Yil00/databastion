//! The SQL Server Audit source's proofs and level (ADR-0051 decision 6,
//! "Levels and proofs", refinement item 1 option (a')): one rule shared by
//! `check()` and the Audit stream.
//!
//! Grant set (a'): `VIEW SERVER SECURITY AUDIT` (reads the audit through
//! `sys.fn_get_audit_file`) and `VIEW ANY SECURITY DEFINITION` (makes the
//! audit and specification catalogs visible). `VIEW SERVER SECURITY STATE`
//! is not used: the audit's own `AUDIT_SESSION_CHANGED` (`AUSC`) records
//! prove its starts and stops (measured on 2022: written at `STATE = OFF`
//! and `ON`, at a clean service restart and after an unclean stop); what
//! only `sys.dm_server_audit_status` gives, the `ON_FAILURE = CONTINUE`
//! failure counter, is reported as not evaluated.
//!
//! **Partial** when all hold, else **Limited** (a record read in the last
//! 24 h) or **None**; never Full:
//! 1. SQL Server 2022 or later, the account outside the refusal list and
//!    holding `VIEW SERVER SECURITY AUDIT`;
//! 2. the named audit is a `FILE` audit (`sys.server_file_audits`), enabled,
//!    with no `WHERE` predicate (`audit.server_audit_filtered`);
//! 3. reads logged in every monitored database (`audit.reads_not_logged`);
//! 4. `AUDIT_CHANGE_GROUP` in an enabled server specification
//!    (`audit.audit_changes_not_audited`);
//! 5. no gap in the last 24 h (a file lost to rollover, a restart of the
//!    audit: `audit.records_dropped`);
//! 6. a record parsed in the last 24 h (`audit.partial_pending_first_record`);
//! 7. the catalogs visible (`VIEW ANY SECURITY DEFINITION`); without them
//!    the poll's file pattern cannot be built either, so there is no
//!    source at all (`privilege.not_evaluated`, `view_any_security_definition`).
//!
//! The Extended Events source has its own rule (`xe::probe`); the
//! preference between them is `check()`'s and the stream's.

use std::collections::BTreeSet;
use std::time::Duration;

use databastion_core::config::sqlserver::{SqlserverAuditConfig, SqlserverAuditSource};
use databastion_core::{AuditLevel, NoteCode, NoteLabel, TargetNote};

use crate::conn::{Session, Shape};
use crate::error::{SsError, Stage};
use crate::sql;
use crate::token::Value;

/// The permission that reads the audit (2022+).
pub(crate) const READ_GRANT: &str = "VIEW SERVER SECURITY AUDIT";
/// The permission that shows the audit catalogs (2022+).
pub(crate) const CATALOG_GRANT: &str = "VIEW ANY SECURITY DEFINITION";
/// The Audit grants of the SQL Server Audit source (option (a')).
pub(crate) const SOURCE_GRANTS: &[&str] = &[READ_GRANT, CATALOG_GRANT];
/// First major version whose SQL Server Audit can be read without
/// `CONTROL SERVER`.
pub(crate) const MIN_AUDIT_MAJOR: i64 = 16;

/// What the catalogs say of the audit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Probe {
    pub(crate) found: bool,
    pub(crate) enabled: bool,
    pub(crate) no_predicate: bool,
    /// `sys.server_audits.on_failure`: 0 `CONTINUE`, 1 `SHUTDOWN`, 2
    /// `FAIL_OPERATION`.
    pub(crate) on_failure: i64,
    pub(crate) guid: String,
    pub(crate) folder: String,
    /// The audit's name as the catalog writes it.
    pub(crate) name: String,
    pub(crate) queue_delay: Duration,
    pub(crate) reads_server: bool,
    pub(crate) audit_change: bool,
    pub(crate) failed_login: bool,
    /// Monitored databases whose reads are not logged.
    pub(crate) dbs_without_reads: u64,
    /// A catalog read failed or was cut: the proofs it carries fail.
    pub(crate) incomplete: bool,
}

impl Probe {
    /// The quoted file pattern of the poll (`sql::audit_pattern`), from
    /// the catalog's folder, name and GUID.
    pub(crate) fn pattern(&self) -> Option<String> {
        sql::audit_pattern(&self.folder, &self.name, &self.guid)
    }
}

/// The audit named in `agent.yaml` for the SQL Server Audit source, if
/// that source applies.
pub(crate) fn audit_name(cfg: Option<&SqlserverAuditConfig>) -> Option<&str> {
    let cfg = cfg?;
    match cfg.source {
        SqlserverAuditSource::Auto | SqlserverAuditSource::SqlserverAudit => {
            cfg.audit_name.as_deref()
        }
        SqlserverAuditSource::SqlserverXevents => None,
    }
}

/// Reads the proofs of `name` on session `s` (constant texts, decision 6
/// "Exact text"); `dbs` are the monitored databases.
pub(crate) async fn probe(
    s: &mut Session,
    name: &str,
    dbs: &[String],
    stage: Stage,
) -> Result<Probe, SsError> {
    let mut p = Probe::default();
    let audit = sql::quote_literal(name)
        .and_then(|q| sql::render(sql::AUDIT_FILE, &[("audit", &q)]))
        .ok_or(SsError::new(databastion_core::FailureCode::Internal, stage))?;
    let rows = match s.rows(&audit, stage, Shape::rows(7, 2)).await {
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
    p.found = true;
    p.enabled = int(0) == Some(1);
    p.no_predicate = int(1) == Some(1);
    p.on_failure = int(2).unwrap_or(-1);
    p.guid = text(3).to_owned();
    p.folder = text(4).to_owned();
    p.queue_delay = Duration::from_millis(u64::try_from(int(5).unwrap_or(1000)).unwrap_or(1000));
    p.name = text(6).to_owned();
    let Some(guid) = sql::quote_guid(&p.guid) else {
        p.incomplete = true;
        return Ok(p);
    };
    let specs = sql::render(sql::AUDIT_SPECIFICATIONS, &[("guid", &guid)])
        .ok_or(SsError::new(databastion_core::FailureCode::Internal, stage))?;
    match s.rows(&specs, stage, Shape::rows(2, 513)).await {
        Ok(rows) => {
            if rows.len() > 512 {
                p.incomplete = true;
            }
            for r in rows.iter().take(512) {
                let group = r.first().and_then(Value::as_text).unwrap_or_default();
                let result = r.get(1).and_then(Value::as_text).unwrap_or_default();
                let success = result.starts_with("SUCCESS");
                match group {
                    "SCHEMA_OBJECT_ACCESS_GROUP" if success => p.reads_server = true,
                    "AUDIT_CHANGE_GROUP" if success => p.audit_change = true,
                    "FAILED_LOGIN_GROUP" => p.failed_login = true,
                    _ => {}
                }
            }
        }
        Err(e) if !e.fatal => p.incomplete = true,
        Err(e) => return Err(e),
    }
    if !p.reads_server {
        for db in dbs {
            let Some(stmt) = sql::quote_ident(db).and_then(|q| {
                sql::render(sql::AUDIT_DATABASE_READS, &[("db", &q), ("guid", &guid)])
            }) else {
                p.dbs_without_reads += 1;
                continue;
            };
            match s.rows(&stmt, stage, Shape::rows(1, 1)).await {
                Ok(rows) => {
                    if rows.first().and_then(|r| r.first()).and_then(Value::as_int) == Some(0) {
                        p.dbs_without_reads += 1;
                    }
                }
                Err(e) if !e.fatal => {
                    p.incomplete = true;
                    p.dbs_without_reads += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }
    Ok(p)
}

/// What the Audit stream knows (see `audit::Shared`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StreamFacts {
    pub(crate) running: bool,
    /// A record was parsed in the last 24 h.
    pub(crate) fresh: bool,
    /// A gap (file lost, audit restarted) in the last 24 h.
    pub(crate) gap: bool,
    /// Records dropped in the last 24 h.
    pub(crate) dropped: u64,
}

/// Everything the level depends on.
pub(crate) struct Inputs<'a> {
    pub(crate) cfg: Option<&'a SqlserverAuditConfig>,
    pub(crate) major: i64,
    pub(crate) perms: &'a BTreeSet<String>,
    /// The refusal list blocks Audit.
    pub(crate) blocks: bool,
    pub(crate) probe: Option<&'a Probe>,
    pub(crate) stream: StreamFacts,
}

/// The level, its notes and local details.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Level {
    pub(crate) level: AuditLevel,
    pub(crate) notes: Vec<TargetNote>,
    pub(crate) details: Vec<&'static str>,
    /// The SQL Server Audit source is usable (the stream may run).
    pub(crate) source: bool,
}

/// The level rule (see the module documentation).
pub(crate) fn level(i: &Inputs<'_>) -> Level {
    let mut out = Level {
        level: AuditLevel::None,
        notes: Vec::new(),
        details: Vec::new(),
        source: false,
    };
    let none = |mut out: Level, note: Option<TargetNote>, detail: &'static str| {
        out.notes.extend(note);
        out.details.push(detail);
        out
    };
    if i.blocks {
        return none(
            out,
            None,
            "Audit refused: the account holds a right of the refusal list",
        );
    }
    let Some(cfg) = i.cfg else {
        return none(
            out,
            Some(TargetNote::new(NoteCode::AuditSourceNotConfigured)),
            "no sqlserver.audit block in agent.yaml",
        );
    };
    if audit_name(Some(cfg)).is_none() {
        // No server audit named: this source does not apply (the Extended
        // Events session's rule decides, `xe::probe`).
        return out;
    }
    if i.major < MIN_AUDIT_MAJOR {
        return none(
            out,
            Some(TargetNote::new(
                NoteCode::AuditSqlserverAuditNeedsControlServer,
            )),
            "SQL Server Audit needs CONTROL SERVER before SQL Server 2022 (refused)",
        );
    }
    if !i.perms.contains(READ_GRANT) {
        return none(
            out,
            Some(TargetNote::new(NoteCode::AuditSourceNotConfigured)),
            "GRANT VIEW SERVER SECURITY AUDIT is missing: the audit cannot be read",
        );
    }
    if !i.perms.contains(CATALOG_GRANT) {
        return none(
            out,
            Some(
                TargetNote::new(NoteCode::PrivilegeNotEvaluated)
                    .with_labels([NoteLabel::sqlserver("view_any_security_definition")]),
            ),
            "GRANT VIEW ANY SECURITY DEFINITION is missing: the audit catalogs, and the audit's \
             file folder the poll needs, are invisible",
        );
    }
    let Some(p) = i.probe else {
        return none(
            out,
            Some(
                TargetNote::new(NoteCode::PrivilegeNotEvaluated)
                    .with_labels([NoteLabel::sqlserver("view_any_security_definition")]),
            ),
            "the audit catalogs could not be read",
        );
    };
    if !p.found {
        return none(
            out,
            Some(TargetNote::new(NoteCode::AuditSourceNotConfigured)),
            "the named server audit does not exist or has no FILE target",
        );
    }
    out.source = true;
    out.notes
        .push(TargetNote::new(NoteCode::AuditLogWithoutRowCounts));
    // Decision 6 measurement obligation (M2): what this source cannot see.
    out.details.push(AUDIT_INVISIBLE_DETAIL);
    if !invisible_measured(i.major) {
        out.details.push(INVISIBLE_NOT_MEASURED);
    }
    let mut proofs = !p.incomplete;
    if !p.enabled {
        proofs = false;
        out.notes
            .push(TargetNote::new(NoteCode::AuditSourceNotConfigured));
        out.details.push("the server audit is disabled");
    }
    if !p.no_predicate {
        proofs = false;
        out.notes
            .push(TargetNote::new(NoteCode::AuditServerAuditFiltered));
    }
    if !p.reads_server && p.dbs_without_reads > 0 {
        proofs = false;
        out.notes
            .push(TargetNote::new(NoteCode::AuditReadsNotLogged).with_count(p.dbs_without_reads));
    }
    if !p.audit_change {
        proofs = false;
        out.notes
            .push(TargetNote::new(NoteCode::AuditAuditChangesNotAudited));
    }
    if !p.failed_login {
        out.notes
            .push(TargetNote::new(NoteCode::AuditFailedLoginsNotAudited));
    }
    if p.on_failure == 0 {
        // Option (a'): the failure counter of `ON_FAILURE = CONTINUE` is in
        // sys.dm_server_audit_status, which this grant set does not read.
        // Label revision `2026_10_c` (core `notes`): `other` until the
        // console lists it.
        out.notes.push(
            TargetNote::new(NoteCode::PrivilegeNotEvaluated)
                .with_labels([NoteLabel::sqlserver("on_failure_probe")]),
        );
        out.details
            .push("ON_FAILURE = CONTINUE: records lost to a failing target are not counted");
    }
    if p.incomplete {
        out.details.push("an audit catalog read failed or was cut");
    }
    if i.stream.gap {
        proofs = false;
    }
    if i.stream.dropped > 0 {
        out.notes
            .push(TargetNote::new(NoteCode::AuditRecordsDropped).with_count(i.stream.dropped));
    }
    // Partial only while a stream reads the audit (review L2): records read
    // before a stream stopped prove nothing about now.
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

/// The measurement obligation of decision 6 (M2), measured by the
/// integration drift test `listed_object_reads_are_recorded_or_named_invisible`
/// on each listed version: objects of the three always-reported lists
/// whose reads **that run** leave no record on each source, whatever the
/// account (a low-privilege login and `sa` alike). Measured on 2022
/// (16.0.4305.5, 2026-10-18) with the dev service's specification
/// (`SCHEMA_OBJECT_ACCESS_GROUP`, no `DBCC_GROUP`) and session. The local
/// details below ([`AUDIT_INVISIBLE_DETAIL`], [`XE_INVISIBLE_DETAIL`]) say
/// the same, and are updated with it.
#[cfg(test)]
pub(crate) struct Invisible {
    /// SQL Server versions (major) the lists were measured on; on any
    /// other, the drift test prints its table and asks for a measurement.
    pub(crate) measured: &'static [u32],
    /// SQL Server Audit: the `DBCC` reads (no `DBCC_GROUP` in the
    /// specification) and the built-in functions, which check no object
    /// permission.
    pub(crate) audit: &'static [&'static str],
    /// SQL Server Audit: reads refused with these errors leave no record
    /// (a `DBCC` permission, 2571; a Query Store read refused, 262); other
    /// refusals are recorded (`succeeded = 0`).
    pub(crate) audit_refused: &'static [i32],
    /// Extended Events: statements calling these leave no statement event
    /// at all (the server hides them).
    pub(crate) xevents: &'static [&'static str],
    /// Extended Events: the reads refused **while they run** (object,
    /// error), which leave a statement event; every other refused or
    /// failed read is refused as it compiles and leaves none.
    pub(crate) xevents_runtime_errors: &'static [(&'static str, i32)],
    /// SQL Server Audit: the P9-D join (`dm_exec_query_stats` ×
    /// `dm_exec_sql_text`) refused for a low-privilege login leaves a
    /// record (`true`, measured on 2022 on 2026-10-18) or not (P9-D).
    pub(crate) audit_p9d_join_refused: bool,
}

/// The versions (major) [`AUDIT_INVISIBLE_DETAIL`] and
/// [`XE_INVISIBLE_DETAIL`] were measured on; on another, the local detail
/// adds [`INVISIBLE_NOT_MEASURED`] (security review of #276, L1).
pub(crate) const INVISIBLE_MEASURED: &[u32] = &[16];

/// Whether the invisible reads were measured on SQL Server `major`.
pub(crate) fn invisible_measured(major: i64) -> bool {
    u32::try_from(major).is_ok_and(|m| INVISIBLE_MEASURED.contains(&m))
}

/// The local detail on a version not measured yet.
pub(crate) const INVISIBLE_NOT_MEASURED: &str = "reads of the always-reported objects not measured \
on this SQL Server version: other reads may be invisible on this source";

/// See [`Invisible`].
#[cfg(test)]
pub(crate) const INVISIBLE: Invisible = Invisible {
    measured: INVISIBLE_MEASURED,
    audit: &[
        "inputbuffer",
        "show_statistics",
        "page",
        "loginproperty",
        "certprivatekey",
        "pwdcompare",
    ],
    audit_refused: &[262, 2571],
    xevents: &["certprivatekey", "pwdcompare"],
    xevents_runtime_errors: &[("dm_exec_input_buffer", 300), ("sp_readerrorlog", 27219)],
    audit_p9d_join_refused: true,
};

/// The local detail of `INVISIBLE` for SQL Server Audit.
pub(crate) const AUDIT_INVISIBLE_DETAIL: &str = "reads invisible on SQL Server Audit (measured on \
2022): DBCC INPUTBUFFER, DBCC SHOW_STATISTICS and DBCC PAGE without DBCC_GROUP in a specification, \
LOGINPROPERTY, CERTPRIVATEKEY and PWDCOMPARE (built-in functions, no permission check recorded), \
DBCC or Query Store reads refused by a permission, and reads refused by a missing server permission \
may leave no record";

/// The local detail of `INVISIBLE` for Extended Events.
pub(crate) const XE_INVISIBLE_DETAIL: &str = "Extended Events: reads invisible (measured on 2022): \
statements calling CERTPRIVATEKEY or PWDCOMPARE (the server leaves no statement event) and reads \
refused by a permission as they compile (no statement completes)";

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SqlserverAuditConfig {
        SqlserverAuditConfig {
            source: SqlserverAuditSource::SqlserverAudit,
            audit_name: Some("a".into()),
            xe_session: None,
        }
    }

    fn full_probe() -> Probe {
        Probe {
            found: true,
            enabled: true,
            no_predicate: true,
            on_failure: 1,
            guid: "B5BEF79B-88AC-4A47-91AE-0081BBD71D51".into(),
            folder: "/var/opt/mssql/audit/".into(),
            name: "a".into(),
            queue_delay: Duration::from_secs(1),
            reads_server: true,
            audit_change: true,
            failed_login: true,
            dbs_without_reads: 0,
            incomplete: false,
        }
    }

    fn perms(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn codes(l: &Level) -> Vec<&'static str> {
        l.notes.iter().map(|n| n.code().as_str()).collect()
    }

    #[test]
    fn partial_needs_every_proof_and_a_fresh_record() {
        let c = cfg();
        let p = full_probe();
        let pm = perms(SOURCE_GRANTS);
        let mut i = Inputs {
            cfg: Some(&c),
            major: 16,
            perms: &pm,
            blocks: false,
            probe: Some(&p),
            stream: StreamFacts {
                running: true,
                fresh: true,
                gap: false,
                dropped: 0,
            },
        };
        let l = level(&i);
        assert_eq!(l.level, AuditLevel::Partial, "{:?}", codes(&l));
        assert!(l.source);
        // Review of #276, L1: a version not measured says so.
        assert!(!l.details.contains(&INVISIBLE_NOT_MEASURED));
        // (2019 has no SQL Server Audit source: the rule stops before.)
        let other = level(&Inputs { major: 17, ..i });
        assert!(other.details.contains(&INVISIBLE_NOT_MEASURED));
        // Decision 6 measurement obligation (M2): the reads this source
        // cannot see are named in the local detail.
        assert!(
            l.details.contains(&AUDIT_INVISIBLE_DETAIL),
            "{:?}",
            l.details
        );
        // No stream running: Limited at most (review L2).
        i.stream.running = false;
        assert_eq!(level(&i).level, AuditLevel::Limited);
        i.stream.running = true;
        i.stream.fresh = false;
        let l = level(&i);
        assert_eq!(l.level, AuditLevel::Limited);
        assert!(codes(&l).contains(&"audit.partial_pending_first_record"));
        i.stream.fresh = true;
        i.stream.gap = true;
        i.stream.dropped = 3;
        let l = level(&i);
        assert_eq!(l.level, AuditLevel::Limited);
        assert!(codes(&l).contains(&"audit.records_dropped"));
        for (f, note) in [
            (
                (|p: &mut Probe| p.no_predicate = false) as fn(&mut Probe),
                "audit.server_audit_filtered",
            ),
            (
                |p: &mut Probe| p.audit_change = false,
                "audit.audit_changes_not_audited",
            ),
            (
                |p: &mut Probe| {
                    p.reads_server = false;
                    p.dbs_without_reads = 2;
                },
                "audit.reads_not_logged",
            ),
            (
                |p: &mut Probe| p.enabled = false,
                "audit.source_not_configured",
            ),
        ] {
            let mut q = full_probe();
            f(&mut q);
            let at = |fresh: bool| {
                level(&Inputs {
                    cfg: Some(&c),
                    major: 16,
                    perms: &pm,
                    blocks: false,
                    probe: Some(&q),
                    stream: StreamFacts {
                        running: true,
                        fresh,
                        gap: false,
                        dropped: 0,
                    },
                })
            };
            let l = at(true);
            assert_eq!(l.level, AuditLevel::Limited, "{note}");
            assert!(codes(&l).contains(&note), "{note}");
            assert_eq!(at(false).level, AuditLevel::None, "{note}");
        }
    }

    #[test]
    fn no_source_is_none() {
        let c = cfg();
        let p = full_probe();
        let pm = perms(SOURCE_GRANTS);
        let base = |major, perms, blocks| Inputs {
            cfg: Some(&c),
            major,
            perms,
            blocks,
            probe: Some(&p),
            stream: StreamFacts {
                running: true,
                fresh: true,
                gap: false,
                dropped: 0,
            },
        };
        let l = level(&base(15, &pm, false));
        assert_eq!(l.level, AuditLevel::None);
        assert!(codes(&l).contains(&"audit.sqlserver_audit_needs_control_server"));
        assert_eq!(level(&base(16, &pm, true)).level, AuditLevel::None);
        let only_read = perms(&[READ_GRANT]);
        let l = level(&base(16, &only_read, false));
        assert_eq!(l.level, AuditLevel::None);
        assert!(codes(&l).contains(&"privilege.not_evaluated"));
        let none = BTreeSet::new();
        assert_eq!(level(&base(16, &none, false)).level, AuditLevel::None);
        let mut i = base(16, &pm, false);
        i.cfg = None;
        assert!(codes(&level(&i)).contains(&"audit.source_not_configured"));
    }

    #[test]
    fn on_failure_continue_is_not_evaluated() {
        let c = cfg();
        let mut p = full_probe();
        p.on_failure = 0;
        let pm = perms(SOURCE_GRANTS);
        let l = level(&Inputs {
            cfg: Some(&c),
            major: 17,
            perms: &pm,
            blocks: false,
            probe: Some(&p),
            stream: StreamFacts {
                running: true,
                fresh: true,
                gap: false,
                dropped: 0,
            },
        });
        // Not a Partial proof (ADR-0051 decision 6): a note only, with
        // its own label (revision `2026_10_c`), never `other`.
        assert_eq!(l.level, AuditLevel::Partial);
        assert!(codes(&l).contains(&"privilege.not_evaluated"));
        let note = l
            .notes
            .iter()
            .find(|n| n.code().as_str() == "privilege.not_evaluated")
            .unwrap();
        let labels: Vec<String> = note.labels().iter().map(|l| l.as_str()).collect();
        assert_eq!(labels, ["on_failure_probe"]);
    }
}
