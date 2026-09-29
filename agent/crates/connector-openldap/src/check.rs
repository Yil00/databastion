//! `check()`: reachability, the audit level proven from `cn=accesslog`,
//! and what a read-only account can tell of its own privileges (ADR-0029
//! decisions 4, 10 and 11).
//!
//! - Reachability: TLS, bind, Who am I?, root DSE.
//! - Privileges, never by trying a write (I4): `cn=config` readable; the
//!   `userPassword` / `authPassword` types disclosed by an attributes-only
//!   search of the first entries of each naming context (values never
//!   transferred); `cn=accesslog` readable while no Audit stream runs.
//!   Write access cannot be evaluated: always noted.
//! - Level: Full when every naming context has a search record in
//!   `cn=accesslog` from the last 24 h (looked up, and after one base
//!   search of the context when there is none), Partial when some do,
//!   Limited when none do, None when the log is not readable.
//!
//! The report is recomputed at most every [`REPORT_INTERVAL`] per target;
//! every explanation is a closed note (a code and a count).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use databastion_classifiers::masking::EventSource;
use databastion_core::audit::own::SharedOwnUsage;
use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditLevel, FailureCode, NoteCode, NoteLabel, Notes, TargetHealth, TargetNote,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::catalog::{self, RootDse};
use crate::conn::{Session, Timeouts};
use crate::dn;
use crate::error::{LdError, Stage};
use crate::proto::{Entry, Filter, Scope, Search};
use crate::time;

/// Timeout of each `check()` operation.
const CHECK_OP_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound of a whole `check()` (the core allows 10 s).
const CHECK_TIMEOUT: Duration = Duration::from_secs(9);
/// Period of the detailed report.
pub(crate) const REPORT_INTERVAL: Duration = Duration::from_secs(600);
/// A search record seen within this period proves reads are logged.
pub(crate) const RECORD_FRESHNESS: Duration = Duration::from_secs(24 * 3600);
/// Naming contexts proven per report (the others wait for the next one).
const MAX_PROVEN_PER_REPORT: usize = 8;
/// Naming contexts probed for readable password attributes per report.
const MAX_PASSWORD_PROBES: usize = 8;
/// Bound of the privilege and audit-source evaluation within a check.
const REPORT_TIMEOUT: Duration = Duration::from_secs(5);
/// Credential attributes probed (attributes-only).
pub(crate) const PASSWORD_ATTRIBUTES: [&str; 2] = ["userPassword", "authPassword"];
/// Entries of each naming context the password-attribute probe looks at.
/// A presence filter on `userPassword` would scan the whole context for an
/// account that may not search it (the recommended one): the probe reads
/// the first entries instead, types only.
pub(crate) const PASSWORD_PROBE_ENTRIES: u32 = 64;

/// The detailed report of a target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) config_readable: bool,
    pub(crate) password_readable: bool,
    /// `None`: not evaluated (a probe failed).
    pub(crate) accesslog_readable: Option<bool>,
}

struct Cached {
    at: Instant,
    report: Report,
}

/// The Audit source of a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    Accesslog,
    None,
}

impl Source {
    pub(crate) fn event_source(self) -> Option<EventSource> {
        match self {
            Self::Accesslog => Some(EventSource::OpenldapAccesslog),
            Self::None => None,
        }
    }
}

/// Per-target state of `check()` and of the Audit stream.
#[derive(Default)]
pub(crate) struct CheckState {
    reports: Mutex<HashMap<String, Cached>>,
    sources: Mutex<HashMap<String, EventSource>>,
    /// Running Audit streams per target.
    streams: Mutex<HashMap<String, usize>>,
    own_usage: Mutex<HashMap<String, SharedOwnUsage>>,
    /// Log entries dropped, and when the count started (24 h).
    dropped: Mutex<HashMap<String, (u64, Instant)>>,
    /// Per (target, canonical naming context): when a search record of it
    /// was last seen in `cn=accesslog`.
    proofs: Mutex<HashMap<(String, String), Instant>>,
    /// Per (target, canonical naming context): whether a search that ended
    /// in a size limit (after returning entries) was found in the log, and
    /// when that was tested (security review M1: `olcAccessLogSuccess:
    /// TRUE` logs successful operations only).
    failures_logged: Mutex<HashMap<(String, String), (bool, Instant)>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Marks an Audit stream as running for a target while alive.
pub(crate) struct StreamGuard<'a> {
    state: &'a CheckState,
    target_id: String,
}

impl Drop for StreamGuard<'_> {
    fn drop(&mut self) {
        let mut map = lock(&self.state.streams);
        if let Some(n) = map.get_mut(&self.target_id) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                map.remove(&self.target_id);
            }
        }
    }
}

impl CheckState {
    /// The Audit stream of `target_id` starts.
    pub(crate) fn stream_started(&self, target_id: &str) -> StreamGuard<'_> {
        *lock(&self.streams).entry(target_id.to_owned()).or_insert(0) += 1;
        StreamGuard {
            state: self,
            target_id: target_id.to_owned(),
        }
    }

    fn stream_running(&self, target_id: &str) -> bool {
        lock(&self.streams).contains_key(target_id)
    }

    /// A search record of the naming context `context` (canonical) was
    /// seen.
    pub(crate) fn note_search(&self, target_id: &str, context: &str) {
        lock(&self.proofs).insert((target_id.to_owned(), context.to_owned()), Instant::now());
    }

    /// Whether a search record of `context` was seen recently.
    pub(crate) fn proven(&self, target_id: &str, context: &str) -> bool {
        lock(&self.proofs)
            .get(&(target_id.to_owned(), context.to_owned()))
            .is_some_and(|t| t.elapsed() < RECORD_FRESHNESS)
    }

    /// Whether failed searches of `context` are logged: `Some(true)` when a
    /// record of one was seen, `Some(false)` when the check's own
    /// size-limited search left none, `None` when not known (24 h).
    pub(crate) fn failures_logged(&self, target_id: &str, context: &str) -> Option<bool> {
        lock(&self.failures_logged)
            .get(&(target_id.to_owned(), context.to_owned()))
            .filter(|(_, t)| t.elapsed() < RECORD_FRESHNESS)
            .map(|(b, _)| *b)
    }

    /// Records whether failed searches of `context` are logged.
    pub(crate) fn note_failures_logged(&self, target_id: &str, context: &str, logged: bool) {
        lock(&self.failures_logged).insert(
            (target_id.to_owned(), context.to_owned()),
            (logged, Instant::now()),
        );
    }

    /// Log entries of `target_id` dropped by the stream.
    pub(crate) fn note_dropped(&self, target_id: &str, n: u64) {
        let mut map = lock(&self.dropped);
        let entry = map
            .entry(target_id.to_owned())
            .or_insert((0, Instant::now()));
        if entry.1.elapsed() >= RECORD_FRESHNESS {
            *entry = (0, Instant::now());
        }
        entry.0 = entry.0.saturating_add(n);
    }

    fn dropped(&self, target_id: &str) -> u64 {
        lock(&self.dropped)
            .get(target_id)
            .filter(|(_, since)| since.elapsed() < RECORD_FRESHNESS)
            .map_or(0, |(n, _)| *n)
    }

    /// The agent's own-read counters of `target_id`.
    pub(crate) fn own_usage(&self, target_id: &str) -> SharedOwnUsage {
        std::sync::Arc::clone(
            lock(&self.own_usage)
                .entry(target_id.to_owned())
                .or_default(),
        )
    }

    /// Source of the level last reported for `target_id`.
    pub(crate) fn audit_source(&self, target_id: &str) -> Option<EventSource> {
        lock(&self.sources).get(target_id).copied()
    }

    fn set_source(&self, target_id: &str, source: Option<EventSource>) {
        let mut map = lock(&self.sources);
        match source {
            Some(s) => {
                map.insert(target_id.to_owned(), s);
            }
            None => {
                map.remove(target_id);
            }
        }
    }

    fn due(&self, key: &str) -> bool {
        lock(&self.reports)
            .get(key)
            .is_none_or(|c| c.at.elapsed() >= REPORT_INTERVAL)
    }

    /// Stores a report; `true` if it differs from the previous one.
    fn store(&self, key: String, report: Report) -> bool {
        let mut map = lock(&self.reports);
        let changed = map.get(&key).is_none_or(|c| c.report != report);
        map.insert(
            key,
            Cached {
                at: Instant::now(),
                report,
            },
        );
        changed
    }

    fn cached(&self, key: &str) -> Option<Report> {
        lock(&self.reports).get(key).map(|c| c.report.clone())
    }
}

/// The level and source of a target (decision 10): `check()` and the
/// Audit stream use this rule.
pub(crate) fn choose(
    readable: bool,
    proven: usize,
    contexts: usize,
    failures_unlogged: usize,
) -> (AuditLevel, Source) {
    if !readable {
        return (AuditLevel::None, Source::None);
    }
    let level = if contexts > 0 && proven >= contexts && failures_unlogged == 0 {
        AuditLevel::Full
    } else if proven > 0 {
        AuditLevel::Partial
    } else {
        AuditLevel::Limited
    };
    (level, Source::Accesslog)
}

/// The data naming contexts of the root DSE (the log excluded): raw and
/// canonical forms.
pub(crate) fn data_contexts(dse: &RootDse, accesslog_base: &str) -> Vec<(String, String)> {
    let log = dn::canon(accesslog_base).unwrap_or_default();
    dse.naming_contexts
        .iter()
        .filter_map(|raw| {
            let canon = dn::canon(raw)?;
            (!canon.is_empty() && canon != log).then(|| (raw.clone(), canon))
        })
        .collect()
}

fn unreachable(e: &LdError, mut notes: Vec<TargetNote>) -> TargetHealth {
    notes.push(
        TargetNote::new(NoteCode::CheckStageFailed)
            .with_labels([NoteLabel::stage(e.stage.as_str())]),
    );
    TargetHealth {
        reachable: false,
        audit_level: AuditLevel::None,
        failure: Some(e.code),
        detail: Some(format!(
            "{} failed (result {})",
            e.stage.as_str(),
            e.engine_code().unwrap_or_else(|| "none".to_owned())
        )),
        notes,
    }
}

/// `check()` of a target.
pub(crate) async fn check(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    match tokio::time::timeout(CHECK_TIMEOUT, check_inner(state, target)).await {
        Ok((h, source)) => {
            state.set_source(&target.id, source.event_source());
            h
        }
        Err(_) => {
            state.set_source(&target.id, None);
            TargetHealth {
                reachable: false,
                audit_level: AuditLevel::None,
                failure: Some(FailureCode::Timeout),
                detail: Some("check timed out".to_owned()),
                notes: vec![TargetNote::new(NoteCode::CheckTimedOut)],
            }
        }
    }
}

/// A search of the check: `Ok(Some(entries))`, `Ok(None)` when the server
/// refused it (insufficient access, no such object), a fatal error
/// otherwise. `on_entry` sees the entries.
async fn probe<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    search: &Search<'_>,
    on_entry: &mut (dyn FnMut(Entry) + Send),
) -> Result<Option<u64>, LdError> {
    match s.search(Stage::Check, search, on_entry).await {
        Ok(o) if o.error(Stage::Check).is_none() => Ok(Some(o.entries)),
        Ok(o) => {
            tracing::debug!(result = o.code, "check probe refused");
            Ok(None)
        }
        Err(e) if !e.fatal => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether the base entry `dn` is readable (attributes `1.1`).
pub(crate) async fn base_readable<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    base: &str,
) -> Result<bool, LdError> {
    let search = Search {
        base,
        scope: Scope::Base,
        size_limit: 1,
        time_limit: 0,
        types_only: false,
        filter: Filter::Present("objectClass"),
        attributes: &["1.1"],
    };
    Ok(probe(s, &search, &mut |_: Entry| {})
        .await?
        .is_some_and(|n| n > 0))
}

/// Which search records [`search_record`] looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// `reqResult` 0.
    Succeeded,
    /// Any other result: `olcAccessLogSuccess` is all or nothing, so one
    /// failed operation logged proves they all are.
    Failed,
}

/// Whether `cn=accesslog` holds a search record of `context` from the last
/// 24 h with the given outcome.
pub(crate) async fn search_record<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    accesslog_base: &str,
    context: &str,
    outcome: Outcome,
) -> Result<bool, LdError> {
    let success = Filter::Eq("reqResult", "0".to_owned());
    let result = match outcome {
        Outcome::Succeeded => success,
        Outcome::Failed => Filter::Not(Box::new(success)),
    };
    let since = time::csn_at(SystemTime::now() - RECORD_FRESHNESS);
    let search = Search {
        base: accesslog_base,
        scope: Scope::One,
        size_limit: 1,
        time_limit: 0,
        types_only: false,
        filter: Filter::And(vec![
            Filter::Eq("objectClass", "auditSearch".to_owned()),
            result,
            Filter::Extensible {
                rule: "dnSubtreeMatch",
                attr: "reqDN",
                value: context.to_owned(),
            },
            Filter::Ge("entryCSN", since),
        ]),
        attributes: &["1.1"],
    };
    Ok(probe(s, &search, &mut |_: Entry| {})
        .await?
        .is_some_and(|n| n > 0))
}

/// Privileges and the log's readability.
async fn report<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut Session<S>,
    dse: &RootDse,
    contexts: &[(String, String)],
    accesslog_base: &str,
) -> Result<Report, LdError> {
    let mut r = Report::default();
    if let Some(config) = &dse.config_context {
        r.config_readable = base_readable(s, config).await?;
    }
    for (raw, _) in contexts.iter().take(MAX_PASSWORD_PROBES) {
        let search = Search {
            base: raw,
            scope: Scope::Sub,
            size_limit: PASSWORD_PROBE_ENTRIES,
            time_limit: 0,
            types_only: true,
            filter: Filter::Present("objectClass"),
            attributes: &PASSWORD_ATTRIBUTES,
        };
        let mut disclosed = false;
        let mut on_entry = |e: Entry| {
            disclosed |= PASSWORD_ATTRIBUTES.iter().any(|a| {
                e.attributes.iter().any(|x| {
                    x.name
                        .split(';')
                        .next()
                        .is_some_and(|n| n.eq_ignore_ascii_case(a))
                })
            });
        };
        probe(s, &search, &mut on_entry).await?;
        if disclosed {
            r.password_readable = true;
            break;
        }
    }
    r.accesslog_readable = Some(base_readable(s, accesslog_base).await?);
    Ok(r)
}

/// Looks for a recent search record of each unproven context; when there
/// is none, runs one base search of the context and looks again.
async fn prove<S: AsyncRead + AsyncWrite + Unpin>(
    state: &CheckState,
    target: &TargetConfig,
    s: &mut Session<S>,
    contexts: &[(String, String)],
    accesslog_base: &str,
) -> Result<(), LdError> {
    for (raw, canon) in contexts
        .iter()
        .filter(|(_, c)| !state.proven(&target.id, c))
        .take(MAX_PROVEN_PER_REPORT)
    {
        let mut found = search_record(s, accesslog_base, raw, Outcome::Succeeded).await?;
        if !found {
            // A read of the context itself: a server logging reads records
            // it at once.
            base_readable(s, raw).await?;
            found = search_record(s, accesslog_base, raw, Outcome::Succeeded).await?;
        }
        if found {
            state.note_search(&target.id, canon);
        }
    }
    // Failed operations (a search cut by a limit after returning entries:
    // a capped export) must be logged too: `olcAccessLogSuccess: TRUE`
    // leaves them out, and the agent cannot read that setting. A base read
    // of an entry that does not exist fails on any context (32).
    for (raw, canon) in contexts
        .iter()
        .filter(|(_, c)| state.failures_logged(&target.id, c) != Some(true))
        .take(MAX_PROVEN_PER_REPORT)
    {
        if search_record(s, accesslog_base, raw, Outcome::Failed).await? {
            state.note_failures_logged(&target.id, canon, true);
            continue;
        }
        let probe_dn = format!("{ABSENT_RDN},{raw}");
        base_readable(s, &probe_dn).await?;
        let logged = search_record(s, accesslog_base, raw, Outcome::Failed).await?;
        state.note_failures_logged(&target.id, canon, logged);
    }
    Ok(())
}

/// The RDN of the entry the check reads to cause a failed search
/// (`noSuchObject`); it is not expected to exist.
pub(crate) const ABSENT_RDN: &str = "cn=databastion-absent-probe";

async fn check_inner(state: &CheckState, target: &TargetConfig) -> (TargetHealth, Source) {
    let mut detail: Vec<String> = Vec::new();
    let mut codes = Notes::default();
    let settings = target.openldap_settings();
    let mut session = match Session::connect(target, Timeouts::new(CHECK_OP_TIMEOUT)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                target_id = %target.id,
                stage = e.stage.as_str(),
                result = e.result,
                code = %e.code,
                "target check failed"
            );
            return (unreachable(&e, codes.into_vec()), Source::None);
        }
    };
    let dse = match catalog::root_dse(&mut session, Stage::Check).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(
                target_id = %target.id,
                result = e.result,
                "root DSE not readable"
            );
            return (unreachable(&e, codes.into_vec()), Source::None);
        }
    };
    let contexts = data_contexts(&dse, &settings.accesslog_base);
    // The report has its own bound, so a slow server still gets a
    // reachability answer; what it could not evaluate is noted.
    let mut incomplete: Option<TargetNote> = None;
    if state.due(&target.id) && !session.is_broken() {
        let evaluated = tokio::time::timeout(REPORT_TIMEOUT, async {
            let r = report(&mut session, &dse, &contexts, &settings.accesslog_base).await?;
            if r.accesslog_readable == Some(true) {
                prove(
                    state,
                    target,
                    &mut session,
                    &contexts,
                    &settings.accesslog_base,
                )
                .await?;
            }
            Ok::<Report, LdError>(r)
        })
        .await;
        match evaluated {
            Ok(Ok(r)) => {
                if state.store(target.id.clone(), r.clone()) {
                    log_report(target, &r);
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    target_id = %target.id,
                    stage = e.stage.as_str(),
                    result = e.result,
                    "privileges and audit source not evaluated"
                );
                incomplete = Some(
                    TargetNote::new(NoteCode::CheckStageFailed)
                        .with_labels([NoteLabel::stage(e.stage.as_str())]),
                );
            }
            Err(_) => {
                tracing::warn!(
                    target_id = %target.id,
                    "privileges and audit source not evaluated in time"
                );
                incomplete = Some(TargetNote::new(NoteCode::CheckTimedOut));
                // The session may be in the middle of a search.
                drop(session);
                session = match Session::connect(target, Timeouts::new(CHECK_OP_TIMEOUT)).await {
                    Ok(s) => s,
                    Err(e) => return (unreachable(&e, codes.into_vec()), Source::None),
                };
            }
        }
    }
    let report = state.cached(&target.id);
    if report.is_none() {
        codes.add(incomplete.unwrap_or_else(|| TargetNote::new(NoteCode::CheckTimedOut)));
    }
    let readable = report
        .as_ref()
        .is_some_and(|r| r.accesslog_readable == Some(true));
    let proven = contexts
        .iter()
        .filter(|(_, c)| state.proven(&target.id, c))
        .count();
    let failures_unlogged = contexts
        .iter()
        // Unknown counts as not proven (review N1): Full needs a logged
        // failed operation for every context.
        .filter(|(_, c)| state.failures_logged(&target.id, c) != Some(true))
        .count();
    let (level, source) = choose(readable, proven, contexts.len(), failures_unlogged);
    match report.as_ref().and_then(|r| r.accesslog_readable) {
        Some(true) => {
            if proven < contexts.len() {
                let missing = contexts.len() - proven;
                detail.push(format!(
                    "{missing} of {} naming context(s) without a search record in the \
                     accesslog in the last 24 h: reads there are not logged",
                    contexts.len()
                ));
                codes.add(
                    TargetNote::new(NoteCode::AuditReadsNotLogged)
                        .with_count(u64::try_from(missing).unwrap_or(u64::MAX)),
                );
            }
            if failures_unlogged > 0 {
                detail.push(format!(
                    "{failures_unlogged} naming context(s) where no failed operation is proven \
                     to be logged (olcAccessLogSuccess: TRUE, or not checked yet): at most \
                     Partial"
                ));
                codes.add(
                    TargetNote::new(NoteCode::AuditFailedOperationsNotLogged)
                        .with_count(u64::try_from(failures_unlogged).unwrap_or(u64::MAX)),
                );
            }
            if !state.stream_running(&target.id) {
                detail.push(
                    "accesslog readable while no Audit stream runs (other users' filters and \
                     values are readable)"
                        .to_owned(),
                );
                codes.add(TargetNote::new(NoteCode::PrivilegeAccesslogWithoutAudit));
            }
        }
        Some(false) => {
            detail.push("accesslog not readable or missing: no Audit source".to_owned());
            codes.add(TargetNote::new(NoteCode::AuditAccesslogNotReadable));
        }
        None => detail.push("accesslog not evaluated".to_owned()),
    }
    let dropped = state.dropped(&target.id);
    if dropped > 0 {
        detail.push(format!(
            "{dropped} accesslog record(s) dropped in the last 24 h (not parsable)"
        ));
        codes.add(TargetNote::new(NoteCode::AuditRecordsDropped).with_count(dropped));
    }
    if let Some(r) = &report {
        if r.config_readable {
            detail.push("cn=config readable by the service DN".to_owned());
            codes.add(TargetNote::new(NoteCode::PrivilegeConfigReadable));
        }
        if r.password_readable {
            detail.push("userPassword / authPassword readable by the service DN".to_owned());
            codes.add(TargetNote::new(
                NoteCode::PrivilegePasswordAttributesReadable,
            ));
        }
    }
    codes.add(TargetNote::new(NoteCode::PrivilegeWriteNotEvaluated));
    detail.push("write access not evaluated (no effective-rights query)".to_owned());
    if !session.is_broken() {
        session.close().await;
    }
    (
        TargetHealth {
            reachable: true,
            audit_level: level,
            failure: None,
            detail: Some(format!("audit level {level:?}; {}", detail.join("; "))),
            notes: codes.into_vec(),
        },
        source,
    )
}

fn log_report(target: &TargetConfig, r: &Report) {
    if r.config_readable || r.password_readable {
        tracing::warn!(
            target_id = %target.id,
            config_readable = r.config_readable,
            password_attributes_readable = r.password_readable,
            "the agent's service DN is over-privileged"
        );
    } else {
        tracing::info!(
            target_id = %target.id,
            accesslog_readable = ?r.accesslog_readable,
            "service DN: cn=config and password attributes not readable"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_proven_per_naming_context() {
        assert_eq!(choose(false, 3, 3, 0), (AuditLevel::None, Source::None));
        assert_eq!(choose(true, 2, 2, 0), (AuditLevel::Full, Source::Accesslog));
        // Failed searches not logged: never Full.
        assert_eq!(
            choose(true, 2, 2, 1),
            (AuditLevel::Partial, Source::Accesslog)
        );
        assert_eq!(
            choose(true, 1, 2, 0),
            (AuditLevel::Partial, Source::Accesslog)
        );
        assert_eq!(
            choose(true, 0, 2, 0),
            (AuditLevel::Limited, Source::Accesslog)
        );
        assert_eq!(
            choose(true, 0, 0, 0),
            (AuditLevel::Limited, Source::Accesslog)
        );
    }

    #[test]
    fn every_note_is_registered_for_openldap() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../shared/protocol/target-notes.json"
        ))
        .unwrap();
        for code in [
            NoteCode::AuditAccesslogNotReadable,
            NoteCode::AuditReadsNotLogged,
            NoteCode::AuditFailedOperationsNotLogged,
            NoteCode::AuditRecordsDropped,
            NoteCode::CheckStageFailed,
            NoteCode::CheckTimedOut,
            NoteCode::PrivilegeAccesslogWithoutAudit,
            NoteCode::PrivilegeConfigReadable,
            NoteCode::PrivilegePasswordAttributesReadable,
            NoteCode::PrivilegeWriteNotEvaluated,
        ] {
            let engines = v[code.as_str()]["engines"]
                .as_array()
                .unwrap_or_else(|| panic!("{} is not registered", code.as_str()));
            assert!(
                engines.iter().any(|e| e == "openldap"),
                "{} is not registered for openldap",
                code.as_str()
            );
        }
    }

    #[test]
    fn check_failures_are_noted_with_their_stage_only() {
        let e = LdError::result(49, Stage::Auth);
        let h = unreachable(&e, Vec::new());
        assert!(!h.reachable);
        assert_eq!(h.failure, Some(FailureCode::AuthenticationFailed));
        assert_eq!(h.notes[0].labels()[0].as_str(), "stage_auth");
        assert_eq!(h.detail.as_deref(), Some("auth failed (result 49)"));
    }

    #[test]
    fn proofs_and_drops_expire() {
        let state = CheckState::default();
        assert!(!state.proven("t", "dc=x"));
        state.note_search("t", "dc=x");
        assert!(state.proven("t", "dc=x"));
        assert!(!state.proven("other", "dc=x"));
        state.note_dropped("t", 2);
        state.note_dropped("t", 3);
        assert_eq!(state.dropped("t"), 5);
        let guard = state.stream_started("t");
        assert!(state.stream_running("t"));
        drop(guard);
        assert!(!state.stream_running("t"));
    }

    #[test]
    fn data_contexts_leave_the_log_out() {
        let dse = RootDse {
            naming_contexts: vec!["cn=accesslog".to_owned(), "dc=Example,dc=org".to_owned()],
            ..RootDse::default()
        };
        assert_eq!(
            data_contexts(&dse, "CN=AccessLog"),
            vec![(
                "dc=Example,dc=org".to_owned(),
                "dc=example,dc=org".to_owned()
            )]
        );
    }
}
