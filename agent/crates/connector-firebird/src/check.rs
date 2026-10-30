//! `check()` (ADR-0060 decisions 2 to 4, refinement R3): reachability over
//! the checked loopback peer with SRP-256 and ChaCha wire encryption, the
//! version (4.0 or 5.0), the wire encryption and the read-only transaction
//! as the server reports them, the forwarder rule, then the account's
//! privileges in every declared database against the refusal and
//! over-privilege lists.
//!
//! Audit comes with lot 3 (decision 10): every target reports
//! `audit.source_not_configured` and the level `none`. A target reached
//! through a tunnel reports `security.firebird_tunnel` at every check.
//!
//! An account on the refusal list, or whose refusal list could not be
//! evaluated completely, gets `privilege.refused` (or
//! `privilege.not_evaluated`): Discovery and Audit refuse to run (open
//! question 4).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use databastion_core::config::TargetConfig;
use databastion_core::{
    AuditLevel, FailureCode, NoteCode, NoteLabel, Notes, TargetHealth, TargetNote,
};
use tokio::time::Instant;

use crate::catalog;
use crate::conn::{self, Endpoint, Session};
use crate::error::{Detail, FbError, Stage};
use crate::privileges::{Evaluation, Facts, Grant, Mapping, Membership};
use crate::sql::{self, Col, Value};

/// Per-statement timeout of `check()` (decision 4).
pub(crate) const CHECK_STATEMENT: Duration = Duration::from_secs(3);
/// Whole `check()` budget (decision 4: 9 s, under the core's 10 s).
pub(crate) const CHECK_TOTAL: Duration = Duration::from_secs(9);
/// Most catalog rows read by one privilege statement.
const MAX_CATALOG_ROWS: usize = 16_384;
/// Supported majors (decision 2).
const MAJORS: [u32; 2] = [4, 5];

/// Shared state of the connector.
#[derive(Default)]
pub(crate) struct CheckState {
    versions: Mutex<HashMap<String, String>>,
    /// Per target: whether the last check blocks Discovery and Audit (a
    /// refused right, or a refusal list not evaluated completely).
    blocked: Mutex<HashMap<String, bool>>,
}

impl CheckState {
    pub(crate) fn version(&self, target_id: &str) -> Option<String> {
        self.versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .cloned()
    }

    fn set_version(&self, target_id: &str, version: Option<String>) {
        let mut map = self
            .versions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match version {
            Some(v) => {
                map.insert(target_id.to_owned(), v);
            }
            None => {
                map.remove(target_id);
            }
        }
    }

    /// Whether Discovery and Audit must not run for `target_id`: blocked
    /// by the last check, or never checked (fail closed).
    pub(crate) fn blocks(&self, target_id: &str) -> bool {
        self.blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(target_id)
            .copied()
            .unwrap_or(true)
    }

    pub(crate) fn set_blocked(&self, target_id: &str, blocked: bool) {
        self.blocked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target_id.to_owned(), blocked);
    }
}

/// The major version of `ENGINE_VERSION` (`5.0.4`): 4 or 5, else refused
/// (decision 2: Firebird 3.0 and 6.0 refused).
pub(crate) fn major_of(version: &str) -> Option<u32> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let rest_ok = parts.all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    (rest_ok && MAJORS.contains(&major)).then_some(major)
}

fn failed(e: FbError, target: &TargetConfig) -> TargetHealth {
    tracing::warn!(
        target_id = %target.id,
        stage = e.stage.as_str(),
        gds = e.gds,
        code = %e.code,
        detail = e.detail.map(Detail::as_str),
        "Firebird check failed"
    );
    let note = if e.code == FailureCode::Timeout {
        TargetNote::new(NoteCode::CheckTimedOut)
    } else {
        TargetNote::new(NoteCode::CheckStageFailed)
            .with_labels([NoteLabel::stage(e.stage.as_str())])
    };
    let mut notes = vec![note];
    if target.firebird_settings().is_some_and(|s| s.tunnel) {
        notes.push(TargetNote::new(NoteCode::SecurityFirebirdTunnel));
    }
    TargetHealth {
        reachable: false,
        audit_level: AuditLevel::None,
        failure: Some(e.code),
        detail: Some(format!(
            "stage {}{}",
            e.stage.as_str(),
            e.detail
                .map(|d| format!(": {}", d.as_str()))
                .unwrap_or_default()
        )),
        notes,
    }
}

/// `check()` of one target.
pub(crate) async fn check(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    let deadline = Instant::now() + CHECK_TOTAL;
    let out = match tokio::time::timeout_at(deadline, run(state, target, deadline)).await {
        Ok(Ok(h)) => return h,
        Ok(Err(e)) => e,
        Err(_) => FbError::new(FailureCode::Timeout, Stage::Check),
    };
    state.set_version(&target.id, None);
    state.set_blocked(&target.id, true);
    failed(out, target)
}

async fn run(
    state: &CheckState,
    target: &TargetConfig,
    deadline: Instant,
) -> Result<TargetHealth, FbError> {
    let settings = target
        .firebird_settings()
        .ok_or(FbError::new(FailureCode::Internal, Stage::Connect))?;
    let password = target
        .secret
        .read()
        .map_err(|_| FbError::new(FailureCode::AuthenticationFailed, Stage::Secret))?;
    let endpoint = Endpoint::of(target)?;
    let mut notes = Notes::default();
    let mut detail: Vec<String> = Vec::new();
    if settings.tunnel {
        notes.add(TargetNote::new(NoteCode::SecurityFirebirdTunnel));
        detail.push("reached through an operator-run tunnel (firebird.tunnel)".to_owned());
    }
    let mut eval = Evaluation::default();
    let mut coverage = Coverage::default();
    let mut version: Option<String> = None;
    for db in &settings.databases {
        let mut s = conn::connect(
            &endpoint,
            password.as_bytes(),
            &db.attach,
            deadline,
            CHECK_STATEMENT,
        )
        .await?;
        let result = database(&mut s, settings.tunnel, settings.extended_grants, deadline).await;
        let read = match &result {
            Ok(_) => Some(catalog::read(&mut s, deadline).await),
            Err(_) => None,
        };
        s.close().await;
        let (v, facts) = result?;
        let read = read.transpose()?.unwrap_or_default();
        detail.push(format!("Firebird {v}, wire encryption {}", facts.plugin));
        version = Some(v);
        eval.add(&facts.facts);
        coverage.add(&read);
    }
    if let Some(v) = &version {
        state.set_version(&target.id, Some(v.clone()));
    }
    eval.notes(&mut notes);
    coverage.notes(&mut notes, &mut detail);
    // Audit: lot 3 (decision 10).
    notes.add(TargetNote::new(NoteCode::AuditSourceNotConfigured));
    let summary = eval.summary();
    if !summary.is_empty() {
        detail.push(summary);
    }
    state.set_blocked(&target.id, eval.blocks());
    tracing::info!(target_id = %target.id, detail = %detail.join("; "), "Firebird checked");
    Ok(TargetHealth {
        reachable: true,
        audit_level: AuditLevel::None,
        failure: None,
        detail: Some(detail.join("; ")),
        notes: notes.into_vec(),
    })
}

/// What the catalogs of the declared databases show (decision 5): the
/// coverage notes, and the CAS store guard's readable credential columns
/// (ADR-0041 decision 6), summed over the databases.
#[derive(Debug, Default)]
struct Coverage {
    counts: catalog::Counts,
    prefixed: u64,
    cas: u64,
    cas_complete: bool,
    databases: u64,
    /// Catalog rows dropped (review L3).
    dropped: u64,
}

impl Coverage {
    fn add(&mut self, c: &catalog::Catalog) {
        if self.databases == 0 {
            self.cas_complete = true;
        }
        self.databases += 1;
        let cas = c.cas_readable();
        self.cas += cas.readable;
        self.cas_complete &= cas.complete && c.columns.is_some();
        self.dropped += c.dropped();
        if let (Some(r), Some(cols)) = (&c.relations, &c.columns) {
            let n = catalog::counts(r, &cols.list);
            self.counts.views += n.views;
            self.counts.external += n.external;
            self.counts.temporary += n.temporary;
            self.counts.computed += n.computed;
            self.counts.without_select += n.without_select;
            self.prefixed += r
                .iter()
                .filter(|x| catalog::system_prefixed(&x.name) && !catalog::never_sampled(&x.name))
                .count() as u64;
        }
    }

    fn notes(&self, notes: &mut Notes, detail: &mut Vec<String>) {
        let c = &self.counts;
        for (code, n) in [
            (NoteCode::CoverageViewsNotSampled, c.views),
            (NoteCode::CoverageComputedColumnsNotSampled, c.computed),
            (NoteCode::CoverageExternalFileTables, c.external),
            (NoteCode::CoverageRelationsWithoutSelect, c.without_select),
        ] {
            if n > 0 {
                notes.add(TargetNote::new(code).with_count(n));
            }
        }
        if c.temporary > 0 {
            detail.push(format!(
                "{} global temporary table(s) not sampled (their rows belong to other attachments)",
                c.temporary
            ));
        }
        if self.prefixed > 0 {
            detail.push(format!(
                "{} user table(s) named with a system prefix (RDB$, MON$, SEC$, PLG$), sampled as \
                 user tables",
                self.prefixed
            ));
        }
        if self.dropped > 0 {
            detail.push(format!(
                "{} catalog row(s) with a name that is not UTF-8 or cannot be quoted: their \
                 relations are not sampled",
                self.dropped
            ));
        }
        if self.cas > 0 {
            notes.add(
                TargetNote::new(NoteCode::PrivilegeTicketCredentialsReadable).with_count(self.cas),
            );
            detail.push(format!(
                "the account can read credential columns of {} CAS ticket registry or audit trail \
                 table(s) (grant SELECT on another table, or revoke it)",
                self.cas
            ));
        } else if self.databases > 0 && !self.cas_complete {
            notes.merge(
                TargetNote::new(NoteCode::PrivilegeNotEvaluated),
                databastion_core::CountMerge::Sum,
            );
            detail.push(
                "the CAS store guard's catalog read was cut, failed or dropped a row".to_owned(),
            );
        }
    }
}

/// What one database's check read.
pub(crate) struct DatabaseFacts {
    pub(crate) facts: Facts,
    pub(crate) plugin: &'static str,
}

fn text(row: &[Value], i: usize) -> Option<String> {
    row.get(i).and_then(Value::as_text).map(str::to_owned)
}

/// Every row of a read through `f`, or `None` when any row has a NULL key
/// column (`f` returns `None`; review N3): such rows are counted in
/// `dropped` and the read is not evaluated (fail closed).
fn all_rows<T>(
    rows: &[Vec<Value>],
    dropped: &mut u64,
    f: impl Fn(&[Value]) -> Option<T>,
) -> Option<Vec<T>> {
    let mut out = Vec::with_capacity(rows.len());
    let mut missing = 0u64;
    for row in rows {
        match f(row) {
            Some(v) => out.push(v),
            None => missing += 1,
        }
    }
    *dropped = dropped.saturating_add(missing);
    (missing == 0).then_some(out)
}

/// The mappings of `statement` (review L2).
async fn mappings(
    s: &mut Session,
    statement: &'static str,
    dropped: &mut u64,
    deadline: Instant,
) -> Result<Option<Vec<Mapping>>, FbError> {
    Ok(soft(
        s.query(
            statement,
            &[
                Col::Text(16),
                Col::Text(252),
                Col::Text(252),
                Col::Bool,
                Col::Int,
                Col::Text(252),
            ],
            MAX_CATALOG_ROWS,
            deadline,
        )
        .await,
    )?
    .filter(|r| !r.cut)
    .and_then(|r| {
        all_rows(&r.rows, dropped, |row| {
            Some(Mapping {
                using: text(row, 0)?,
                plugin: text(row, 1),
                from_type: text(row, 2),
                from_matches: row.get(3)?.as_bool().unwrap_or(true),
                to_type: row.get(4)?.as_int()?,
                to: text(row, 5),
            })
        })
    }))
}

/// The non-fatal outcome of a read: `None` when it failed or was cut (the
/// evaluation then fails closed); a fatal error ends the check.
fn soft<T>(r: Result<T, FbError>) -> Result<Option<T>, FbError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if !e.fatal => Ok(None),
        Err(e) => Err(e),
    }
}

/// What every attachment checks before anything else (decisions 2 to 4):
/// the version (4.0 or 5.0), the wire encryption and the read-only
/// read-committed transaction as the server reports them, the forwarder
/// rule (unless the operator declared a tunnel), and the server-side idle
/// timeout. Returns the version and its major.
pub(crate) async fn prepare(
    s: &mut Session,
    tunnel: bool,
    deadline: Instant,
) -> Result<(String, u32), FbError> {
    // Decision 2: the version, before any other read.
    let rows = s
        .query(sql::VERSION, &[Col::Text(128)], 1, deadline)
        .await?;
    let version = rows
        .rows
        .first()
        .and_then(|r| text(r, 0))
        .unwrap_or_default();
    let major = major_of(&version).ok_or(
        FbError::new(FailureCode::Unsupported, Stage::Check)
            .with_detail(Detail::UnsupportedVersion),
    )?;
    // Decisions 3 and 4: the wire encryption and the transaction, as the
    // server reports them for this attachment.
    let rows = s
        .query(
            sql::SESSION,
            &[Col::Text(32), Col::Text(252), Col::Text(32), Col::Text(124)],
            1,
            deadline,
        )
        .await?;
    let row = rows.rows.first().cloned().unwrap_or_default();
    if text(&row, 0).as_deref() != Some("TRUE") || text(&row, 1).as_deref() != Some(s.plugin_name())
    {
        return Err(FbError::new(FailureCode::TargetUnreachable, Stage::Tls)
            .with_detail(Detail::WireCryptNotVerified));
    }
    if text(&row, 2).as_deref() != Some("TRUE")
        || text(&row, 3).as_deref() != Some("READ COMMITTED")
    {
        return Err(FbError::new(FailureCode::Unsupported, Stage::SessionSetup)
            .with_detail(Detail::TransactionNotVerified));
    }
    // Decision 3 (M2): the server's view of the connection is the agent's
    // socket, unless the operator declared a tunnel.
    let rows = s
        .query(
            sql::OWN_ATTACHMENT,
            &[Col::Int, Col::Text(64), Col::Text(1020), Col::Int],
            1,
            deadline,
        )
        .await?;
    let row = rows.rows.first().cloned().unwrap_or_default();
    // The agent's own attachment (decision 6, R1 rule 1).
    if let (Some(Value::Int(id)), Some(Value::Int(pid))) = (row.first(), row.get(3))
        && let (Ok(id), Ok(pid)) = (u64::try_from(*id), u32::try_from(*pid))
    {
        s.register_own(id, pid);
    }
    if !tunnel {
        let same = match (s.local, text(&row, 1), text(&row, 2)) {
            (Some(local), Some(protocol), Some(remote)) => {
                crate::peer::same_as_server_view(&protocol, &remote, local)
            }
            _ => false,
        };
        if !same {
            return Err(FbError::new(FailureCode::TargetUnreachable, Stage::Connect)
                .with_detail(Detail::Forwarder));
        }
    }
    // The server-side safety net (decision 3).
    s.exec(sql::IDLE_TIMEOUT, deadline).await?;
    Ok((version, major))
}

pub(crate) async fn database(
    s: &mut Session,
    tunnel: bool,
    extended_grants: bool,
    deadline: Instant,
) -> Result<(String, DatabaseFacts), FbError> {
    let (version, major) = prepare(s, tunnel, deadline).await?;
    let mut f = Facts {
        major,
        extended_grants,
        ..Facts::default()
    };
    let identity = soft(
        s.query(
            sql::IDENTITY,
            &[
                Col::Text(252),
                Col::Text(252),
                Col::Bool,
                Col::Text(252),
                Col::Int,
            ],
            1,
            deadline,
        )
        .await,
    )?;
    if let Some(row) = identity.and_then(|r| r.rows.into_iter().next()) {
        f.current_user = text(&row, 0);
        f.admin_role_in_use = row.get(2).and_then(Value::as_bool);
        f.owner = text(&row, 3);
        f.security_admin = match row.get(4).and_then(Value::as_int) {
            Some(1) => Some(true),
            Some(0) => Some(false),
            _ => None,
        };
    }
    let mut effective = soft(
        s.query(sql::SYSTEM_PRIVILEGES_4, &[Col::Bool; 26], 1, deadline)
            .await,
    )?
    .and_then(|r| r.rows.into_iter().next())
    .map(|row| {
        row.iter()
            .map(|v| v.as_bool() == Some(true))
            .collect::<Vec<_>>()
    });
    if major >= 5 {
        let more = soft(
            s.query(sql::SYSTEM_PRIVILEGES_5, &[Col::Bool], 1, deadline)
                .await,
        )?
        .and_then(|r| r.rows.into_iter().next())
        .and_then(|row| row.first().and_then(Value::as_bool));
        effective = match (effective, more) {
            (Some(mut e), Some(m)) => {
                e.push(m);
                Some(e)
            }
            _ => None,
        };
    }
    f.effective = effective;
    f.memberships = soft(
        s.query(
            sql::ROLE_MEMBERSHIPS,
            &[Col::Text(252), Col::Int, Col::Text(252), Col::Int],
            MAX_CATALOG_ROWS,
            deadline,
        )
        .await,
    )?
    .filter(|r| !r.cut)
    .and_then(|r| {
        all_rows(&r.rows, &mut f.dropped_rows, |row| {
            Some(Membership {
                grantee: text(row, 0)?,
                grantee_type: row.get(1)?.as_int()?,
                role: text(row, 2)?,
                admin: row.get(3)?.as_int().unwrap_or(1),
            })
        })
    });
    f.role_masks = soft(
        s.query(
            sql::ROLE_PRIVILEGES,
            &[Col::Text(252), Col::Octets(8)],
            MAX_CATALOG_ROWS,
            deadline,
        )
        .await,
    )?
    .filter(|r| !r.cut)
    .and_then(|r| {
        all_rows(&r.rows, &mut f.dropped_rows, |row| {
            Some((
                text(row, 0)?,
                // A NULL mask: no system privilege.
                row.get(1)
                    .and_then(Value::as_bytes)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default(),
            ))
        })
    });
    f.grants = soft(
        s.query(
            sql::OBJECT_GRANTS,
            &[
                Col::Text(252),
                Col::Int,
                Col::Text(24),
                Col::Int,
                Col::Text(252),
                Col::Int,
                Col::Bool,
                Col::Int,
            ],
            MAX_CATALOG_ROWS,
            deadline,
        )
        .await,
    )?
    .filter(|r| !r.cut)
    .and_then(|r| {
        all_rows(&r.rows, &mut f.dropped_rows, |row| {
            Some(Grant {
                grantee: text(row, 0)?,
                grantee_type: row.get(1)?.as_int()?,
                privilege: text(row, 2)?,
                grant_option: row.get(3)?.as_int().unwrap_or(0),
                // An object not found in its catalog (NULL flag) is
                // counted as the account's (fail closed).
                system: row.get(7).and_then(Value::as_int).unwrap_or(0) != 0,
            })
        })
    });
    f.mappings = mappings(s, sql::AUTH_MAPPINGS, &mut f.dropped_rows, deadline).await?;
    f.global_mappings =
        mappings(s, sql::GLOBAL_AUTH_MAPPINGS, &mut f.dropped_rows, deadline).await?;
    f.owned = soft(s.query(sql::OWNED_OBJECTS, &[Col::Int], 1, deadline).await)?
        .and_then(|r| r.rows.into_iter().next())
        .and_then(|row| row.first().and_then(Value::as_int));
    f.triggers = soft(
        s.query(sql::DATABASE_TRIGGERS, &[Col::Int, Col::Int], 1, deadline)
            .await,
    )?
    .and_then(|r| r.rows.into_iter().next())
    .and_then(|row| Some((row.first()?.as_int()?, row.get(1)?.as_int()?)));
    f.readable = credential_relations(s, deadline).await?;
    s.commit(deadline).await?;
    Ok((
        version,
        DatabaseFacts {
            facts: f,
            plugin: s.plugin_name(),
        },
    ))
}

/// The one-bit probes of decision 4 (M5) and R3, on the relations of the
/// credential list that exist in the database. A probe refused with
/// `no permission` is a relation the account cannot read; any other
/// failure leaves the list not evaluated (`None`).
async fn credential_relations(
    s: &mut Session,
    deadline: Instant,
) -> Result<Option<Vec<(String, bool)>>, FbError> {
    let Some(present) = soft(
        s.query(
            sql::CREDENTIAL_RELATIONS,
            &[Col::Text(252)],
            sql::PROBES.len() + 1,
            deadline,
        )
        .await,
    )?
    else {
        return Ok(None);
    };
    let present: Vec<String> = present.rows.iter().filter_map(|r| text(r, 0)).collect();
    let mut out = Vec::new();
    for (relation, probe) in sql::PROBES {
        if !present.iter().any(|p| p == relation) {
            continue;
        }
        match s.query(probe, &[Col::Int], 1, deadline).await {
            Ok(rows) => {
                let readable = rows
                    .rows
                    .first()
                    .and_then(|r| r.first())
                    .and_then(Value::as_int)
                    == Some(1);
                out.push(((*relation).to_owned(), readable));
            }
            Err(e) if e.code == FailureCode::PermissionDenied && !e.fatal => {
                out.push(((*relation).to_owned(), false));
            }
            Err(e) if !e.fatal => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Review N3: one row with a NULL key column leaves the read not
    /// evaluated, and is counted.
    #[test]
    fn rows_with_a_null_key_column_fail_the_read_closed() {
        let rows = vec![
            vec![Value::Int(1)],
            vec![Value::Null],
            vec![Value::Int(3)],
            vec![Value::Null],
        ];
        let mut dropped = 0;
        assert_eq!(all_rows(&rows, &mut dropped, |r| r[0].as_int()), None);
        assert_eq!(dropped, 2);
        let mut dropped = 0;
        assert_eq!(
            all_rows(&rows[..1], &mut dropped, |r| r[0].as_int()),
            Some(vec![1])
        );
        assert_eq!(dropped, 0);
    }

    /// Review L3: a dropped catalog row leaves the CAS store guard not
    /// evaluated (it could be a ticket registry), and is in the detail.
    #[test]
    fn a_dropped_catalog_row_leaves_the_cas_guard_not_evaluated() {
        let raw = |b: &[u8]| Value::Bytes(zeroize::Zeroizing::new(b.to_vec()));
        let rel = |name: Value| {
            vec![
                name,
                Value::Int(0),
                Value::Bool(false),
                Value::Bool(false),
                Value::Bool(true),
            ]
        };
        let (list, dropped) =
            catalog::relations(&[rel(raw(b"CUSTOMERS")), rel(raw(&[0xC3, 0x28]))]);
        let read = catalog::Catalog {
            relations: Some(list),
            relations_dropped: dropped,
            columns: Some(catalog::Columns::default()),
            ..catalog::Catalog::default()
        };
        let mut cov = Coverage::default();
        cov.add(&read);
        let (mut notes, mut detail) = (Notes::default(), Vec::new());
        cov.notes(&mut notes, &mut detail);
        let notes = notes.into_vec();
        assert!(
            notes
                .iter()
                .any(|n| n.code() == NoteCode::PrivilegeNotEvaluated),
            "{notes:?}"
        );
        assert!(
            detail.iter().any(|d| d.starts_with("1 catalog row(s)")),
            "{detail:?}"
        );
        assert!(!detail.iter().any(|d| d.contains('\u{fffd}')));
    }

    #[test]
    fn only_firebird_4_and_5() {
        assert_eq!(major_of("5.0.4"), Some(5));
        assert_eq!(major_of("4.0.7"), Some(4));
        for v in [
            "3.0.14",
            "6.0.0",
            "5",
            "",
            "5.0.x",
            "5..1",
            "LI-V5.0.4.1812",
        ] {
            assert_eq!(major_of(v), if v == "5" { Some(5) } else { None }, "{v}");
        }
    }

    #[test]
    fn an_unchecked_target_is_blocked() {
        let s = CheckState::default();
        assert!(s.blocks("t"));
        s.set_blocked("t", false);
        assert!(!s.blocks("t"));
    }
}
