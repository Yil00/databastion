//! `check()` (ADR-0051 decisions 3, 4 and 7; refinement items 1, 2, 5
//! and 6): reachability over verified TLS, version and edition, the
//! account's permissions against the refusal list and the over-privilege
//! list, the merged `password_hash` probe, logon triggers, the RLS tiers
//! of the monitored databases (reported from the first heartbeat) and the
//! CAS store guard's credential columns.
//!
//! An account on the refusal list gets `privilege.refused`: Discovery
//! refuses to run (open question 4), and so will Audit.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::Duration;

use databastion_core::cas_guard;
use databastion_core::config::TargetConfig;
use databastion_core::config::sqlserver::RlsVisibility;
use databastion_core::{
    AuditLevel, FailureCode, NoteCode, NoteLabel, Notes, TargetHealth, TargetNote,
};

use crate::conn::{self, Session, Shape, TlsChoice};
use crate::error::{Detail, SsError, Stage};
use crate::sql;
use crate::tls;
use crate::token::Value;

/// Per-statement timeout of `check()` (decision 5).
pub(crate) const CHECK_STATEMENT: Duration = Duration::from_secs(3);
/// Whole `check()` budget (decision 5: 9 s, under the core's 10 s).
pub(crate) const CHECK_TOTAL: Duration = Duration::from_secs(9);
/// Most roles followed (decision 4).
pub(crate) const MAX_ROLES: usize = 64;

/// Supported majors (decision 3): 2019, 2022, 2025.
pub(crate) const MIN_MAJOR: i64 = 15;
/// Accepted `EngineEdition` values (decision 3): Standard, Enterprise
/// (with Developer and Evaluation), Express.
pub(crate) const EDITIONS: &[i64] = &[2, 3, 4];

/// Shared state of the connector.
#[derive(Default)]
pub(crate) struct CheckState {
    pub(crate) choice: TlsChoice,
    versions: Mutex<HashMap<String, String>>,
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
}

/// The server's version and edition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version {
    pub(crate) edition: i64,
    pub(crate) product: String,
    pub(crate) major: i64,
}

/// Reads and checks the version (decision 3). Refused: below 2019, an
/// edition outside the list (Azure among them).
pub(crate) async fn version(s: &mut Session) -> Result<Version, SsError> {
    let rows = s
        .rows(sql::VERSION, Stage::Check, Shape::rows(3, 1))
        .await?;
    let row = rows.first().ok_or(SsError::protocol(Stage::Check))?;
    let edition = row.first().and_then(Value::as_int).unwrap_or(-1);
    let product = row
        .get(1)
        .and_then(Value::as_text)
        .unwrap_or_default()
        .to_owned();
    let major = row
        .get(2)
        .and_then(Value::as_text)
        .and_then(|m| m.parse::<i64>().ok())
        .unwrap_or(0);
    let v = Version {
        edition,
        product,
        major,
    };
    if major < MIN_MAJOR
        || !EDITIONS.contains(&edition)
        || i64::from(s.info.loginack_major) < MIN_MAJOR
    {
        return Err(SsError::new(FailureCode::Unsupported, Stage::Check)
            .with_detail(Detail::UnsupportedServer));
    }
    Ok(v)
}

/// The `ProductVersion` as the contract accepts it, else `None`.
pub(crate) fn contract_version(v: &str) -> Option<String> {
    (!v.is_empty()
        && v.len() <= 32
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-')))
    .then(|| v.to_owned())
}

/// Server permissions never held (decision 4, refinement item 5).
const SERVER_REFUSED: &[&str] = &[
    "CONTROL SERVER",
    "ALTER ANY SERVER AUDIT",
    "ALTER ANY EVENT SESSION",
    "ALTER ANY EVENT SESSION ENABLE",
    "ALTER ANY EVENT SESSION DISABLE",
    "ALTER ANY EVENT SESSION ADD EVENT",
    "ALTER ANY EVENT SESSION DROP EVENT",
    "ALTER ANY EVENT SESSION ADD TARGET",
    "ALTER ANY EVENT SESSION DROP TARGET",
    "ALTER ANY EVENT SESSION OPTION",
    "CREATE ANY EVENT SESSION",
    "DROP ANY EVENT SESSION",
    "ALTER ANY LOGIN",
    "ALTER ANY SERVER ROLE",
    "IMPERSONATE ANY LOGIN",
    "VIEW ANY CRYPTOGRAPHICALLY SECURED DEFINITION",
];

/// Server permissions every login holds or `public` holds by default.
const SERVER_EXPECTED: &[&str] = &["CONNECT SQL", "VIEW ANY DATABASE"];

/// The Audit permissions (decision 4, refinement item 1): expected only
/// while an Audit stream uses them; none runs in this lot.
const SERVER_AUDIT: &[&str] = &[
    "VIEW SERVER SECURITY AUDIT",
    "VIEW ANY SECURITY DEFINITION",
    "VIEW SERVER SECURITY STATE",
    "VIEW SERVER PERFORMANCE STATE",
    "VIEW SERVER STATE",
];

/// Fixed server roles that are refused.
const ROLES_REFUSED: &[&str] = &["sysadmin", "securityadmin", "##MS_LoginManager##"];

/// Database permissions never held, in any accessible database (decision
/// 4, M3; refinement item 5).
const DATABASE_REFUSED: &[&str] = &[
    "CONTROL",
    "ALTER ANY DATABASE AUDIT",
    "ALTER ANY DATABASE EVENT SESSION",
    "ALTER ANY DATABASE EVENT SESSION ADD EVENT",
    "ALTER ANY DATABASE EVENT SESSION ADD TARGET",
    "ALTER ANY DATABASE EVENT SESSION DISABLE",
    "ALTER ANY DATABASE EVENT SESSION DROP EVENT",
    "ALTER ANY DATABASE EVENT SESSION DROP TARGET",
    "ALTER ANY DATABASE EVENT SESSION ENABLE",
    "ALTER ANY DATABASE EVENT SESSION OPTION",
    "CREATE ANY DATABASE EVENT SESSION",
    "DROP ANY DATABASE EVENT SESSION",
];

/// What `public` holds in every database by default: accepted only when
/// it comes from `public` (security review M5; measured on 2022).
const PUBLIC_DEFAULTS: &[&str] = &[
    "VIEW ANY COLUMN ENCRYPTION KEY DEFINITION",
    "VIEW ANY COLUMN MASTER KEY DEFINITION",
];

/// Database permissions implied by the RLS opt-in (`VIEW DEFINITION` and
/// what it covers on 2022+).
const DATABASE_RLS: &[&str] = &[
    "VIEW DEFINITION",
    "VIEW SECURITY DEFINITION",
    "VIEW PERFORMANCE DEFINITION",
];

/// Database permissions implied by a server Audit permission, reported
/// with that permission rather than again per database.
const DATABASE_FROM_SERVER: &[(&str, &str)] = &[
    ("VIEW DATABASE STATE", "VIEW SERVER STATE"),
    (
        "VIEW DATABASE PERFORMANCE STATE",
        "VIEW SERVER PERFORMANCE STATE",
    ),
    ("VIEW DATABASE SECURITY STATE", "VIEW SERVER SECURITY STATE"),
    ("VIEW DATABASE STATE", "VIEW SERVER PERFORMANCE STATE"),
    ("VIEW DATABASE SECURITY AUDIT", "VIEW SERVER SECURITY AUDIT"),
    ("VIEW DEFINITION", "VIEW ANY DEFINITION"),
    ("VIEW SECURITY DEFINITION", "VIEW ANY SECURITY DEFINITION"),
    ("VIEW SECURITY DEFINITION", "VIEW ANY DEFINITION"),
    ("VIEW PERFORMANCE DEFINITION", "VIEW ANY DEFINITION"),
    (
        "VIEW PERFORMANCE DEFINITION",
        "VIEW ANY PERFORMANCE DEFINITION",
    ),
];

/// Securable classes: server principal (101), database principal (4).
const CLASS_SERVER_PRINCIPAL: i64 = 101;
const CLASS_DATABASE_PRINCIPAL: i64 = 4;
/// Permissions on a principal that let the account act as, or change,
/// another principal (decision 4).
const PRINCIPAL_REFUSED: &[&str] = &["IMPERSONATE", "CONTROL", "ALTER", "TAKE OWNERSHIP"];

/// The evaluation of the account.
#[derive(Debug, Default)]
pub(crate) struct Evaluation {
    pub(crate) refused: BTreeSet<String>,
    pub(crate) global: BTreeSet<String>,
    pub(crate) audit_grants: BTreeSet<String>,
    pub(crate) server_roles: BTreeSet<String>,
    pub(crate) database_roles: BTreeSet<String>,
    pub(crate) beyond_select: BTreeSet<String>,
    pub(crate) grant_option: bool,
    pub(crate) extended_variant: bool,
    pub(crate) owner_of_objects: u64,
    /// Labels of what could not be evaluated.
    pub(crate) not_evaluated: BTreeSet<&'static str>,
    pub(crate) hash_exposed: bool,
    pub(crate) server_perms: BTreeSet<String>,
    /// Refusal-list reads that failed or were cut (security review M3):
    /// closed local reasons. Any one blocks Discovery (and Audit), as a
    /// refusal does: the refusal list fails closed.
    pub(crate) incomplete: BTreeSet<&'static str>,
}

impl Evaluation {
    /// A right of the refusal list is held (`privilege.refused`).
    pub(crate) fn is_refused(&self) -> bool {
        !self.refused.is_empty() || self.hash_exposed
    }

    /// Discovery and Audit must not run: refused, or the refusal list
    /// could not be evaluated completely.
    pub(crate) fn blocks(&self) -> bool {
        self.is_refused() || !self.incomplete.is_empty()
    }
}

fn texts(rows: &[Vec<Value>], col: usize) -> Vec<String> {
    rows.iter()
        .filter_map(|r| r.get(col).and_then(Value::as_text).map(str::to_owned))
        .collect()
}

/// Evaluates the account (decision 4) in every accessible database.
pub(crate) async fn evaluate(
    s: &mut Session,
    target: &TargetConfig,
) -> Result<Evaluation, SsError> {
    let settings = target.sqlserver_settings();
    let mut ev = Evaluation::default();
    // Effective server permissions.
    let perms = s
        .rows(sql::SERVER_PERMISSIONS, Stage::Check, Shape::rows(1, 513))
        .await?;
    let perms: BTreeSet<String> = texts(&perms, 0).into_iter().collect();
    for p in &perms {
        if SERVER_REFUSED.contains(&p.as_str()) {
            ev.refused.insert(p.clone());
        } else if SERVER_AUDIT.contains(&p.as_str()) {
            ev.audit_grants.insert(p.clone());
        } else if !SERVER_EXPECTED.contains(&p.as_str()) {
            ev.global.insert(p.clone());
        }
    }
    ev.server_perms = perms;
    // Server roles.
    let roles = s
        .rows(
            sql::SERVER_ROLES,
            Stage::Check,
            Shape::rows(1, MAX_ROLES + 1),
        )
        .await?;
    if roles.len() > MAX_ROLES {
        ev.incomplete.insert("more than 64 server roles");
    }
    for r in texts(&roles, 0) {
        if ROLES_REFUSED.contains(&r.as_str()) {
            ev.refused.insert(r);
        } else {
            ev.server_roles.insert(r);
        }
    }
    // Securable-level server grants.
    let grants = s
        .rows(sql::SERVER_GRANTS, Stage::Check, Shape::rows(4, 513))
        .await?;
    for row in &grants {
        let name = row.first().and_then(Value::as_text).unwrap_or_default();
        let state = row.get(1).and_then(Value::as_text).unwrap_or_default();
        let class = row.get(2).and_then(Value::as_int).unwrap_or(-1);
        let to_public = row.get(3).and_then(Value::as_int) == Some(1);
        if class == CLASS_SERVER_PRINCIPAL && PRINCIPAL_REFUSED.contains(&name) {
            ev.refused.insert(name.to_owned());
        } else if state == "W" && !to_public {
            ev.grant_option = true;
        }
    }
    // The merged password_hash probe (refinement item 1).
    match s
        .rows(sql::PASSWORD_HASH_PROBE, Stage::Check, Shape::rows(1, 1))
        .await
    {
        Ok(rows) => match rows.first().and_then(|r| r.first()).and_then(Value::as_int) {
            Some(1) => ev.hash_exposed = true,
            Some(0) => {}
            Some(2) => {
                ev.not_evaluated.insert("password_hash_probe");
                if ev.server_perms.contains("VIEW ANY SECURITY DEFINITION") {
                    tracing::warn!(
                        target_id = %target.id,
                        "password_hash probe: other logins hidden although VIEW ANY SECURITY \
                         DEFINITION is held (a DENY?): not evaluated"
                    );
                }
            }
            _ => {
                ev.not_evaluated.insert("password_hash_probe");
            }
        },
        Err(e) if !e.fatal => {
            ev.not_evaluated.insert("password_hash_probe");
        }
        Err(e) => return Err(e),
    }
    // Every accessible database (M3).
    let dbs = s
        .rows(
            sql::ACCESSIBLE_DATABASES,
            Stage::Check,
            Shape::rows(1, 1025),
        )
        .await?;
    if dbs.len() > 1024 {
        ev.incomplete.insert("more than 1024 accessible databases");
    }
    for db in texts(&dbs, 0).iter().take(1024) {
        database(s, db, &settings, &mut ev).await?;
    }
    Ok(ev)
}

async fn database(
    s: &mut Session,
    db: &str,
    settings: &databastion_core::config::sqlserver::SqlserverTargetConfig,
    ev: &mut Evaluation,
) -> Result<(), SsError> {
    let rls = settings.rls_visibility == Some(RlsVisibility::ViewDefinition);
    let stmts = (
        sql::in_database(sql::DATABASE_GRANTS, db),
        sql::in_database(sql::DATABASE_PERMISSIONS, db),
        sql::in_database(sql::DATABASE_ROLES, db),
    );
    let (Some(grants), Some(perms), Some(roles)) = stmts else {
        ev.incomplete
            .insert("a database name the connector cannot quote");
        return Ok(());
    };
    // Securable-level grants first: what `public` holds by default is
    // known before the effective permissions are judged (review M5).
    let mut public = BTreeSet::new();
    match s.rows(&grants, Stage::Check, Shape::rows(4, 1025)).await {
        Ok(rows) => {
            if rows.len() > 1024 {
                ev.incomplete.insert("more than 1024 database grants");
            }
            for row in &rows {
                let name = row.first().and_then(Value::as_text).unwrap_or_default();
                let state = row.get(1).and_then(Value::as_text).unwrap_or_default();
                let class = row.get(2).and_then(Value::as_int).unwrap_or(-1);
                let to_public = row.get(3).and_then(Value::as_int) == Some(1);
                if (class == CLASS_DATABASE_PRINCIPAL && PRINCIPAL_REFUSED.contains(&name))
                    || DATABASE_REFUSED.contains(&name)
                {
                    ev.refused.insert(name.to_owned());
                    continue;
                }
                if to_public {
                    if class == 0 {
                        public.insert(name.to_owned());
                    }
                    continue;
                }
                if state == "W" {
                    ev.grant_option = true;
                }
                if !grant_allowed(name, class, rls) {
                    ev.beyond_select.insert(name.to_owned());
                }
            }
        }
        Err(e) if !e.fatal => {
            ev.incomplete
                .insert("a database grant list could not be read");
        }
        Err(e) => return Err(e),
    }
    match s.rows(&perms, Stage::Check, Shape::rows(1, 513)).await {
        Ok(rows) => {
            if rows.len() > 512 {
                ev.incomplete.insert("more than 512 database permissions");
            }
            for p in texts(&rows, 0) {
                match effective_db_permission(&p, &ev.server_perms, &public, rls) {
                    DbPerm::Refused => {
                        ev.refused.insert(p);
                    }
                    DbPerm::Expected => {}
                    DbPerm::Beyond => {
                        ev.beyond_select.insert(p);
                    }
                }
            }
        }
        Err(e) if !e.fatal => {
            ev.incomplete
                .insert("database permissions could not be read");
        }
        Err(e) => return Err(e),
    }
    match s
        .rows(&roles, Stage::Check, Shape::rows(1, MAX_ROLES + 1))
        .await
    {
        Ok(rows) => {
            if rows.len() > MAX_ROLES {
                ev.incomplete.insert("more than 64 database roles");
            }
            for r in texts(&rows, 0) {
                match r.as_str() {
                    "db_owner" => {
                        ev.refused.insert(r);
                    }
                    "db_datareader" if settings.extended_grants => ev.extended_variant = true,
                    _ => {
                        ev.database_roles.insert(r);
                    }
                }
            }
        }
        Err(e) if !e.fatal => {
            ev.incomplete.insert("database roles could not be read");
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

/// A securable-level grant to the user or its roles that is expected:
/// `SELECT`, `CONNECT`, and database `VIEW DEFINITION` with the RLS
/// opt-in. Anything else (the Always Encrypted key-definition
/// permissions included, review M5) is beyond `SELECT`.
pub(crate) fn grant_allowed(name: &str, class: i64, rls: bool) -> bool {
    matches!(name, "SELECT" | "CONNECT") || (rls && class == 0 && name == "VIEW DEFINITION")
}

/// How an effective database permission is judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DbPerm {
    Refused,
    Expected,
    Beyond,
}

/// Judges an effective database permission: the refusal list; expected
/// (`CONNECT`, database `SELECT`, the RLS opt-in's `VIEW DEFINITION` and
/// what it implies, what a held server Audit permission implies, and the
/// Always Encrypted key-definition permissions **only when `public` holds
/// them**, review M5); otherwise beyond `SELECT`.
pub(crate) fn effective_db_permission(
    p: &str,
    server: &BTreeSet<String>,
    public: &BTreeSet<String>,
    rls: bool,
) -> DbPerm {
    if DATABASE_REFUSED.contains(&p) {
        return DbPerm::Refused;
    }
    let implied = DATABASE_FROM_SERVER
        .iter()
        .any(|(d, srv)| *d == p && server.contains(*srv));
    let public_default = PUBLIC_DEFAULTS.contains(&p) && public.contains(p);
    if matches!(p, "CONNECT" | "SELECT")
        || implied
        || public_default
        || (rls && DATABASE_RLS.contains(&p))
    {
        DbPerm::Expected
    } else {
        DbPerm::Beyond
    }
}

/// RLS tier of one monitored database (refinement item 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RlsTier {
    /// Policies visible and complete: the per-table rule applies.
    Visible,
    /// Every table of the database is skipped (`coverage.rls_not_verifiable`).
    NotVerifiable(&'static str),
}

/// The RLS tier of `db` (tiers (ii) and (iii)). Tier (i), a table-level
/// flag readable without the policy catalog, was measured on SQL Server
/// 2022 (docs/measurements/phase9-engine-facts.md): no such property
/// exists (`OBJECTPROPERTY` / `OBJECTPROPERTYEX` `TableHasRowLevelSecurity`
/// return `NULL`, `sys.tables` has no such column), so it is never used.
pub(crate) async fn rls_tier(
    s: &mut Session,
    db: &str,
    target: &TargetConfig,
) -> Result<RlsTier, SsError> {
    if target.sqlserver_settings().rls_visibility != Some(RlsVisibility::ViewDefinition) {
        return Ok(RlsTier::NotVerifiable(
            "the row-level security policy catalog is invisible to the account: declare \
             sqlserver.rls_visibility: view_definition and GRANT VIEW DEFINITION in this database \
             (it exposes module definitions to whoever holds the credentials; user guide)",
        ));
    }
    let probe =
        |t| sql::in_database(t, db).ok_or(SsError::new(FailureCode::Internal, Stage::Check));
    let held = match s
        .rows(
            &probe(sql::RLS_VIEW_DEFINITION)?,
            Stage::Check,
            Shape::rows(1, 1),
        )
        .await
    {
        Ok(rows) => rows.first().and_then(|r| r.first()).and_then(Value::as_int),
        Err(e) if !e.fatal => None,
        Err(e) => return Err(e),
    };
    if held != Some(1) {
        return Ok(RlsTier::NotVerifiable(
            "rls_visibility: view_definition is declared but VIEW DEFINITION is not effective in \
             this database",
        ));
    }
    // Server scope first (security review M4): a DENY of the server
    // definition-visibility permissions to the login, its server roles or
    // `public` can hide a policy whatever the database grants say.
    let server = match s
        .rows(sql::RLS_SERVER_DENIES, Stage::Check, Shape::rows(1, 1))
        .await
    {
        Ok(rows) => rows.first().and_then(|r| r.first()).and_then(Value::as_int),
        Err(e) if !e.fatal => None,
        Err(e) => return Err(e),
    };
    match server {
        Some(0) => {}
        Some(_) => {
            return Ok(RlsTier::NotVerifiable(
                "a server-level DENY of VIEW ANY DEFINITION, VIEW ANY SECURITY DEFINITION, VIEW \
                 SERVER SECURITY STATE or CONTROL SERVER to the login, one of its server roles or \
                 public can hide a policy",
            ));
        }
        None => {
            return Ok(RlsTier::NotVerifiable(
                "the server-level DENY proof could not be read",
            ));
        }
    }
    let row = match s
        .rows(&probe(sql::RLS_DENIES)?, Stage::Check, Shape::rows(3, 1))
        .await
    {
        Ok(rows) => rows.into_iter().next(),
        Err(e) if !e.fatal => None,
        Err(e) => return Err(e),
    };
    let int = |i: usize| row.as_ref().and_then(|r| r.get(i)).and_then(Value::as_int);
    match (int(0), int(1), int(2)) {
        (Some(0), Some(roles), Some(1)) if roles <= MAX_ROLES as i64 => Ok(RlsTier::Visible),
        (Some(d), _, _) if d > 0 => Ok(RlsTier::NotVerifiable(
            "a DENY of VIEW DEFINITION, VIEW SECURITY DEFINITION or CONTROL to the agent, one of \
             its roles or public can hide a policy",
        )),
        _ => Ok(RlsTier::NotVerifiable(
            "the DENY proof could not be read (or more than 64 roles)",
        )),
    }
}

/// The monitored databases: the user databases the account can enter,
/// filtered by `sqlserver.databases` (case-insensitive).
pub(crate) async fn monitored_databases(
    s: &mut Session,
    target: &TargetConfig,
) -> Result<(Vec<String>, bool), SsError> {
    let rows = s
        .rows(
            sql::USER_DATABASES,
            Stage::Introspection,
            Shape::rows(1, 1025),
        )
        .await?;
    let cut = rows.len() > 1024;
    let declared = target.sqlserver_settings().databases;
    let dbs = texts(&rows, 0)
        .into_iter()
        .take(1024)
        .filter(|d| {
            declared
                .as_ref()
                .is_none_or(|l| l.iter().any(|x| x.to_lowercase() == d.to_lowercase()))
        })
        .collect();
    Ok((dbs, cut))
}

/// A table of the CAS guard's read: id, name, columns with their `SELECT`.
type CasTable = (i64, String, Vec<(String, bool)>);

/// The CAS guard's credential columns readable by the account in the
/// monitored databases (ADR-0041 decision 6).
async fn cas_readable(
    s: &mut Session,
    dbs: &[String],
    target: &TargetConfig,
) -> Result<cas_guard::ReadableCheck, SsError> {
    let stores = target.cas_stores();
    let mut out = cas_guard::ReadableCheck {
        readable: 0,
        complete: true,
    };
    for db in dbs {
        let Some(stmt) = sql::in_database(sql::CAS_COLUMNS, db) else {
            out.complete = false;
            continue;
        };
        let rows = match s.rows(&stmt, Stage::Check, Shape::rows(4, 20_001)).await {
            Ok(r) => r,
            Err(e) if !e.fatal => {
                out.complete = false;
                continue;
            }
            Err(e) => return Err(e),
        };
        if rows.len() > 20_000 {
            out.complete = false;
        }
        // Group per table: (name, [(column, readable)]).
        let mut tables: Vec<CasTable> = Vec::new();
        for row in rows.iter().take(20_000) {
            let id = row.first().and_then(Value::as_int).unwrap_or(-1);
            let name = row.get(1).and_then(Value::as_text).unwrap_or_default();
            let col = row.get(2).and_then(Value::as_text).unwrap_or_default();
            let readable = row.get(3).and_then(Value::as_int) == Some(1);
            match tables.last_mut() {
                Some((last, _, cols)) if *last == id => cols.push((col.to_owned(), readable)),
                _ => tables.push((id, name.to_owned(), vec![(col.to_owned(), readable)])),
            }
        }
        for (_, name, cols) in &tables {
            let kind = cas_guard::recognize(
                stores,
                [name.as_str()],
                cols.iter().map(|(c, _)| c.as_str()),
            );
            if let Some(kind) = kind
                && cols
                    .iter()
                    .any(|(c, r)| *r && cas_guard::is_credential_column(kind, c))
            {
                out.readable += 1;
            }
        }
    }
    Ok(out)
}

fn labels<'a>(names: impl IntoIterator<Item = &'a String>) -> Vec<NoteLabel> {
    names
        .into_iter()
        .map(|n| NoteLabel::sqlserver_name(n))
        .collect()
}

/// The notes of an evaluation.
pub(crate) fn evaluation_notes(ev: &Evaluation, notes: &mut Notes) {
    if ev.is_refused() {
        // The probe's label first, then at most 15 others: the 16-label
        // cap can never drop it (review L4).
        let mut l = Vec::new();
        if ev.hash_exposed {
            l.push(NoteLabel::sqlserver("password_hash_probe"));
        }
        l.extend(labels(&ev.refused).into_iter().take(16 - l.len()));
        notes.add(TargetNote::new(NoteCode::PrivilegeRefused).with_labels(l));
    }
    if !ev.global.is_empty() {
        notes.add(
            TargetNote::new(NoteCode::PrivilegeGlobalPrivileges).with_labels(labels(&ev.global)),
        );
    }
    if !ev.audit_grants.is_empty() {
        notes.add(
            TargetNote::new(NoteCode::PrivilegeAuditGrantWithoutAudit)
                .with_labels(labels(&ev.audit_grants)),
        );
    }
    if !ev.server_roles.is_empty() {
        notes.add(
            TargetNote::new(NoteCode::PrivilegeServerRoles)
                .with_count(ev.server_roles.len() as u64)
                .with_labels(labels(&ev.server_roles)),
        );
    }
    if !ev.database_roles.is_empty() {
        notes.add(
            TargetNote::new(NoteCode::PrivilegeDatabaseRoles)
                .with_count(ev.database_roles.len() as u64)
                .with_labels(labels(&ev.database_roles)),
        );
    }
    if !ev.beyond_select.is_empty() {
        notes.add(
            TargetNote::new(NoteCode::PrivilegeBeyondSelect).with_labels(labels(&ev.beyond_select)),
        );
    }
    if ev.grant_option {
        notes.add(TargetNote::new(NoteCode::PrivilegeGrantOption));
    }
    if ev.extended_variant {
        notes.add(
            TargetNote::new(NoteCode::PrivilegeExtendedVariant)
                .with_labels([NoteLabel::sqlserver("db_datareader")]),
        );
    }
    if ev.owner_of_objects > 0 {
        notes.add(
            TargetNote::new(NoteCode::PrivilegeOwnerOfObjects).with_count(ev.owner_of_objects),
        );
    }
    if !ev.incomplete.is_empty() {
        notes.merge(
            TargetNote::new(NoteCode::PrivilegeNotEvaluated).with_labels([NoteLabel::OTHER]),
            databastion_core::CountMerge::Sum,
        );
    }
    if !ev.not_evaluated.is_empty() {
        notes.merge(
            TargetNote::new(NoteCode::PrivilegeNotEvaluated)
                .with_labels(ev.not_evaluated.iter().map(|l| NoteLabel::sqlserver(l))),
            databastion_core::CountMerge::Sum,
        );
    }
}

fn failed(e: SsError, target: &TargetConfig) -> TargetHealth {
    tracing::warn!(
        target_id = %target.id,
        stage = e.stage.as_str(),
        number = e.number,
        code = %e.code,
        detail = e.detail.map(Detail::as_str),
        "SQL Server check failed"
    );
    let note = if e.code == FailureCode::Timeout {
        TargetNote::new(NoteCode::CheckTimedOut)
    } else {
        TargetNote::new(NoteCode::CheckStageFailed)
            .with_labels([NoteLabel::stage(e.stage.as_str())])
    };
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
        notes: vec![note],
    }
}

/// `check()` of one target.
pub(crate) async fn check(state: &CheckState, target: &TargetConfig) -> TargetHealth {
    match tokio::time::timeout(CHECK_TOTAL, run(state, target)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            state.set_version(&target.id, None);
            failed(e, target)
        }
        Err(_) => failed(SsError::new(FailureCode::Timeout, Stage::Check), target),
    }
}

async fn run(state: &CheckState, target: &TargetConfig) -> Result<TargetHealth, SsError> {
    let settings = target.sqlserver_settings();
    let tls = tls::configs(settings.ca_file.as_deref())
        .ok_or(SsError::new(FailureCode::Internal, Stage::Tls))?;
    let mut s = conn::connect(target, &tls, &state.choice, CHECK_STATEMENT).await?;
    let result = checked(state, target, &mut s).await;
    s.close().await;
    result
}

async fn checked(
    state: &CheckState,
    target: &TargetConfig,
    s: &mut Session,
) -> Result<TargetHealth, SsError> {
    let v = version(s).await?;
    state.set_version(&target.id, contract_version(&v.product));
    let mut notes = Notes::default();
    let mut detail = vec![format!(
        "SQL Server {} (edition {}), {} encryption",
        v.product,
        v.edition,
        match s.mode {
            conn::Mode::Strict => "strict",
            conn::Mode::Mandatory => "mandatory",
        }
    )];
    let ev = evaluate(s, target).await?;
    evaluation_notes(&ev, &mut notes);
    if ev.is_refused() {
        detail.push(
            "the account holds a right of the refusal list: Discovery and Audit do not run"
                .to_owned(),
        );
    }
    if !ev.incomplete.is_empty() {
        let why: Vec<&str> = ev.incomplete.iter().copied().collect();
        detail.push(format!(
            "the refusal list could not be evaluated completely ({}): Discovery and Audit do \
             not run",
            why.join(", ")
        ));
    }
    // Logon triggers (decision 7, refinement item 6): evaluated only when
    // the catalog is visible; never "no logon trigger" otherwise.
    let visible = [
        "VIEW ANY DEFINITION",
        "VIEW ANY SECURITY DEFINITION",
        "CONTROL SERVER",
    ]
    .iter()
    .any(|p| ev.server_perms.contains(*p));
    if visible {
        match s
            .rows(sql::LOGON_TRIGGERS, Stage::Check, Shape::rows(1, 1))
            .await
        {
            Ok(rows) => {
                let n = rows
                    .first()
                    .and_then(|r| r.first())
                    .and_then(Value::as_int)
                    .unwrap_or(0);
                if n > 0 {
                    notes.add(
                        TargetNote::new(NoteCode::SecurityLoginEventTrigger).with_count(n as u64),
                    );
                }
            }
            Err(e) if !e.fatal => notes.add(
                TargetNote::new(NoteCode::PrivilegeNotEvaluated).with_labels([NoteLabel::OTHER]),
            ),
            Err(e) => return Err(e),
        }
    } else {
        // The logon-trigger label is a pending P9-C item: `other` until then.
        notes.merge(
            TargetNote::new(NoteCode::PrivilegeNotEvaluated).with_labels([NoteLabel::OTHER]),
            databastion_core::CountMerge::Sum,
        );
    }
    // RLS tiers, from the first heartbeat (refinement item 2).
    if !ev.blocks() {
        let (dbs, _) = monitored_databases(s, target).await?;
        let mut not_verifiable = 0u64;
        let mut counts = [0u64; 4];
        for db in &dbs {
            if let Some(stmt) = sql::in_database(sql::COLUMN_COUNTS, db) {
                match s.rows(&stmt, Stage::Check, Shape::rows(4, 1)).await {
                    Ok(rows) => {
                        for (i, c) in counts.iter_mut().enumerate() {
                            let n = rows
                                .first()
                                .and_then(|r| r.get(i))
                                .and_then(Value::as_int)
                                .unwrap_or(0);
                            *c = c.saturating_add(u64::try_from(n).unwrap_or(0));
                        }
                    }
                    Err(e) if !e.fatal => {}
                    Err(e) => return Err(e),
                }
            }
            if let RlsTier::NotVerifiable(why) = rls_tier(s, db, target).await? {
                not_verifiable += 1;
                tracing::info!(target_id = %target.id, reason = why, "row-level security not verifiable: database skipped by Discovery");
            }
        }
        for (code, n) in [
            (NoteCode::CoverageMaskedColumns, counts[0]),
            (NoteCode::CoverageEncryptedColumns, counts[1]),
            (NoteCode::CoverageComputedColumnsNotSampled, counts[2]),
            (NoteCode::CoverageViewsNotSampled, counts[3]),
        ] {
            if n > 0 {
                notes.add(TargetNote::new(code).with_count(n));
            }
        }
        if not_verifiable > 0 {
            notes.add(
                TargetNote::new(NoteCode::CoverageRlsNotVerifiable).with_count(not_verifiable),
            );
        }
        let cas = cas_readable(s, &dbs, target).await?;
        if cas.readable > 0 {
            notes.add(
                TargetNote::new(NoteCode::PrivilegeTicketCredentialsReadable)
                    .with_count(cas.readable),
            );
        } else if !cas.complete {
            notes.merge(
                TargetNote::new(NoteCode::PrivilegeNotEvaluated).with_labels([NoteLabel::OTHER]),
                databastion_core::CountMerge::Sum,
            );
        }
    }
    tracing::info!(target_id = %target.id, detail = %detail.join("; "), "SQL Server checked");
    Ok(TargetHealth {
        reachable: true,
        // No Audit source in this lot (P9-A lot 3).
        audit_level: AuditLevel::None,
        failure: None,
        detail: Some(detail.join("; ")),
        notes: notes.into_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_versions() {
        assert_eq!(
            contract_version("16.0.4305.5").as_deref(),
            Some("16.0.4305.5")
        );
        assert_eq!(contract_version("16.0 (RTM)"), None);
        assert_eq!(contract_version(""), None);
    }

    /// Review M5: the Always Encrypted key-definition permissions are
    /// expected only from `public`.
    #[test]
    fn public_defaults_only_from_public() {
        let none = BTreeSet::new();
        let public: BTreeSet<String> =
            ["VIEW ANY COLUMN ENCRYPTION KEY DEFINITION".to_owned()].into();
        let p = "VIEW ANY COLUMN ENCRYPTION KEY DEFINITION";
        assert_eq!(
            effective_db_permission(p, &none, &public, false),
            DbPerm::Expected
        );
        assert_eq!(
            effective_db_permission(p, &none, &none, false),
            DbPerm::Beyond
        );
        assert!(!grant_allowed(p, 0, false));
        assert_eq!(
            effective_db_permission("CONTROL", &none, &public, false),
            DbPerm::Refused
        );
        assert_eq!(
            effective_db_permission("CONNECT", &none, &none, false),
            DbPerm::Expected
        );
        assert_eq!(
            effective_db_permission("VIEW DEFINITION", &none, &none, false),
            DbPerm::Beyond
        );
        assert_eq!(
            effective_db_permission("VIEW DEFINITION", &none, &none, true),
            DbPerm::Expected
        );
    }

    /// Review M3 and L4: an incomplete evaluation blocks, and the hash
    /// probe's label survives the 16-label cap.
    #[test]
    fn incomplete_evaluation_blocks_and_hash_label_survives() {
        let mut ev = Evaluation::default();
        assert!(!ev.blocks());
        ev.incomplete.insert("more than 64 database roles");
        assert!(ev.blocks() && !ev.is_refused());
        let mut notes = Notes::default();
        evaluation_notes(&ev, &mut notes);
        assert_eq!(notes.as_slice()[0].code(), NoteCode::PrivilegeNotEvaluated);
        let mut ev = Evaluation {
            hash_exposed: true,
            ..Evaluation::default()
        };
        for p in SERVER_REFUSED {
            ev.refused.insert((*p).to_owned());
        }
        ev.refused.insert("sysadmin".into());
        ev.refused.insert("db_owner".into());
        let mut notes = Notes::default();
        evaluation_notes(&ev, &mut notes);
        let l: Vec<String> = notes.as_slice()[0]
            .labels()
            .iter()
            .map(|l| l.as_str())
            .collect();
        assert!(l.contains(&"password_hash_probe".to_owned()), "{l:?}");
    }

    #[test]
    fn refusal_labels_map_to_the_contract() {
        let mut ev = Evaluation::default();
        ev.refused.insert("CONTROL SERVER".into());
        ev.refused.insert("db_owner".into());
        ev.refused.insert("##MS_LoginManager##".into());
        ev.refused.insert("ALTER ANY DATABASE EVENT SESSION".into());
        let mut notes = Notes::default();
        evaluation_notes(&ev, &mut notes);
        let n = &notes.as_slice()[0];
        assert_eq!(n.code(), NoteCode::PrivilegeRefused);
        let l: Vec<String> = n.labels().iter().map(|l| l.as_str()).collect();
        for want in ["control_server", "db_owner", "ms_login_manager", "other"] {
            assert!(l.contains(&want.to_owned()), "{want} in {l:?}");
        }
    }
}
