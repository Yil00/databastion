//! Integration tests against the dev `sqlserver` profile (`make
//! dev-sqlserver`, dev/README.md "SQL Server"): SQL Server 2022 Express
//! over TLS with the dev CA, the agent login `databastion` (minimal
//! variant) and the seeded `retail` database.
//!
//! Skipped unless `DATABASTION_IT_SQLSERVER=1`. Variables:
//! - `DATABASTION_IT_SQLSERVER_CA`: the dev CA (`docker compose … exec -T
//!   sqlserver cat /var/opt/mssql/databastion-tls/ca.pem`);
//! - `SQLSERVER_DATABASTION_PASSWORD`, `SQLSERVER_SA_PASSWORD` (dev/.env);
//! - `SQLSERVER_PORT` (default 1433);
//! - `DATABASTION_IT_SQLSERVER_THROWAWAY`: the fake password of the
//!   throwaway logins the tests create ([`PW`]);
//! - `DATABASTION_DEV_SQLSERVER_FORCE_STRICT=1` when the server forces
//!   strict encryption (dev service on 2025): the tests then expect
//!   `strict` and use it for their own sessions;
//! - `DATABASTION_IT_SQLSERVER_MAJOR` (optional, set by CI): the major
//!   version the server must report (15, 16 or 17), so an entry of the
//!   engine matrix cannot silently test another image.
//!
//! The TLS mode reached is asserted per version (ADR-0051 refinement item
//! 3): `mandatory` and the `auto` fallback on 2019 and 2022 (and 2025
//! without forced strict), `strict` and `auto` reaching strict on 2025
//! with forced strict.
//!
//! `sa` is used by the tests only, to create throwaway logins and grants
//! (the refusal tests, the RLS tiers); the connector never uses it (P9-A
//! obligation L13). Throwaway logins are dropped at the end of each test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::time::Duration;

use databastion_classifiers::masking::{HmacKey, MaskedFinding};
use databastion_core::config::{Limits, TargetConfig, TargetEngine};
use databastion_core::{
    Connector, ConnectorError, FindingSink, NoteCode, ScanCoverage, ScanJob, ScanParams,
    TargetHealth,
};

use crate::SqlserverConnector;
use crate::conn::{self, Session, Shape, TlsChoice};
use crate::error::{Detail, Stage};
use crate::tls;
use crate::token::Value;

fn enabled() -> bool {
    std::env::var("DATABASTION_IT_SQLSERVER").as_deref() == Ok("1")
}

/// The tests change logins and grants on one server: one at a time.
async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));
    LOCK.lock().await
}

fn port() -> u16 {
    std::env::var("SQLSERVER_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1433)
}

fn ca() -> String {
    std::env::var("DATABASTION_IT_SQLSERVER_CA").expect("DATABASTION_IT_SQLSERVER_CA")
}

/// Whether the dev server forces strict encryption (TDS 8.0).
fn strict_forced() -> bool {
    std::env::var("DATABASTION_DEV_SQLSERVER_FORCE_STRICT").as_deref() == Ok("1")
}

/// The TLS setting the tests' own sessions use: the mode the server
/// accepts (`mandatory` is refused by a server forcing strict).
fn own_tls() -> &'static str {
    if strict_forced() {
        "tls: strict"
    } else {
        "tls: mandatory"
    }
}

/// The server's major version (15: 2019, 16: 2022, 17: 2025), checked
/// against `DATABASTION_IT_SQLSERVER_MAJOR` when set.
async fn major() -> u32 {
    let c = SqlserverConnector::new();
    let t = agent("");
    let h = c.check(&t).await;
    assert!(h.reachable, "{:?}", h.detail);
    let v = c.server_version(&t).unwrap();
    let major: u32 = v.split('.').next().unwrap().parse().unwrap();
    assert!((15..=17).contains(&major), "{v}");
    if let Ok(want) = std::env::var("DATABASTION_IT_SQLSERVER_MAJOR").map(|v| v.trim().to_owned())
        && !want.is_empty()
    {
        assert_eq!(major.to_string(), want, "server version {v}");
    }
    if strict_forced() {
        assert!(major >= 17, "forced strict needs 2025 on Linux: {v}");
    }
    major
}

/// A target of the dev profile.
/// A private per-run `state_dir`, so that the "strict seen" marks of
/// `auto` targets never land outside the temporary directory (the tests
/// may run as root).
fn state_dir() -> &'static str {
    static STATE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let dir = std::env::temp_dir().join(format!(
            "databastion-it-sqlserver-state-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir.to_str().unwrap().to_owned()
    });
    &STATE
}

fn target(account: &str, secret_env: &str, sqlserver: &str) -> TargetConfig {
    target_in(state_dir(), account, secret_env, sqlserver)
}

/// A target of the dev profile with its own `state_dir`.
fn target_in(state_dir: &str, account: &str, secret_env: &str, sqlserver: &str) -> TargetConfig {
    let yaml = format!(
        "{{console: {{url: \"https://c.example\"}}, state_dir: {state_dir}, targets: [{{id: it, \
         engine: sqlserver, host: 127.0.0.1, port: {port}, account: {account}, \
         secret: {{env: {secret_env}}}, \
         sqlserver: {{ca_file: \"{ca}\"{sep}{sqlserver}}}}}]}}",
        port = port(),
        ca = ca(),
        sep = if sqlserver.is_empty() { "" } else { ", " },
    );
    databastion_core::AgentConfig::parse(&yaml).unwrap().targets[0].clone()
}

fn agent(sqlserver: &str) -> TargetConfig {
    target("databastion", "SQLSERVER_DATABASTION_PASSWORD", sqlserver)
}

/// The fake password of throwaway logins.
const PW: &str = "Fake-IT-Passw0rd-marker";

fn throwaway_target(name: &str, sqlserver: &str) -> TargetConfig {
    assert_eq!(
        std::env::var("DATABASTION_IT_SQLSERVER_THROWAWAY").as_deref(),
        Ok(PW),
        "DATABASTION_IT_SQLSERVER_THROWAWAY must hold the fake marker"
    );
    target(name, "DATABASTION_IT_SQLSERVER_THROWAWAY", sqlserver)
}

/// A raw `sa` session (tests only).
async fn sa() -> Session {
    let t = target("sa", "SQLSERVER_SA_PASSWORD", own_tls());
    let tls = tls::configs(t.sqlserver_settings().ca_file.as_deref()).unwrap();
    conn::connect(&t, &tls, &TlsChoice::default(), Duration::from_secs(30))
        .await
        .unwrap()
}

async fn exec(s: &mut Session, sql: &str) {
    s.run(sql, Stage::Check, Shape::rows(0, 0), |_| {
        conn::Flow::Continue
    })
    .await
    .unwrap_or_else(|e| panic!("{sql}: {e:?}"));
}

async fn exec_ok(s: &mut Session, sql: &str) {
    let _ = s
        .run(sql, Stage::Check, Shape::rows(0, 0), |_| {
            conn::Flow::Continue
        })
        .await;
}

/// `sql` in database `db` (tests only: the connector never sends `USE`
/// nor dynamic SQL).
fn in_db(db: &str, sql: &str) -> String {
    format!(
        "EXEC [{db}].sys.sp_executesql N'{}'",
        sql.replace('\'', "''")
    )
}

/// Creates a throwaway login `name` with a user in `retail` (schema
/// `SELECT` on `crm` and `finance`), then runs `extra` as `sa`.
async fn throwaway(s: &mut Session, name: &str, extra: &[String]) {
    drop_login(s, name).await;
    exec(
        s,
        &format!("CREATE LOGIN [{name}] WITH PASSWORD = N'{PW}', CHECK_POLICY = OFF"),
    )
    .await;
    exec(
        s,
        &in_db(
            "retail",
            &format!(
                "CREATE USER [{name}] FOR LOGIN [{name}]; GRANT SELECT ON SCHEMA::crm TO \
                 [{name}]; GRANT SELECT ON SCHEMA::finance TO [{name}]"
            ),
        ),
    )
    .await;
    for e in extra {
        exec(s, e).await;
    }
}

async fn drop_login(s: &mut Session, name: &str) {
    exec_ok(
        s,
        &format!("ALTER SERVER ROLE sysadmin DROP MEMBER [{name}]"),
    )
    .await;
    for db in ["retail", "msdb", "model"] {
        exec_ok(
            s,
            &in_db(
                db,
                &format!("IF USER_ID(N'{name}') IS NOT NULL DROP USER [{name}]"),
            ),
        )
        .await;
    }
    exec_ok(
        s,
        &format!("IF SUSER_ID(N'{name}') IS NOT NULL DROP LOGIN [{name}]"),
    )
    .await;
}

fn codes(h: &TargetHealth) -> Vec<String> {
    h.notes
        .iter()
        .map(|n| {
            format!(
                "{}{:?}{:?}",
                n.code().as_str(),
                n.count(),
                n.labels().iter().map(|l| l.as_str()).collect::<Vec<_>>()
            )
        })
        .collect()
}

fn has(h: &TargetHealth, code: NoteCode) -> bool {
    h.notes.iter().any(|n| n.code() == code)
}

fn key() -> Arc<HmacKey> {
    Arc::new(HmacKey::new(&[7u8; 32]).unwrap())
}

fn unpaced() -> Limits {
    Limits {
        discovery_duty_cycle_percent: 100,
        ..Limits::default()
    }
}

struct Scan {
    result: Result<(), ConnectorError>,
    findings: Vec<MaskedFinding>,
    coverage: ScanCoverage,
}

async fn scan(t: &TargetConfig) -> Scan {
    let c = SqlserverConnector::new();
    let job = ScanJob::new(ScanParams::contract_defaults(), t, &unpaced(), key());
    let (sink, mut rx) = FindingSink::channel(10_000);
    let result = c.discover(&job, &sink).await;
    let coverage = databastion_core::test_support::coverage_of(&sink);
    drop(sink);
    let mut findings = Vec::new();
    while let Ok(f) = rx.try_recv() {
        findings.push(f);
    }
    Scan {
        result,
        findings,
        coverage,
    }
}

fn located(findings: &[MaskedFinding]) -> Vec<String> {
    findings
        .iter()
        .map(|f| {
            let l = f.location().unwrap();
            format!(
                "{}.{}.{}.{} {}",
                l.database.as_str(),
                l.schema.as_ref().map(|s| s.as_str()).unwrap_or_default(),
                l.object.as_str(),
                l.field.as_str(),
                f.classifier().as_str()
            )
        })
        .collect()
}

fn truth() -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../dev/ground-truth.json"
        ))
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn check_minimal_login() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let mut s = sa().await;
    exec(
        &mut s,
        &in_db("retail", "REVOKE VIEW DEFINITION TO databastion"),
    )
    .await;
    let c = SqlserverConnector::new();
    // Without the RLS opt-in: every monitored database not verifiable.
    let t = agent("tls: auto");
    let h = c.check(&t).await;
    eprintln!("minimal: {:?} {:?}", h.detail, codes(&h));
    assert!(h.reachable, "{:?}", h.detail);
    assert!(!has(&h, NoteCode::PrivilegeRefused), "{:?}", codes(&h));
    assert!(has(&h, NoteCode::CoverageRlsNotVerifiable));
    assert!(has(&h, NoteCode::CoverageMaskedColumns));
    assert!(has(&h, NoteCode::CoverageEncryptedColumns));
    assert!(has(&h, NoteCode::CoverageComputedColumnsNotSampled));
    // The Audit grants of the dev account, with no Audit stream yet.
    assert!(has(&h, NoteCode::PrivilegeAuditGrantWithoutAudit));
    // Logon triggers invisible to the minimal variant: not evaluated,
    // never reported as absent.
    assert!(has(&h, NoteCode::PrivilegeNotEvaluated));
    assert!(!has(&h, NoteCode::SecurityLoginEventTrigger));
    // The TLS modes of the version: `tls_modes_by_version`.
    major().await;
    let h = c.check(&agent(own_tls())).await;
    assert!(h.reachable);
    // Without the opt-in, Discovery samples nothing: every table skipped
    // as row-level security not verifiable.
    let s = scan(&agent("")).await;
    s.result.unwrap();
    assert!(s.findings.is_empty());
    assert_eq!(s.coverage.sampled, 0);
    assert!(s.coverage.row_level_security >= 8, "{:?}", s.coverage);
    // Back to the dev account's grant (dev/sqlserver/initdb).
    let mut sa = sa().await;
    exec(
        &mut sa,
        &in_db("retail", "GRANT VIEW DEFINITION TO databastion"),
    )
    .await;
}

/// ADR-0051 decision 2 and refinement item 3, per version (lot 1 review
/// M2): which TLS mode each setting reaches, the `auto` fallback and its
/// in-memory retry, and the persisted "strict seen" mark (set only after
/// a strict session; cleared when `tls` is not `auto`, re-review R4).
#[tokio::test]
async fn tls_modes_by_version() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let major = major().await;
    let state =
        std::env::temp_dir().join(format!("databastion-it-sqlserver-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    std::fs::create_dir_all(&state).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let dir = state.to_str().unwrap();
    let with = |tls: &str| {
        target_in(
            dir,
            "databastion",
            "SQLSERVER_DATABASTION_PASSWORD",
            &format!("tls: {tls}"),
        )
    };
    let mark = state.join(conn::STRICT_SEEN_DIR).join("it");
    let configs = tls::configs(with("auto").sqlserver_settings().ca_file.as_deref()).unwrap();
    let c = SqlserverConnector::new();
    eprintln!("major {major}, forced strict {}", strict_forced());
    if strict_forced() {
        // Strict on 2025: `strict` works, `mandatory` is refused (the
        // server disconnects a TDS 7.x PRELOGIN), `auto` reaches strict
        // and marks the target "strict seen".
        let s = conn::connect(
            &with("strict"),
            &configs,
            &TlsChoice::default(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(s.mode, conn::Mode::Strict);
        s.close().await;
        let h = c.check(&with("mandatory")).await;
        assert!(
            !h.reachable,
            "mandatory against forced strict: {:?}",
            h.detail
        );
        let choice = TlsChoice::default();
        let s = conn::connect(&with("auto"), &configs, &choice, Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(s.mode, conn::Mode::Strict, "auto on forced strict");
        s.close().await;
        assert!(mark.is_file(), "strict seen not persisted");
        assert!(conn::persisted_strict_seen(&with("auto")));
        // A fresh process (new in-memory state) keeps strict.
        let s = conn::connect(
            &with("auto"),
            &configs,
            &TlsChoice::default(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(s.mode, conn::Mode::Strict);
        s.close().await;
        // `tls: strict` (not `auto`) clears the mark.
        let s = conn::connect(
            &with("strict"),
            &configs,
            &TlsChoice::default(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        s.close().await;
        assert!(!mark.exists(), "strict seen not cleared by tls: strict");
    } else {
        // 2019, 2022 (and 2025 without forced strict) on Linux: no strict
        // encryption. `strict` fails with the local detail, `mandatory`
        // works, `auto` falls back once to `mandatory`, never marks the
        // target, and connects in `mandatory` directly within the hour.
        let h = c.check(&with("strict")).await;
        assert!(!h.reachable, "strict on {major}");
        let detail = h.detail.unwrap();
        assert!(
            detail.contains("strict encryption not available"),
            "{detail}"
        );
        let s = conn::connect(
            &with("mandatory"),
            &configs,
            &TlsChoice::default(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(s.mode, conn::Mode::Mandatory);
        s.close().await;
        let choice = TlsChoice::default();
        for attempt in ["fallback", "in-memory retry"] {
            let s = conn::connect(&with("auto"), &configs, &choice, Duration::from_secs(10))
                .await
                .unwrap();
            assert_eq!(s.mode, conn::Mode::Mandatory, "auto, {attempt}");
            s.close().await;
        }
        assert!(!mark.exists(), "strict seen set without a strict session");
        let h = c.check(&with("auto")).await;
        assert!(h.reachable, "{:?}", h.detail);
        assert!(!mark.exists());
    }
    let _ = std::fs::remove_dir_all(&state);
}

#[tokio::test]
async fn discovery_matches_the_ground_truth_and_keeps_i2() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let mut s = sa().await;
    exec(
        &mut s,
        &in_db("retail", "GRANT VIEW DEFINITION TO databastion"),
    )
    .await;
    let t = agent("rls_visibility: view_definition");
    let h = SqlserverConnector::new().check(&t).await;
    eprintln!("opt-in: {:?}", codes(&h));
    assert!(
        !has(&h, NoteCode::CoverageRlsNotVerifiable),
        "{:?}",
        codes(&h)
    );
    assert!(!has(&h, NoteCode::PrivilegeRefused));
    let scan = scan(&t).await;
    scan.result.as_ref().unwrap();
    eprintln!("coverage: {:?}", scan.coverage);
    let got = located(&scan.findings);
    for l in &got {
        eprintln!("finding {l}");
    }
    let truth = truth();
    let mut values: Vec<String> = Vec::new();
    let mut checked = 0;
    for loc in truth["locations"].as_array().unwrap() {
        if loc["engine"] != "sqlserver" {
            continue;
        }
        let name = |k: &str| loc[k].as_str().unwrap_or_default().to_owned();
        let object = loc["expected_normalized_name"]
            .as_str()
            .map_or_else(|| name("object"), str::to_owned);
        let at = format!(
            "{}.{}.{}.{}",
            name("database"),
            name("container"),
            object,
            name("field")
        );
        let expected: Vec<&str> = loc["expected_classifiers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c.as_str())
            .collect();
        for c in &expected {
            assert!(got.contains(&format!("{at} {c}")), "missing {at} {c}");
            checked += 1;
        }
        // Negative controls and skipped fixtures: no finding.
        if expected.is_empty() {
            assert!(
                !got.iter().any(|g| g.starts_with(&format!("{at} "))),
                "unexpected finding at {at}"
            );
        }
        for v in loc["values"].as_array().into_iter().flatten() {
            if let Some(v) = v.as_str().filter(|v| v.len() >= 6) {
                values.push(v.to_owned());
            }
        }
        for v in loc["name_values"].as_array().into_iter().flatten() {
            values.push(v.as_str().unwrap().to_owned());
        }
    }
    assert!(checked >= 15, "{checked}");
    // Skipped fixtures counted: the RLS table, the synonym and the views,
    // the ticket registry.
    assert!(scan.coverage.row_level_security >= 1, "{:?}", scan.coverage);
    assert!(scan.coverage.unsupported >= 2, "{:?}", scan.coverage);
    assert!(scan.coverage.sampled >= 8, "{:?}", scan.coverage);
    // I2: no ground-truth value, nor the e-mail in the table name, in the
    // contract JSON.
    let json = databastion_core::test_support::contract_findings_json(
        &scan.findings,
        TargetEngine::Sqlserver,
    );
    assert!(json.contains("\"engine\":\"sqlserver\""));
    for v in &values {
        assert!(
            !json.contains(v.as_str()),
            "raw ground-truth value in the contract JSON"
        );
    }
}

/// Refinement item 2, M1: a lower-scope `DENY` keeps the whole-database
/// skip, whether to `public`, to the agent or to one of its roles.
#[tokio::test]
async fn rls_opt_in_fails_closed_on_a_deny() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let mut s = sa().await;
    let name = "it_rls_deny";
    // A run stopped half-way leaves its DENY to `public` behind.
    exec_ok(
        &mut s,
        &in_db(
            "retail",
            "REVOKE VIEW DEFINITION ON SCHEMA::security TO public",
        ),
    )
    .await;
    exec_ok(
        &mut s,
        &in_db("master", "REVOKE VIEW ANY DEFINITION TO public"),
    )
    .await;
    // ... and its server role, with its DENY.
    drop_login(&mut s, name).await;
    exec_ok(&mut s, "DROP SERVER ROLE it_rls_srvrole").await;
    throwaway(
        &mut s,
        name,
        &[
            in_db("retail", &format!("GRANT VIEW DEFINITION TO [{name}]")),
            in_db(
                "retail",
                "IF DATABASE_PRINCIPAL_ID(N'it_rls_role') IS NULL CREATE ROLE it_rls_role",
            ),
            in_db(
                "retail",
                &format!("ALTER ROLE it_rls_role ADD MEMBER [{name}]"),
            ),
        ],
    )
    .await;
    let t = throwaway_target(name, "rls_visibility: view_definition");
    let c = SqlserverConnector::new();
    let h = c.check(&t).await;
    assert!(
        !has(&h, NoteCode::CoverageRlsNotVerifiable),
        "{:?}",
        codes(&h)
    );
    for grantee in ["public", name, "it_rls_role"] {
        exec(
            &mut s,
            &in_db(
                "retail",
                &format!("DENY VIEW DEFINITION ON SCHEMA::security TO [{grantee}]"),
            ),
        )
        .await;
        let h = c.check(&t).await;
        assert!(
            has(&h, NoteCode::CoverageRlsNotVerifiable),
            "DENY to {grantee}: {:?}",
            codes(&h)
        );
        let scan = scan(&t).await;
        scan.result.unwrap();
        assert!(scan.findings.is_empty(), "DENY to {grantee}");
        exec(
            &mut s,
            &in_db(
                "retail",
                &format!("REVOKE VIEW DEFINITION ON SCHEMA::security TO [{grantee}]"),
            ),
        )
        .await;
    }
    // Server scope (review M4, re-review R1): a DENY of VIEW ANY
    // DEFINITION to the login, to `public` and to a server role the login
    // is a member of. Through `sp_executesql` in a literal: the session's
    // own run-time deny-list refuses a bare text naming DEFINITION, test
    // or not.
    exec(
        &mut s,
        "IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'it_rls_srvrole') \
         CREATE SERVER ROLE it_rls_srvrole",
    )
    .await;
    exec(
        &mut s,
        &format!("ALTER SERVER ROLE it_rls_srvrole ADD MEMBER [{name}]"),
    )
    .await;
    for grantee in [name, "public", "it_rls_srvrole"] {
        exec(
            &mut s,
            &in_db(
                "master",
                &format!("DENY VIEW ANY DEFINITION TO [{grantee}]"),
            ),
        )
        .await;
        // The tier proof itself fails; with the definitions hidden, parts
        // of the refusal list are unreadable too, which blocks Discovery
        // anyway (review M3).
        let tls = tls::configs(t.sqlserver_settings().ca_file.as_deref()).unwrap();
        let mut ts = conn::connect(&t, &tls, &TlsChoice::default(), Duration::from_secs(10))
            .await
            .unwrap();
        let tier = crate::check::rls_tier(&mut ts, "retail", &t).await.unwrap();
        assert!(
            matches!(tier, crate::check::RlsTier::NotVerifiable(_)),
            "server DENY to {grantee}: {tier:?}"
        );
        ts.close().await;
        let h = c.check(&t).await;
        assert!(
            has(&h, NoteCode::CoverageRlsNotVerifiable) || has(&h, NoteCode::PrivilegeNotEvaluated),
            "server DENY to {grantee}: {:?}",
            codes(&h)
        );
        let scan = scan(&t).await;
        assert!(scan.findings.is_empty(), "server DENY to {grantee}");
        exec(
            &mut s,
            &in_db(
                "master",
                &format!("REVOKE VIEW ANY DEFINITION TO [{grantee}]"),
            ),
        )
        .await;
        // The DENY lifted: the tier is proven again.
        let h = c.check(&t).await;
        assert!(
            !has(&h, NoteCode::CoverageRlsNotVerifiable),
            "after the server DENY to {grantee}: {:?}",
            codes(&h)
        );
    }
    drop_login(&mut s, name).await;
    exec_ok(&mut s, &in_db("retail", "DROP ROLE it_rls_role")).await;
    exec_ok(&mut s, "DROP SERVER ROLE it_rls_srvrole").await;
}

/// P9-A obligation L13 and refinement item 5: refused accounts.
#[tokio::test]
async fn refused_accounts() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let mut s = sa().await;
    let cases: Vec<(&str, Vec<String>, &str)> = vec![
        (
            "it_sysadmin",
            vec!["ALTER SERVER ROLE sysadmin ADD MEMBER [it_sysadmin]".to_owned()],
            "sysadmin",
        ),
        (
            "it_dbowner",
            vec![
                in_db("msdb", "CREATE USER [it_dbowner] FOR LOGIN [it_dbowner]"),
                in_db("msdb", "ALTER ROLE db_owner ADD MEMBER [it_dbowner]"),
            ],
            "db_owner",
        ),
        (
            "it_impersonate",
            vec!["GRANT IMPERSONATE ON LOGIN::[sa] TO [it_impersonate]".to_owned()],
            "impersonate",
        ),
        (
            "it_xe",
            vec!["GRANT ALTER ANY EVENT SESSION TO [it_xe]".to_owned()],
            "alter_any_event_session",
        ),
    ];
    let c = SqlserverConnector::new();
    for (name, extra, label) in cases {
        throwaway(&mut s, name, &extra).await;
        let t = throwaway_target(name, "rls_visibility: view_definition");
        let h = c.check(&t).await;
        eprintln!("{name}: {:?}", codes(&h));
        let refused = h
            .notes
            .iter()
            .find(|n| n.code() == NoteCode::PrivilegeRefused)
            .unwrap_or_else(|| panic!("{name} not refused: {:?}", codes(&h)));
        // Labels of the 2026_10 revision are kept by the agent; the core
        // sends them only once negotiated.
        assert!(
            refused.labels().iter().any(|l| l.as_str() == label),
            "{name}: {:?}",
            codes(&h)
        );
        let scan = scan(&t).await;
        assert!(scan.result.is_err(), "{name}: Discovery must refuse");
        assert!(scan.findings.is_empty());
        drop_login(&mut s, name).await;
    }
    // Refinement item 5: the database-scoped event-session permissions
    // cannot be granted on boxed SQL Server 2022 (error 4631, measured);
    // where they can, the evaluation refuses them (unit-tested labels).
    throwaway(
        &mut s,
        "it_dbxe",
        &[in_db("msdb", "CREATE USER [it_dbxe] FOR LOGIN [it_dbxe]")],
    )
    .await;
    let r = s
        .run(
            &in_db(
                "msdb",
                "GRANT ALTER ANY DATABASE EVENT SESSION TO [it_dbxe]",
            ),
            Stage::Check,
            Shape::rows(0, 0),
            |_| conn::Flow::Continue,
        )
        .await;
    match r {
        Err(e) => assert_eq!(e.number, Some(4631), "{e:?}"),
        Ok(_) => {
            let h = c.check(&throwaway_target("it_dbxe", "")).await;
            assert!(has(&h, NoteCode::PrivilegeRefused), "{:?}", codes(&h));
        }
    }
    drop_login(&mut s, "it_dbxe").await;
    // `sa` itself.
    let h = c.check(&target("sa", "SQLSERVER_SA_PASSWORD", "")).await;
    assert!(has(&h, NoteCode::PrivilegeRefused), "{:?}", codes(&h));
}

/// Decision 2 (M9): SQL Server's fallback certificate is refused, with
/// the local detail. A throwaway server of the same image without a
/// configured certificate is not started here (disk and time); instead the
/// TLS layer is pointed at the dev server with a CA that did not sign it,
/// and the fallback marker test covers the detail.
#[tokio::test]
async fn untrusted_certificate_is_refused() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let other_ca_path = crate::fake::other_ca_file();
    let other_ca = other_ca_path.to_str().unwrap();
    let yaml = format!(
        "{{console: {{url: \"https://c.example\"}}, state_dir: {}, targets: [{{id: it, \
         engine: sqlserver, host: 127.0.0.1, port: {}, account: databastion, \
         secret: {{env: SQLSERVER_DATABASTION_PASSWORD}}, sqlserver: {{ca_file: \"{other_ca}\", \
         {}}}}}]}}",
        state_dir(),
        port(),
        own_tls()
    );
    let t = databastion_core::AgentConfig::parse(&yaml).unwrap().targets[0].clone();
    let h = SqlserverConnector::new().check(&t).await;
    let _ = std::fs::remove_file(&other_ca_path);
    assert!(!h.reachable);
    let detail = h.detail.unwrap();
    assert!(detail.contains("stage tls"), "{detail}");
    assert!(
        detail.contains("did not verify"),
        "a certificate error, not a missing CA file: {detail}"
    );
    // Wrong host name: the dev certificate names localhost and 127.0.0.1
    // only.
    let _ = Detail::FallbackCertificate;
}

/// Measurement gate (refinement item 7, M3): what the minimal and the
/// opt-in accounts read from the credential-bearing list of decision 4.
/// Prints a table for docs/measurements/phase9-engine-facts.md.
#[tokio::test]
async fn measure_credential_bearing_reads() {
    if !enabled() || std::env::var("DATABASTION_IT_SQLSERVER_MEASURE").as_deref() != Ok("1") {
        return;
    }
    let _g = serial().await;
    let mut sa = sa().await;
    throwaway(&mut sa, "it_min", &[]).await;
    throwaway(
        &mut sa,
        "it_vd",
        &[in_db("retail", "GRANT VIEW DEFINITION TO [it_vd]")],
    )
    .await;
    let probes: &[(&str, &str)] = &[
        (
            "sys.sql_logins other rows / hashes",
            "SELECT CONVERT(int, COUNT(*)), CONVERT(int, COUNT(password_hash)) FROM sys.sql_logins WHERE sid <> SUSER_SID()",
        ),
        (
            "LOGINPROPERTY('sa','PasswordHash')",
            "SELECT CONVERT(int, CASE WHEN LOGINPROPERTY('sa', 'PasswordHash') IS NULL THEN 0 ELSE 1 END), 0",
        ),
        (
            "sys.credentials",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM sys.credentials",
        ),
        (
            "retail sys.database_scoped_credentials",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM [retail].sys.database_scoped_credentials",
        ),
        (
            "sys.linked_logins",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM sys.linked_logins",
        ),
        (
            "sys.servers rows / provider_string set",
            "SELECT CONVERT(int, COUNT(*)), CONVERT(int, COUNT(provider_string)) FROM sys.servers",
        ),
        (
            "sys.servers data_source of linked servers",
            "SELECT CONVERT(int, COUNT(data_source)), 0 FROM sys.servers WHERE is_linked = 1",
        ),
        (
            "retail sys.external_data_sources",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM [retail].sys.external_data_sources",
        ),
        (
            "retail sys.column_encryption_key_values",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM [retail].sys.column_encryption_key_values",
        ),
        (
            "retail sys.column_master_keys",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM [retail].sys.column_master_keys",
        ),
        (
            "retail sys.symmetric_keys",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM [retail].sys.symmetric_keys",
        ),
        (
            "retail sys.asymmetric_keys",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM [retail].sys.asymmetric_keys",
        ),
        (
            "master sys.certificates",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM master.sys.certificates",
        ),
        (
            "retail sys.key_encryptions",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM [retail].sys.key_encryptions",
        ),
        (
            "sys.master_key_passwords",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM sys.master_key_passwords",
        ),
        (
            "sys.server_triggers",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM sys.server_triggers",
        ),
        (
            "retail sys.security_policies",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM [retail].sys.security_policies",
        ),
        (
            "retail sys.sql_modules definitions",
            "SELECT CONVERT(int, COUNT(definition)), 0 FROM [retail].sys.sql_modules",
        ),
        (
            "msdb.dbo.sysmail_server",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM msdb.dbo.sysmail_server",
        ),
        (
            "msdb.dbo.sysproxies",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM msdb.dbo.sysproxies",
        ),
        (
            "msdb.dbo.sysssispackages",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM msdb.dbo.sysssispackages",
        ),
        (
            "other sessions in sys.dm_exec_sessions",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM sys.dm_exec_sessions WHERE session_id <> @@SPID",
        ),
        (
            "sys.dm_exec_connections",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM sys.dm_exec_connections",
        ),
        (
            "tier (i) OBJECTPROPERTY TableHasRowLevelSecurity",
            "SELECT CONVERT(int, OBJECTPROPERTY(OBJECT_ID(N'retail.crm.regional_contacts'), 'TableHasRowLevelSecurity')), 0",
        ),
        (
            "tier (i) OBJECTPROPERTYEX TableHasRowLevelSecurity",
            "SELECT CONVERT(int, OBJECTPROPERTYEX(OBJECT_ID(N'retail.crm.regional_contacts'), 'TableHasRowLevelSecurity')), 0",
        ),
        (
            "tier (i) sys.tables columns naming security",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM sys.all_columns WHERE object_id = OBJECT_ID(N'sys.tables') AND (name LIKE N'%security%' OR name LIKE N'%predicate%' OR name LIKE N'%policy%')",
        ),
        (
            "fn_my_permissions SERVER",
            "SELECT CONVERT(int, COUNT(*)), 0 FROM sys.fn_my_permissions(NULL, 'SERVER')",
        ),
    ];
    let c = SqlserverConnector::new();
    for (account, opt) in [("it_min", ""), ("it_vd", "rls_visibility: view_definition")] {
        let t = throwaway_target(account, opt);
        let tls = tls::configs(t.sqlserver_settings().ca_file.as_deref()).unwrap();
        let mut sess = conn::connect(&t, &tls, &TlsChoice::default(), Duration::from_secs(10))
            .await
            .unwrap();
        for (label, sql) in probes {
            let r = sess.rows(sql, Stage::Check, Shape::rows(2, 1)).await;
            let shown = match r {
                Ok(rows) => {
                    let a = rows[0][0]
                        .as_int()
                        .map_or("NULL".to_owned(), |v| v.to_string());
                    let b = rows[0][1]
                        .as_int()
                        .map_or("NULL".to_owned(), |v| v.to_string());
                    format!("{a} / {b}")
                }
                Err(e) => format!("error {:?}", e.number),
            };
            eprintln!("MEASURE | {account} | {label} | {shown}");
        }
        let perms = sess
            .rows(
                "SELECT TOP (100) CONVERT(nvarchar(128), permission_name) FROM sys.fn_my_permissions(NULL, 'SERVER')",
                Stage::Check,
                Shape::rows(1, 100),
            )
            .await
            .unwrap();
        let p: Vec<&str> = perms.iter().filter_map(|r| r[0].as_text()).collect();
        eprintln!("MEASURE | {account} | server permissions | {p:?}");
        let perms = sess
            .rows(
                "SELECT TOP (100) CONVERT(nvarchar(128), permission_name) FROM sys.fn_builtin_permissions(N'DATABASE') WHERE HAS_PERMS_BY_NAME(N'retail', N'DATABASE', permission_name) = 1",
                Stage::Check,
                Shape::rows(1, 100),
            )
            .await
            .unwrap();
        let p: Vec<&str> = perms.iter().filter_map(|r| r[0].as_text()).collect();
        eprintln!("MEASURE | {account} | retail permissions | {p:?}");
        sess.close().await;
        let h = c.check(&t).await;
        eprintln!("MEASURE | {account} | check notes | {:?}", codes(&h));
    }
    drop_login(&mut sa, "it_min").await;
    drop_login(&mut sa, "it_vd").await;
    let _ = Value::Null;
}

/// Security review C1: a table and a column named after the template
/// placeholders, with brackets, quotes and comment openers, are sampled
/// with a statement that differs from the template only by the quoted
/// names.
#[tokio::test]
async fn hostile_names_stay_quoted() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let mut s = sa().await;
    let table = "t{from}]x'--/*";
    let column = "c{dbname}{select}]y'";
    let qt = crate::sql::quote_ident(table).unwrap();
    let qc = crate::sql::quote_ident(column).unwrap();
    exec(
        &mut s,
        &in_db(
            "retail",
            &format!(
                "IF OBJECT_ID(N'crm.{}') IS NOT NULL DROP TABLE crm.{qt}; CREATE TABLE crm.{qt} ({qc} nvarchar(100)); \
                 INSERT INTO crm.{qt} VALUES (N'fake.one@example.com'), (N'fake.two@example.com')",
                qt.replace('\'', "''")
            ),
        ),
    )
    .await;
    let built = crate::sql::sample_statement(
        "retail",
        "crm",
        table,
        &[(column, crate::sql::Sampled::Text)],
        10,
        None,
    )
    .unwrap();
    let benign = crate::sql::sample_statement(
        "retail",
        "crm",
        "x",
        &[("x", crate::sql::Sampled::Text)],
        10,
        None,
    )
    .unwrap();
    assert_eq!(crate::sql::unquoted(&built), crate::sql::unquoted(&benign));
    assert_eq!(
        built,
        benign
            .replace("[x], 4000", &format!("{qc}, 4000"))
            .replace("[crm].[x]", &format!("[crm].{qt}"))
    );
    // The agent samples it: the server parsed the text as one statement.
    let t = agent("rls_visibility: view_definition");
    let tls = tls::configs(t.sqlserver_settings().ca_file.as_deref()).unwrap();
    let mut agent_s = conn::connect(&t, &tls, &TlsChoice::default(), Duration::from_secs(10))
        .await
        .unwrap();
    let rows = agent_s
        .rows(&built, Stage::Sample, Shape::rows(1, 10))
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    agent_s.close().await;
    exec(&mut s, &in_db("retail", &format!("DROP TABLE crm.{qt}"))).await;
}
