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
//! 3): `mandatory` and the `auto` fallback on 2019 and 2022, `strict` and
//! `auto` reaching strict on 2025 with forced strict.
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
    let mut s = conn::connect(&t, &tls, &TlsChoice::default(), Duration::from_secs(30))
        .await
        .unwrap();
    // The test's own statements are off the agent's allow-list.
    s.any_text = true;
    s
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

/// Whether the note `code` carries `label`.
fn has_label(h: &TargetHealth, code: NoteCode, label: &str) -> bool {
    h.notes
        .iter()
        .any(|n| n.code() == code && n.labels().iter().any(|l| l.as_str() == label))
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
    assert!(
        has_label(&h, NoteCode::PrivilegeNotEvaluated, "logon_trigger_probe"),
        "{:?}",
        codes(&h)
    );
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
        // 2019 and 2022 on Linux: no strict encryption. `strict` fails
        // with the local detail, `mandatory` works, `auto` falls back once
        // to `mandatory`, never marks the target, and connects in
        // `mandatory` directly within the hour. (2025 without forced
        // strict is not covered: no CI entry runs it.)
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
            h.reachable,
            "after the server DENY to {grantee}: {:?}",
            h.detail
        );
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
            assert!(
                has_label(
                    &h,
                    NoteCode::PrivilegeRefused,
                    "alter_any_database_event_session"
                ),
                "{:?}",
                codes(&h)
            );
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
        sess.any_text = true;
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

/// A session of `account` that is **not** one of the agent's own for the
/// target `it` (registered under another target id): what someone holding
/// the agent's credentials, or another client, opens.
async fn foreign_session(account: &str, secret_env: &str) -> Session {
    let mut t = target(account, secret_env, own_tls());
    t.id = "it-foreign".to_owned();
    let tls = tls::configs(t.sqlserver_settings().ca_file.as_deref()).unwrap();
    let mut s = conn::connect(&t, &tls, &TlsChoice::default(), Duration::from_secs(30))
        .await
        .unwrap();
    s.any_text = true;
    s
}

/// Rows of `sql` (tests only), errors ignored.
async fn try_rows(s: &mut Session, sql: &str, columns: usize) -> Option<Vec<Vec<Value>>> {
    match s
        .rows(sql, Stage::Check, Shape::rows(columns, 10_000))
        .await
    {
        Ok(r) => Some(r),
        Err(e) => {
            eprintln!("try_rows: {e:?}");
            None
        }
    }
}

/// The audit settings of the dev audit (dev/sqlserver/initdb/30-audit.sql).
const AUDIT: &str = "rls_visibility: view_definition, audit: {source: sqlserver_audit, audit_name: databastion_audit}";

fn names_of(ev: &databastion_classifiers::masking::MaskedEvent) -> Vec<String> {
    ev.objects()
        .iter()
        .map(|o| {
            format!(
                "{}.{}.{}",
                o.database().as_str(),
                o.schema().map_or("-", |s| s.as_str()),
                o.object().as_str()
            )
        })
        .collect()
}

/// The account of an event as the test diagnostics print it (`[it]`
/// lines, shown in CI's failure summary): the login, except for failed
/// logins, whose name tried is never printed.
fn shown_account(e: &databastion_classifiers::masking::MaskedEvent) -> String {
    if e.principal().send_name() {
        e.principal().account_name().to_owned()
    } else {
        "<fingerprinted>".to_owned()
    }
}

/// ADR-0051 decision 6 and refinement item 1 (a'), P9-A lot 2: the SQL
/// Server Audit source end to end against the dev audit. A dump-like read
/// raises a read with `shape.full_table_read`; a failed login, a denied
/// `xp_cmdshell` and credential DCL are reported (the DCL never leaks its
/// password); the agent's own `check()`, Discovery and polls are left
/// out while the same login from another session is reported; no
/// ground-truth value leaves in the events; the position survives a
/// restart of the stream. SQL Server 2019: no source (`CONTROL SERVER`).
#[tokio::test]
async fn audit_reports_reads_and_leaves_the_agents_own_out() {
    // The test's future is large in a debug build: on the heap, not on the
    // test thread's 2 MiB stack.
    Box::pin(audit_scenario()).await;
}

async fn audit_scenario() {
    use databastion_classifiers::masking::{EventAction, MaskedEvent, Signal};
    use databastion_core::AuditLevel;

    if !enabled() {
        return;
    }
    let _g = serial().await;
    let major = Box::pin(major()).await;
    let mut s = Box::pin(sa()).await;
    let c = Arc::new(SqlserverConnector::new());
    let t = agent(&format!("{}, {AUDIT}", own_tls()));
    if major < 16 {
        let h = Box::pin(c.check(&t)).await;
        assert_eq!(h.audit_level, AuditLevel::None);
        assert!(
            has(&h, NoteCode::AuditSqlserverAuditNeedsControlServer),
            "{:?}",
            codes(&h)
        );
        return;
    }
    // Option (a'): the dev account's Audit grants (dev/sqlserver/initdb).
    Box::pin(exec(
        &mut s,
        &in_db(
            "master",
            "GRANT VIEW SERVER SECURITY AUDIT TO databastion; GRANT VIEW ANY SECURITY \
             DEFINITION TO databastion",
        ),
    ))
    .await;
    Box::pin(exec(
        &mut s,
        &in_db("retail", "GRANT VIEW DEFINITION TO databastion"),
    ))
    .await;
    Box::pin(throwaway(&mut s, "it_dump", &[])).await;
    Box::pin(drop_login(&mut s, "it_cred")).await;

    // Before any stream: every proof but a fresh record.
    let h = Box::pin(c.check(&t)).await;
    eprintln!(
        "\n[it] audit, no stream: {:?} {:?}",
        h.audit_level,
        codes(&h)
    );
    assert!(h.reachable, "{:?}", h.detail);
    assert_eq!(h.audit_level, AuditLevel::Limited, "{:?}", codes(&h));
    assert!(has(&h, NoteCode::AuditPartialPendingFirstRecord));
    assert!(has(&h, NoteCode::AuditLogWithoutRowCounts));
    assert!(has(&h, NoteCode::PrivilegeAuditGrantWithoutAudit));
    // ON_FAILURE = CONTINUE in the dev audit: its counter is not read.
    assert!(has(&h, NoteCode::PrivilegeNotEvaluated));
    assert!(c.audit_source(&t).is_some());

    let dir = std::env::temp_dir().join(format!(
        "databastion-sqlserver-audit-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let limits = Limits {
        min_audit_poll_interval_s: 1,
        ..Limits::default()
    };
    let start = |c: &Arc<SqlserverConnector>| {
        let cfg = databastion_core::AuditConfig::local(&t, 1, &limits).with_state_dir(dir.clone());
        let (sink, rx) = databastion_core::EventSink::channel(8192);
        let c2 = Arc::clone(c);
        (
            tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await }),
            rx,
        )
    };
    let (stream, mut rx) = start(&c);
    // The first start skips the audit's history.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!stream.is_finished(), "{:?}", stream.await);

    // The agent's own activity while the stream reads: check() and a
    // Discovery scan (sampling, CAS ticket counts, catalog reads).
    let h = Box::pin(c.check(&t)).await;
    assert!(!has(&h, NoteCode::PrivilegeRefused), "{:?}", codes(&h));
    let scan = {
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
        let (sink, mut frx) = FindingSink::channel(10_000);
        let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
        let r = Box::pin(c.discover(&job, &sink)).await;
        drop(sink);
        drain.await.unwrap();
        r
    };
    scan.unwrap();

    // Someone else: a dump-like read, a read with a ground-truth value in
    // its text, a denied xp_cmdshell.
    let truth = truth();
    let email = truth["locations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["engine"] == "sqlserver")
        .flat_map(|l| l["values"].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(str::to_owned))
        .find(|v| v.contains('@'))
        .expect("a ground-truth e-mail");
    {
        let mut d = Box::pin(foreign_session(
            "it_dump",
            "DATABASTION_IT_SQLSERVER_THROWAWAY",
        ))
        .await;
        Box::pin(try_rows(
            &mut d,
            "SELECT id, customer_id FROM retail.crm.customer_notes",
            2,
        ))
        .await;
        Box::pin(try_rows(
            &mut d,
            &format!(
                "SELECT id FROM retail.crm.customers WHERE email = N'{}'",
                email.replace('\'', "''")
            ),
            1,
        ))
        .await;
        Box::pin(exec_ok(&mut d, "EXEC master.dbo.xp_cmdshell 'whoami'")).await;
        d.close().await;
    }
    // The agent's login from a session that is not the agent's own.
    {
        let mut f = Box::pin(foreign_session(
            "databastion",
            "SQLSERVER_DATABASTION_PASSWORD",
        ))
        .await;
        Box::pin(try_rows(
            &mut f,
            "SELECT TOP (3) email FROM retail.crm.customers",
            1,
        ))
        .await;
        f.close().await;
    }
    // A failed login (the name tried is fingerprinted).
    {
        let mut bad = target(
            "it_no_such_login",
            "DATABASTION_IT_SQLSERVER_THROWAWAY",
            own_tls(),
        );
        bad.id = "it-foreign".to_owned();
        let tls = tls::configs(bad.sqlserver_settings().ca_file.as_deref()).unwrap();
        assert!(
            Box::pin(conn::connect(
                &bad,
                &tls,
                &TlsChoice::default(),
                Duration::from_secs(10)
            ))
            .await
            .is_err()
        );
    }
    // Credential DCL and password-taking calls in forms the server does
    // not mask itself: the marker never leaves the agent.
    let marker = "CredMarker7Zq9xYz";
    Box::pin(drop_login(&mut s, "it_cred2")).await;
    Box::pin(exec(
        &mut s,
        &format!("EXEC sp_addlogin it_cred2, {marker}"),
    ))
    .await;
    Box::pin(exec_ok(&mut s, "DROP CREDENTIAL it_cred_c")).await;
    Box::pin(exec(
        &mut s,
        &format!("CREATE CREDENTIAL it_cred_c WITH IDENTITY = 'i', SECRET = '{marker}'"),
    ))
    .await;
    Box::pin(exec(&mut s, "DROP CREDENTIAL it_cred_c")).await;
    Box::pin(drop_login(&mut s, "it_cred2")).await;
    {
        let mut d = Box::pin(foreign_session(
            "it_dump",
            "DATABASTION_IT_SQLSERVER_THROWAWAY",
        ))
        .await;
        Box::pin(try_rows(
            &mut d,
            &format!(
                "SELECT TOP (1) id FROM retail.crm.customers WHERE \
                 ENCRYPTBYPASSPHRASE('{marker}', N'x') IS NOT NULL"
            ),
            1,
        ))
        .await;
        d.close().await;
    }
    // The server's internal statement of fn_my_permissions, which the
    // agent's own sessions produce, from a session that is not its own.
    {
        let mut f = Box::pin(foreign_session(
            "databastion",
            "SQLSERVER_DATABASTION_PASSWORD",
        ))
        .await;
        Box::pin(try_rows(&mut f, crate::sql::SERVER_PERMISSIONS, 1)).await;
        f.close().await;
    }

    tokio::time::sleep(Duration::from_secs(6)).await;
    let h = Box::pin(c.check(&t)).await;
    eprintln!("[it] audit, streaming: {:?} {:?}", h.audit_level, codes(&h));
    assert_eq!(h.audit_level, AuditLevel::Partial, "{:?}", codes(&h));
    // The source's grants are expected while the stream uses them.
    assert!(!has_label(
        &h,
        NoteCode::PrivilegeAuditGrantWithoutAudit,
        "view_any_security_definition"
    ));
    stream.abort();
    let _ = stream.await;
    let mut events: Vec<MaskedEvent> = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    for e in &events {
        eprintln!(
            "[it] event {:?} {} {:?} {:?} always={}",
            e.action(),
            shown_account(e),
            names_of(e),
            e.signals(),
            e.always_report()
        );
    }
    let by = |who: &str| -> Vec<&MaskedEvent> {
        events
            .iter()
            .filter(|e| e.principal().account_name().eq_ignore_ascii_case(who))
            .collect()
    };
    // The dump-like read.
    let dump = by("it_dump");
    assert!(
        dump.iter().any(|e| e.action() == EventAction::Read
            && names_of(e).contains(&"retail.crm.customer_notes".to_owned())
            && e.signals().contains(&Signal::FullTableRead)),
        "no whole-table read reported"
    );
    // The denied xp_cmdshell.
    assert!(
        dump.iter()
            .any(|e| e.signals().contains(&Signal::RemoteDataAccess) && e.always_report()),
        "no remote data access reported"
    );
    // The failed login, fingerprinted.
    assert!(
        events.iter().any(|e| e.action() == EventAction::AuthFailure
            && !e.principal().send_name()
            && e.principal().account_name() == "it_no_such_login"),
        "no failed login reported"
    );
    // The credential DCL, by `sa`.
    assert!(
        by("sa").iter().any(|e| e.action() == EventAction::Dcl),
        "no DCL reported"
    );
    // The agent's login: only the foreign sessions' statements (their
    // session read-backs, a read, and the agent's own permission read with
    // the statement the server runs inside fn_my_permissions: constants of
    // the agent, but from sessions that are not its own), nothing of the
    // agent's own check(), Discovery or polls.
    let agent_events = by("databastion");
    assert!(
        agent_events
            .iter()
            .any(|e| names_of(e) == ["retail.crm.customers"]),
        "the agent's login from another session must be reported"
    );
    assert!(
        agent_events
            .iter()
            .any(|e| names_of(e) == ["master.sys.fn_builtin_permissions"]),
        "the server's internal statement from another session must be reported"
    );
    for e in &agent_events {
        assert!(
            [
                vec!["retail.crm.customers".to_owned()],
                vec!["master.sys.dm_exec_sessions".to_owned()],
                vec!["master.sys.fn_builtin_permissions".to_owned()],
                vec!["master.sys.fn_my_permissions".to_owned()],
            ]
            .contains(&names_of(e))
                && e.action() == EventAction::Read,
            "an own statement reported: {:?} {:?}",
            e.action(),
            names_of(e)
        );
    }
    assert!(agent_events.len() <= 6, "own statements reported");
    // Not vacuous: the agent's own catalog reads, sampling and polls were
    // in the audit and were left out.
    let [exact, sampling, polls, _statistics] = c.state.audit.own_left_out(&t.id);
    eprintln!("[it] own left out: exact {exact}, sampling {sampling}, polls {polls}");
    assert!(
        exact > 10 && sampling >= 5 && polls >= 2,
        "{exact} {sampling} {polls}"
    );
    // I2: no ground-truth value, nor the DCL password, in what is sent.
    let json = databastion_core::test_support::contract_events_json(&events, &key());
    assert!(json.contains("\"source\":\"sqlserver_audit\""), "{json}");
    assert!(!json.contains(marker), "credential DCL leaked");
    assert!(
        !json.contains("it_no_such_login"),
        "failed login name in clear"
    );
    for loc in truth["locations"].as_array().unwrap() {
        for v in loc["values"].as_array().into_iter().flatten() {
            if let Some(v) = v.as_str().filter(|v| v.len() >= 6) {
                assert!(!json.contains(v), "a ground-truth value in the events");
            }
        }
    }

    // A restart of the stream: the position is kept, nothing already
    // read is reported again.
    let (stream, mut rx) = start(&c);
    tokio::time::sleep(Duration::from_secs(5)).await;
    stream.abort();
    let _ = stream.await;
    let mut again = Vec::new();
    while let Ok(e) = rx.try_recv() {
        again.push(e);
    }
    for e in &again {
        eprintln!(
            "[it] after restart {:?} {} {:?}",
            e.action(),
            shown_account(e),
            names_of(e)
        );
    }
    assert!(
        !again
            .iter()
            .any(|e| e.principal().account_name().eq_ignore_ascii_case("it_dump")),
        "events reported twice after a restart"
    );
    assert!(
        !again.iter().any(|e| e
            .principal()
            .account_name()
            .eq_ignore_ascii_case("databastion")),
        "the agent's own statements reported after a restart"
    );
    Box::pin(drop_login(&mut s, "it_dump")).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// P9-A obligation L4: the closed list of `sys` built-in functions
/// (`classifiers::query::tsql::SYS_FUNCTIONS`) holds every function of
/// the server's `sys` schema, so a schema-qualified call of a built-in is
/// never taken for user code (a missing name only reports more, but the
/// list must follow the matrix images).
#[tokio::test]
async fn sys_function_list_matches_the_server() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let mut s = sa().await;
    let rows = s
        .rows(
            "SELECT CONVERT(nvarchar(128), LOWER(name)) FROM sys.all_objects WHERE schema_id = \
             SCHEMA_ID('sys') AND type IN ('FN', 'IF', 'TF', 'FS', 'FT', 'AF')",
            Stage::Check,
            Shape::rows(1, 4096),
        )
        .await
        .unwrap();
    let list = databastion_classifiers::query::tsql::SYS_FUNCTIONS;
    let missing: Vec<String> = rows
        .iter()
        .filter_map(|r| r.first().and_then(Value::as_text).map(str::to_owned))
        .filter(|n| !list.contains(&n.as_str()))
        .collect();
    assert!(rows.len() > 100, "{}", rows.len());
    assert!(
        missing.is_empty(),
        "sys functions not in SYS_FUNCTIONS: {missing:?}"
    );
}

/// The Extended Events settings of the dev session
/// (dev/sqlserver/initdb/30-audit.sql).
const XE: &str = "rls_visibility: view_definition, audit: {source: sqlserver_xevents, xe_session: databastion_xe}";

/// ADR-0051 decision 6, P9-A lot 3: the Extended Events source end to end
/// against the dev session (the only Audit source on SQL Server 2019). A
/// dump-like read raises a read of the table with `shape.full_table_read`
/// and its row count; a failed login is fingerprinted; credential DCL and
/// password-taking calls never leak their marker; the agent's own
/// `check()`, Discovery and polls are left out while the same login from
/// another session is reported; no ground-truth value leaves in the
/// events; the position survives a restart of the stream.
#[tokio::test]
async fn xe_reports_reads_and_leaves_the_agents_own_out() {
    Box::pin(xe_scenario()).await;
}

#[allow(clippy::too_many_lines)]
async fn xe_scenario() {
    use databastion_classifiers::masking::{EventAction, MaskedEvent, Signal};
    use databastion_core::AuditLevel;

    if !enabled() {
        return;
    }
    let _g = serial().await;
    let major = Box::pin(major()).await;
    let mut s = Box::pin(sa()).await;
    let c = Arc::new(SqlserverConnector::new());
    let t = agent(&format!("{}, {XE}", own_tls()));
    // The Extended Events grant of decision 4 (the dev account holds it on
    // 2019 already).
    let grant = if major >= 16 {
        "VIEW SERVER PERFORMANCE STATE"
    } else {
        "VIEW SERVER STATE"
    };
    Box::pin(exec(
        &mut s,
        &in_db("master", &format!("GRANT {grant} TO databastion")),
    ))
    .await;
    Box::pin(exec(
        &mut s,
        &in_db("retail", "GRANT VIEW DEFINITION TO databastion"),
    ))
    .await;
    Box::pin(throwaway(&mut s, "it_xdump", &[])).await;

    // `source: auto` with both sources named: SQL Server Audit when usable
    // (2022+ with its grants), else the session (2019: CONTROL SERVER).
    {
        let c2 = SqlserverConnector::new();
        let both = agent(&format!(
            "{}, rls_visibility: view_definition, audit: {{audit_name: databastion_audit, \
             xe_session: databastion_xe}}",
            own_tls()
        ));
        let h = Box::pin(c2.check(&both)).await;
        eprintln!(
            "[it] xe, auto: {:?} {:?}",
            c2.audit_source(&both),
            codes(&h)
        );
        if major < 16 {
            assert_eq!(
                c2.audit_source(&both),
                Some(databastion_classifiers::masking::EventSource::SqlserverXevents)
            );
            assert!(has(&h, NoteCode::AuditSqlserverAuditNeedsControlServer));
        } else {
            assert_eq!(
                c2.audit_source(&both),
                Some(databastion_classifiers::masking::EventSource::SqlserverAudit)
            );
        }
    }
    let h = Box::pin(c.check(&t)).await;
    eprintln!("\n[it] xe, no stream: {:?} {:?}", h.audit_level, codes(&h));
    assert!(h.reachable, "{:?}", h.detail);
    assert_eq!(h.audit_level, AuditLevel::Limited, "{:?}", codes(&h));
    assert!(has(&h, NoteCode::AuditPartialPendingFirstRecord));
    assert!(!has(&h, NoteCode::AuditXeEventsMissing), "{:?}", codes(&h));
    assert!(!has(&h, NoteCode::AuditXeSessionFiltered));
    assert!(!has(&h, NoteCode::AuditXeCausalityOff));
    assert!(!has(&h, NoteCode::AuditLogWithoutRowCounts));
    assert_eq!(
        c.audit_source(&t),
        Some(databastion_classifiers::masking::EventSource::SqlserverXevents)
    );

    // Statistics the agent's own reads make the server build (on system
    // base tables, measured on a fresh 2025 server) are server statements
    // in the agent's sessions that no own rule covers (refinement item 4
    // pairs a build with a statement naming the same table only): built
    // before the stream starts, so the test checks the agent's routine
    // statements on a server that has them (see the lot 3 implementation
    // notes of ADR-0051).
    {
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
        let (sink, mut frx) = FindingSink::channel(10_000);
        let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
        Box::pin(c.discover(&job, &sink)).await.unwrap();
        drop(sink);
        drain.await.unwrap();
    }
    let dir = std::env::temp_dir().join(format!("databastion-sqlserver-xe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let limits = Limits {
        min_audit_poll_interval_s: 1,
        ..Limits::default()
    };
    let start = |c: &Arc<SqlserverConnector>| {
        let cfg = databastion_core::AuditConfig::local(&t, 1, &limits).with_state_dir(dir.clone());
        let (sink, rx) = databastion_core::EventSink::channel(8192);
        let c2 = Arc::clone(c);
        (
            tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await }),
            rx,
        )
    };
    let (stream, mut rx) = start(&c);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!stream.is_finished(), "{:?}", stream.await);

    // The agent's own activity while the stream reads.
    let h = Box::pin(c.check(&t)).await;
    assert!(!has(&h, NoteCode::PrivilegeRefused), "{:?}", codes(&h));
    {
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
        let (sink, mut frx) = FindingSink::channel(10_000);
        let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
        Box::pin(c.discover(&job, &sink)).await.unwrap();
        drop(sink);
        drain.await.unwrap();
    }

    // Someone else.
    let truth = truth();
    let email = truth["locations"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["engine"] == "sqlserver")
        .flat_map(|l| l["values"].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(str::to_owned))
        .find(|v| v.contains('@'))
        .expect("a ground-truth e-mail");
    let marker = "XeCredMarker7Zq9";
    {
        let mut d = Box::pin(foreign_session(
            "it_xdump",
            "DATABASTION_IT_SQLSERVER_THROWAWAY",
        ))
        .await;
        Box::pin(try_rows(
            &mut d,
            "SELECT id, customer_id FROM retail.crm.customer_notes",
            2,
        ))
        .await;
        Box::pin(try_rows(
            &mut d,
            &format!(
                "SELECT id FROM retail.crm.customers WHERE email = N'{}'",
                email.replace('\'', "''")
            ),
            1,
        ))
        .await;
        // A parameterized read (an ORM's RPC): its inner statement keeps
        // its table.
        Box::pin(d.rpc(
            "SELECT TOP (1) id FROM retail.crm.customers WHERE email = @p1",
            &[crate::tds::Param::NVarChar(email.clone())],
            Stage::Check,
            Shape::rows(1, 10),
            |_| conn::Flow::Continue,
        ))
        .await
        .unwrap();
        Box::pin(exec_ok(&mut d, "EXEC master.dbo.xp_cmdshell 'whoami'")).await;
        Box::pin(try_rows(
            &mut d,
            &format!(
                "SELECT TOP (1) id FROM retail.crm.customers WHERE \
                 ENCRYPTBYPASSPHRASE('{marker}', N'x') IS NOT NULL"
            ),
            1,
        ))
        .await;
        d.close().await;
    }
    // The agent's login from a session that is not the agent's own.
    {
        let mut f = Box::pin(foreign_session(
            "databastion",
            "SQLSERVER_DATABASTION_PASSWORD",
        ))
        .await;
        Box::pin(try_rows(
            &mut f,
            "SELECT TOP (3) email FROM retail.crm.customers",
            1,
        ))
        .await;
        Box::pin(try_rows(&mut f, crate::sql::SERVER_PERMISSIONS, 1)).await;
        f.close().await;
    }
    // A failed login.
    {
        let mut bad = target(
            "it_no_such_xlogin",
            "DATABASTION_IT_SQLSERVER_THROWAWAY",
            own_tls(),
        );
        bad.id = "it-foreign".to_owned();
        let tls = tls::configs(bad.sqlserver_settings().ca_file.as_deref()).unwrap();
        assert!(
            Box::pin(conn::connect(
                &bad,
                &tls,
                &TlsChoice::default(),
                Duration::from_secs(10)
            ))
            .await
            .is_err()
        );
    }
    // Credential DCL in forms the server does not mask itself.
    Box::pin(drop_login(&mut s, "it_xcred")).await;
    Box::pin(exec(
        &mut s,
        &format!("EXEC sp_addlogin it_xcred, {marker}"),
    ))
    .await;
    Box::pin(exec_ok(&mut s, "DROP CREDENTIAL it_xcred_c")).await;
    Box::pin(exec(
        &mut s,
        &format!("CREATE CREDENTIAL it_xcred_c WITH IDENTITY = 'i', SECRET = '{marker}'"),
    ))
    .await;
    Box::pin(exec(&mut s, "DROP CREDENTIAL it_xcred_c")).await;
    Box::pin(drop_login(&mut s, "it_xcred")).await;

    // The session's dispatch latency is 5 s.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let h = Box::pin(c.check(&t)).await;
    eprintln!("[it] xe, streaming: {:?} {:?}", h.audit_level, codes(&h));
    assert_eq!(h.audit_level, AuditLevel::Partial, "{:?}", codes(&h));
    // The source's grant is expected while the stream uses it.
    let label = grant.to_lowercase().replace(' ', "_");
    assert!(
        !has_label(&h, NoteCode::PrivilegeAuditGrantWithoutAudit, &label),
        "{:?}",
        codes(&h)
    );
    stream.abort();
    let _ = stream.await;
    let mut events: Vec<MaskedEvent> = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    for e in &events {
        eprintln!(
            "[it] xe event {:?} {} {:?} {:?} rows={:?} always={}",
            e.action(),
            shown_account(e),
            names_of(e),
            e.signals(),
            e.rows(),
            e.always_report()
        );
    }
    let by = |who: &str| -> Vec<&MaskedEvent> {
        events
            .iter()
            .filter(|e| e.principal().account_name().eq_ignore_ascii_case(who))
            .collect()
    };
    let dump = by("it_xdump");
    assert!(
        dump.iter().any(|e| e.action() == EventAction::Read
            && names_of(e) == ["retail.crm.customer_notes"]
            && e.signals().contains(&Signal::FullTableRead)
            && e.rows().is_some()),
        "no whole-table read reported"
    );
    assert!(
        dump.iter()
            .filter(|e| names_of(e) == ["retail.crm.customers"])
            .count()
            >= 2,
        "the filtered read and the parameterized RPC must name their table"
    );
    // The ENCRYPTBYPASSPHRASE read: recorded by the server as `-- SELECT`
    // (measured on 2019), a read of `*`, always reported. The refused
    // xp_cmdshell leaves no statement event (measured on 2019).
    assert!(
        dump.iter().any(|e| e.action() == EventAction::Read
            && e.always_report()
            && names_of(e) == ["master.-.*"]),
        "the password-taking read must be reported"
    );
    assert!(
        events.iter().any(|e| e.action() == EventAction::AuthFailure
            && !e.principal().send_name()
            && e.principal().account_name() == "it_no_such_xlogin"),
        "no failed login reported"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.action() == EventAction::AuthFailure
                && e.principal().account_name() == "it_no_such_xlogin")
            .count(),
        1,
        "a failed login is counted once"
    );
    assert!(
        by("sa").iter().any(|e| e.action() == EventAction::Dcl),
        "no DCL reported"
    );
    // The agent's login: only the foreign session's statements.
    let agent_events = by("databastion");
    assert!(
        agent_events
            .iter()
            .any(|e| names_of(e) == ["retail.crm.customers"]),
        "the agent's login from another session must be reported"
    );
    for e in &agent_events {
        let ok = e.action() == EventAction::Read
            && names_of(e).iter().all(|n| {
                n == "retail.crm.customers"
                    || n.ends_with(".sys.dm_exec_sessions")
                    || n.ends_with(".sys.fn_my_permissions")
                    || n.ends_with(".sys.fn_builtin_permissions")
            });
        assert!(
            ok,
            "an own statement reported: {:?} {:?}",
            e.action(),
            names_of(e)
        );
    }
    assert!(agent_events.len() <= 6, "own statements reported");
    // The agent's sessions were read on the event clock (CI failure of
    // PR #251).
    let calibrated = crate::audit::own::calibrated(&t.id);
    eprintln!("[it] xe: sessions calibrated on the event clock {calibrated}");
    assert!(calibrated > 0);
    let [exact, sampling, polls, _statistics] = c.state.audit.own_left_out(&t.id);
    eprintln!("[it] xe own left out: exact {exact}, sampling {sampling}, polls {polls}");
    assert!(
        exact > 10 && sampling >= 5 && polls >= 2,
        "{exact} {sampling} {polls}"
    );
    // I2.
    let json = databastion_core::test_support::contract_events_json(&events, &key());
    assert!(json.contains("\"source\":\"sqlserver_xevents\""), "{json}");
    assert!(!json.contains(marker), "credential DCL leaked");
    assert!(
        !json.contains("it_no_such_xlogin"),
        "failed login name in clear"
    );
    for loc in truth["locations"].as_array().unwrap() {
        for v in loc["values"].as_array().into_iter().flatten() {
            if let Some(v) = v.as_str().filter(|v| v.len() >= 6) {
                assert!(!json.contains(v), "a ground-truth value in the events");
            }
        }
    }

    // A restart of the stream: the position is kept.
    let (stream, mut rx) = start(&c);
    tokio::time::sleep(Duration::from_secs(5)).await;
    stream.abort();
    let _ = stream.await;
    let mut again = Vec::new();
    while let Ok(e) = rx.try_recv() {
        again.push(e);
    }
    for e in &again {
        eprintln!(
            "[it] xe after restart {:?} {} {:?}",
            e.action(),
            shown_account(e),
            names_of(e)
        );
    }
    assert!(
        !again.iter().any(|e| e
            .principal()
            .account_name()
            .eq_ignore_ascii_case("it_xdump")),
        "events reported twice after a restart"
    );
    assert!(
        !again.iter().any(|e| e
            .principal()
            .account_name()
            .eq_ignore_ascii_case("databastion")),
        "the agent's own statements reported after a restart"
    );
    // The operator stops and starts the session (decision 6, "Position and
    // gaps"): whatever happened in between was not recorded, a gap.
    Box::pin(exec(
        &mut s,
        "ALTER EVENT SESSION databastion_xe ON SERVER STATE = STOP",
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    Box::pin(exec(
        &mut s,
        "ALTER EVENT SESSION databastion_xe ON SERVER STATE = START",
    ))
    .await;
    let (stream, _rx) = start(&c);
    tokio::time::sleep(Duration::from_secs(4)).await;
    let h = Box::pin(c.check(&t)).await;
    eprintln!(
        "[it] xe, after a session restart: {:?} {:?}",
        h.audit_level,
        codes(&h)
    );
    stream.abort();
    let _ = stream.await;
    assert_eq!(h.audit_level, AuditLevel::Limited, "{:?}", codes(&h));
    assert!(has(&h, NoteCode::AuditRecordsDropped), "{:?}", codes(&h));
    Box::pin(drop_login(&mut s, "it_xdump")).await;
    if major >= 16 {
        Box::pin(exec(
            &mut s,
            &in_db("master", &format!("REVOKE {grant} FROM databastion")),
        ))
        .await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Measurement (not a check; `DATABASTION_IT_SQLSERVER_MEASURE=1`): the
/// skew between the time a source stamps a statement with (SQL Server
/// Audit `event_time`, Extended Events `timestamp_utc`) and the server's
/// `SYSUTCDATETIME()` read just before and just after the statement on the
/// same session (lot 2 follow-up: the own-session clean end is computed on
/// `SYSUTCDATETIME()`). Prints the largest overshoot past the "after" time
/// and the largest lead before the "before" time, in microseconds. Run as
/// `sa` (2019: reading the audit needs `CONTROL SERVER`).
#[tokio::test]
async fn measure_event_time_skew() {
    if !enabled() || std::env::var("DATABASTION_IT_SQLSERVER_MEASURE").as_deref() != Ok("1") {
        return;
    }
    let _g = serial().await;
    let mut s = Box::pin(sa()).await;
    let now = "SELECT CONVERT(bigint, DATEDIFF_BIG(microsecond, '19700101', SYSUTCDATETIME()))";
    let tag = std::process::id();
    let mut spans = Vec::new();
    for i in 0..200u32 {
        let t0 = s.rows(now, Stage::Check, Shape::rows(1, 1)).await.unwrap()[0][0]
            .as_int()
            .unwrap();
        let q = format!("SELECT TOP (1) id FROM retail.crm.customers WHERE id = -{tag}{i:03}");
        s.rows(&q, Stage::Check, Shape::rows(1, 1)).await.unwrap();
        let t1 = s.rows(now, Stage::Check, Shape::rows(1, 1)).await.unwrap()[0][0]
            .as_int()
            .unwrap();
        spans.push((format!("-{tag}{i:03}"), t0, t1));
    }
    tokio::time::sleep(Duration::from_secs(8)).await;
    let like = format!("%WHERE id = -{tag}%");
    let sources = [
        (
            "sqlserver_audit",
            format!(
                "SELECT TOP (1000) CONVERT(bigint, DATEDIFF_BIG(microsecond, '19700101', event_time)), \
                 CONVERT(nvarchar(200), statement) FROM sys.fn_get_audit_file(N'/var/opt/mssql/audit/*.sqlaudit', \
                 NULL, NULL) WHERE statement LIKE N'{like}'"
            ),
        ),
        (
            "sqlserver_xevents",
            format!(
                "SELECT TOP (1000) CONVERT(bigint, DATEDIFF_BIG(microsecond, '19700101', timestamp_utc)), \
                 CONVERT(nvarchar(200), SUBSTRING(event_data, CHARINDEX(N'WHERE id = -', event_data), 40)) \
                 FROM sys.fn_xe_file_target_read_file(N'/var/opt/mssql/xe/databastion_xe_0_*.xel', NULL, NULL, \
                 NULL) WHERE object_name = N'sql_statement_completed' AND event_data LIKE N'{like}'"
            ),
        ),
    ];
    for (name, sql) in sources {
        let Some(rows) = try_rows(&mut s, &sql, 2).await else {
            eprintln!("[it] skew {name}: not readable");
            continue;
        };
        let (mut over, mut lead, mut n) = (i64::MIN, i64::MIN, 0);
        for r in &rows {
            let at = r[0].as_int().unwrap();
            let text = r[1].as_text().unwrap_or_default();
            if let Some((_, t0, t1)) = spans.iter().find(|(k, _, _)| {
                text.contains(&format!("= {k}")) && !text.contains(&format!("= {k}0"))
            }) {
                over = over.max(at - t1);
                lead = lead.max(t0 - at);
                n += 1;
            }
        }
        eprintln!(
            "[it] skew {name}: {n} statements, largest overshoot past the next SYSUTCDATETIME() {over} us, largest lead before the previous one {lead} us"
        );
    }
}

/// Runs an Extended Events stream of `t` (state in `dir`) while `work`
/// runs, then 12 s more (the dev session's dispatch latency is 5 s), and
/// returns its events.
async fn xe_stream_around<F: std::future::Future<Output = ()>>(
    c: &Arc<SqlserverConnector>,
    t: &TargetConfig,
    dir: &std::path::Path,
    work: F,
) -> Vec<databastion_classifiers::masking::MaskedEvent> {
    let limits = Limits {
        min_audit_poll_interval_s: 1,
        ..Limits::default()
    };
    let cfg = databastion_core::AuditConfig::local(t, 1, &limits).with_state_dir(dir.to_path_buf());
    let (sink, mut rx) = databastion_core::EventSink::channel(8192);
    let c2 = Arc::clone(c);
    let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!stream.is_finished(), "{:?}", stream.await);
    work.await;
    tokio::time::sleep(Duration::from_secs(12)).await;
    stream.abort();
    let _ = stream.await;
    let mut events = Vec::new();
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    events
}

/// The Extended Events grant of the server's version, granted to the dev
/// account for a test (2019: held already).
async fn xe_grant(s: &mut Session, major: u32) -> &'static str {
    let grant = if major >= 16 {
        "VIEW SERVER PERFORMANCE STATE"
    } else {
        "VIEW SERVER STATE"
    };
    Box::pin(exec(
        s,
        &in_db("master", &format!("GRANT {grant} TO databastion")),
    ))
    .await;
    Box::pin(exec(
        s,
        &in_db("retail", "GRANT VIEW DEFINITION TO databastion"),
    ))
    .await;
    grant
}

/// ADR-0051 refinement of 2026-10-15, case 1 and the drift test of item 4:
/// a first read of a column by a client makes the server build statistics
/// (`StatMan`) followed by its internal statements; on the allow-listed
/// image, with causality, the build and its internal statements are left
/// out, and the client's read alone is reported. With
/// `DATABASTION_IT_SQLSERVER_CAPTURE=<file>`, the session's events of that
/// activity are written to `<file>` (the unit fixtures, fake data only).
#[tokio::test]
async fn xe_statistics_builds_match_the_fixture() {
    Box::pin(xe_statistics_scenario()).await;
}

async fn xe_statistics_scenario() {
    use databastion_classifiers::masking::EventAction;

    if !enabled() {
        return;
    }
    let _g = serial().await;
    let major = Box::pin(major()).await;
    let mut s = Box::pin(sa()).await;
    let c = Arc::new(SqlserverConnector::new());
    let t = agent(&format!("{}, {XE}", own_tls()));
    let grant = Box::pin(xe_grant(&mut s, major)).await;
    let table = format!("it_stats_{}", std::process::id());
    Box::pin(exec(
        &mut s,
        &in_db(
            "retail",
            &format!(
                "CREATE TABLE crm.{table} (id int, v int); INSERT INTO crm.{table} \
                 SELECT TOP (500) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)), 7 FROM sys.all_objects"
            ),
        ),
    ))
    .await;
    Box::pin(throwaway(&mut s, "it_xstats", &[])).await;
    // Statistics of the agent's own reads first (pre-warm).
    let _ = Box::pin(c.check(&t)).await;
    let dir = std::env::temp_dir().join(format!(
        "databastion-sqlserver-xestats-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A first read of a column in a batch (the build at nest level 2),
    // then of another column inside `sp_executesql` (nest level 3).
    let q = format!("SELECT TOP (5) id FROM retail.crm.{table} WHERE v = 3");
    let q3 = format!("EXEC sp_executesql N'SELECT TOP (5) v FROM retail.crm.{table} WHERE id = 3'");
    let events = Box::pin(xe_stream_around(&c, &t, &dir, async {
        let mut d = Box::pin(foreign_session(
            "it_xstats",
            "DATABASTION_IT_SQLSERVER_THROWAWAY",
        ))
        .await;
        Box::pin(try_rows(&mut d, &q, 1)).await;
        Box::pin(try_rows(&mut d, &q3, 1)).await;
        d.close().await;
    }))
    .await;
    let mine: Vec<_> = events
        .iter()
        .filter(|e| {
            e.principal()
                .account_name()
                .eq_ignore_ascii_case("it_xstats")
        })
        .collect();
    for e in &mine {
        eprintln!(
            "[it] xe statistics event {:?} {:?} always={}",
            e.action(),
            names_of(e),
            e.always_report()
        );
    }
    let [_, _, _, statistics] = c.state.audit.own_left_out(&t.id);
    eprintln!("[it] xe statistics statements left out: {statistics}");
    if let Ok(path) = std::env::var("DATABASTION_IT_SQLSERVER_CAPTURE") {
        let rows = try_rows(
            &mut s,
            "SELECT TOP (64) CONVERT(nvarchar(4000), event_data) FROM \
             sys.fn_xe_file_target_read_file(N'/var/opt/mssql/xe/databastion_xe_0_*.xel', NULL, NULL, NULL) \
             WHERE event_data LIKE N'%it[_]xstats%' AND object_name = N'sp_statement_completed' \
             OR (event_data LIKE N'%it[_]stats[_]%' AND event_data LIKE N'%it[_]xstats%')",
            1,
        )
        .await
        .unwrap_or_default();
        let lines: Vec<String> = rows
            .iter()
            .filter_map(|r| {
                r.first()
                    .and_then(Value::as_text)
                    .map(|x| x.replace('\n', " "))
            })
            .collect();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    }
    let reads = mine
        .iter()
        .filter(|e| {
            e.action() == EventAction::Read && names_of(e) == [format!("retail.crm.{table}")]
        })
        .count();
    assert_eq!(
        reads, 2,
        "the builds are left out: the client's two reads alone name the table"
    );
    // The builds' internal statements, at the build's nest level minus one
    // (case 1 as revised on 2026-10-16): left out at both depths.
    let others: Vec<_> = mine
        .iter()
        .filter(|e| {
            names_of(e) != [format!("retail.crm.{table}")]
                && !names_of(e)
                    .iter()
                    .all(|n| n.ends_with(".sys.dm_exec_sessions"))
        })
        .collect();
    // One: the batch `EXEC sp_executesql N'…'` itself, in the session's
    // database `master` (dynamic SQL in text: `*`, always reported); no
    // internal statement.
    assert_eq!(others.len(), 1, "{} other events", others.len());
    for e in &others {
        assert!(
            e.action() == EventAction::Read && e.always_report() && names_of(e) == ["master.-.*"],
            "an unexpected event: {:?} {:?}",
            e.action(),
            names_of(e)
        );
    }
    eprintln!(
        "[it] xe statistics: other events {} (major {major})",
        others.len()
    );
    assert!(
        statistics >= 4,
        "the builds and their internal statements are left out: {statistics}"
    );
    Box::pin(drop_login(&mut s, "it_xstats")).await;
    Box::pin(exec(
        &mut s,
        &in_db("retail", &format!("DROP TABLE crm.{table}")),
    ))
    .await;
    if major >= 16 {
        Box::pin(exec(
            &mut s,
            &in_db("master", &format!("REVOKE {grant} FROM databastion")),
        ))
        .await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// ADR-0051 refinement of 2026-10-15, case 2: on a **fresh** server (no
/// statistics built yet; `DATABASTION_IT_SQLSERVER_FRESH=1`, run first on a
/// new data volume), the agent's own `check()` and Discovery make the server
/// build statistics on system base tables in its sessions; they are left
/// out with their internal statements of the accepted shape. The two
/// measured residuals (internal statements at nest level 1 under builds at nest level 2, and a
/// build whose catalog statement comes in a later read) are tolerated and
/// counted; nothing else of the agent's is reported. On 2022 and later, a
/// `check()` naming an audit as well (`source: auto`, as an operator may
/// configure it while the stream reads the session) sends the
/// `audit_file` proof, whose build on `sys.sysguidrefs` is left out too
/// (the addendum of 2026-10-16). With
/// `DATABASTION_IT_SQLSERVER_CAPTURE=<file>`, the events of that build's
/// activity are written to `<file>` (the unit fixtures, fake data only).
#[tokio::test]
async fn xe_fresh_server_own_reads_raise_no_event() {
    Box::pin(xe_fresh_scenario()).await;
}

async fn xe_fresh_scenario() {
    if !enabled() || std::env::var("DATABASTION_IT_SQLSERVER_FRESH").as_deref() != Ok("1") {
        return;
    }
    let _g = serial().await;
    let mut s = Box::pin(sa()).await;
    let major = {
        let c = SqlserverConnector::new();
        let t = agent("");
        let _ = Box::pin(c.check(&t)).await;
        c.server_version(&t)
            .and_then(|v| v.split('.').next().and_then(|m| m.parse::<u32>().ok()))
            .unwrap()
    };
    let grant = Box::pin(xe_grant(&mut s, major)).await;
    let c = Arc::new(SqlserverConnector::new());
    let t = agent(&format!("{}, {XE}", own_tls()));
    let dir = std::env::temp_dir().join(format!(
        "databastion-sqlserver-xefresh-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // The same target naming an audit too: its `check()` sends the
    // `audit_file` proof (2022 and later). The own-session registry is
    // keyed by the target id, as for one agent's check and stream. The
    // audit does not exist, so the proof stops there. A third `check()`
    // names the dev service's audit: its next proof
    // (`audit_specifications`) builds statistics on `sys.sysaudacts`
    // (measured on 2022 on 2026-10-16), on case 2's list since 2026-10-18.
    let t_spec = agent(&format!(
        "{}, rls_visibility: view_definition, audit: {{source: auto, audit_name: databastion_audit, \
         xe_session: databastion_xe}}",
        own_tls()
    ));
    let t_audit = agent(&format!(
        "{}, rls_visibility: view_definition, audit: {{source: auto, audit_name: it_no_such_audit, \
         xe_session: databastion_xe}}",
        own_tls()
    ));
    let events = Box::pin(xe_stream_around(&c, &t, &dir, async {
        let _ = Box::pin(c.check(&t)).await;
        let _ = Box::pin(SqlserverConnector::new().check(&t_audit)).await;
        let _ = Box::pin(SqlserverConnector::new().check(&t_spec)).await;
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
        let (sink, mut frx) = FindingSink::channel(10_000);
        let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
        Box::pin(c.discover(&job, &sink)).await.unwrap();
        drop(sink);
        drain.await.unwrap();
    }))
    .await;
    let own: Vec<_> = events
        .iter()
        .filter(|e| {
            e.principal()
                .account_name()
                .eq_ignore_ascii_case("databastion")
        })
        .collect();
    for e in &own {
        eprintln!(
            "[it] xe fresh: own event reported {:?} {:?}",
            e.action(),
            names_of(e)
        );
    }
    let [exact, _, _, statistics] = c.state.audit.own_left_out(&t.id);
    eprintln!("[it] xe fresh: exact {exact}, statistics statements left out {statistics}");
    // What can remain (ADR-0051 refinement of 2026-10-16): a build on a
    // credential-bearing base table (`sysowners`, `sysxlgns`: reported by
    // decision, item 3), and a build whose catalog statement reached the
    // file only after the bounded deferral (item 4). No internal statement
    // (item 2), no other own statement, no other table.
    let mut internal = 0;
    let mut unpaired = 0;
    let mut credential = 0;
    for e in &own {
        let names = names_of(e);
        if e.always_report() && names.iter().all(|n| n.ends_with(".-.*")) {
            internal += 1;
        } else if names
            .iter()
            .all(|n| matches!(n.as_str(), "retail.sys.sysowners" | "retail.sys.sysxlgns"))
        {
            credential += 1;
        } else if names.iter().all(|n| {
            n.strip_prefix("retail.sys.")
                .or_else(|| n.strip_prefix("master.sys."))
                .is_some_and(|t| crate::audit::xe::events::SYS_BASE_TABLES.contains(&t))
        }) {
            unpaired += 1;
        } else {
            panic!("the agent's own reads raised an event on a fresh server: {names:?}");
        }
    }
    eprintln!(
        "[it] xe fresh: internal statements reported {internal}, builds unpaired {unpaired}, \
         credential tables {credential}"
    );
    assert_eq!(
        internal, 0,
        "internal statements of the builds are left out"
    );
    assert!(
        statistics > 0,
        "not a fresh server: no statistics build was seen"
    );
    if major >= 16 {
        Box::pin(xe_fresh_sysguidrefs(&mut s, &own)).await;
        Box::pin(exec(
            &mut s,
            &in_db("master", &format!("REVOKE {grant} FROM databastion")),
        ))
        .await;
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `audit_file` proof's build on `sys.sysguidrefs` in the fresh run: in
/// the session's file, from the agent's login, and not reported (`own`:
/// the agent's events the stream reported). Captures its activity's events
/// with `DATABASTION_IT_SQLSERVER_CAPTURE`.
async fn xe_fresh_sysguidrefs(
    s: &mut Session,
    own: &[&databastion_classifiers::masking::MaskedEvent],
) {
    const FILES: &str = "sys.fn_xe_file_target_read_file(N'/var/opt/mssql/xe/databastion_xe_0_*.xel', \
                         NULL, NULL, NULL)";
    let read = |rows: Option<Vec<Vec<Value>>>| -> Vec<String> {
        rows.unwrap_or_default()
            .iter()
            .filter_map(|r| {
                r.first()
                    .and_then(Value::as_text)
                    .map(|x| x.replace('\n', " "))
            })
            .collect()
    };
    let builds = read(
        Box::pin(try_rows(
            s,
            &format!(
                "SELECT TOP (64) CONVERT(nvarchar(4000), event_data) FROM {FILES} \
                 WHERE object_name = N'sp_statement_completed' AND event_data LIKE N'%StatMan%' \
                 AND event_data LIKE N'%sysguidrefs%' AND event_data LIKE N'%databastion%'"
            ),
            1,
        ))
        .await,
    );
    eprintln!("[it] xe fresh: builds on sysguidrefs {}", builds.len());
    assert!(
        !builds.is_empty(),
        "not a fresh server: the audit_file proof built no statistics on sysguidrefs"
    );
    assert!(
        !own.iter()
            .any(|e| names_of(e).iter().any(|n| n.ends_with(".sys.sysguidrefs"))),
        "the build on sysguidrefs paired with the audit_file proof is left out"
    );
    // The `audit_specifications` proof's build on `sys.sysaudacts` (ADR-0051
    // note of 2026-10-18): left out when the server built one.
    let audacts = read(
        Box::pin(try_rows(
            s,
            &format!(
                "SELECT TOP (64) CONVERT(nvarchar(4000), event_data) FROM {FILES} \
                 WHERE object_name = N'sp_statement_completed' AND event_data LIKE N'%StatMan%' \
                 AND event_data LIKE N'%sysaudacts%' AND event_data LIKE N'%databastion%'"
            ),
            1,
        ))
        .await,
    );
    eprintln!("[it] xe fresh: builds on sysaudacts {}", audacts.len());
    assert!(
        !own.iter()
            .any(|e| names_of(e).iter().any(|n| n.ends_with(".sys.sysaudacts"))),
        "the build on sysaudacts paired with the audit_specifications proof is left out"
    );
    let builds: Vec<String> = builds.into_iter().chain(audacts).collect();
    let Ok(path) = std::env::var("DATABASTION_IT_SQLSERVER_CAPTURE") else {
        return;
    };
    let activity = |x: &str| -> Option<String> {
        let at = x.find("name=\"attach_activity_id\"")?;
        let rest = &x[at..];
        let v = &rest[rest.find("<value>")? + 7..];
        let v = &v[..v.find("</value>")?];
        Some(v.rsplit_once('-')?.0.to_owned())
    };
    let mut lines = Vec::new();
    let guids: std::collections::BTreeSet<String> =
        builds.iter().filter_map(|b| activity(b)).collect();
    for guid in guids {
        assert!(guid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'));
        lines.extend(read(
            Box::pin(try_rows(
                s,
                &format!(
                    "SELECT TOP (64) CONVERT(nvarchar(4000), event_data) FROM {FILES} \
                     WHERE event_data LIKE N'%{guid}-%'"
                ),
                1,
            ))
            .await,
        ));
    }
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
}

/// Re-review N1: the first start's floor is bounded. A saved position
/// whose floor is far ahead of the server's clock (what a server clock
/// stepped back gives) and that has left its history phase: what the
/// stream reads below it is counted as dropped, never reported nor
/// silent, and the floor ends once a caught-up read started the source's
/// delivery delay after the first start, so a later read is reported.
#[tokio::test]
async fn floor_ahead_of_the_server_clock_is_counted_then_ends() {
    Box::pin(floor_scenario()).await;
}

async fn floor_scenario() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let major = Box::pin(major()).await;
    let mut s = Box::pin(sa()).await;
    let grant = Box::pin(xe_grant(&mut s, major)).await;
    let login = "it_floor";
    let before = "it_floor_old";
    Box::pin(throwaway(&mut s, login, &[])).await;
    Box::pin(throwaway(&mut s, before, &[])).await;
    let mut sources = vec![(XE, "sqlserver_xevents")];
    if major >= 16 {
        sources.push((AUDIT, "sqlserver_audit"));
    }
    for (settings, cursor) in sources {
        let c = Arc::new(SqlserverConnector::new());
        let t = agent(&format!("{}, {settings}", own_tls()));
        let dir = std::env::temp_dir().join(format!(
            "databastion-sqlserver-floor-{}-{cursor}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let limits = Limits {
            min_audit_poll_interval_s: 1,
            ..Limits::default()
        };
        let cfg = databastion_core::AuditConfig::local(&t, 1, &limits).with_state_dir(dir.clone());
        // A read written to the source before the first start the floor is set at: below
        // the floor.
        let mut d = Box::pin(foreign_session(
            before,
            "DATABASTION_IT_SQLSERVER_THROWAWAY",
        ))
        .await;
        Box::pin(try_rows(
            &mut d,
            "SELECT TOP (1) id FROM retail.crm.customers",
            1,
        ))
        .await;
        d.close().await;
        // From the start of the file set, out of the history phase, under
        // a floor an hour ahead.
        let seeded = crate::audit::Cursor {
            floor: Some(
                i64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_micros(),
                )
                .unwrap()
                    + 3_600_000_000,
            ),
            floor_set_ms: crate::audit::agent_now_ms(),
            ..crate::audit::Cursor::default()
        };
        cfg.cursor(cursor).unwrap().save(&seeded.encode()).unwrap();
        let (sink, mut rx) = databastion_core::EventSink::channel(8192);
        let c2 = Arc::clone(&c);
        let stream = tokio::spawn(async move { c2.audit_stream(&cfg, &sink).await });
        // Past the delivery delay (5 s session latency, 1 s queue delay).
        tokio::time::sleep(Duration::from_secs(9)).await;
        assert!(!stream.is_finished(), "{:?}", stream.await);
        let dropped = c.state.audit.facts(&t.id).dropped;
        let mut d = Box::pin(foreign_session(login, "DATABASTION_IT_SQLSERVER_THROWAWAY")).await;
        Box::pin(try_rows(
            &mut d,
            "SELECT TOP (1) id FROM retail.crm.customers",
            1,
        ))
        .await;
        d.close().await;
        tokio::time::sleep(Duration::from_secs(12)).await;
        stream.abort();
        let _ = stream.await;
        let mut events = Vec::new();
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        eprintln!(
            "[it] floor ({cursor}): {} events, dropped below the floor {dropped}",
            events.len()
        );
        assert!(dropped > 0, "{cursor}: what the floor left out is counted");
        // Nothing of the file set before the floor ended is reported (the
        // read made before the stream started), the read made after it is.
        for e in &events {
            eprintln!(
                "[it] floor ({cursor}): event {} {:?} {:?}",
                e.principal().account_name(),
                e.action(),
                names_of(e)
            );
            assert!(
                !e.principal().account_name().eq_ignore_ascii_case(before),
                "{cursor}: an event below the floor was reported"
            );
        }
        assert!(
            events.iter().any(|e| {
                e.principal().account_name().eq_ignore_ascii_case(login)
                    && names_of(e).iter().any(|n| n == "retail.crm.customers")
            }),
            "{cursor}: the read after the floor ended is reported"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    Box::pin(drop_login(&mut s, login)).await;
    Box::pin(drop_login(&mut s, before)).await;
    if major >= 16 {
        Box::pin(exec(
            &mut s,
            &in_db("master", &format!("REVOKE {grant} FROM databastion")),
        ))
        .await;
    }
}

/// Follow-up of the lot 3 final review (L1), the `e2e-sqlserver` CI job: a
/// first start (a long backlog to skip) followed by a Discovery scan with
/// Audit on reports no `audit.records_dropped`, on both sources: the
/// history boundary goes by order, not by the time the catch-up takes.
#[tokio::test]
async fn a_first_start_and_a_scan_drop_nothing() {
    Box::pin(first_start_scenario()).await;
}

async fn first_start_scenario() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let major = Box::pin(major()).await;
    let mut s = Box::pin(sa()).await;
    let grant = Box::pin(xe_grant(&mut s, major)).await;
    let mut sources = vec![(XE, "xevents")];
    if major >= 16 {
        sources.push((AUDIT, "audit"));
    }
    for (settings, label) in sources {
        let c = Arc::new(SqlserverConnector::new());
        let t = agent(&format!("{}, {settings}", own_tls()));
        let dir = std::env::temp_dir().join(format!(
            "databastion-sqlserver-first-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let c2 = Arc::clone(&c);
        let t2 = t.clone();
        let _events = Box::pin(xe_stream_around(&c, &t, &dir, async move {
            let job = ScanJob::new(ScanParams::contract_defaults(), &t2, &unpaced(), key());
            let (sink, mut frx) = FindingSink::channel(10_000);
            let drain = tokio::spawn(async move { while frx.recv().await.is_some() {} });
            Box::pin(c2.discover(&job, &sink)).await.unwrap();
            drop(sink);
            drain.await.unwrap();
        }))
        .await;
        let dropped = c.state.audit.facts(&t.id).dropped;
        eprintln!("[it] first start ({label}): records dropped {dropped}");
        assert_eq!(dropped, 0, "{label}: a first start and a scan drop nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }
    if major >= 16 {
        Box::pin(exec(
            &mut s,
            &in_db("master", &format!("REVOKE {grant} FROM databastion")),
        ))
        .await;
    }
}

/// End-of-phase-9 review of G7 / N1, H1: SQL Server ignores trailing
/// spaces in identifiers, so `[sys].[sql_logins ]` and `[sys ].[...]`
/// resolve to the catalog views (an unknown name fails with error 208),
/// and the analyzer names them as the listed objects.
#[tokio::test]
async fn trailing_spaces_in_bracketed_names_resolve_to_the_listed_views() {
    if !enabled() {
        return;
    }
    let _g = serial().await;
    let mut sa = sa().await;
    for (text, listed) in [
        (
            "IF EXISTS (SELECT 1 FROM [sys].[sql_logins ]) PRINT ''",
            "sql_logins",
        ),
        (
            "IF EXISTS (SELECT 1 FROM [sys  ].[sql_logins]) PRINT ''",
            "sql_logins",
        ),
        (
            "IF EXISTS (SELECT 1 FROM sys.dm_exec_requests r CROSS APPLY [sys].[dm_exec_sql_text ](r.sql_handle) t) PRINT ''",
            "dm_exec_sql_text",
        ),
    ] {
        exec(&mut sa, text).await;
        let a = databastion_classifiers::query::tsql::analyze_tsql(text, false);
        assert!(a.listed.contains(&listed), "{text}: {:?}", a.listed);
    }
}
