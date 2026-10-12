//! Integration tests of ADR-0050 (credential- and value-bearing catalogs as
//! reads) and of the ADR-0012 refinement of 2026-10-12 (the two-key reads
//! of `pg_db_role_setting` and `pg_proc.proconfig`, and the parameter
//! grants, capping Full at Partial), against a PostgreSQL server:
//!
//! - a `pg_read_all_data` member reads `pg_authid.rolpassword`,
//!   `pg_shadow.passwd` (PgBouncer's `auth_query`),
//!   `pg_subscription.subconninfo` and `pg_largeobject`; an unprivileged
//!   role reads `pg_db_role_setting.setconfig`, `pg_roles.rolconfig`,
//!   `pg_proc.proconfig` and a user view over `pg_authid`; a mapped role
//!   reads its own `pg_user_mappings.umoptions`; a superuser reads
//!   `pg_hba_file_rules`: each gives a read event naming the entry, always
//!   reported, on every source (the pgaudit log files, then
//!   `pg_stat_statements`); reads without secret columns and the agent's
//!   own `check()` (its two-key reads included) give none; no fake secret
//!   reaches an event, a log line or a `Debug` output (I2);
//! - per-role, role-in-database, database and function overrides of the
//!   two log settings, a revoked `pg_db_role_setting` and (15+) the
//!   parameter grants each cap a Full target at Partial with a local
//!   detail, and their reset restores Full; with a `pg_stat_statements`
//!   stream of the target running, the two-key reads are not sent;
//! - the server facts the decisions rest on (pinning, one assertion each),
//!   and the drift test of the list (every major version).
//!
//! Same prerequisites as `it.rs`. Fixtures are created in the test database
//! and dropped at the end; nothing is added to `dev/`.

#![allow(clippy::print_stderr)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use databastion_classifiers::masking::{EventAction, MaskedEvent};
use databastion_core::{AuditLevel, Connector};

use super::it::{
    Logs, SERIAL, TempDir, admin, admin_url, agent_url, audit_logs, audit_target, collect_until,
    describe, raw_client, skip, start_audit_with,
};
use crate::PostgresConnector;
use crate::audit::events::SECRET_RELATIONS;
use crate::conn::{Session, Timeouts};
use crate::discover::normalize;
use crate::sql;

/// A role mapped to a foreign server (its own password).
const SEC_APP: &str = "databastion_it_sec_app";
/// A `pg_read_all_data` member.
const SEC_RAD: &str = "databastion_it_sec_rad";
/// A role without any grant.
const SEC_PLAIN: &str = "databastion_it_sec_plain";
/// A role reading the catalogs without their secret columns.
const SEC_QUIET: &str = "databastion_it_sec_quiet";
/// The role whose overrides cap the level.
const SEC_OTHER: &str = "databastion_it_sec_other";
/// A superuser (its grants are not flagged).
const SEC_SUPER: &str = "databastion_it_sec_super";
const SEC_PASSWORD: &str = "dev-only-it-sec-FAKE";
/// Marker in every planted secret: never in an event, a log or a `Debug`
/// output (I2).
const SEC_MARK: &str = "Sk7Qz-it-secret";
const SERVER: &str = "databastion_it_sec_srv";
const SUBSCRIPTION: &str = "databastion_it_sec_sub";
const VIEW_PW: &str = "databastion_it_sec_v_pw";
const VIEW_ROLES: &str = "databastion_it_sec_v_roles";
const FN_SECRET: &str = "databastion_it_sec_fn";
const FN_HIDE: &str = "databastion_it_sec_hide";
/// The `pg_hba.conf` line the test adds where it can (user name).
const HBA_USER: &str = "databastion_it_sec_hba";

/// Whether pgaudit is loaded on the server.
async fn pgaudit_loaded(a: &tokio_postgres::Client) -> bool {
    let n: i64 = a
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_settings WHERE name = 'pgaudit.log'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    n > 0
}

async fn server_version(a: &tokio_postgres::Client) -> i32 {
    let v: String = a
        .query_one("SHOW server_version_num", &[])
        .await
        .unwrap()
        .get(0);
    v.parse().unwrap()
}

/// Drops every fixture (left over by an interrupted run too).
async fn teardown(a: &tokio_postgres::Client, db: &str) {
    let _ = a
        .batch_execute(&format!(
            "ALTER SUBSCRIPTION {SUBSCRIPTION} DISABLE; \
             ALTER SUBSCRIPTION {SUBSCRIPTION} SET (slot_name = NONE)"
        ))
        .await;
    for s in [
        format!("DROP SUBSCRIPTION IF EXISTS {SUBSCRIPTION}"),
        format!("DROP SERVER IF EXISTS {SERVER} CASCADE"),
        format!("DROP VIEW IF EXISTS public.{VIEW_PW}"),
        format!("DROP VIEW IF EXISTS public.{VIEW_ROLES}"),
        format!("DROP FUNCTION IF EXISTS public.{FN_SECRET}()"),
        format!("DROP FUNCTION IF EXISTS public.{FN_HIDE}()"),
        format!("ALTER DATABASE \"{db}\" RESET app.jwt_secret"),
        format!("ALTER DATABASE \"{db}\" RESET log_min_messages"),
        "GRANT SELECT ON pg_catalog.pg_db_role_setting TO PUBLIC".to_owned(),
        "SELECT pg_catalog.lo_unlink(m.oid) FROM pg_catalog.pg_largeobject_metadata m \
         JOIN pg_catalog.pg_roles r ON r.oid = m.lomowner WHERE r.rolname = current_user \
         AND m.oid IN (SELECT l.loid FROM pg_catalog.pg_largeobject l \
         WHERE position(pg_catalog.convert_to('Sk7Qz', 'UTF8') IN l.data) > 0)"
            .to_owned(),
    ] {
        let _ = a.batch_execute(&s).await;
    }
    if server_version(a).await >= 150_000 {
        for role in [SEC_OTHER, SEC_SUPER, "PUBLIC"] {
            let _ = a
                .batch_execute(&format!(
                    "REVOKE SET ON PARAMETER log_min_messages FROM {role}; \
                     REVOKE ALTER SYSTEM ON PARAMETER log_min_error_statement FROM {role}"
                ))
                .await;
        }
    }
    for role in [SEC_APP, SEC_RAD, SEC_PLAIN, SEC_QUIET, SEC_OTHER, SEC_SUPER] {
        let _ = a
            .batch_execute(&format!(
                "REVOKE ALL ON DATABASE \"{db}\" FROM {role}; DROP OWNED BY {role}; \
                 DROP ROLE IF EXISTS {role}"
            ))
            .await;
    }
}

/// Creates the roles and plants the fake secrets.
async fn setup(a: &tokio_postgres::Client, db: &str) {
    teardown(a, db).await;
    let mut s = String::new();
    for role in [SEC_APP, SEC_RAD, SEC_PLAIN, SEC_QUIET, SEC_OTHER] {
        s.push_str(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD '{SEC_PASSWORD}'; \
             GRANT CONNECT ON DATABASE \"{db}\" TO {role}; "
        ));
    }
    s.push_str(&format!(
        "CREATE ROLE {SEC_SUPER} SUPERUSER NOLOGIN; \
         GRANT pg_read_all_data TO {SEC_RAD}; \
         CREATE EXTENSION IF NOT EXISTS postgres_fdw; \
         CREATE SERVER {SERVER} FOREIGN DATA WRAPPER postgres_fdw \
           OPTIONS (host 'fake.invalid', dbname 'x'); \
         GRANT USAGE ON FOREIGN SERVER {SERVER} TO {SEC_APP}; \
         CREATE USER MAPPING FOR {SEC_APP} SERVER {SERVER} \
           OPTIONS (user 'ru', password '{SEC_MARK}-fdw'); \
         CREATE USER MAPPING FOR {SEC_OTHER} SERVER {SERVER} \
           OPTIONS (user 'ro', password '{SEC_MARK}-fdw2'); \
         SELECT pg_catalog.lo_from_bytea(0, pg_catalog.convert_to('{SEC_MARK}-lo', 'UTF8')); \
         ALTER ROLE {SEC_APP} SET app.api_key = '{SEC_MARK}-role'; \
         ALTER DATABASE \"{db}\" SET app.jwt_secret = '{SEC_MARK}-db'; \
         CREATE FUNCTION public.{FN_SECRET}() RETURNS int LANGUAGE sql \
           SET app.k = '{SEC_MARK}-fn' AS 'SELECT 1'; \
         CREATE VIEW public.{VIEW_PW} AS SELECT rolname, rolpassword AS p FROM pg_catalog.pg_authid; \
         CREATE VIEW public.{VIEW_ROLES} AS SELECT rolname FROM pg_catalog.pg_roles; \
         GRANT USAGE ON SCHEMA public TO {SEC_PLAIN}; \
         GRANT SELECT ON public.{VIEW_PW}, public.{VIEW_ROLES} TO {SEC_PLAIN}; "
    ));
    a.batch_execute(&s).await.unwrap();
    // `connect = false`: no connection to the fake publisher.
    a.batch_execute(&format!(
        "CREATE SUBSCRIPTION {SUBSCRIPTION} \
           CONNECTION 'host=fake.invalid dbname=x password={SEC_MARK}-sub' \
           PUBLICATION p WITH (connect = false)"
    ))
    .await
    .unwrap();
}

/// Adds a `radius` line with a fake secret to the server's `pg_hba.conf`
/// when the test can write it (the local cluster; not a container), without
/// a reload (`pg_hba_file_rules` reads the file). Returns the file and its
/// former content, to restore.
async fn add_hba_line(a: &tokio_postgres::Client) -> Option<(PathBuf, String)> {
    let path: String = a.query_one("SHOW hba_file", &[]).await.ok()?.get(0);
    let path = PathBuf::from(path);
    let before = std::fs::read_to_string(&path).ok()?;
    let line = format!(
        "host all {HBA_USER} 192.0.2.1/32 radius radiusservers=\"127.0.0.1\" \
         radiussecrets=\"{SEC_MARK}-radius\"\n\
         host all {HBA_USER} 192.0.2.2/32 ldap ldapserver=fake.invalid ldapbasedn=\"dc=x\" \
         ldapbinddn=\"cn=b\" ldapbindpasswd=\"{SEC_MARK}-ldap\"\n"
    );
    std::fs::write(&path, format!("{line}{before}")).ok()?;
    Some((path, before))
}

/// A read event of `user` naming `schema.object` (`None`: no schema),
/// always reported.
fn secret_read(e: &MaskedEvent, user: &str, schema: Option<&str>, object: &str) -> bool {
    e.principal().account_name() == user
        && e.action() == EventAction::Read
        && e.always_report()
        && e.objects().iter().any(|o| {
            o.schema().map(|s| s.as_str().to_owned())
                == schema.map(|s| normalize(s).as_str().to_owned())
                && o.object().as_str() == normalize(object).as_str()
        })
}

/// ADR-0050 against the server, on every available source.
#[tokio::test]
async fn secret_reads_are_named_and_always_reported() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let logs = Logs::default();
    let _guard = logs.capture();
    let a = admin(&adm, &u.dbname).await;
    setup(&a, &u.dbname).await;
    let hba = add_hba_line(&a).await;
    let mut sources: Vec<(String, Option<(PathBuf, &'static str)>)> = audit_logs()
        .into_iter()
        .map(|(p, f)| (format!("pgaudit {f}"), Some((p, f))))
        .collect();
    sources.push(("pg_stat_statements".to_owned(), None));
    let mut outputs = String::new();
    for (i, (label, log)) in sources.into_iter().enumerate() {
        let (_dir, t) = audit_target(
            &u,
            &format!("pg-secrets-{i}"),
            log.as_ref().map(|(p, f)| (p.as_path(), *f)),
        );
        let connector = Arc::new(PostgresConnector::new());
        let health = connector.check(&t).await;
        if log.is_none() && health.audit_level != AuditLevel::Limited {
            skip("pss", "pg_stat_statements is not usable by the agent role");
            continue;
        }
        let state = TempDir::new();
        let (task, mut rx) = start_audit_with(Arc::clone(&connector), &t, &state.0);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let client = |role: &'static str| raw_client(&adm, role, SEC_PASSWORD, &u.dbname);
        let rad = client(SEC_RAD).await;
        let plain = client(SEC_PLAIN).await;
        let app = client(SEC_APP).await;
        let quiet = client(SEC_QUIET).await;
        for q in [
            "SELECT rolname, rolpassword FROM pg_authid",
            "SELECT subconninfo FROM pg_subscription",
            "SELECT data FROM pg_largeobject",
        ] {
            rad.simple_query(q).await.unwrap();
        }
        // PgBouncer's default `auth_query`, with a bound parameter.
        rad.query(
            "SELECT usename, passwd FROM pg_shadow WHERE usename=$1",
            &[&SEC_APP],
        )
        .await
        .unwrap();
        for q in [
            "SELECT setconfig FROM pg_db_role_setting".to_owned(),
            "SELECT rolconfig FROM pg_roles".to_owned(),
            "SELECT proconfig FROM pg_proc WHERE proconfig IS NOT NULL".to_owned(),
            format!("SELECT p FROM public.{VIEW_PW}"),
        ] {
            plain.simple_query(&q).await.unwrap();
        }
        let own: Vec<tokio_postgres::SimpleQueryMessage> = app
            .simple_query("SELECT umoptions FROM pg_user_mappings")
            .await
            .unwrap();
        assert!(!own.is_empty());
        a.simple_query("SELECT r.options FROM pg_hba_file_rules r")
            .await
            .unwrap();
        // Reads without secret columns (an exporter, `psql`'s `\du`).
        for q in [
            "SELECT rolname FROM pg_roles",
            "SELECT r.rolname FROM pg_roles r WHERE r.rolsuper",
            "SELECT p.proname, p.prorettype FROM pg_proc p LIMIT 5",
            "SELECT subname, subenabled FROM pg_subscription",
            "SELECT srvname FROM pg_foreign_server",
        ] {
            quiet.simple_query(q).await.unwrap();
        }
        let pgaudit = log.is_some();
        let done = |ev: &[MaskedEvent]| {
            let has = |user: &str, schema: Option<&str>, object: &str| {
                ev.iter().any(|e| secret_read(e, user, schema, object))
            };
            let c = Some("pg_catalog");
            has(SEC_RAD, c, "pg_authid")
                && has(SEC_RAD, c, "pg_subscription")
                && has(SEC_RAD, c, "pg_largeobject")
                && has(SEC_RAD, c, "pg_shadow")
                && has(SEC_PLAIN, c, "pg_db_role_setting")
                && has(SEC_PLAIN, c, "pg_roles")
                && has(SEC_PLAIN, c, "pg_proc")
                && has(SEC_APP, c, "pg_user_mappings")
                && has(&adm.user, c, "pg_hba_file_rules")
                && if pgaudit {
                    // The user view's `pg_authid` record (decision 3).
                    has(SEC_PLAIN, c, "pg_authid")
                } else {
                    // Named by the view only (residual), under the filters.
                    ev.iter().any(|e| {
                        e.principal().account_name() == SEC_PLAIN
                            && e.objects().iter().any(|o| o.object().as_str() == VIEW_PW)
                    })
                }
        };
        let mut events = Vec::new();
        collect_until(&mut rx, &mut events, Duration::from_secs(40), done).await;
        // The agent's own check(), its two-key reads included (pgaudit at
        // Full), then a few more polls.
        for _ in 0..2 {
            assert!(connector.check(&t).await.reachable, "{label}");
        }
        collect_until(&mut rx, &mut events, Duration::from_secs(6), |_| false).await;
        task.abort();
        let all: Vec<String> = events.iter().map(describe).collect();
        eprintln!("{label} events ({}):\n{}", all.len(), all.join("\n"));
        assert!(done(&events), "{label}: {all:#?}");
        assert!(
            !events
                .iter()
                .any(|e| e.principal().account_name() == SEC_QUIET),
            "{label}: reads without secret columns: {all:#?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| e.principal().account_name() == u.user),
            "{label}: the agent's own statements: {all:#?}"
        );
        for e in &events {
            outputs.push_str(&format!("{e:?}\n"));
        }
        outputs.push_str(&all.join("\n"));
        outputs.push_str(&format!("{health:?}"));
    }
    if let Some((path, before)) = hba {
        std::fs::write(path, before).unwrap();
    }
    teardown(&a, &u.dbname).await;
    outputs.push_str(&logs.text());
    assert!(
        !outputs.contains(SEC_MARK),
        "a planted secret reached the agent's output"
    );
}

/// The level and local detail of `check()` (the stream's freshness rule
/// satisfied).
async fn level(
    connector: &PostgresConnector,
    t: &databastion_core::config::TargetConfig,
) -> (AuditLevel, String) {
    connector.check_state.note_record(&t.id);
    let h = connector.check(t).await;
    assert!(h.reachable);
    (h.audit_level, h.detail.unwrap_or_default())
}

/// The calls of the two-key reads counted by `pg_stat_statements` for the
/// agent's role.
async fn two_key_calls(a: &tokio_postgres::Client, agent: &str) -> i64 {
    let Some(pss) = super::it::pss_schema(a).await else {
        return 0;
    };
    a.query_one(
        &format!(
            "SELECT COALESCE(sum(s.calls), 0)::int8 FROM \"{pss}\".pg_stat_statements s \
             JOIN pg_catalog.pg_roles r ON r.oid = s.userid \
             WHERE r.rolname = $1 AND (s.query LIKE '%pg_db_role_setting%' \
             OR s.query LIKE '%proconfig%')"
        ),
        &[&agent],
    )
    .await
    .unwrap()
    .get(0)
}

/// The ADR-0012 refinement of 2026-10-12 against the server (pgaudit and
/// its log needed for Full).
#[tokio::test]
async fn log_overrides_cap_full() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let logs = Logs::default();
    let _guard = logs.capture();
    let a = admin(&adm, &u.dbname).await;
    if !pgaudit_loaded(&a).await {
        skip("pgaudit", "pgaudit is not loaded: no Full level to cap");
        return;
    }
    let Some((log, format)) = audit_logs().into_iter().next() else {
        return;
    };
    setup(&a, &u.dbname).await;
    let (_dir, t) = audit_target(&u, "pg-overrides", Some((&log, format)));
    let connector = PostgresConnector::new();
    let (l, detail) = level(&connector, &t).await;
    assert_eq!(l, AuditLevel::Full, "{detail}");
    let version = server_version(&a).await;
    let db = u.dbname.clone();
    let mut cases: Vec<(String, String, String)> = vec![
        (
            format!("ALTER ROLE {SEC_OTHER} SET log_min_messages = fatal"),
            format!("ALTER ROLE {SEC_OTHER} RESET log_min_messages"),
            format!("log_min_messages above error for role(s) {SEC_OTHER}"),
        ),
        (
            format!(
                "ALTER ROLE {SEC_OTHER} IN DATABASE \"{db}\" SET log_min_error_statement = panic"
            ),
            format!("ALTER ROLE {SEC_OTHER} IN DATABASE \"{db}\" RESET log_min_error_statement"),
            format!("log_min_error_statement above error for role(s) {SEC_OTHER}"),
        ),
        (
            // Canonical name, any case (stored in lower case).
            format!("ALTER ROLE {SEC_OTHER} SET \"LOG_MIN_ERROR_STATEMENT\" = 'PANIC'"),
            format!("ALTER ROLE {SEC_OTHER} RESET log_min_error_statement"),
            format!("log_min_error_statement above error for role(s) {SEC_OTHER}"),
        ),
        (
            // The session sees it too (ADR-0037 item 6).
            format!("ALTER DATABASE \"{db}\" SET log_min_messages = log"),
            format!("ALTER DATABASE \"{db}\" RESET log_min_messages"),
            "log_min_messages".to_owned(),
        ),
        (
            "REVOKE SELECT ON pg_catalog.pg_db_role_setting FROM PUBLIC".to_owned(),
            "GRANT SELECT ON pg_catalog.pg_db_role_setting TO PUBLIC".to_owned(),
            "not read (SQLSTATE 42501)".to_owned(),
        ),
        (
            format!(
                "CREATE FUNCTION public.{FN_HIDE}() RETURNS int LANGUAGE sql \
                 SET log_min_messages = fatal AS 'SELECT 1'"
            ),
            format!("DROP FUNCTION public.{FN_HIDE}()"),
            format!("SET clause of function(s) public.{FN_HIDE}"),
        ),
    ];
    if version >= 150_000 {
        cases.extend([
            (
                format!("GRANT SET ON PARAMETER log_min_messages TO {SEC_OTHER}"),
                format!("REVOKE SET ON PARAMETER log_min_messages FROM {SEC_OTHER}"),
                format!("SET on log_min_messages granted to role(s) {SEC_OTHER}"),
            ),
            (
                format!("GRANT ALTER SYSTEM ON PARAMETER log_min_error_statement TO {SEC_OTHER}"),
                format!(
                    "REVOKE ALTER SYSTEM ON PARAMETER log_min_error_statement FROM {SEC_OTHER}"
                ),
                format!("ALTER SYSTEM on log_min_error_statement granted to role(s) {SEC_OTHER}"),
            ),
            (
                "GRANT SET ON PARAMETER log_min_messages TO PUBLIC".to_owned(),
                "REVOKE SET ON PARAMETER log_min_messages FROM PUBLIC".to_owned(),
                "SET on log_min_messages granted to every role".to_owned(),
            ),
        ]);
    }
    for (apply, reset, want) in &cases {
        a.batch_execute(apply).await.unwrap();
        let (l, detail) = level(&connector, &t).await;
        eprintln!("{apply}: {l:?}");
        assert_eq!(l, AuditLevel::Partial, "{apply}: {detail}");
        assert!(detail.contains(want.as_str()), "{apply}: {detail}");
        for value in ["fatal", "panic", "PANIC"] {
            assert!(!detail.contains(value), "{value} in {detail}");
        }
        a.batch_execute(reset).await.unwrap();
        let (l, detail) = level(&connector, &t).await;
        assert_eq!(l, AuditLevel::Full, "after {reset}: {detail}");
    }
    if version >= 150_000 {
        // A superuser's grant is not flagged.
        a.batch_execute(&format!(
            "GRANT SET ON PARAMETER log_min_messages TO {SEC_SUPER}"
        ))
        .await
        .unwrap();
        let (l, detail) = level(&connector, &t).await;
        assert_eq!(l, AuditLevel::Full, "{detail}");
        a.batch_execute(&format!(
            "REVOKE SET ON PARAMETER log_min_messages FROM {SEC_SUPER}"
        ))
        .await
        .unwrap();
    }
    // With a `pg_stat_statements` stream of the target running: not sent,
    // and not proven.
    let before = two_key_calls(&a, &u.user).await;
    {
        let periods = connector.check_state.pss_periods(&t.id);
        periods.lock().unwrap().start(SystemTime::now());
        let (l, detail) = level(&connector, &t).await;
        assert_eq!(l, AuditLevel::Partial, "{detail}");
        assert!(detail.contains("pg_stat_statements stream"), "{detail}");
        periods
            .lock()
            .unwrap()
            .stop(SystemTime::now(), Duration::from_secs(0));
    }
    assert_eq!(
        two_key_calls(&a, &u.user).await,
        before,
        "sent while a pss stream ran"
    );
    let (l, _) = level(&connector, &t).await;
    assert_eq!(l, AuditLevel::Full);
    assert!(two_key_calls(&a, &u.user).await > before || super::it::pss_schema(&a).await.is_none());
    // The minimal-variant role reads the catalog with no grant.
    let readable: bool = a
        .query_one(
            "SELECT pg_catalog.has_table_privilege($1, 'pg_catalog.pg_db_role_setting', 'SELECT')",
            &[&u.user],
        )
        .await
        .unwrap()
        .get(0);
    assert!(readable);
    // Every row of the two-key reads holds one of the two keys, never a
    // planted secret (fake secrets in `ALTER ROLE`, `ALTER DATABASE` and a
    // function's `SET` clause).
    a.batch_execute(&format!(
        "ALTER ROLE {SEC_OTHER} SET log_min_messages = fatal; \
         CREATE FUNCTION public.{FN_HIDE}() RETURNS int LANGUAGE sql \
           SET log_min_error_statement = panic AS 'SELECT 1'"
    ))
    .await
    .unwrap();
    let (_, detail) = level(&connector, &t).await;
    let session = Session::connect(&t, &u.dbname, Timeouts::new(Duration::from_secs(5)))
        .await
        .unwrap();
    let mut seen = 0;
    for (statement, key_column) in [
        (sql::ROLE_LOG_OVERRIDES, 3),
        (sql::FUNCTION_LOG_OVERRIDES, 2),
    ] {
        let tx = session
            .begin(Timeouts::new(Duration::from_secs(5)))
            .await
            .unwrap();
        let rows = tx
            .query(crate::error::Stage::Check, statement, &[])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        for r in &rows {
            let key = crate::wire::catalog_text(r, key_column).unwrap().unwrap();
            assert!(
                ["log_min_messages", "log_min_error_statement"].contains(&key.as_str()),
                "{key}"
            );
            for i in 0..r.len() {
                if let Ok(Some(v)) = crate::wire::catalog_text(r, i) {
                    assert!(!v.contains(SEC_MARK));
                }
            }
            seen += 1;
        }
    }
    assert!(seen >= 2, "{seen}");
    drop(session);
    a.batch_execute(&format!(
        "ALTER ROLE {SEC_OTHER} RESET log_min_messages; DROP FUNCTION public.{FN_HIDE}()"
    ))
    .await
    .unwrap();
    teardown(&a, &u.dbname).await;
    let output = format!("{detail}\n{}", logs.text());
    assert!(
        !output.contains(SEC_MARK),
        "a planted secret reached the agent's output"
    );
}

/// The pgaudit records written since `from` by sessions of `user`, waiting
/// up to 10 s for at least `want`.
async fn records_of(
    path: &std::path::Path,
    format: &str,
    from: u64,
    user: &str,
    want: usize,
) -> Vec<crate::audit::records::AuditRecord> {
    use std::io::{Read as _, Seek as _};
    let fmt = if format == "jsonlog" {
        crate::audit::records::Format::Jsonlog
    } else {
        crate::audit::records::Format::Csvlog
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut f = std::fs::File::open(path).unwrap();
        f.seek(std::io::SeekFrom::Start(from)).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        let out: Vec<_> = buf
            .split(|b| *b == b'\n')
            .filter_map(|l| crate::audit::records::parse_record(fmt, l, "LOG"))
            .filter(|r| r.user == user)
            .collect();
        if out.len() >= want || std::time::Instant::now() > deadline {
            return out;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// The first column of `q` as text, read by `c` (`None`: no row or NULL).
async fn first_text(c: &tokio_postgres::Client, q: &str) -> Option<String> {
    let rows = c.simple_query(q).await.unwrap();
    rows.into_iter().find_map(|m| match m {
        tokio_postgres::SimpleQueryMessage::Row(r) => r.get(0).map(str::to_owned),
        _ => None,
    })
}

/// ADR-0050 decision 8 and the ADR-0012 refinement, pinning: the server
/// facts the decisions rest on, one assertion each.
#[tokio::test]
async fn secret_catalogs_server_facts() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let a = admin(&adm, &u.dbname).await;
    let version = server_version(&a).await;
    eprintln!("server_version_num {version}");
    setup(&a, &u.dbname).await;
    let hba = add_hba_line(&a).await;
    let client = |role: &'static str| raw_client(&adm, role, SEC_PASSWORD, &u.dbname);
    let rad = client(SEC_RAD).await;
    let plain = client(SEC_PLAIN).await;
    let app = client(SEC_APP).await;
    // pg_read_all_data reads SCRAM verifiers, subscription connection
    // strings and large objects.
    let pw = first_text(
        &rad,
        &format!("SELECT rolpassword FROM pg_authid WHERE rolname = '{SEC_APP}'"),
    )
    .await
    .unwrap();
    assert!(pw.starts_with("SCRAM-SHA-256$"), "verifier format");
    let conninfo = first_text(
        &rad,
        &format!("SELECT subconninfo FROM pg_subscription WHERE subname = '{SUBSCRIPTION}'"),
    )
    .await
    .unwrap();
    assert!(conninfo.contains(&format!("{SEC_MARK}-sub")));
    let lo = first_text(
        &rad,
        &format!(
            "SELECT count(*) FROM pg_largeobject \
             WHERE position(convert_to('{SEC_MARK}-lo', 'UTF8') IN data) > 0"
        ),
    )
    .await
    .unwrap();
    assert_eq!(lo, "1");
    let shadow = first_text(
        &rad,
        &format!("SELECT passwd FROM pg_shadow WHERE usename = '{SEC_APP}'"),
    )
    .await
    .unwrap();
    assert!(shadow.starts_with("SCRAM-SHA-256$"));
    // Every role reads every setting in clear.
    let setconfig = first_text(
        &plain,
        "SELECT string_agg(array_to_string(setconfig, ','), ',') FROM pg_db_role_setting",
    )
    .await
    .unwrap();
    assert!(setconfig.contains(&format!("{SEC_MARK}-role")));
    assert!(setconfig.contains(&format!("{SEC_MARK}-db")));
    let rolconfig = first_text(
        &plain,
        &format!(
            "SELECT array_to_string(rolconfig, ',') FROM pg_roles WHERE rolname = '{SEC_APP}'"
        ),
    )
    .await
    .unwrap();
    assert!(rolconfig.contains(&format!("{SEC_MARK}-role")));
    let proconfig = first_text(
        &plain,
        &format!(
            "SELECT array_to_string(proconfig, ',') FROM pg_proc WHERE proname = '{FN_SECRET}'"
        ),
    )
    .await
    .unwrap();
    assert!(proconfig.contains(&format!("{SEC_MARK}-fn")));
    // `pg_roles.rolpassword` is masked.
    let masked = first_text(
        &plain,
        &format!("SELECT rolpassword FROM pg_roles WHERE rolname = '{SEC_APP}'"),
    )
    .await
    .unwrap();
    assert_eq!(masked, "********");
    // A database setting is readable in the session by every role.
    let db_setting = first_text(&plain, "SELECT current_setting('app.jwt_secret', true)")
        .await
        .unwrap_or_default();
    assert!(db_setting.contains(&format!("{SEC_MARK}-db")));
    // The mapped role reads its own remote password through the view;
    // pg_read_all_data reads NULL there for another role's mapping.
    let own = first_text(
        &app,
        "SELECT array_to_string(umoptions, ',') FROM pg_user_mappings",
    )
    .await
    .unwrap();
    assert!(own.contains(&format!("{SEC_MARK}-fdw")));
    let other = first_text(
        &rad,
        &format!(
            "SELECT array_to_string(umoptions, ',') FROM pg_user_mappings \
             WHERE usename = '{SEC_APP}'"
        ),
    )
    .await;
    assert!(
        other.is_none(),
        "pg_read_all_data reads another role's mapping options"
    );
    let raw_mapping = first_text(
        &rad,
        "SELECT count(*) FROM pg_user_mapping WHERE umoptions IS NOT NULL",
    )
    .await
    .unwrap();
    assert_ne!(raw_mapping, "0", "pg_read_all_data reads pg_user_mapping");
    // An unprivileged role is refused `pg_authid` and `pg_hba_file_rules`.
    assert!(plain.simple_query("SELECT 1 FROM pg_authid").await.is_err());
    assert!(
        plain
            .simple_query("SELECT 1 FROM pg_hba_file_rules")
            .await
            .is_err()
    );
    // `pg_hba_file_rules` and `pg_show_all_file_settings`: functions of no
    // argument behind the views of the same names.
    for (f, n) in [
        ("pg_hba_file_rules", "0"),
        ("pg_show_all_file_settings", "0"),
    ] {
        let args = first_text(
            &a,
            &format!("SELECT string_agg(pronargs::text, ',') FROM pg_proc WHERE proname = '{f}'"),
        )
        .await
        .unwrap();
        assert_eq!(args, n, "{f}");
    }
    if hba.is_some() {
        let options = first_text(
            &a,
            &format!(
                "SELECT string_agg(array_to_string(options, ','), ';') FROM pg_hba_file_rules \
                 WHERE '{HBA_USER}' = ANY (user_name)"
            ),
        )
        .await
        .unwrap();
        assert!(
            options.contains(&format!("{SEC_MARK}-radius")),
            "radiussecrets in clear"
        );
        assert!(
            options.contains(&format!("{SEC_MARK}-ldap")),
            "ldapbindpasswd in clear"
        );
    } else {
        eprintln!("pg_hba.conf not writable here: the options column is not pinned");
    }
    // Setting names are stored in their canonical form.
    a.batch_execute(&format!(
        "ALTER ROLE {SEC_OTHER} SET \"LOG_MIN_ERROR_STATEMENT\" = 'PANIC'"
    ))
    .await
    .unwrap();
    let stored = first_text(
        &a,
        &format!(
            "SELECT array_to_string(s.setconfig, ',') FROM pg_db_role_setting s \
             JOIN pg_roles r ON r.oid = s.setrole WHERE r.rolname = '{SEC_OTHER}'"
        ),
    )
    .await
    .unwrap();
    assert_eq!(stored, "log_min_error_statement=PANIC");
    a.batch_execute(&format!("ALTER ROLE {SEC_OTHER} RESET ALL"))
        .await
        .unwrap();
    // `pg_parameter_acl` (15+) is readable by every role; absent on 14.
    let acl = first_text(
        &a,
        "SELECT count(*) FROM pg_class WHERE relname = 'pg_parameter_acl' \
         AND relnamespace = 'pg_catalog'::regnamespace",
    )
    .await
    .unwrap();
    assert_eq!(acl, if version >= 150_000 { "1" } else { "0" });
    if version >= 150_000 {
        let readable = first_text(
            &a,
            &format!(
                "SELECT has_table_privilege('{}', 'pg_catalog.pg_parameter_acl', 'SELECT')",
                u.user
            ),
        )
        .await
        .unwrap();
        assert_eq!(readable, "t");
        // PARAMETER_GRANTS leaves out superusers and the agent's role.
        a.batch_execute(&format!(
            "GRANT SET ON PARAMETER log_min_messages TO {SEC_OTHER}, {SEC_SUPER}, {}",
            u.user
        ))
        .await
        .unwrap();
        let agent = raw_client(&u, &u.user, &u.password, &u.dbname).await;
        let grantees: BTreeSet<String> = agent
            .query(sql::PARAMETER_GRANTS, &[])
            .await
            .unwrap()
            .iter()
            .filter_map(|r| r.get::<_, Option<String>>(1))
            .collect();
        assert_eq!(grantees, BTreeSet::from([SEC_OTHER.to_owned()]));
        // The agent's own grant: an over-privilege in check()'s detail.
        let (_dir, t) = audit_target(&u, "pg-own-grant", None);
        let detail = PostgresConnector::new()
            .check(&t)
            .await
            .detail
            .unwrap_or_default();
        assert!(
            detail.contains(crate::check::PARAMETER_GRANT_LABEL),
            "{detail}"
        );
        a.batch_execute(&format!(
            "REVOKE SET ON PARAMETER log_min_messages FROM {SEC_OTHER}, {SEC_SUPER}, {}",
            u.user
        ))
        .await
        .unwrap();
    }
    // The minimal-variant role reads pg_db_role_setting with no grant.
    let readable = first_text(
        &a,
        &format!(
            "SELECT has_table_privilege('{}', 'pg_catalog.pg_db_role_setting', 'SELECT')",
            u.user
        ),
    )
    .await
    .unwrap();
    assert_eq!(readable, "t");
    // pg_stat_statements stores the two-key read with its constants as
    // `$n`: its stored text cannot tell a replay with other keys.
    if let Some(pss) = super::it::pss_schema(&a).await {
        let agent = raw_client(&u, &u.user, &u.password, &u.dbname).await;
        agent.query(sql::ROLE_LOG_OVERRIDES, &[]).await.unwrap();
        let stored = first_text(
            &a,
            &format!(
                "SELECT s.query FROM \"{pss}\".pg_stat_statements s \
                 JOIN pg_roles r ON r.oid = s.userid \
                 WHERE r.rolname = '{}' AND s.query LIKE '%pg_db_role_setting%' LIMIT 1",
                u.user
            ),
        )
        .await
        .unwrap();
        assert!(!stored.contains("log_min_messages"), "{stored}");
        assert!(stored.contains("ANY ($"), "{stored}");
        eprintln!("pg_stat_statements form: {stored}");
    }
    // pgaudit relation records (log_relation = on, log_catalog on / off).
    if pgaudit_loaded(&a).await
        && let Some((path, format)) = audit_logs().into_iter().next()
    {
        let reader = SEC_PLAIN.to_owned();
        let size = |p: &std::path::Path| std::fs::metadata(p).map_or(0, |m| m.len());
        let enable = format!(
            "ALTER ROLE {SEC_PLAIN} SET pgaudit.log = 'read'; \
             ALTER ROLE {SEC_PLAIN} SET pgaudit.log_relation = on"
        );
        a.batch_execute(&enable).await.unwrap();
        let plain = client(SEC_PLAIN).await;
        let objects = |recs: &[crate::audit::records::AuditRecord]| -> BTreeSet<String> {
            recs.iter()
                .map(|r| format!("{} {}", r.audit.object_type, r.audit.object_name.as_str()))
                .collect()
        };
        let from = size(&path);
        plain
            .simple_query("SELECT rolname FROM pg_roles WHERE rolsuper")
            .await
            .unwrap();
        let recs = records_of(&path, format, from, &reader, 3).await;
        let got = objects(&recs);
        for want in [
            "VIEW pg_catalog.pg_roles",
            "TABLE pg_catalog.pg_authid",
            "TABLE pg_catalog.pg_db_role_setting",
        ] {
            assert!(got.contains(want), "{got:?}");
        }
        let from = size(&path);
        plain
            .simple_query(&format!("SELECT p FROM public.{VIEW_PW}"))
            .await
            .unwrap();
        let got = objects(&records_of(&path, format, from, &reader, 2).await);
        assert!(got.contains(&format!("VIEW public.{VIEW_PW}")), "{got:?}");
        assert!(got.contains("TABLE pg_catalog.pg_authid"), "{got:?}");
        // log_catalog = off: a catalog-only read is not logged; a user view
        // gets its own record only; `information_schema` entries are
        // logged.
        a.batch_execute(&format!(
            "ALTER ROLE {SEC_PLAIN} SET pgaudit.log_catalog = off"
        ))
        .await
        .unwrap();
        let plain = client(SEC_PLAIN).await;
        let from = size(&path);
        plain
            .simple_query("SELECT setconfig FROM pg_db_role_setting")
            .await
            .unwrap();
        plain
            .simple_query(&format!("SELECT p FROM public.{VIEW_PW}"))
            .await
            .unwrap();
        plain
            .simple_query("SELECT option_name FROM information_schema.user_mapping_options")
            .await
            .unwrap();
        let recs = records_of(&path, format, from, &reader, 2).await;
        let texts: BTreeSet<&str> = recs.iter().map(|r| r.audit.statement.as_str()).collect();
        assert!(
            !texts.iter().any(|t| t.contains("pg_db_role_setting")),
            "{texts:?}"
        );
        let got = objects(&recs);
        assert!(got.contains(&format!("VIEW public.{VIEW_PW}")), "{got:?}");
        assert!(!got.contains("TABLE pg_catalog.pg_authid"), "{got:?}");
        assert!(
            texts.iter().any(|t| t.contains("user_mapping_options")),
            "{texts:?}"
        );
        a.batch_execute(&format!("ALTER ROLE {SEC_PLAIN} RESET ALL"))
            .await
            .unwrap();
    } else {
        skip(
            "pgaudit",
            "pgaudit records not pinned (no pgaudit log here)",
        );
    }
    if let Some((path, before)) = hba {
        std::fs::write(path, before).unwrap();
    }
    teardown(&a, &u.dbname).await;
}

/// The columns and views of decision 8's drift test that are not on the
/// list, each with the reason (they hold no credential or stored value,
/// or are the reading session's own).
const NOT_SECRET: [(&str, &str); 35] = [
    (
        "pg_catalog.pg_attribute.attoptions",
        "attribute options (n_distinct…)",
    ),
    (
        "pg_catalog.pg_attribute.attfdwoptions",
        "FDW column options (open question 3)",
    ),
    ("pg_catalog.pg_class.reloptions", "storage parameters"),
    ("pg_catalog.pg_tablespace.spcoptions", "tablespace costs"),
    (
        "pg_catalog.pg_foreign_data_wrapper.fdwoptions",
        "FDW options (open question 3)",
    ),
    (
        "pg_catalog.pg_foreign_table.ftoptions",
        "foreign table options (open question 3)",
    ),
    (
        "pg_catalog.pg_stat_wal_receiver.conninfo",
        "password obfuscated by the server",
    ),
    (
        "pg_catalog.pg_settings.*",
        "the session's own settings (open question 6)",
    ),
    ("pg_catalog.pg_file_settings.*", "listed (every column)"),
    ("pg_catalog.pg_hba_file_rules.*", "listed (every column)"),
    ("pg_catalog.pg_largeobject.data", "listed (every column)"),
    (
        "pg_catalog.pg_statistic_ext_data.*",
        "an ADR-0048 statistics relation",
    ),
    (
        "pg_catalog.pg_ident_file_mappings.*",
        "user name maps, no secret",
    ),
    (
        "pg_catalog.pg_stats_ext.*",
        "an ADR-0048 statistics relation",
    ),
    (
        "pg_catalog.pg_stats_ext_exprs.*",
        "an ADR-0048 statistics relation",
    ),
    ("pg_catalog.pg_stat_subscription_stats.*", "counters"),
    ("pg_catalog.pg_replication_origin_status.*", "positions"),
    ("information_schema.attributes.*", "column metadata"),
    (
        "information_schema.foreign_data_wrapper_options.*",
        "FDW options (open question 3)",
    ),
    (
        "information_schema.foreign_table_options.*",
        "foreign table options (open question 3)",
    ),
    (
        "information_schema._pg_foreign_data_wrappers.*",
        "FDW options (open question 3)",
    ),
    (
        "information_schema._pg_foreign_tables.*",
        "foreign table options (open question 3)",
    ),
    (
        "information_schema._pg_foreign_table_columns.attfdwoptions",
        "FDW column options (open question 3)",
    ),
    (
        "information_schema.column_options.option_value",
        "FDW column options (open question 3)",
    ),
    (
        "information_schema.sequences.maximum_value",
        "a sequence bound",
    ),
    (
        "information_schema.sequences.minimum_value",
        "a sequence bound",
    ),
    (
        "information_schema.sequences.start_value",
        "a sequence bound",
    ),
    (
        "information_schema.sql_implementation_info.*",
        "server constants",
    ),
    ("information_schema.sql_sizing.*", "server constants"),
    (
        "pg_catalog.pg_extension.extconfig",
        "oids of an extension's configuration tables",
    ),
    ("pg_catalog.pg_sequences.last_value", "a sequence position"),
    ("pg_catalog.pg_sequences.max_value", "a sequence bound"),
    ("pg_catalog.pg_sequences.min_value", "a sequence bound"),
    ("pg_catalog.pg_sequences.start_value", "a sequence bound"),
    (
        "pg_catalog.pg_trigger.tgargs",
        "trigger arguments: code, as function bodies (ADR-0050 open question 10)",
    ),
];

/// The secret columns of decision 1 (views reading one are listed or
/// excepted).
const SECRET_COLUMNS: [&str; 9] = [
    "rolpassword",
    "passwd",
    "useconfig",
    "rolconfig",
    "setconfig",
    "umoptions",
    "srvoptions",
    "subconninfo",
    "proconfig",
];

/// Views of decision 8's drift test whose definition names a secret
/// column without exposing it, with the reason.
const VIEWS_NOT_EXPOSING: [(&str, &str); 3] = [
    ("pg_catalog.pg_stat_activity", "reads pg_authid for names"),
    ("information_schema.user_mappings", "names only"),
    ("information_schema.foreign_servers", "names only"),
];

fn listed_relation(schema: &str, name: &str) -> bool {
    SECRET_RELATIONS
        .iter()
        .any(|e| !e.function && e.schema == schema && e.name == name)
}

fn excepted(schema: &str, rel: &str, col: &str) -> bool {
    NOT_SECRET
        .iter()
        .any(|(k, _)| *k == format!("{schema}.{rel}.{col}") || *k == format!("{schema}.{rel}.*"))
}

/// ADR-0050 decision 8, drift: every relation of `pg_catalog` and
/// `information_schema` with a column whose name holds `password`,
/// `passwd`, `conninfo`, `config` or `options`, or ends in `_value`, and
/// every `bytea` column of `pg_catalog`, is listed or excepted with a
/// reason; every view whose definition reads a secret column is listed or
/// excepted; and every entry of the list exists on this server.
#[tokio::test]
async fn secret_catalogs_match_the_server() {
    let Some(adm) = admin_url() else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let a = admin(&adm, &adm.dbname).await;
    let rows = a
        .query(
            "SELECT n.nspname::text, c.relname::text, a.attname::text, t.typname::text \
             FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 \
               AND NOT a.attisdropped \
             JOIN pg_catalog.pg_type t ON t.oid = a.atttypid \
             WHERE n.nspname IN ('pg_catalog', 'information_schema') \
               AND c.relkind IN ('r', 'v', 'm', 'p', 'f') \
               AND (a.attname ~ '(password|passwd|conninfo|config|options)' \
                    OR a.attname ~ '_value$' \
                    OR (n.nspname = 'pg_catalog' AND t.typname = 'bytea')) \
             ORDER BY 1, 2, 3",
            &[],
        )
        .await
        .unwrap();
    let mut missing = Vec::new();
    for r in &rows {
        let (schema, rel, col): (String, String, String) = (r.get(0), r.get(1), r.get(2));
        if listed_relation(&schema, &rel) || excepted(&schema, &rel, &col) {
            continue;
        }
        missing.push(format!("{schema}.{rel}.{col}"));
    }
    let pattern = SECRET_COLUMNS.join("|");
    let views = a
        .query(
            &format!(
                "SELECT n.nspname::text, c.relname::text FROM pg_catalog.pg_class c \
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                 WHERE n.nspname IN ('pg_catalog', 'information_schema') AND c.relkind = 'v' \
                   AND pg_catalog.pg_get_viewdef(c.oid) ~ '({pattern})' ORDER BY 1, 2"
            ),
            &[],
        )
        .await
        .unwrap();
    for r in &views {
        let (schema, rel): (String, String) = (r.get(0), r.get(1));
        let name = format!("{schema}.{rel}");
        if listed_relation(&schema, &rel)
            || VIEWS_NOT_EXPOSING.iter().any(|(v, _)| *v == name)
            || excepted(&schema, &rel, "*")
        {
            continue;
        }
        missing.push(format!("view {name}"));
    }
    assert!(missing.is_empty(), "not listed nor excepted: {missing:#?}");
    // Every entry exists (relations and functions).
    for e in SECRET_RELATIONS {
        let q = if e.function {
            format!(
                "SELECT count(*) FROM pg_catalog.pg_proc WHERE proname = '{}' \
                 AND pronamespace = '{}'::regnamespace",
                e.name, e.schema
            )
        } else {
            format!(
                "SELECT count(*) FROM pg_catalog.pg_class WHERE relname = '{}' \
                 AND relnamespace = '{}'::regnamespace",
                e.name, e.schema
            )
        };
        let n: i64 = a.query_one(&q, &[]).await.unwrap().get(0);
        assert!(n >= 1, "{}.{} missing", e.schema, e.name);
        // Each listed secret column exists on its relation.
        for c in e.columns {
            let n: i64 = a
                .query_one(
                    &format!(
                        "SELECT count(*) FROM pg_catalog.pg_attribute WHERE attname = '{c}' \
                         AND attrelid = '{}.{}'::regclass",
                        e.schema, e.name
                    ),
                    &[],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(n, 1, "{}.{c}", e.name);
        }
    }
    // The exception lists hold no listed relation, except the entries
    // listed with every column (their own reason says so).
    for (k, why) in NOT_SECRET.iter().chain(VIEWS_NOT_EXPOSING.iter()) {
        let mut parts = k.split('.');
        let (schema, rel) = (parts.next().unwrap(), parts.next().unwrap());
        assert_eq!(
            listed_relation(schema, rel),
            why.starts_with("listed"),
            "{k}: {why}"
        );
    }
}
