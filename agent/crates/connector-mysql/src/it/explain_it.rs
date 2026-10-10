//! `EXPLAIN` / `DESCRIBE` of a statement as a read (ADR-0047) against the
//! dev servers, on the three sources: `performance_schema` (MySQL 8.4 and
//! MariaDB 11.4), the MariaDB `server_audit` log (`QUERY_DML` and `TABLE`
//! records) and the Percona `audit_log_filter` JSON log.
//!
//! A second account walks a table with `EXPLAIN SELECT * FROM t WHERE id =
//! n` (the optimizer reads the `const` row) and `SHOW WARNINGS` (Note 1003
//! holds its values on MySQL), and gets one read event naming the table
//! per explain, always reported (never dropped by `min_rows`) and with no
//! row count; its `DESCRIBE t` and its literal probe shape (`EXPLAIN SELECT
//! 1 FROM t`) give none. The agent's own readability probes (`check()`)
//! give none on any source. No seeded value reaches an event or a log.

use databastion_classifiers::masking::{EventAction, EventSource, MaskedEvent};

use super::audit_it::{audit_target, collect_until, describe, env_path, percona, start_audit};
use super::*;

/// Test database.
const EX_DB: &str = "databastion_explain_it";
/// The account that explains (`SELECT` on [`EX_DB`] only).
const EX_USER: &str = "databastion_it_explainer";
/// The agent's account of the `performance_schema` test.
const EX_AGENT: &str = "databastion_it_ex_agent";
/// Seeded values: never in an event or a log line (I2).
const EX_EMAIL: &str = "explain-it-4Kp@example.test";
/// Explains of the walk (one per primary key).
const WALK: u64 = 3;

/// The fixture: a table with seeded rows, and the explaining account.
async fn ex_fixture(a: &mut Session) {
    for statement in [
        format!("DROP DATABASE IF EXISTS {EX_DB}"),
        format!("CREATE DATABASE {EX_DB}"),
        format!(
            "CREATE TABLE {EX_DB}.customers (id INT PRIMARY KEY, email VARCHAR(200) UNIQUE, \
             name VARCHAR(100)) ENGINE=InnoDB"
        ),
        format!(
            "INSERT INTO {EX_DB}.customers VALUES (1, '1{EX_EMAIL}', 'Alice 4Kp'), \
             (2, '2{EX_EMAIL}', 'Bob 4Kp'), (3, '3{EX_EMAIL}', 'Carol 4Kp')"
        ),
        format!("DROP USER IF EXISTS '{EX_USER}'@'%'"),
        format!("CREATE USER '{EX_USER}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        format!("GRANT SELECT ON {EX_DB}.* TO '{EX_USER}'@'%'"),
    ] {
        exec(a, &statement).await;
    }
}

/// The explaining session, kept open until the events are collected
/// (`performance_schema` names a statement's account from its session's
/// thread).
struct Held {
    _dir: TempDir,
    _session: Session,
}

/// The second account's traffic: the walk, each explain followed by `SHOW
/// WARNINGS`, then the metadata form and the probe shape.
async fn ex_traffic(server: &Server) -> Held {
    let (dir, t) = target(server, EX_USER, IT_PASSWORD);
    let mut s = Session::connect(&t, Timeouts::new(Duration::from_secs(30)))
        .await
        .unwrap();
    for n in 1..=WALK {
        let rows = s
            .query(
                Stage::Check,
                &format!("EXPLAIN SELECT * FROM {EX_DB}.customers WHERE id = {n}"),
            )
            .await
            .unwrap();
        assert!(!rows.is_empty(), "{}: no plan", server.name);
        s.query(Stage::Check, "SHOW WARNINGS").await.unwrap();
    }
    for statement in [
        format!("DESCRIBE {EX_DB}.customers"),
        format!("EXPLAIN SELECT 1 FROM {EX_DB}.customers"),
    ] {
        s.query(Stage::Check, &statement).await.unwrap();
    }
    Held {
        _dir: dir,
        _session: s,
    }
}

/// An explain event of the walk: a read of the table, always reported,
/// with no row count and no signal.
fn walk_read(e: &MaskedEvent) -> bool {
    e.principal().account_name() == EX_USER
        && e.action() == EventAction::Read
        && e.always_report()
        && e.rows().is_none()
        && e.signals().is_empty()
        && e.objects().len() == 1
        && e.objects()
            .iter()
            .all(|o| o.database().as_str() == EX_DB && o.object().as_str() == "customers")
}

fn walk_reads(ev: &[MaskedEvent]) -> usize {
    ev.iter().filter(|e| walk_read(e)).count()
}

/// Checks the events and logs of one source: one read per explain of the
/// walk, no other event from the explaining account but connections, no
/// event naming the agent's probe tables, and no seeded value anywhere.
fn ex_check(label: &str, ev: &[MaskedEvent], logs: &Logs) {
    let all: Vec<String> = ev.iter().map(describe).collect();
    eprintln!("{label} events ({}):\n{}", all.len(), all.join("\n"));
    assert_eq!(walk_reads(ev), WALK as usize, "{label}: {all:#?}");
    assert!(
        ev.iter()
            .filter(|e| e.principal().account_name() == EX_USER)
            .all(|e| walk_read(e) || e.action() == EventAction::Connect),
        "{label}: DESCRIBE, SHOW WARNINGS or the probe shape gave an event: {all:#?}"
    );
    // The agent's readability probes (`check()`): no event, from any
    // principal (a digest-only record has none).
    assert!(
        !ev.iter().any(|e| e.objects().iter().any(|o| {
            o.database().as_str() == "performance_schema"
                && o.object().as_str().starts_with("events_statements_")
        })),
        "{label}: a probe gave an event: {all:#?}"
    );
    let joined = all.join("\n");
    for leak in ["4Kp", "Alice", "example.test"] {
        assert!(!joined.contains(leak), "{label}: {leak} in an event");
        assert!(!logs.text().contains(leak), "{label}: {leak} in the logs");
    }
}

/// ADR-0047 on the `performance_schema` source (MySQL and MariaDB).
#[tokio::test]
async fn explains_are_reads_on_performance_schema() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        ex_fixture(&mut a).await;
        exec(&mut a, &format!("DROP USER IF EXISTS '{EX_AGENT}'@'%'")).await;
        exec(
            &mut a,
            &format!("CREATE USER '{EX_AGENT}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
        exec(
            &mut a,
            &format!("GRANT SELECT ON performance_schema.* TO '{EX_AGENT}'@'%'"),
        )
        .await;
        let (_d, t) = target(&server, EX_AGENT, IT_PASSWORD);
        let connector = Arc::new(MysqlConnector::new());
        let health = connector.check(&t).await;
        assert_eq!(
            health.audit_level,
            AuditLevel::Partial,
            "{}: {health:?}",
            server.name
        );
        assert_eq!(
            connector.audit_source(&t),
            Some(EventSource::PerformanceSchema)
        );
        tokio::time::sleep(Duration::from_secs(3)).await;
        let state = TempDir::new();
        let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        // The agent's probes, on heartbeat sessions the stream sees.
        for _ in 0..3 {
            assert!(connector.check(&t).await.reachable, "{}", server.name);
        }
        let held = ex_traffic(&server).await;
        let mut ev: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx, &mut ev, Duration::from_secs(30), |e| {
            walk_reads(e) >= WALK as usize
        })
        .await;
        for _ in 0..2 {
            assert!(connector.check(&t).await.reachable, "{}", server.name);
        }
        collect_until(&mut rx, &mut ev, Duration::from_secs(4), |_| false).await;
        task.abort();
        drop(held);
        ex_check(&format!("{} performance_schema", server.name), &ev, &logs);
        for user in [EX_AGENT, EX_USER] {
            exec(&mut a, &format!("DROP USER IF EXISTS '{user}'@'%'")).await;
        }
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {EX_DB}")).await;
    }
}

/// ADR-0047 on the audit log files: MariaDB `server_audit` (with `TABLE`
/// read records of the explained statement) and the Percona
/// `audit_log_filter` JSON log (with `table_access` records).
#[tokio::test]
async fn explains_are_reads_on_audit_logs() {
    let _serial = SERIAL.lock().await;
    let mariadb = servers()
        .into_iter()
        .find(|s| s.name == "mariadb")
        .and_then(|s| {
            let log = env_path("DATABASTION_TEST_MARIADB_AUDIT_LOG", "mariadb-audit")?;
            Some((s, log, "server_audit", EventSource::MariadbServerAudit))
        });
    let percona = percona().and_then(|s| {
        let log = env_path("DATABASTION_TEST_PERCONA_AUDIT_LOG", "percona-audit")?;
        Some((s, log, "json", EventSource::MysqlAuditLog))
    });
    for (server, log, format, source) in mariadb.into_iter().chain(percona) {
        let Some(admin) = server.admin.clone() else {
            continue;
        };
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        ex_fixture(&mut a).await;
        let (_d, t) = audit_target(
            &server,
            &server.url.user,
            &server.url.password,
            Some((&log, format)),
        );
        let connector = Arc::new(MysqlConnector::new());
        assert!(connector.check(&t).await.reachable, "{format}");
        assert_eq!(connector.audit_source(&t), Some(source));
        let state = TempDir::new();
        let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        for _ in 0..3 {
            assert!(connector.check(&t).await.reachable, "{format}");
        }
        let held = ex_traffic(&server).await;
        let mut ev: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx, &mut ev, Duration::from_secs(30), |e| {
            walk_reads(e) >= WALK as usize
        })
        .await;
        // The probe shape's records are grouped until the connection's
        // next record: its disconnection.
        drop(held);
        collect_until(&mut rx, &mut ev, Duration::from_secs(4), |_| false).await;
        task.abort();
        ex_check(&format!("{} {format}", server.name), &ev, &logs);
        exec(&mut a, &format!("DROP USER IF EXISTS '{EX_USER}'@'%'")).await;
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {EX_DB}")).await;
    }
}
