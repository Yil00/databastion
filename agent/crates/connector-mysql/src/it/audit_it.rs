//! Audit integration tests (P4-B) against the dev servers.
//!
//! - `DATABASTION_TEST_MARIADB_AUDIT_LOG`: the MariaDB `server_audit` log
//!   as the agent host sees it (`dev/.state/logs/mariadb/server_audit.log`,
//!   bind-mounted, 0644 in dev only). Skip key `mariadb-audit`.
//! - `DATABASTION_TEST_PERCONA_URL`, `…_ADMIN_URL`, `…_CA_FILE`: the Percona
//!   Server of `dev/` (skip key `percona`), and
//!   `DATABASTION_TEST_PERCONA_AUDIT_LOG`, its `audit_log_filter` JSON log
//!   (`dev/.state/logs/percona/audit_filter.log`, skip key
//!   `percona-audit`).
//! - `DATABASTION_TEST_<S>_DUMP_CMD` (`MARIADB`, `PERCONA`, `MYSQL`): a shell command
//!   running the real `mysqldump` / `mariadb-dump` against the server (e.g.
//!   `docker compose -f …/dev/docker-compose.yml exec -T … mariadb-dump …`).
//!   Without it, only the simulated dump runs (skip key `mysqldump`).
//! - The `performance_schema` source runs on MySQL and MariaDB with a test
//!   account created with the Audit grant (the dev agent accounts stay
//!   minimal).
//!
//! Client addresses are those the server reports (`USER()`): in CI the
//! servers run in Docker and see the bridge gateway, never loopback.

use std::path::Path;

use databastion_classifiers::masking::{ClientAddr, EventAction, EventSource, MaskedEvent};

use super::*;
use crate::check::CheckState;

/// Marker planted in literals of audited statements: it must never appear
/// in an event or a log line (I2, ADR-0007).
const AUDIT_MARKER: &str = "it-audit-marker-7Qz@example.test";
/// Test database of the `performance_schema` tests.
const AUDIT_DB: &str = "databastion_audit_it";
/// Test account of the MariaDB `performance_schema` test.
const PFS_USER: &str = "databastion_it_pfs";
/// Rows of the large table (above `volume.large_result`).
const BIG_ROWS: u64 = 20_000;

type Events = Vec<MaskedEvent>;

fn describe(e: &MaskedEvent) -> String {
    format!(
        "{:?} user={} app={:?} client={:?} objects={:?} rows={:?} signals={:?} source={}",
        e.action(),
        if e.principal().send_name() {
            e.principal().account_name()
        } else {
            "<fingerprint>"
        },
        e.principal().application(),
        e.principal().client(),
        e.objects()
            .iter()
            .map(|o| format!("{}.{}", o.database().as_str(), o.object().as_str()))
            .collect::<Vec<_>>(),
        e.rows(),
        e.signals().iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        e.source().as_str()
    )
}

fn has(events: &[MaskedEvent], object: &str, signal: &str) -> bool {
    events.iter().any(|e| {
        e.objects().iter().any(|o| o.object().as_str() == object)
            && e.signals().iter().any(|s| s.as_str() == signal)
    })
}

/// Collects events until `done` holds or `timeout`.
async fn collect_until(
    rx: &mut tokio::sync::mpsc::Receiver<MaskedEvent>,
    out: &mut Events,
    timeout: Duration,
    done: impl Fn(&[MaskedEvent]) -> bool,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !done(out) {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(e)) => out.push(e),
            _ => break,
        }
    }
}

/// Runs `audit_stream` in a task (poll interval 1 s, cursors in `state`).
fn start_audit(
    connector: Arc<MysqlConnector>,
    t: &TargetConfig,
    state: &Path,
) -> (
    tokio::task::JoinHandle<Result<(), ConnectorError>>,
    tokio::sync::mpsc::Receiver<MaskedEvent>,
) {
    let limits = Limits {
        min_audit_poll_interval_s: 1,
        ..Limits::default()
    };
    let cfg = databastion_core::AuditConfig::local(t, 1, &limits).with_state_dir(state.to_owned());
    let (sink, rx) = databastion_core::EventSink::channel(10_000);
    let task = tokio::spawn(async move { connector.audit_stream(&cfg, &sink).await });
    (task, rx)
}

/// A target for `user` with the dev TLS settings and an optional audit log.
fn audit_target(
    server: &Server,
    user: &str,
    password: &str,
    log: Option<(&Path, &str)>,
) -> (TempDir, TargetConfig) {
    let audit = log.map_or(String::new(), |(p, f)| {
        format!(", audit_log: {{path: \"{}\", format: {f}}}", p.display())
    });
    target_tls(server, user, password, &format!("{}{audit}", server.tls()))
}

fn env_path(var: &str, key: &str) -> Option<PathBuf> {
    // A dev log may belong to the test's own user (the tailer refuses it
    // in production).
    databastion_core::audit::tail::allow_agent_owned_logs_for_tests();
    match std::env::var(var) {
        Ok(p) if !p.is_empty() => Some(PathBuf::from(p)),
        _ => {
            skip(
                key,
                &format!("{var} is not set (audit log of the dev server)"),
            );
            None
        }
    }
}

/// The Percona Server of `dev/`.
fn percona() -> Option<Server> {
    let var = |s: &str| std::env::var(format!("DATABASTION_TEST_PERCONA_{s}")).ok();
    let (Some(url), Some(ca)) = (var("URL").as_deref().and_then(parse_url), var("CA_FILE")) else {
        skip(
            "percona",
            "DATABASTION_TEST_PERCONA_URL / _CA_FILE are not set (start `make dev`)",
        );
        return None;
    };
    Some(Server {
        name: "mysql",
        url,
        admin: var("ADMIN_URL").as_deref().and_then(parse_url),
        ca: Some(ca),
    })
}

/// Runs the real dump command of `server` (`DATABASTION_TEST_<S>_DUMP_CMD`).
fn real_dump(label: &str) -> bool {
    let var = format!("DATABASTION_TEST_{label}_DUMP_CMD");
    let Ok(cmd) = std::env::var(&var) else {
        skip(
            "mysqldump",
            &format!("{var} is not set (real dump tool run)"),
        );
        return false;
    };
    let out = std::process::Command::new("sh")
        .args(["-c", &cmd])
        .stdout(std::process::Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => true,
        Ok(o) => panic!(
            "{var} failed: {:?} {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => panic!("{var} failed to start: {e}"),
    }
}

/// The client address the server sees for a session (`USER()`).
async fn seen_address(s: &mut Session) -> Option<ClientAddr> {
    let user = scalar(s, "SELECT USER()").await.unwrap_or_default();
    crate::audit::own_address(&user)
}

/// Checks that nothing of the marker reached the events or the logs.
fn assert_no_marker(events: &[MaskedEvent], logs: &Logs) {
    let all: String = events.iter().map(describe).collect::<Vec<_>>().join("\n");
    assert!(!all.contains(AUDIT_MARKER), "marker in events");
    assert!(!all.contains("7Qz"), "marker in events");
    let text = logs.text();
    assert!(!text.contains("7Qz"), "marker in the logs");
}

/// The audit-log source: check(), own address, the simulated and real
/// dumps, `INTO OUTFILE`, a filtered read with a marker literal, and the
/// agent's own Discovery reads.
#[allow(clippy::too_many_arguments)]
async fn audit_log_scenario(
    label: &str,
    server: &Server,
    admin: &Url,
    log: &Path,
    format: &str,
    source: EventSource,
    database: &str,
    table: &str,
) {
    let logs = Logs::default();
    let _guard = logs.capture();
    let state = TempDir::new();
    let (_d, t) = audit_target(
        server,
        &server.url.user,
        &server.url.password,
        Some((log, format)),
    );
    let connector = Arc::new(MysqlConnector::new());
    // No record read yet: one level below Partial, from the log.
    let health = connector.check(&t).await;
    assert!(health.reachable, "{label}: {health:?}");
    assert_eq!(
        health.audit_level,
        AuditLevel::Limited,
        "{label}: {health:?}"
    );
    assert_eq!(connector.audit_source(&t), Some(source));
    let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
    // The tailer starts at the end of the log: let it open it.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let mut a = admin_session(server, admin).await;
    let admin_addr = seen_address(&mut a).await;
    let pre = crate::audit::prerequisites(
        &CheckState::default(),
        &t,
        Timeouts::new(Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert_eq!(
        pre.own_addr, admin_addr,
        "{label}: agent address as seen by the server (same route as the test's)"
    );
    // A simulated dump of one table (what mysqldump / mariadb-dump send).
    let dump = format!("SELECT /*!40001 SQL_NO_CACHE */ * FROM `{database}`.`{table}`");
    a.query(Stage::Check, &dump).await.unwrap();
    // A filtered read with a marker literal: an event, no signal, no
    // marker anywhere.
    a.query(
        Stage::Check,
        &format!("SELECT 1 FROM `{database}`.`{table}` WHERE '{AUDIT_MARKER}' = 'x'"),
    )
    .await
    .unwrap();
    // An export attempt to a server file (refused by the server).
    let refused = a
        .query(
            Stage::Check,
            &format!(
                "SELECT * FROM `{database}`.`{table}` INTO OUTFILE '/nonexistent-dir/it-{AUDIT_MARKER}'"
            ),
        )
        .await;
    assert!(refused.is_err(), "{label}: INTO OUTFILE must fail here");
    drop(a);
    // The agent's own Discovery scan: its sampling reads are left out
    // when the agent's address is known.
    let (r, _) = scan(&agent_target(server).1).await;
    r.unwrap();
    let real = real_dump(label);
    let mut events: Events = Vec::new();
    collect_until(&mut rx, &mut events, Duration::from_secs(30), |ev| {
        has(ev, table, "signature.mysqldump")
            && has(ev, table, "signature.into_outfile")
            && ev.iter().any(|e| {
                e.action() == EventAction::Read
                    && e.signals().is_empty()
                    && e.objects().iter().any(|o| o.object().as_str() == table)
                    && e.principal().account_name() == admin.user
            })
            && (!real
                || ev.iter().any(|e| {
                    e.principal().client() != admin_addr
                        && e.signals()
                            .iter()
                            .any(|s| s.as_str() == "signature.mysqldump")
                }))
    })
    .await;
    // A little more for the agent's own reads, if any slipped through.
    collect_until(&mut rx, &mut events, Duration::from_secs(3), |_| false).await;
    let all: Vec<String> = events.iter().map(describe).collect();
    eprintln!("{label} events ({}):\n{}", all.len(), all.join("\n"));
    assert!(
        has(&events, table, "signature.mysqldump"),
        "{label}: {all:#?}"
    );
    assert!(has(&events, table, "shape.full_table_read"), "{label}");
    assert!(has(&events, table, "signature.into_outfile"), "{label}");
    assert!(
        events.iter().all(|e| e.source() == source),
        "{label}: {all:#?}"
    );
    assert!(
        events.iter().all(|e| e.rows().is_none()),
        "{label}: the audit logs carry no row count"
    );
    if real {
        let dumped: Vec<&MaskedEvent> = events
            .iter()
            .filter(|e| {
                // Run inside the container: another client address than
                // the test's session.
                e.principal().client() != admin_addr
                    && e.signals()
                        .iter()
                        .any(|s| s.as_str() == "signature.mysqldump")
            })
            .collect();
        assert!(!dumped.is_empty(), "{label}: real dump not seen: {all:#?}");
        if source == EventSource::MysqlAuditLog {
            // audit_log_filter logs the client's program_name at connect.
            assert!(
                dumped
                    .iter()
                    .all(|e| e.principal().application() == Some("mysqldump")),
                "{label}: {all:#?}"
            );
        }
    }
    let admin_events: Vec<&MaskedEvent> = events
        .iter()
        .filter(|e| e.principal().account_name() == admin.user)
        .collect();
    assert!(
        admin_events
            .iter()
            .any(|e| e.principal().client() == admin_addr && admin_addr.is_some())
            || admin_addr.is_none(),
        "{label}: client address as logged"
    );
    if pre.own_addr.is_some() {
        assert!(
            !events
                .iter()
                .any(|e| e.principal().account_name() == server.url.user
                    && e.action() == EventAction::Read
                    && e.signals().is_empty()),
            "{label}: the agent's own sampling reads were reported: {all:#?}"
        );
    }
    assert_no_marker(&events, &logs);
    // A record was read: Partial.
    let health = connector.check(&t).await;
    assert_eq!(
        health.audit_level,
        AuditLevel::Partial,
        "{label}: {health:?}"
    );
    task.abort();
}

#[tokio::test]
async fn server_audit_log_gives_events_and_export_signatures() {
    let _serial = SERIAL.lock().await;
    let Some(server) = servers().into_iter().find(|s| s.name == "mariadb") else {
        return;
    };
    let Some(admin) = server.admin() else {
        return;
    };
    let Some(log) = env_path("DATABASTION_TEST_MARIADB_AUDIT_LOG", "mariadb-audit") else {
        return;
    };
    audit_log_scenario(
        "MARIADB",
        &server,
        &admin,
        &log,
        "server_audit",
        EventSource::MariadbServerAudit,
        &server.url.dbname,
        "tickets",
    )
    .await;
}

#[tokio::test]
async fn audit_log_json_gives_events_and_export_signatures() {
    let _serial = SERIAL.lock().await;
    let Some(server) = percona() else {
        return;
    };
    let Some(admin) = server.admin.clone() else {
        skip("percona", "DATABASTION_TEST_PERCONA_ADMIN_URL is not set");
        return;
    };
    let Some(log) = env_path("DATABASTION_TEST_PERCONA_AUDIT_LOG", "percona-audit") else {
        return;
    };
    audit_log_scenario(
        "PERCONA",
        &server,
        &admin,
        &log,
        "json",
        EventSource::MysqlAuditLog,
        &server.url.dbname,
        "employees",
    )
    .await;
}

/// Creates the `performance_schema` test database (a large table).
async fn audit_fixture(a: &mut Session) {
    for statement in [
        format!("DROP DATABASE IF EXISTS {AUDIT_DB}"),
        format!("CREATE DATABASE {AUDIT_DB}"),
        format!("CREATE TABLE {AUDIT_DB}.d (i INT)"),
        format!("INSERT INTO {AUDIT_DB}.d VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)"),
        format!("CREATE TABLE {AUDIT_DB}.big (i INT, v VARCHAR(20))"),
        format!(
            "INSERT INTO {AUDIT_DB}.big SELECT n, CONCAT('v', n) FROM (SELECT \
             a.i * 10000 + b.i * 1000 + c.i * 100 + e.i * 10 + f.i AS n \
             FROM {AUDIT_DB}.d a, {AUDIT_DB}.d b, {AUDIT_DB}.d c, {AUDIT_DB}.d e, {AUDIT_DB}.d f) s \
             WHERE n < {BIG_ROWS}"
        ),
    ] {
        exec(a, &statement).await;
    }
}

#[tokio::test]
async fn performance_schema_gives_events_with_rows() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        audit_fixture(&mut a).await;
        // A test account with the Audit grant (ADR-0018): the dev agent
        // accounts stay minimal (MariaDB reads its server_audit log).
        exec(&mut a, &format!("DROP USER IF EXISTS '{PFS_USER}'@'%'")).await;
        exec(
            &mut a,
            &format!("CREATE USER '{PFS_USER}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        )
        .await;
        exec(
            &mut a,
            &format!(
                "GRANT SELECT ON {}.* TO '{PFS_USER}'@'%'",
                server.url.dbname
            ),
        )
        .await;
        exec(
            &mut a,
            &format!("GRANT SELECT ON performance_schema.* TO '{PFS_USER}'@'%'"),
        )
        .await;
        let (user, password) = (PFS_USER.to_owned(), IT_PASSWORD.to_owned());
        let (_d, t) = audit_target(&server, &user, &password, None);
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
        let detail = health.detail.unwrap_or_default();
        assert!(
            detail.contains("SELECT on performance_schema without Audit enabled"),
            "{}: {detail}",
            server.name
        );
        let state = TempDir::new();
        let (task, mut rx) = start_audit(Arc::clone(&connector), &t, &state.0);
        // First poll places the cursor at the newest statement.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        // While Audit runs, the grant is the Audit grant.
        let detail = connector.check(&t).await.detail.unwrap_or_default();
        assert!(
            !detail.contains("without Audit"),
            "{}: {detail}",
            server.name
        );
        a.query(Stage::Check, &format!("SELECT * FROM {AUDIT_DB}.big"))
            .await
            .unwrap();
        a.query(
            Stage::Check,
            &format!("SELECT /*!40001 SQL_NO_CACHE */ * FROM `{AUDIT_DB}`.`d`"),
        )
        .await
        .unwrap();
        a.query(
            Stage::Check,
            &format!("SELECT i FROM {AUDIT_DB}.big WHERE v = '{AUDIT_MARKER}'"),
        )
        .await
        .unwrap();
        let _ = a
            .query(
                Stage::Check,
                &format!("SELECT * FROM {AUDIT_DB}.d INTO OUTFILE '/nonexistent-dir/x'"),
            )
            .await;
        // The real tool, run inside the container: a short session, ended
        // before the next poll (its account is then unknown), detected by
        // its statements.
        let real = server.name == "mysql" && real_dump("MYSQL");
        // A password statement: MariaDB keeps it in clear in SQL_TEXT.
        exec(&mut a, "DROP USER IF EXISTS 'databastion_it_pw'@'%'").await;
        exec(
            &mut a,
            &format!("CREATE USER 'databastion_it_pw'@'%' IDENTIFIED BY '{AUDIT_MARKER}'"),
        )
        .await;
        exec(&mut a, "DROP USER 'databastion_it_pw'@'%'").await;
        let mut events: Events = Vec::new();
        collect_until(&mut rx, &mut events, Duration::from_secs(30), |ev| {
            has(ev, "big", "volume.large_result")
                && has(ev, "d", "signature.mysqldump")
                && has(ev, "d", "signature.into_outfile")
                && ev.iter().any(|e| e.action() == EventAction::Dcl)
                && (!real || has(ev, "employees", "signature.mysqldump"))
        })
        .await;
        let all: Vec<String> = events.iter().map(describe).collect();
        eprintln!(
            "{} performance_schema events:\n{}",
            server.name,
            all.join("\n")
        );
        assert!(
            has(&events, "big", "volume.large_result"),
            "{}: {all:#?}",
            server.name
        );
        assert!(
            has(&events, "big", "shape.full_table_read"),
            "{}",
            server.name
        );
        assert!(
            events.iter().any(|e| e.rows() == Some(BIG_ROWS)
                && e.objects().iter().any(|o| o.object().as_str() == "big")),
            "{}: rows of the large read: {all:#?}",
            server.name
        );
        assert!(has(&events, "d", "signature.mysqldump"), "{}", server.name);
        assert!(
            has(&events, "d", "signature.into_outfile"),
            "{}",
            server.name
        );
        assert!(
            events.iter().any(|e| e.action() == EventAction::Dcl),
            "{}",
            server.name
        );
        if real {
            assert!(
                has(&events, "employees", "signature.mysqldump"),
                "{}: real mysqldump not seen: {all:#?}",
                server.name
            );
        }
        assert!(
            events
                .iter()
                .all(|e| e.source() == EventSource::PerformanceSchema)
        );
        // The admin session is still connected: named, with its address.
        let admin_addr = seen_address(&mut a).await;
        assert!(
            events
                .iter()
                .any(|e| e.principal().account_name() == admin.user
                    && e.principal().client() == admin_addr),
            "{}: {all:#?}",
            server.name
        );
        let now = std::time::SystemTime::now();
        assert!(events.iter().all(|e| e.ts() <= now));
        assert_no_marker(&events, &logs);
        // Phase 7 (ADR-0025 decision 11): the stream re-probes its
        // prerequisites on its held session (every 3 s in tests), so it
        // never holds a second connection of the account.
        let mut most = 0u64;
        for _ in 0..40 {
            let n = scalar(
                &mut a,
                &format!(
                    "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE USER = '{PFS_USER}'"
                ),
            )
            .await
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
            most = most.max(n);
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert_eq!(most, 1, "{}: Audit connections held at once", server.name);
        // Phase 7: the cursor is persisted. After a quiet poll (the cursor
        // saved past everything handed over), the agent stops.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        task.abort();
        let _ = task.await;
        let saved = std::fs::read(state.0.join(format!("{}.performance_schema.cursor", t.id)))
            .expect("performance_schema cursor saved");
        let saved = String::from_utf8_lossy(&saved);
        assert!(saved.contains("\"boot\""), "{}: {saved}", server.name);
        assert!(!saved.contains(AUDIT_MARKER), "{}", server.name);
        // What runs while the agent is stopped is reported after its
        // restart (a new connector: nothing kept in memory), and what was
        // reported before is not reported again.
        exec(&mut a, &format!("CREATE TABLE {AUDIT_DB}.stopped (i INT)")).await;
        a.query(
            Stage::Check,
            &format!("SELECT /*!40001 SQL_NO_CACHE */ * FROM `{AUDIT_DB}`.`stopped`"),
        )
        .await
        .unwrap();
        let restarted = Arc::new(MysqlConnector::new());
        let (task, mut rx) = start_audit(Arc::clone(&restarted), &t, &state.0);
        let mut after: Events = Vec::new();
        collect_until(&mut rx, &mut after, Duration::from_secs(30), |ev| {
            has(ev, "stopped", "signature.mysqldump")
        })
        .await;
        let all: Vec<String> = after.iter().map(describe).collect();
        assert!(
            has(&after, "stopped", "signature.mysqldump"),
            "{}: a statement run while the agent was stopped: {all:#?}",
            server.name
        );
        assert!(
            !has(&after, "big", "volume.large_result"),
            "{}: reported again after the restart: {all:#?}",
            server.name
        );
        assert_no_marker(&after, &logs);
        task.abort();
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {AUDIT_DB}")).await;
        exec(&mut a, &format!("DROP USER IF EXISTS '{PFS_USER}'@'%'")).await;
    }
}
