//! The agent's own sessions on the `performance_schema` source (phase 8
//! follow-ups: security reviews of #186, L1, and of #197, M3), against the
//! dev MySQL, MariaDB and Percona servers.
//!
//! Two targets with the same account on one server, each with its stream:
//! - a Discovery scan of the first target, run between two polls of its
//!   stream (poll interval [`SLOW_POLL_S`] s), so that its sessions have
//!   ended when the stream reads their statements: they are the agent's
//!   (pinned), charged to its budget and left out, for its own stream and
//!   for the sibling's;
//! - the first stream reconnects (its session replaced as a stale one) and
//!   the sibling stream restarts from its saved cursor: the ended poll
//!   sessions' probes and polls are dropped, not reported as reads of the
//!   statement-text tables by an unknown principal.
//!
//! No event has an unknown principal, except the dev healthchecks' reads
//! of `hr.employees` (`dev/docker-compose.yml`); no event has the agent's
//! account (its address as the server sees it is an IP literal on the dev
//! network); each target's own-read budget holds a charge of the scanned
//! tables on `events_statements_history_long` (the per-thread tables of
//! the Limited level drop a thread's statements when it ends); no sampled
//! value reaches an event or a log line (I2).

use std::sync::atomic::Ordering;

use databastion_classifiers::masking::{EventSource, MaskedEvent};

use super::audit_it::{collect_until, describe, percona};
use super::*;
use crate::audit::FORCE_PS_RECONNECT;

/// The agent's account of the test.
const OS_USER: &str = "databastion_it_osess";
/// The scanned database.
const OS_DB: &str = "databastion_own_sessions_it";
/// A value in the scanned table: never in an event or a log line.
const OS_MARKER: &str = "own-sessions-marker-4Kp@example.test";
/// Columns of the wide table, with long names: sampled in several batches
/// (extra batches consume sampling credits).
const WIDE_COLUMNS: usize = 30;
/// Poll interval of the first target's stream.
const SLOW_POLL_S: u32 = 6;

fn wide_column(i: usize) -> String {
    format!("c{i:02}_{}", "x".repeat(56))
}

/// Runs `audit_stream` in a task (poll interval `poll_s`, cursors in
/// `state`).
fn stream(
    connector: &Arc<MysqlConnector>,
    t: &TargetConfig,
    state: &std::path::Path,
    poll_s: u32,
) -> (
    tokio::task::JoinHandle<Result<(), ConnectorError>>,
    tokio::sync::mpsc::Receiver<MaskedEvent>,
) {
    let limits = Limits {
        min_audit_poll_interval_s: 1,
        ..Limits::default()
    };
    let cfg =
        databastion_core::AuditConfig::local(t, poll_s, &limits).with_state_dir(state.to_owned());
    let (sink, rx) = databastion_core::EventSink::channel(10_000);
    let connector = Arc::clone(connector);
    let task = tokio::spawn(async move { connector.audit_stream(&cfg, &sink).await });
    (task, rx)
}

/// The dev healthchecks read `hr.employees` (MySQL as the dev agent
/// account, Percona as `root`), from sessions that end before the poll.
fn healthcheck(e: &MaskedEvent) -> bool {
    !e.objects().is_empty()
        && e.objects()
            .iter()
            .all(|o| o.database().as_str() == "hr" && o.object().as_str() == "employees")
}

fn charged(connector: &MysqlConnector, t: &TargetConfig, table: &str) -> bool {
    connector
        .check_state
        .own_usage(&t.id)
        .lock()
        .unwrap()
        .budgeted_objects()
        .iter()
        .any(|k| k.starts_with(OS_DB) && k.ends_with(&format!("\0{table}")))
}

async fn fixture(a: &mut Session) {
    exec(a, &format!("DROP DATABASE IF EXISTS {OS_DB}")).await;
    exec(a, &format!("CREATE DATABASE {OS_DB}")).await;
    exec(
        a,
        &format!("CREATE TABLE {OS_DB}.narrow (id INT PRIMARY KEY, email VARCHAR(64))"),
    )
    .await;
    for i in 1..=5 {
        exec(
            a,
            &format!("INSERT INTO {OS_DB}.narrow VALUES ({i}, '{i}{OS_MARKER}')"),
        )
        .await;
    }
    let columns: Vec<String> = (0..WIDE_COLUMNS)
        .map(|i| format!("`{}` VARCHAR(16)", wide_column(i)))
        .collect();
    exec(
        a,
        &format!(
            "CREATE TABLE {OS_DB}.wide (id INT PRIMARY KEY, {})",
            columns.join(", ")
        ),
    )
    .await;
    let values: Vec<String> = (0..WIDE_COLUMNS).map(|i| format!("'v{i}'")).collect();
    for i in 1..=5 {
        exec(
            a,
            &format!(
                "INSERT INTO {OS_DB}.wide VALUES ({i}, {})",
                values.join(", ")
            ),
        )
        .await;
    }
    exec(a, &format!("DROP USER IF EXISTS '{OS_USER}'@'%'")).await;
    exec(
        a,
        &format!("CREATE USER '{OS_USER}'@'%' IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
    )
    .await;
    exec(a, &format!("GRANT SELECT ON {OS_DB}.* TO '{OS_USER}'@'%'")).await;
    exec(
        a,
        &format!("GRANT SELECT ON performance_schema.* TO '{OS_USER}'@'%'"),
    )
    .await;
}

/// Phase 8 follow-ups (security reviews of #186, L1, and of #197, M3): a
/// Discovery scan followed by polls, a reconnected stream and a sibling
/// stream give no unknown-principal event and charge the agent's budget.
#[tokio::test]
async fn the_agents_own_sessions_are_never_unknown_principals() {
    let _serial = SERIAL.lock().await;
    let mut all = servers();
    all.extend(percona());
    for server in all {
        let Some(admin) = server.admin() else {
            continue;
        };
        let logs = Logs::default();
        let _guard = logs.capture();
        let mut a = admin_session(&server, &admin).await;
        let version = scalar(&mut a, "SELECT VERSION()").await.unwrap_or_default();
        fixture(&mut a).await;
        let (_d1, t1) = super::audit_it::audit_target(&server, OS_USER, IT_PASSWORD, None);
        let (_d2, mut t2) = super::audit_it::audit_target(&server, OS_USER, IT_PASSWORD, None);
        t2.id = "my-it-2".to_owned();
        let connector = Arc::new(MysqlConnector::new());
        let mut long_history = true;
        for t in [&t1, &t2] {
            let health = connector.check(t).await;
            long_history &= health.audit_level == AuditLevel::Partial;
            // Percona's dev service keeps `events_statements_history_long`
            // disabled: Limited, from `events_statements_history`.
            assert!(
                matches!(
                    health.audit_level,
                    AuditLevel::Partial | AuditLevel::Limited
                ),
                "{} {version}: {health:?}",
                server.name
            );
            assert_eq!(
                connector.audit_source(t),
                Some(EventSource::PerformanceSchema)
            );
        }
        // The agent's address as the server sees it.
        let own_addr = {
            let mut s = Session::connect(&t1, Timeouts::new(Duration::from_secs(10)))
                .await
                .unwrap();
            let user = scalar(&mut s, "SELECT USER()").await.unwrap_or_default();
            s.close().await;
            crate::audit::own_address(&user)
        };
        // Statements of earlier tests' ended sessions stay out of the
        // streams' first overlap window (2 s).
        tokio::time::sleep(Duration::from_secs(3)).await;
        let (s1, s2) = (TempDir::new(), TempDir::new());
        let (task1, mut rx1) = stream(&connector, &t1, &s1.0, SLOW_POLL_S);
        let (task2, mut rx2) = stream(&connector, &t2, &s2.0, 1);
        // The first polls place the cursors at the newest statement.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        // Both streams' sessions are noted as the agent's poll sessions.
        {
            let rows = a
                .query(
                    Stage::Audit,
                    &format!(
                        "SELECT THREAD_ID FROM performance_schema.threads \
                         WHERE PROCESSLIST_USER = '{OS_USER}'"
                    ),
                )
                .await
                .unwrap();
            let threads: Vec<u64> = rows
                .iter()
                .filter_map(|r| r.first().cloned().flatten()?.parse().ok())
                .collect();
            assert_eq!(threads.len(), 2, "{}: {threads:?}", server.name);
            let polls = connector.check_state.poll_threads();
            let polls = polls.lock().unwrap();
            for thread in threads {
                assert!(
                    polls.contains_thread(thread),
                    "{}: poll thread {thread} not noted",
                    server.name
                );
            }
        }
        // 1. A Discovery scan of the first target between two polls of its
        // stream: its sessions have ended when that stream reads them.
        let started = Instant::now();
        let mut findings = Vec::new();
        {
            let job = ScanJob::new(ScanParams::contract_defaults(), &t1, &unpaced(), key());
            let (sink, mut frx) = FindingSink::channel(100_000);
            connector.discover(&job, &sink).await.unwrap();
            drop(sink);
            while let Some(f) = frx.recv().await {
                findings.push(f);
            }
        }
        let scan_time = started.elapsed();
        assert!(
            findings
                .iter()
                .any(|f| f.location().is_some_and(|l| l.object.as_str() == "narrow")),
            "{} {version}: the scan found nothing",
            server.name
        );
        // Two polls of the first stream after the scan.
        tokio::time::sleep(Duration::from_secs(u64::from(2 * SLOW_POLL_S + 2))).await;
        // 2. The first stream reconnects (a stale session replaced).
        FORCE_PS_RECONNECT.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(u64::from(SLOW_POLL_S + 2))).await;
        assert!(
            !FORCE_PS_RECONNECT.load(Ordering::SeqCst),
            "{}: the stream did not reconnect",
            server.name
        );
        // 3. The sibling stream restarts from its saved cursor.
        task2.abort();
        let _ = task2.await;
        let mut ev2: Vec<MaskedEvent> = Vec::new();
        collect_until(&mut rx2, &mut ev2, Duration::from_millis(200), |_| false).await;
        let (task2, mut rx2) = stream(&connector, &t2, &s2.0, 1);
        tokio::time::sleep(Duration::from_secs(3)).await;
        // 4. Heartbeats on both targets.
        for _ in 0..2 {
            for t in [&t1, &t2] {
                assert!(connector.check(t).await.reachable, "{}", server.name);
            }
        }
        let mut ev1: Vec<MaskedEvent> = Vec::new();
        collect_until(
            &mut rx1,
            &mut ev1,
            Duration::from_secs(u64::from(SLOW_POLL_S + 2)),
            |_| false,
        )
        .await;
        collect_until(&mut rx2, &mut ev2, Duration::from_secs(2), |_| false).await;
        task1.abort();
        task2.abort();
        let _ = task1.await;
        let _ = task2.await;
        for (label, ev) in [("stream 1", &ev1), ("stream 2 (sibling)", &ev2)] {
            let all: Vec<String> = ev.iter().map(describe).collect();
            eprintln!(
                "{} {version} {label} events ({}, scan {scan_time:?}):\n{}",
                server.name,
                all.len(),
                all.join("\n")
            );
            let unknown: Vec<String> = ev
                .iter()
                .filter(|e| !e.principal().send_name() && !healthcheck(e))
                .map(describe)
                .collect();
            assert!(
                unknown.is_empty(),
                "{} {version} {label}: unknown-principal events: {unknown:#?}",
                server.name
            );
            if own_addr.is_some() {
                assert!(
                    !ev.iter().any(|e| e.principal().account_name() == OS_USER),
                    "{} {version} {label}: the agent's own traffic was reported: {all:#?}",
                    server.name
                );
            }
            assert!(
                !all.iter().any(|d| d.contains(OS_MARKER)),
                "{}: a value in an event",
                server.name
            );
        }
        // The scan was charged to each target's own budget (the sibling
        // knows the pins too). The per-thread tables (Limited) drop a
        // thread's statements when it ends: a scan between two polls is
        // not seen there at all.
        if long_history {
            for t in [&t1, &t2] {
                for table in ["narrow", "wide"] {
                    assert!(
                        charged(&connector, t, table),
                        "{} {version} {}: {table} not charged",
                        server.name,
                        t.id
                    );
                }
            }
        } else {
            eprintln!(
                "{} {version}: per-thread statement history (Limited): no charge expected",
                server.name
            );
        }
        let text = logs.text();
        assert!(!text.contains(OS_MARKER), "a value in the logs");
        assert!(
            !text.contains("databastion_pin = '"),
            "a pin nonce in the logs"
        );
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {OS_DB}")).await;
        exec(&mut a, &format!("DROP USER IF EXISTS '{OS_USER}'@'%'")).await;
    }
}

/// Security review of #205, M2: a nonce copied into another session never
/// pins that session. The agent's pin reads its own thread only (by
/// `CONNECTION_ID()` in `threads`), also when the agent's thread is not
/// instrumented. On MySQL 8.4 and MariaDB 10.11 to 11.8 an uninstrumented
/// thread still shows its user variables, so both copies are visible (the
/// control count below): without the own-thread condition the pin would
/// have failed closed on two rows, or pinned the copier if the agent's own
/// row were missing.
#[tokio::test]
async fn a_copied_nonce_never_pins_another_session() {
    let _serial = SERIAL.lock().await;
    let mut all = servers();
    all.extend(percona());
    for server in all {
        let Some(admin) = server.admin() else {
            continue;
        };
        let mut a = admin_session(&server, &admin).await;
        let version = scalar(&mut a, "SELECT VERSION()").await.unwrap_or_default();
        fixture(&mut a).await;
        let (_d, t) = super::audit_it::audit_target(&server, OS_USER, IT_PASSWORD, None);
        for instrumented in [true, false] {
            let nonce = format!("{:032x}", 0x5eed_u128 + u128::from(instrumented));
            let mut s = Session::connect(&t, Timeouts::new(Duration::from_secs(10)))
                .await
                .unwrap();
            let conn = scalar(&mut s, "SELECT CONNECTION_ID()").await.unwrap();
            let thread_of = |c: &str| {
                format!(
                    "SELECT THREAD_ID FROM performance_schema.threads WHERE PROCESSLIST_ID = {c}"
                )
            };
            let own_thread: u64 = scalar(&mut a, &thread_of(&conn))
                .await
                .unwrap()
                .parse()
                .unwrap();
            let admin_conn = scalar(&mut a, "SELECT CONNECTION_ID()").await.unwrap();
            let admin_thread: u64 = scalar(&mut a, &thread_of(&admin_conn))
                .await
                .unwrap()
                .parse()
                .unwrap();
            if !instrumented {
                exec(
                    &mut a,
                    &format!(
                        "UPDATE performance_schema.threads SET INSTRUMENTED = 'NO' \
                         WHERE PROCESSLIST_ID = {conn}"
                    ),
                )
                .await;
            }
            // The copier holds the nonce before the agent's pin.
            exec(&mut a, &format!("SET @databastion_pin = '{nonce}'")).await;
            let pinned =
                crate::audit::pfs::pinned_session_with(&mut s, Stage::Sample, Some(nonce.clone()))
                    .await
                    .unwrap();
            let copies = scalar(
                &mut a,
                &format!(
                    "SELECT COUNT(*) FROM performance_schema.user_variables_by_thread \
                     WHERE VARIABLE_NAME = 'databastion_pin' AND VARIABLE_VALUE = '{nonce}'"
                ),
            )
            .await;
            eprintln!(
                "{} {version} (agent thread instrumented: {instrumented}): rows holding the \
                 nonce {copies:?}, pinned {:?}",
                server.name,
                pinned.as_ref().map(|p| p.thread)
            );
            assert!(
                pinned.as_ref().is_none_or(|p| p.thread != admin_thread),
                "{} {version}: the copier's session was pinned",
                server.name
            );
            if instrumented {
                let p = pinned.unwrap_or_else(|| panic!("{} {version}: no pin", server.name));
                assert_eq!(p.thread, own_thread, "{} {version}", server.name);
                assert!(p.run.is_some(), "{} {version}: no server run", server.name);
                assert!(p.uptime > 0, "{} {version}", server.name);
            } else {
                assert!(
                    pinned.as_ref().is_none_or(|p| p.thread == own_thread),
                    "{} {version}",
                    server.name
                );
            }
            exec(&mut a, "SET @databastion_pin = NULL").await;
            s.close().await;
        }
        exec(&mut a, &format!("DROP DATABASE IF EXISTS {OS_DB}")).await;
        exec(&mut a, &format!("DROP USER IF EXISTS '{OS_USER}'@'%'")).await;
    }
}
