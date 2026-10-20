//! Integration tests of ADR-0054 decision 5 (agent test obligation)
//! against a PostgreSQL server: the names the connector hands to the core,
//! which are the names the console receives and compares its
//! case-sensitive exceptions with (ADR-0054 decision 4).
//!
//! - A quoted mixed-case relation in a quoted mixed-case schema
//!   (`"CrmArchive"."CrmCustomers"`, column `"ContactEmail"`) is named as in
//!   the catalog, case kept, by every Audit source (the pgaudit `jsonlog`
//!   and `csvlog` files, `pg_stat_statements`) and by Discovery; its
//!   lowercase twin `"CrmArchive".crmcustomers` (reached by an unquoted
//!   `"CrmArchive".CrmCustomers`, which the server folds) keeps its own
//!   lowercase name: the two never merge.
//! - Relations whose names differ from `crm.names_it` only by a character
//!   ADR-0009 strips (U+200B) or maps with NFKC (a fullwidth `ｎ`, U+FF4E)
//!   reach the console as `crm.names_it`, the same name as the plain
//!   relation: the residual risk "Normalization merges names" of ADR-0054,
//!   pinned here as the current behaviour.
//!
//! Same prerequisites as `it.rs`. The fixtures (the schema `CrmArchive`
//! with two tables, three tables of `crm` and a reader role) are created
//! here and dropped at the end; nothing is added to `dev/`.

#![allow(clippy::print_stderr)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use databastion_classifiers::masking::{EventAction, EventSource, MaskedEvent, MaskedFinding};
use databastion_core::{AuditLevel, Connector, FindingSink, ScanJob, ScanParams};

use super::it::{
    Logs, SERIAL, TempDir, admin, admin_url, agent_url, audit_logs, audit_target, collect_until,
    describe, key, raw_client, start_audit_with, target, unpaced,
};
use crate::PostgresConnector;

/// The reader whose statements the Audit sources report.
const NAMES_ROLE: &str = "databastion_it_names";
const NAMES_PASSWORD: &str = "dev-only-it-names-FAKE";
/// Marker in the local part of the fixtures' e-mail addresses: never in
/// an event, a finding or a log line (I2). Lowercase letters only, so the
/// addresses stay personal mailboxes for the e-mail classifier.
const NAMES_MARK: &str = "nmqzxw";

/// The quoted mixed-case schema and relation, and the column of the
/// mixed-case relation.
const MIXED_SCHEMA: &str = "CrmArchive";
const MIXED_TABLE: &str = "CrmCustomers";
const MIXED_COLUMN: &str = "ContactEmail";

/// `crm.names_it`, the same name with a zero-width space (stripped by
/// ADR-0009 normalization) and with a fullwidth `ｎ` (NFKC maps it to `n`).
const PLAIN: &str = "names_it";
const ZERO_WIDTH: &str = "names\u{200B}_it";
const FULLWIDTH: &str = "\u{FF4E}ames_it";

/// What the reader runs: the mixed-case relation quoted, its lowercase
/// twin through an unquoted name (folded by the server), and the three
/// relations whose names normalize to `names_it`.
fn reads() -> Vec<String> {
    vec![
        format!(
            "SELECT \"{MIXED_COLUMN}\" FROM \"{MIXED_SCHEMA}\".\"{MIXED_TABLE}\" WHERE id < 10"
        ),
        format!("SELECT contactemail FROM \"{MIXED_SCHEMA}\".CrmCustomers WHERE id < 11"),
        format!("SELECT email FROM crm.{PLAIN} WHERE id < 12"),
        format!("SELECT email FROM crm.\"{ZERO_WIDTH}\" WHERE id < 13"),
        format!("SELECT email FROM crm.\"{FULLWIDTH}\" WHERE id < 14"),
    ]
}

/// The (schema, object) names every source must give for [`reads`],
/// exactly: case kept, and the three `names_it` relations merged.
fn expected_objects() -> BTreeSet<(String, String)> {
    [
        (MIXED_SCHEMA, MIXED_TABLE),
        (MIXED_SCHEMA, "crmcustomers"),
        ("crm", PLAIN),
    ]
    .into_iter()
    .map(|(s, o)| (s.to_owned(), o.to_owned()))
    .collect()
}

/// The sources of the test server: the pgaudit log files, then
/// `pg_stat_statements`.
fn sources() -> Vec<(String, Option<(PathBuf, &'static str)>)> {
    let mut out: Vec<(String, Option<(PathBuf, &'static str)>)> = audit_logs()
        .into_iter()
        .map(|(p, f)| (format!("pgaudit {f}"), Some((p, f))))
        .collect();
    out.push(("pg_stat_statements".to_owned(), None));
    out
}

/// (database, schema, object) of every object of `e`.
fn objects(e: &MaskedEvent) -> Vec<(String, String, String)> {
    e.objects()
        .iter()
        .map(|o| {
            (
                o.database().as_str().to_owned(),
                o.schema().map_or("", |s| s.as_str()).to_owned(),
                o.object().as_str().to_owned(),
            )
        })
        .collect()
}

/// The reader's read events.
fn reader_reads(ev: &[MaskedEvent]) -> Vec<&MaskedEvent> {
    ev.iter()
        .filter(|e| e.principal().account_name() == NAMES_ROLE && e.action() == EventAction::Read)
        .collect()
}

/// The reader's events naming `crm.names_it`.
fn names_it_events(ev: &[MaskedEvent]) -> usize {
    reader_reads(ev)
        .iter()
        .filter(|e| objects(e).iter().any(|(_, s, o)| s == "crm" && o == PLAIN))
        .count()
}

/// Creates the fixtures (dropped first: a failed run leaves them).
async fn create_fixtures(a: &tokio_postgres::Client, agent: &str, db: &str) {
    drop_fixtures(a, db).await;
    let email = |col: &str| {
        format!("'jane.{NAMES_MARK}' || g || '@example.com' AS {col} FROM generate_series(1, 60) g")
    };
    a.batch_execute(&format!(
        "SET log_min_error_statement = panic; \
         CREATE ROLE {NAMES_ROLE} LOGIN PASSWORD '{NAMES_PASSWORD}'; \
         GRANT CONNECT ON DATABASE \"{db}\" TO {NAMES_ROLE}; \
         CREATE SCHEMA \"{MIXED_SCHEMA}\"; \
         CREATE TABLE \"{MIXED_SCHEMA}\".\"{MIXED_TABLE}\" AS SELECT g AS id, {mixed}; \
         CREATE TABLE \"{MIXED_SCHEMA}\".crmcustomers AS SELECT g AS id, {lower}; \
         CREATE TABLE crm.{PLAIN} AS SELECT g AS id, {plain}; \
         CREATE TABLE crm.\"{ZERO_WIDTH}\" AS SELECT g AS id, {plain}; \
         CREATE TABLE crm.\"{FULLWIDTH}\" AS SELECT g AS id, {plain}; \
         GRANT USAGE ON SCHEMA \"{MIXED_SCHEMA}\", crm TO {NAMES_ROLE}, {agent}; \
         GRANT SELECT ON ALL TABLES IN SCHEMA \"{MIXED_SCHEMA}\" TO {NAMES_ROLE}, {agent}; \
         GRANT SELECT ON crm.{PLAIN}, crm.\"{ZERO_WIDTH}\", crm.\"{FULLWIDTH}\" \
           TO {NAMES_ROLE}, {agent};",
        mixed = email(&format!("\"{MIXED_COLUMN}\"")),
        lower = email("contactemail"),
        plain = email("email"),
    ))
    .await
    .unwrap();
    // The catalog holds five distinct relations: the server compares names
    // with case and never normalizes them.
    let n: i64 = a
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_class c \
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
             WHERE (n.nspname = $1 AND c.relname = ANY($2)) \
                OR (n.nspname = 'crm' AND c.relname = ANY($3))",
            &[
                &MIXED_SCHEMA,
                &vec![MIXED_TABLE, "crmcustomers"],
                &vec![PLAIN, ZERO_WIDTH, FULLWIDTH],
            ],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(n, 5, "fixture relations in the catalog");
}

async fn drop_fixtures(a: &tokio_postgres::Client, db: &str) {
    a.batch_execute(&format!(
        "DROP SCHEMA IF EXISTS \"{MIXED_SCHEMA}\" CASCADE; \
         DROP TABLE IF EXISTS crm.{PLAIN}, crm.\"{ZERO_WIDTH}\", crm.\"{FULLWIDTH}\"; \
         DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{NAMES_ROLE}') THEN \
           REVOKE ALL ON SCHEMA crm FROM {NAMES_ROLE}; \
           REVOKE ALL ON DATABASE \"{db}\" FROM {NAMES_ROLE}; \
           DROP ROLE {NAMES_ROLE}; END IF; END $$;"
    ))
    .await
    .unwrap();
}

/// ADR-0054 decision 5, Audit: on every available source, the reader's
/// events name the mixed-case relation `CrmArchive.CrmCustomers` as in the
/// catalog, its lowercase twin `CrmArchive.crmcustomers` apart, and the
/// three relations `names_it`, `names<U+200B>_it` and `ｎames_it` all as
/// `crm.names_it`, one event per statement; nothing else, and no value.
#[tokio::test]
async fn audit_events_name_relations_as_in_the_catalog() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let logs = Logs::default();
    let _guard = logs.capture();
    let a = admin(&adm, &u.dbname).await;
    create_fixtures(&a, &u.user, &u.dbname).await;
    let expected = expected_objects();
    for (i, (label, log)) in sources().into_iter().enumerate() {
        let (_dir, t) = audit_target(
            &u,
            &format!("pg-names-{i}"),
            log.as_ref().map(|(p, f)| (p.as_path(), *f)),
        );
        let connector = Arc::new(PostgresConnector::new());
        let health = connector.check(&t).await;
        if log.is_none() && health.audit_level != AuditLevel::Limited {
            super::it::skip("pss", "pg_stat_statements is not usable by the agent role");
            continue;
        }
        let state = TempDir::new();
        let (task, mut rx) = start_audit_with(Arc::clone(&connector), &t, &state.0);
        // The tailers open the log; the first poll takes the baseline.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let r = raw_client(&adm, NAMES_ROLE, NAMES_PASSWORD, &u.dbname).await;
        for s in reads() {
            r.simple_query(&s).await.unwrap();
        }
        let done = |ev: &[MaskedEvent]| {
            let seen: BTreeSet<(String, String)> = reader_reads(ev)
                .iter()
                .flat_map(|e| objects(e))
                .map(|(_, s, o)| (s, o))
                .collect();
            seen == expected && names_it_events(ev) >= 3
        };
        let mut events = Vec::new();
        collect_until(&mut rx, &mut events, Duration::from_secs(30), done).await;
        // Anything the source would add past the expected events.
        collect_until(&mut rx, &mut events, Duration::from_secs(3), |_| false).await;
        task.abort();
        drop(r);
        let described: Vec<String> = events.iter().map(describe).collect();
        eprintln!(
            "{label} events ({}):\n{}",
            described.len(),
            described.join("\n")
        );
        let reader = reader_reads(&events);
        // Every reader event names exactly the expected objects, in the
        // shop database, with case kept: no folded `crmarchive`, no
        // `CrmArchive.CrmCustomers` reported as the twin or the reverse.
        let seen: BTreeSet<(String, String, String)> =
            reader.iter().flat_map(|e| objects(e)).collect();
        let want: BTreeSet<(String, String, String)> = expected
            .iter()
            .map(|(s, o)| (u.dbname.clone(), s.clone(), o.clone()))
            .collect();
        assert_eq!(seen, want, "{label}: {described:#?}");
        // One event per statement: the mixed-case relation and its twin
        // once each, `crm.names_it` three times (three distinct relations
        // on the server, one name on the console: ADR-0054 residual).
        assert_eq!(reader.len(), 5, "{label}: {described:#?}");
        for e in &reader {
            assert_eq!(objects(e).len(), 1, "{label}: {described:#?}");
        }
        assert_eq!(names_it_events(&events), 3, "{label}: {described:#?}");
        let source = if log.is_some() {
            EventSource::Pgaudit
        } else {
            EventSource::PgStatStatements
        };
        for e in &reader {
            assert_eq!(e.source(), source, "{label}");
            assert!(!format!("{e:?}").contains(NAMES_MARK), "{label}");
        }
        // The raw names never reach the console: no zero-width space and
        // no fullwidth letter in what the connector hands to the core.
        for d in &described {
            assert!(
                !d.contains('\u{200B}') && !d.contains('\u{FF4E}'),
                "{label}: {d}"
            );
            assert!(!d.contains(NAMES_MARK), "{label}: {d}");
        }
    }
    drop_fixtures(&a, &u.dbname).await;
    assert!(!logs.text().contains(NAMES_MARK));
}

/// ADR-0054 decision 5, Discovery: the findings locate the mixed-case
/// relation and column as in the catalog (`CrmArchive.CrmCustomers`,
/// `ContactEmail`), the lowercase twin apart (`crmcustomers`,
/// `contactemail`), and the three `names_it` relations at one location,
/// `crm.names_it.email`, once per relation.
#[tokio::test]
async fn discovery_locates_relations_as_in_the_catalog() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    let logs = Logs::default();
    let _guard = logs.capture();
    let a = admin(&adm, &u.dbname).await;
    create_fixtures(&a, &u.user, &u.dbname).await;
    let (_dir, t) = target(&u, &u.user, &u.password, &u.dbname, false);
    let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
    let (sink, mut rx) = FindingSink::channel(10_000);
    let r = PostgresConnector::new().discover(&job, &sink).await;
    drop(sink);
    let mut findings: Vec<MaskedFinding> = Vec::new();
    while let Some(f) = rx.recv().await {
        findings.push(f);
    }
    drop_fixtures(&a, &u.dbname).await;
    r.unwrap();
    // (database, schema, object, field, classifier) of the findings on the
    // fixtures: the mixed-case schema, and `crm` relations whose name
    // holds `ames_it`.
    let ours: Vec<(String, String, String, String, &'static str)> = findings
        .iter()
        .filter_map(|f| {
            let l = f.location()?;
            let schema = l.schema.as_ref().map_or("", |s| s.as_str());
            let object = l.object.as_str();
            (schema.eq_ignore_ascii_case(MIXED_SCHEMA)
                || object.contains("ames_it")
                || object.contains("ames\u{200B}_it"))
            .then(|| {
                (
                    l.database.as_str().to_owned(),
                    schema.to_owned(),
                    object.to_owned(),
                    l.field.as_str().to_owned(),
                    f.classifier().as_str(),
                )
            })
        })
        .collect();
    eprintln!("fixture findings: {ours:#?}");
    let at = |s: &str, o: &str, c: &str| {
        (
            u.dbname.clone(),
            s.to_owned(),
            o.to_owned(),
            c.to_owned(),
            "pii.email",
        )
    };
    let mut want = vec![
        at(MIXED_SCHEMA, MIXED_TABLE, MIXED_COLUMN),
        at(MIXED_SCHEMA, "crmcustomers", "contactemail"),
        at("crm", PLAIN, "email"),
        at("crm", PLAIN, "email"),
        at("crm", PLAIN, "email"),
    ];
    let mut got = ours.clone();
    want.sort();
    got.sort();
    assert_eq!(got, want);
    for f in &findings {
        let d = format!("{f:?}");
        assert!(!d.contains('\u{200B}') && !d.contains('\u{FF4E}'), "{d}");
        assert!(!d.contains(NAMES_MARK), "masked samples only (I2): {d}");
    }
    assert!(!logs.text().contains(NAMES_MARK));
}
