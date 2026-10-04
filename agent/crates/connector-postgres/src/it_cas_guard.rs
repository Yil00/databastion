//! Integration tests of the CAS store guard (ADR-0041 decisions 5, 6 and
//! 14) against a PostgreSQL server: a ticket table under a name that is not
//! built in (recognized by its column shape), a plain table holding
//! ticket-id-shaped values (the tripwire), a ticket table recreated after
//! its column grants were set (reported at the next check), the
//! `COM_AUDIT_TRAIL` and `RegisteredServices` rules.
//!
//! Same prerequisites as `it.rs` (`DATABASTION_TEST_PG_URL` and
//! `DATABASTION_TEST_PG_ADMIN_URL`, skipped without them). The fixtures are
//! created here, in their own database (`databastion_cas_guard`, dropped and
//! recreated), with clearly fake values; nothing is added to `dev/`.

#![allow(clippy::print_stderr)]

use databastion_core::{Connector, NoteCode, ScanJob, ScanParams};

use super::it::{Logs, SERIAL, admin, admin_url, agent_url, key, target, unpaced};
use crate::PostgresConnector;

const GUARD_DB: &str = "databastion_cas_guard";
/// A NOLOGIN role granted to the agent's role for the role case.
const READER_ROLE: &str = "databastion_it_cas_reader";

/// Fake ticket ids (never valid anywhere) planted in the fixtures.
const TICKETS: [&str; 6] = [
    "TGT-1-FakeTgtValueAaaaaaaaaaaaaaaa-cas01",
    "TGT-2-FakeTgtValueBbbbbbbbbbbbbbbb-cas01",
    "ST-3-FakeStValueCcccccccccccccccc-cas01",
    "ST-4-FakeStValueDdddddddddddddddd-cas01",
    "PGT-5-FakePgtValueEeeeeeeeeeeeeeee-cas01",
    "AT-6-FakeAtValueFfffffffffffffffff-cas01",
];
/// Fake principals of the ticket table: never read.
const TICKET_PRINCIPALS: [&str; 2] = [
    "ticket.owner.one@example.org",
    "ticket.owner.two@example.org",
];

fn fixtures(agent: &str) -> String {
    let t = TICKETS;
    let p = TICKET_PRINCIPALS;
    format!(
        "CREATE SCHEMA cas; GRANT USAGE ON SCHEMA cas TO \"{agent}\"; \
         -- A JPA ticket table renamed: recognized by its shape. Column grants only.
         CREATE TABLE cas.sso_sessions_v2 (id text PRIMARY KEY, parent_id text, body text, \
           type text, principal_id text, attributes text, creation_time timestamptz, \
           expiration_time timestamptz); \
         INSERT INTO cas.sso_sessions_v2 VALUES \
           ('{t0}', NULL, '{{\"id\":\"{t0}\",\"principal\":\"{p0}\"}}', \
            'org.apereo.cas.ticket.TicketGrantingTicketImpl', '{p0}', '{{}}', now(), now()), \
           ('{t2}', '{t0}', '{{\"id\":\"{t2}\"}}', \
            'org.apereo.cas.ticket.ServiceTicketImpl', '{p0}', '{{}}', now(), now()), \
           ('{t1}', NULL, 'encrypted-body-FAKE', \
            'org.apereo.cas.ticket.registry.EncodedTicket', 'digest-FAKE', '', now(), now()); \
         GRANT SELECT (type, creation_time, expiration_time) ON cas.sso_sessions_v2 \
           TO \"{agent}\"; \
         -- A plain table with ticket-id-shaped values next to e-mail addresses.
         CREATE TABLE cas.app_sessions (session_ref text, email text); \
         INSERT INTO cas.app_sessions SELECT \
             CASE WHEN i % 7 = 0 THEN '{t3}' ELSE 'ref-' || i END, \
             'guard.user' || i || '@example.com' \
           FROM generate_series(1, 40) i; \
         GRANT SELECT ON cas.app_sessions TO \"{agent}\"; \
         -- The audit trail.
         CREATE TABLE cas.\"COM_AUDIT_TRAIL\" (\"AUD_USER\" text, \"AUD_CLIENT_IP\" text, \
           \"AUD_SERVER_IP\" text, \"AUD_RESOURCE\" text, \"AUD_ACTION\" text, \
           \"APPLIC_CD\" text, \"AUD_DATE\" timestamptz); \
         INSERT INTO cas.\"COM_AUDIT_TRAIL\" SELECT 'audit.user' || i || '@example.net', \
             '192.0.2.' || i, '198.51.100.1', '{t4}', 'SERVICE_TICKET_CREATED', 'CAS', now() \
           FROM generate_series(1, 30) i; \
         GRANT SELECT (\"AUD_USER\", \"AUD_CLIENT_IP\", \"AUD_ACTION\", \"AUD_DATE\") \
           ON cas.\"COM_AUDIT_TRAIL\" TO \"{agent}\"; \
         -- The JPA service registry.
         CREATE TABLE cas.\"RegisteredServices\" (id bigint, name text, \"serviceId\" text, \
           body text); \
         INSERT INTO cas.\"RegisteredServices\" SELECT i, 'App' || i, \
             'https://app' || i || '.example.com/.*', \
             '{{\"@class\":\"org.apereo.cas.services.OidcRegisteredService\",\"clientSecret\":\"' || \
             'AKIA' || lpad(i::text, 16, 'Q') || '\",\"contacts\":[{{\"email\":\"owner' || i || \
             '@example.com\"}}]}}' \
           FROM generate_series(1, 20) i; \
         GRANT SELECT ON cas.\"RegisteredServices\" TO \"{agent}\"; \
         -- A ticket table under its built-in name, readable in full.
         CREATE TABLE cas.\"CasTickets\" (id text, body text, type text, principal_id text); \
         INSERT INTO cas.\"CasTickets\" VALUES ('{t5}', '{{}}', \
           'org.apereo.cas.ticket.accesstoken.OAuth20DefaultAccessToken', '{p1}'); \
         GRANT SELECT (type) ON cas.\"CasTickets\" TO \"{agent}\";",
        t0 = t[0],
        t1 = t[1],
        t2 = t[2],
        t3 = t[3],
        t4 = t[4],
        t5 = t[5],
        p0 = p[0],
        p1 = p[1],
    )
}

async fn setup(adm: &super::it::Url, agent: &str) {
    let a = admin(adm, "postgres").await;
    for statement in [
        format!("DROP DATABASE IF EXISTS {GUARD_DB} WITH (FORCE)"),
        format!("CREATE DATABASE {GUARD_DB}"),
    ] {
        a.batch_execute(&statement).await.unwrap();
    }
    let exists = a
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&READER_ROLE])
        .await
        .unwrap()
        .is_some();
    if !exists {
        a.batch_execute(&format!("CREATE ROLE {READER_ROLE} NOLOGIN"))
            .await
            .unwrap();
    }
    a.batch_execute(&format!("REVOKE {READER_ROLE} FROM \"{agent}\""))
        .await
        .unwrap();
    admin(adm, GUARD_DB)
        .await
        .batch_execute(&fixtures(agent))
        .await
        .unwrap();
}

fn ticket_note(notes: &[databastion_core::TargetNote]) -> Option<u64> {
    notes
        .iter()
        .find(|n| n.code() == NoteCode::PrivilegeTicketCredentialsReadable)
        .map(|n| n.count().unwrap_or(0))
}

#[tokio::test]
async fn cas_store_guard_on_postgres() {
    let (Some(u), Some(adm)) = (agent_url(), admin_url()) else {
        return;
    };
    let _serial = SERIAL.lock().await;
    setup(&adm, &u.user).await;
    let (_dir, t) = target(&u, &u.user, &u.password, GUARD_DB, false);

    // Discovery, with every log line captured.
    let logs = Logs::default();
    let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
    let findings = {
        let _guard = logs.capture();
        let (sink, mut rx) = databastion_core::FindingSink::channel(10_000);
        PostgresConnector::new()
            .discover(&job, &sink)
            .await
            .unwrap();
        drop(sink);
        let mut out = Vec::new();
        while let Some(f) = rx.recv().await {
            out.push(f);
        }
        out
    };
    let at = |object: &str, field: &str| {
        findings
            .iter()
            .filter(|f| {
                let l = f.location().unwrap();
                l.object.as_str() == object && l.field.as_str() == field
            })
            .collect::<Vec<_>>()
    };
    // Ticket tables (renamed, built-in name): nothing but the metadata.
    for f in &findings {
        let o = f.location().unwrap().object.as_str();
        assert!(o != "sso_sessions_v2" && o != "CasTickets", "{f:?}");
    }
    assert_eq!(job.cas_guard().registries(), 2);
    // Two clear tickets in the renamed table, one in CasTickets.
    assert_eq!(job.cas_guard().unencrypted(), 3);
    // Tripwire: the ticket-shaped column gives nothing, its neighbour is
    // classified as usual.
    assert!(at("app_sessions", "session_ref").is_empty());
    assert_eq!(at("app_sessions", "email").len(), 1, "{findings:?}");
    assert_eq!(job.cas_guard().tripped(), 1);
    // Audit trail: AUD_RESOURCE never read (so the tripwire did not even
    // see it), AUD_USER without masked samples, the client address as
    // usual.
    assert!(at("COM_AUDIT_TRAIL", "AUD_RESOURCE").is_empty());
    let user = at("COM_AUDIT_TRAIL", "AUD_USER");
    assert_eq!(user.len(), 1, "{findings:?}");
    assert!(user[0].masked_samples().is_empty());
    assert!(!user[0].fingerprints().is_empty());
    // Service registry body: no masked samples, no secret.* fingerprints.
    let body = at("RegisteredServices", "body");
    assert!(!body.is_empty(), "{findings:?}");
    for f in &body {
        assert!(f.masked_samples().is_empty(), "{f:?}");
        if f.classifier().is_secret() {
            assert!(f.fingerprints().is_empty(), "{f:?}");
        }
    }
    // No ticket id nor ticket principal anywhere: findings, logs.
    let text = format!("{findings:?}{}", logs.text());
    for v in TICKETS.iter().chain(&TICKET_PRINCIPALS) {
        assert!(!text.contains(v), "{v} leaked");
    }
    let notes = job.cas_guard().notes();
    assert!(
        notes
            .iter()
            .any(|n| n.code() == NoteCode::CoverageCasGuardTripped)
    );
    assert!(
        notes.iter().any(
            |n| n.code() == NoteCode::SecurityTicketRegistryUnencrypted && n.count() == Some(3)
        )
    );

    // check(): metadata column grants only, nothing reported.
    let c = PostgresConnector::new();
    let h = c.check(&t).await;
    assert!(h.reachable, "{h:?}");
    assert_eq!(ticket_note(&h.notes), None, "{h:?}");

    // A ticket table recreated by a CAS upgrade with a table grant: the
    // next check reports it.
    let g = admin(&adm, GUARD_DB).await;
    g.batch_execute(&format!(
        "DROP TABLE cas.\"CasTickets\"; \
         CREATE TABLE cas.\"CasTickets\" (id text, body text, type text, principal_id text, \
           parent_id text); \
         GRANT SELECT ON cas.\"CasTickets\" TO \"{}\";",
        u.user
    ))
    .await
    .unwrap();
    assert_eq!(ticket_note(&c.check(&t).await.notes), Some(1));
    // Through PUBLIC.
    g.batch_execute(&format!(
        "REVOKE SELECT ON cas.\"CasTickets\" FROM \"{}\"; \
         GRANT SELECT (type) ON cas.\"CasTickets\" TO \"{}\"; \
         GRANT SELECT (body) ON cas.\"CasTickets\" TO PUBLIC;",
        u.user, u.user
    ))
    .await
    .unwrap();
    assert_eq!(ticket_note(&c.check(&t).await.notes), Some(1));
    // Through a role; on the renamed (shape-recognized) table too.
    g.batch_execute(&format!(
        "REVOKE SELECT (body) ON cas.\"CasTickets\" FROM PUBLIC; \
         GRANT SELECT ON cas.\"CasTickets\" TO {READER_ROLE}; \
         GRANT SELECT (principal_id) ON cas.sso_sessions_v2 TO {READER_ROLE};"
    ))
    .await
    .unwrap();
    assert_eq!(ticket_note(&c.check(&t).await.notes), None);
    admin(&adm, "postgres")
        .await
        .batch_execute(&format!("GRANT {READER_ROLE} TO \"{}\"", u.user))
        .await
        .unwrap();
    let readable = ticket_note(&c.check(&t).await.notes);
    // The audit trail's AUD_RESOURCE readable is reported as well.
    g.batch_execute(&format!(
        "GRANT SELECT (\"AUD_RESOURCE\") ON cas.\"COM_AUDIT_TRAIL\" TO \"{}\"",
        u.user
    ))
    .await
    .unwrap();
    let with_audit = ticket_note(&c.check(&t).await.notes);
    admin(&adm, "postgres")
        .await
        .batch_execute(&format!("REVOKE {READER_ROLE} FROM \"{}\"", u.user))
        .await
        .unwrap();
    admin(&adm, "postgres")
        .await
        .batch_execute(&format!("DROP DATABASE {GUARD_DB} WITH (FORCE)"))
        .await
        .unwrap();
    assert_eq!(readable, Some(2));
    assert_eq!(with_audit, Some(3));
}
