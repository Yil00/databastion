//! Integration tests of the CAS store guard (ADR-0041 decisions 5, 6 and
//! 14) against MySQL and MariaDB: a ticket table under a name that is not
//! built in (recognized by its column shape), a plain table holding
//! ticket-id-shaped values (the tripwire), a ticket table recreated with a
//! table grant (reported at the next check), a ticket table readable
//! through a role, the `COM_AUDIT_TRAIL` and `RegisteredServices` rules.
//!
//! Needs `DATABASTION_TEST_<S>_ADMIN_URL` (skipped otherwise, as the other
//! fixture tests). The fixtures are created here, in their own database
//! (`databastion_cas_guard`, dropped and recreated) with clearly fake
//! values, and a test account `databastion_it_cas`; nothing is added to
//! `dev/`.

use super::*;

const GUARD_DB: &str = "databastion_cas_guard";
const CAS_USER: &str = "databastion_it_cas";
const CAS_ROLE: &str = "databastion_it_r_cas";

/// Fake ticket ids planted in the fixtures (never valid anywhere).
const TICKETS: [&str; 5] = [
    "TGT-1-FakeTgtValueAaaaaaaaaaaaaaaa-cas01",
    "ST-2-FakeStValueBbbbbbbbbbbbbbbbb-cas01",
    "ST-3-FakeStValueCcccccccccccccccc-cas01",
    "PGT-4-FakePgtValueDddddddddddddddd-cas01",
    "AT-5-FakeAtValueEeeeeeeeeeeeeeeeee-cas01",
];
/// Fake principals of the ticket tables: never read.
const TICKET_PRINCIPALS: [&str; 2] = [
    "ticket.owner.one@example.org",
    "ticket.owner.two@example.org",
];

async fn drop_fixtures(a: &mut Session) {
    exec(a, &format!("DROP USER IF EXISTS '{CAS_USER}'@'%'")).await;
    exec(a, &format!("DROP ROLE IF EXISTS `{CAS_ROLE}`")).await;
    exec(a, &format!("DROP DATABASE IF EXISTS `{GUARD_DB}`")).await;
}

async fn fixtures(a: &mut Session) {
    let [t0, t1, t2, t3, t4] = TICKETS;
    let [p0, p1] = TICKET_PRINCIPALS;
    let u = format!("'{CAS_USER}'@'%'");
    for s in [
        format!("CREATE DATABASE `{GUARD_DB}`"),
        format!("CREATE USER {u} IDENTIFIED BY '{IT_PASSWORD}' REQUIRE SSL"),
        format!("CREATE ROLE `{CAS_ROLE}`"),
        // A JPA ticket table renamed, readable in full: recognized by its
        // shape, never sampled, and reported by check().
        format!(
            "CREATE TABLE `{GUARD_DB}`.sso_sessions_v2 (id varchar(255), parent_id varchar(255), \
             body text, type varchar(255), principal_id varchar(255), attributes text, \
             creation_time datetime, expiration_time datetime)"
        ),
        format!(
            "INSERT INTO `{GUARD_DB}`.sso_sessions_v2 VALUES \
             ('{t0}', NULL, '{{\"id\":\"{t0}\",\"principal\":\"{p0}\"}}', \
              'org.apereo.cas.ticket.TicketGrantingTicketImpl', '{p0}', '{{}}', NOW(), NOW()), \
             ('{t1}', '{t0}', '{{\"id\":\"{t1}\"}}', 'org.apereo.cas.ticket.ServiceTicketImpl', \
              '{p0}', '{{}}', NOW(), NOW()), \
             ('enc-FAKE', NULL, 'encrypted-body-FAKE', \
              'org.apereo.cas.ticket.registry.EncodedTicket', 'digest-FAKE', '', NOW(), NOW())"
        ),
        format!("GRANT SELECT ON `{GUARD_DB}`.sso_sessions_v2 TO {u}"),
        // A plain table with ticket-id-shaped values next to e-mails.
        format!(
            "CREATE TABLE `{GUARD_DB}`.app_sessions (session_ref varchar(255), email varchar(255))"
        ),
        format!(
            "INSERT INTO `{GUARD_DB}`.app_sessions \
             SELECT IF(seq % 7 = 0, '{t2}', CONCAT('ref-', seq)), \
                    CONCAT('guard.user', seq, '@example.com') \
             FROM (SELECT a.n * 10 + b.n + 1 AS seq FROM \
               (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3) a, \
               (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 \
                UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) b) s"
        ),
        format!("GRANT SELECT ON `{GUARD_DB}`.app_sessions TO {u}"),
        // The audit trail, AUD_RESOURCE not granted.
        format!(
            "CREATE TABLE `{GUARD_DB}`.COM_AUDIT_TRAIL (AUD_USER varchar(255), \
             AUD_CLIENT_IP varchar(64), AUD_RESOURCE varchar(255), AUD_ACTION varchar(64), \
             APPLIC_CD varchar(16), AUD_DATE datetime)"
        ),
        format!(
            "INSERT INTO `{GUARD_DB}`.COM_AUDIT_TRAIL \
             SELECT CONCAT('audit.user', seq, '@example.net'), CONCAT('192.0.2.', seq), '{t3}', \
                    'SERVICE_TICKET_CREATED', 'CAS', NOW() \
             FROM (SELECT a.n * 10 + b.n + 1 AS seq FROM \
               (SELECT 0 n UNION SELECT 1 UNION SELECT 2) a, \
               (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 \
                UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) b) s"
        ),
        format!(
            "GRANT SELECT (AUD_USER, AUD_CLIENT_IP, AUD_ACTION, AUD_DATE) \
             ON `{GUARD_DB}`.COM_AUDIT_TRAIL TO {u}"
        ),
        // The JPA service registry.
        format!(
            "CREATE TABLE `{GUARD_DB}`.RegisteredServices (id bigint, name varchar(255), \
             serviceId varchar(255), body text)"
        ),
        format!(
            "INSERT INTO `{GUARD_DB}`.RegisteredServices \
             SELECT seq, CONCAT('App', seq), CONCAT('https://app', seq, '.example.com/.*'), \
               CONCAT('{{\"@class\":\"org.apereo.cas.services.OidcRegisteredService\",', \
                      '\"clientSecret\":\"AKIA', LPAD(seq, 16, 'Q'), '\",', \
                      '\"contacts\":[{{\"email\":\"owner', seq, '@example.com\"}}]}}') \
             FROM (SELECT a.n * 10 + b.n + 1 AS seq FROM \
               (SELECT 0 n UNION SELECT 1) a, \
               (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 \
                UNION SELECT 5 UNION SELECT 6 UNION SELECT 7 UNION SELECT 8 UNION SELECT 9) b) s"
        ),
        format!("GRANT SELECT ON `{GUARD_DB}`.RegisteredServices TO {u}"),
        // A ticket table under its built-in name, `type` only granted.
        format!(
            "CREATE TABLE `{GUARD_DB}`.cas_tickets (id varchar(255), body text, \
             type varchar(255), principal_id varchar(255))"
        ),
        format!(
            "INSERT INTO `{GUARD_DB}`.cas_tickets VALUES ('{t4}', '{{}}', \
             'org.apereo.cas.ticket.accesstoken.OAuth20DefaultAccessToken', '{p1}')"
        ),
        format!("GRANT SELECT (type) ON `{GUARD_DB}`.cas_tickets TO {u}"),
    ] {
        exec(a, &s).await;
    }
}

fn ticket_note(notes: &[TargetNote]) -> Option<u64> {
    notes
        .iter()
        .find(|n| n.code() == NoteCode::PrivilegeTicketCredentialsReadable)
        .map(|n| n.count().unwrap_or(0))
}

async fn guard_check(t: &TargetConfig) -> Vec<TargetNote> {
    let h = MysqlConnector::new().check(t).await;
    assert!(h.reachable, "{h:?}");
    h.notes
}

#[tokio::test]
async fn cas_store_guard_on_mysql_and_mariadb() {
    let _serial = SERIAL.lock().await;
    for server in servers() {
        let Some(admin) = server.admin() else {
            continue;
        };
        let name = server.name;
        let mysql = server.flavor() == Flavor::Mysql;
        let mut a = admin_session(&server, &admin).await;
        drop_fixtures(&mut a).await;
        fixtures(&mut a).await;
        let (_dir, t) = target(&server, CAS_USER, IT_PASSWORD);

        let logs = Logs::default();
        let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
        let findings = {
            let _guard = logs.capture();
            let (sink, mut rx) = FindingSink::channel(100_000);
            MysqlConnector::new().discover(&job, &sink).await.unwrap();
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
                    l.database.as_str() == GUARD_DB
                        && l.object.as_str() == object
                        && l.field.as_str() == field
                })
                .collect::<Vec<_>>()
        };
        for f in &findings {
            let o = f.location().unwrap().object.as_str();
            assert!(
                o != "sso_sessions_v2" && o != "cas_tickets",
                "{name}: {f:?}"
            );
        }
        // Both ticket tables: metadata only (two clear tickets in the
        // renamed one, one in cas_tickets).
        assert_eq!(job.cas_guard().registries(), 2, "{name}");
        assert_eq!(job.cas_guard().unencrypted(), 3, "{name}");
        assert!(at("app_sessions", "session_ref").is_empty(), "{name}");
        assert_eq!(at("app_sessions", "email").len(), 1, "{name}: {findings:?}");
        assert!(job.cas_guard().tripped() >= 1, "{name}");
        assert!(at("COM_AUDIT_TRAIL", "AUD_RESOURCE").is_empty(), "{name}");
        let user = at("COM_AUDIT_TRAIL", "AUD_USER");
        assert_eq!(user.len(), 1, "{name}: {findings:?}");
        assert!(user[0].masked_samples().is_empty(), "{name}");
        assert!(!user[0].fingerprints().is_empty(), "{name}");
        let body = at("RegisteredServices", "body");
        assert!(!body.is_empty(), "{name}: {findings:?}");
        for f in &body {
            assert!(f.masked_samples().is_empty(), "{name}: {f:?}");
            if f.classifier().is_secret() {
                assert!(f.fingerprints().is_empty(), "{name}: {f:?}");
            }
        }
        let text = format!("{findings:?}{}", logs.text());
        for v in TICKETS.iter().chain(&TICKET_PRINCIPALS) {
            assert!(!text.contains(v), "{name}: {v} leaked");
        }

        // check(): the renamed ticket table is readable in full (table
        // grant): reported; cas_tickets (`type` only) and the audit trail
        // (no AUD_RESOURCE) are not.
        assert_eq!(ticket_note(&guard_check(&t).await), Some(1), "{name}");
        exec(
            &mut a,
            &format!("REVOKE SELECT ON `{GUARD_DB}`.sso_sessions_v2 FROM '{CAS_USER}'@'%'"),
        )
        .await;
        assert_eq!(ticket_note(&guard_check(&t).await), None, "{name}");

        // cas_tickets recreated by a CAS upgrade, with a table grant.
        for s in [
            format!("DROP TABLE `{GUARD_DB}`.cas_tickets"),
            format!(
                "CREATE TABLE `{GUARD_DB}`.cas_tickets (id varchar(255), body text, \
                 type varchar(255), principal_id varchar(255), parent_id varchar(255))"
            ),
            format!("GRANT SELECT ON `{GUARD_DB}`.cas_tickets TO '{CAS_USER}'@'%'"),
        ] {
            exec(&mut a, &s).await;
        }
        assert_eq!(ticket_note(&guard_check(&t).await), Some(1), "{name}");
        exec(
            &mut a,
            &format!("REVOKE SELECT ON `{GUARD_DB}`.cas_tickets FROM '{CAS_USER}'@'%'"),
        )
        .await;
        assert_eq!(ticket_note(&guard_check(&t).await), None, "{name}");

        // Through a role: MySQL evaluates every applicable role (here one
        // that is granted, not enabled); MariaDB only the default role.
        exec(
            &mut a,
            &format!("GRANT SELECT ON `{GUARD_DB}`.cas_tickets TO `{CAS_ROLE}`"),
        )
        .await;
        exec(&mut a, &format!("GRANT `{CAS_ROLE}` TO '{CAS_USER}'@'%'")).await;
        if !mysql {
            exec(
                &mut a,
                &format!("SET DEFAULT ROLE `{CAS_ROLE}` FOR '{CAS_USER}'@'%'"),
            )
            .await;
        }
        let through_role = ticket_note(&guard_check(&t).await);
        // The audit trail's AUD_RESOURCE readable is reported as well.
        exec(
            &mut a,
            &format!(
                "GRANT SELECT (AUD_RESOURCE) ON `{GUARD_DB}`.COM_AUDIT_TRAIL TO '{CAS_USER}'@'%'"
            ),
        )
        .await;
        let with_audit = ticket_note(&guard_check(&t).await);
        drop_fixtures(&mut a).await;
        assert_eq!(through_role, Some(1), "{name}");
        assert_eq!(with_audit, Some(2), "{name}");
    }
}
