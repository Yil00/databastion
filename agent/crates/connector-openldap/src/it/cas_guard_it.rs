//! CAS store guard against the dev `openldap` service (ADR-0041 decision
//! 5, PR #141 review M5). The dev schema has no `casRegisteredService`
//! object class: the registry entries here are recognized by their
//! `description` (a CAS service definition, `@class` in the closed map),
//! the other recognition rule; the object class rule is covered by the
//! scripted server (`fake.rs`).
//!
//! Fixtures under `ou=cas-it,dc=example,dc=org`, written and removed by
//! `DATABASTION_TEST_LDAP_MODIFY_CMD`: a shell command running
//! `ldapmodify -c` as the administrator with the LDIF on its standard
//! input (locally: `ldapmodify -c -x -H ldap://127.0.0.1:1389 -D
//! cn=admin,dc=example,dc=org -w …`; CI: inside the container). Without
//! it, the test is skipped (`ldap-modify` in `DATABASTION_TEST_REQUIRE`
//! makes it a failure).

use super::*;

const BASE: &str = "ou=cas-it,dc=example,dc=org";
const ST: &str = "ST-77-FAKEldapGuardServiceTicket-cas01";
const TGT: &str = "TGT-78-FAKEldapGuardTicketGranting-cas01";

fn modify(ldif: &str) -> bool {
    use std::io::Write as _;
    let Ok(cmd) = std::env::var("DATABASTION_TEST_LDAP_MODIFY_CMD") else {
        skip("ldap-modify", "DATABASTION_TEST_LDAP_MODIFY_CMD is not set");
        return false;
    };
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(ldif.as_bytes())
        .unwrap();
    // `-c`: deleting entries that are not there is not an error here.
    let _ = child.wait().unwrap();
    true
}

fn entries() -> Vec<(String, String)> {
    let mut out = vec![
        (
            BASE.to_owned(),
            "objectClass: organizationalUnit\nou: cas-it\n".to_owned(),
        ),
        (
            format!("ou=registry,{BASE}"),
            "objectClass: organizationalUnit\nou: registry\n".to_owned(),
        ),
        (
            format!("ou=sessions,{BASE}"),
            "objectClass: organizationalUnit\nou: sessions\n".to_owned(),
        ),
        (
            format!("ou=devices,{BASE}"),
            "objectClass: organizationalUnit\nou: devices\n".to_owned(),
        ),
    ];
    for i in 0..6 {
        out.push((
            format!("cn=svc{i},ou=registry,{BASE}"),
            format!(
                "objectClass: applicationProcess\ncn: svc{i}\ndescription: \
                 {{\"@class\":\"org.apereo.cas.services.OidcRegisteredService\",\
                 \"serviceId\":\"https://app{i}.example.com/.*\",\
                 \"clientSecret\":\"AKIA{i:0>16}\",\
                 \"contacts\":[{{\"email\":\"owner{i}@example.com\"}}]}}\n"
            ),
        ));
    }
    for i in 0..6 {
        let description = if i == 3 {
            ST.to_owned()
        } else {
            format!("session.owner{i}@example.org")
        };
        out.push((
            format!("cn=session{i},ou=sessions,{BASE}"),
            format!(
                "objectClass: applicationProcess\ncn: session{i}\ndescription: {description}\n"
            ),
        ));
    }
    for i in 0..3 {
        out.push((
            format!("cn=device{i},ou=devices,{BASE}"),
            format!(
                "objectClass: device\ncn: device{i}\nserialNumber: {TGT}-{i}\ndescription: \
                 holder{i}@example.org\n"
            ),
        ));
    }
    out
}

fn delete_ldif() -> String {
    entries()
        .iter()
        .rev()
        .map(|(dn, _)| format!("dn: {dn}\nchangetype: delete\n\n"))
        .collect()
}

fn add_ldif() -> String {
    entries()
        .iter()
        .map(|(dn, body)| format!("dn: {dn}\nchangetype: add\n{body}\n"))
        .collect()
}

#[tokio::test]
async fn cas_store_guard_on_a_real_server() {
    let _serial = SERIAL.lock().await;
    let Some(s) = server() else { return };
    if !modify(&delete_ldif()) || !modify(&add_ldif()) {
        return;
    }
    // `device` entries are listed as a ticket registry (custom name).
    let (_dir, t) = target_with(
        &s,
        &service_dn(),
        &password(),
        "{tls: disable, cas_stores: {ticket_registry: [device]}}",
    );
    let connector = OpenldapConnector::new();
    let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
    let logs = Logs::default();
    let (r, findings) = {
        let _guard = logs.capture();
        let (sink, mut rx) = FindingSink::channel(4096);
        let r = connector.discover(&job, &sink).await;
        drop(sink);
        let mut out = Vec::new();
        while let Some(f) = rx.recv().await {
            out.push(f);
        }
        (r, out)
    };
    modify(&delete_ldif());
    r.unwrap();
    let text = logs.text();
    for secret in [ST, TGT, "FAKE", "AKIA0000"] {
        assert!(!text.contains(secret), "{secret} in the logs");
        for f in &findings {
            assert!(!format!("{f:?}").contains(secret), "{secret} in {f:?}");
        }
    }
    let in_container = |c: &str| -> Vec<&MaskedFinding> {
        findings
            .iter()
            .filter(|f| {
                f.location()
                    .and_then(|l| l.schema.as_ref())
                    .is_some_and(|s| s.as_str().starts_with(c))
            })
            .collect()
    };
    // Service registry entries (recognized by their `description`):
    // classified, never a masked sample, no `secret.*` fingerprint.
    let registry = in_container("ou=registry,ou=cas-it");
    assert!(!registry.is_empty(), "{findings:?}");
    for f in &registry {
        assert!(f.masked_samples().is_empty(), "{f:?}");
        if f.classifier().is_secret() {
            assert!(f.fingerprints().is_empty(), "{f:?}");
        }
    }
    // The ticket id among the session descriptions trips the attribute.
    assert!(
        in_container("ou=sessions,ou=cas-it")
            .iter()
            .all(|f| f.location().unwrap().field.as_str() != "description"),
        "{findings:?}"
    );
    assert_eq!(job.cas_guard().tripped(), 1);
    // The `device` entries (a ticket registry by `cas_stores`) are never
    // read; one log line per container (review L8), counts only.
    assert!(
        in_container("ou=devices,ou=cas-it").is_empty(),
        "{findings:?}"
    );
    let skipped: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("CAS ticket entries not read"))
        .collect();
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    assert!(skipped[0].contains("\"entries\":3"), "{skipped:?}");
}
