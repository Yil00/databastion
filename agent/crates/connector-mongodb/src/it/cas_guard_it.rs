//! CAS store guard against the dev `mongo` service (ADR-0041 decisions 5
//! and 6, PR #141 review M5). Fixtures created here by the administrator
//! (`DATABASTION_TEST_MONGO_ADMIN_URL`) in their own database
//! (`databastion_cas_it`, dropped and recreated) with their own roles and
//! accounts (`databastion_it_cas*`), so the dev seed is not touched:
//!
//! - a ticket registry under its built-in name and a renamed one (type
//!   field `Type`), read with the `$group` aggregate only, under a role
//!   holding `find` and `listCollections` and nothing else;
//! - an audit trail under its built-in name and a renamed one, read
//!   without `resourceOperatedUpon` and `clientInfo.headers` (checked on
//!   the server's profiler: `--profile 1 --slowms 0` in dev);
//! - a plain collection with a ticket id among its values (tripwire) and
//!   one with invoice numbers of the generic ticket shape among e-mail
//!   addresses (those values only are dropped);
//! - `check()` with the real roles: a database-wide `find` reads the
//!   ticket registries' and audit trails' credentials; a `find` on one
//!   plain collection does not.

use super::*;

const CAS_DB: &str = "databastion_cas_it";
const CAS_USER: &str = "databastion_it_cas";
const CAS_ROLE: &str = "databastion_it_cas_find";
const NARROW_USER: &str = "databastion_it_cas_narrow";
const NARROW_ROLE: &str = "databastion_it_cas_narrow";
const TGT: &str = "TGT-41-FAKEmongoGuardTicketValue-cas01";
const ST: &str = "ST-42-FAKEmongoServiceTicketValue-cas01";
const TGC: &str = "TGC-FAKEmongoCookieValueNeverRead";
const TGT_CLASS: &str = "org.apereo.cas.ticket.TicketGrantingTicketImpl";
const ST_CLASS: &str = "org.apereo.cas.ticket.ServiceTicketImpl";
const ENCODED: &str = "org.apereo.cas.ticket.registry.EncodedTicket";

fn ticket(id: &str, type_key: &str, class: &str, i: i64) -> DocBuf {
    DocBuf::new()
        .str("_id", id)
        .str(type_key, class)
        .str(
            "json",
            &format!("{{\"id\":\"{id}\",\"principal\":\"casuser{i}\"}}"),
        )
        .str("principal", &format!("casuser{i}@example.org"))
        .raw(0x09, "expireAt", &(1_900_000_000_000i64 + i).to_le_bytes())
}

fn audit(i: usize) -> DocBuf {
    DocBuf::new()
        .str("principal", &format!("audit.user{i}@example.net"))
        .str("resourceOperatedUpon", &format!("{TGT}-{i}"))
        .str("actionPerformed", "TICKET_GRANTING_TICKET_CREATED")
        .str("applicationCode", "CAS")
        .doc(
            "clientInfo",
            DocBuf::new()
                .str("clientIpAddress", &format!("192.0.2.{i}"))
                .doc(
                    "headers",
                    DocBuf::new().str("Cookie", &format!("TGC={TGC}")),
                ),
        )
}

async fn insert(s: &mut Session, collection: &str, documents: Vec<DocBuf>) {
    run(
        s,
        CAS_DB,
        DocBuf::new()
            .str("insert", collection)
            .array("documents", documents),
    )
    .await
    .unwrap();
}

async fn cleanup(s: &mut Session) {
    let _ = run(s, CAS_DB, DocBuf::new().i32("dropDatabase", 1)).await;
    for user in [CAS_USER, NARROW_USER] {
        let _ = run(s, "admin", DocBuf::new().str("dropUser", user)).await;
    }
    for role in [CAS_ROLE, NARROW_ROLE] {
        let _ = run(s, "admin", DocBuf::new().str("dropRole", role)).await;
    }
}

async fn fixtures(a: &Url) {
    let mut s = admin_session(a).await;
    cleanup(&mut s).await;
    insert(
        &mut s,
        "serviceTicketsCollection",
        vec![
            ticket(ST, "type", ST_CLASS, 1),
            ticket("ST-43-FAKEsecond-cas01", "type", ST_CLASS, 2),
            ticket("x-encoded-1", "type", ENCODED, 3),
        ],
    )
    .await;
    insert(
        &mut s,
        "sso_tickets_v2",
        vec![
            ticket(TGT, "Type", TGT_CLASS, 4),
            ticket("TGT-44-FAKEsecond-cas01", "Type", TGT_CLASS, 5),
        ],
    )
    .await;
    insert(
        &mut s,
        "MongoDbCasAuditRepository",
        (0..20).map(audit).collect(),
    )
    .await;
    insert(&mut s, "cas_audit_custom", (0..20).map(audit).collect()).await;
    insert(
        &mut s,
        "app_refs",
        (0..30)
            .map(|i| {
                DocBuf::new()
                    .str("ref", if i % 7 == 0 { ST } else { "ref-x" })
                    .str(
                        "contact",
                        &if i % 5 == 0 {
                            format!("INV-2026-{i:04}")
                        } else {
                            format!("guard.user{i}@example.com")
                        },
                    )
            })
            .collect(),
    )
    .await;
    for (role, resource) in [
        (
            CAS_ROLE,
            DocBuf::new().str("db", CAS_DB).str("collection", ""),
        ),
        (
            NARROW_ROLE,
            DocBuf::new()
                .str("db", CAS_DB)
                .str("collection", "app_refs"),
        ),
    ] {
        run(
            &mut s,
            "admin",
            DocBuf::new()
                .str("createRole", role)
                .array(
                    "privileges",
                    vec![
                        DocBuf::new()
                            .doc("resource", resource)
                            .array_str("actions", &["find"]),
                        DocBuf::new()
                            .doc(
                                "resource",
                                DocBuf::new().str("db", CAS_DB).str("collection", ""),
                            )
                            .array_str("actions", &["listCollections"]),
                    ],
                )
                .array("roles", Vec::new()),
        )
        .await
        .unwrap();
    }
    for (user, role) in [(CAS_USER, CAS_ROLE), (NARROW_USER, NARROW_ROLE)] {
        run(
            &mut s,
            "admin",
            DocBuf::new()
                .str("createUser", user)
                .str("pwd", IT_PASSWORD)
                .array(
                    "roles",
                    vec![DocBuf::new().str("role", role).str("db", "admin")],
                )
                .array_str("mechanisms", &["SCRAM-SHA-256"]),
        )
        .await
        .unwrap();
    }
    s.close().await;
}

/// The guard account's operations on the CAS database, from its profiler:
/// (namespace, operation, command bytes).
async fn profiled_ops(a: &Url) -> Vec<(String, String, Vec<u8>)> {
    let mut s = admin_session(a).await;
    let reply = run(
        &mut s,
        CAS_DB,
        DocBuf::new()
            .str("find", "system.profile")
            .doc(
                "filter",
                DocBuf::new().str("user", &format!("{CAS_USER}@admin")),
            )
            .i32("limit", 10_000)
            .i32("batchSize", 10_000)
            .bool("singleBatch", true),
    )
    .await
    .unwrap();
    s.close().await;
    let doc = Doc::new(&reply).unwrap();
    let batch = doc
        .doc("cursor")
        .unwrap()
        .unwrap()
        .array("firstBatch")
        .unwrap()
        .unwrap();
    batch
        .iter()
        .filter_map(|e| match e.unwrap().1 {
            Value::Doc(d) => Some((
                d.str("ns").unwrap().unwrap_or_default().to_owned(),
                d.str("op").unwrap().unwrap_or_default().to_owned(),
                d.doc("command")
                    .unwrap()
                    .map(|c| c.as_bytes().to_vec())
                    .unwrap_or_default(),
            )),
            _ => None,
        })
        .collect()
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

#[tokio::test]
async fn cas_store_guard_on_a_real_server() {
    let _serial = SERIAL.lock().await;
    let Some(_url) = server() else { return };
    let Some(a) = admin() else { return };
    fixtures(&a).await;

    let connector = MongodbConnector::new();
    let (_dir, t) = target(&a, CAS_USER, IT_PASSWORD, "admin");
    // The role authorizes the CAS database only (`listDatabases` with
    // `authorizedDatabases`).
    let job = ScanJob::new(ScanParams::contract_defaults(), &t, &unpaced(), key());
    let logs = Logs::default();
    let (r, findings) = {
        let _guard = logs.capture();
        let (sink, mut rx) = FindingSink::channel(100_000);
        let r = connector.discover(&job, &sink).await;
        drop(sink);
        let mut out = Vec::new();
        while let Some(f) = rx.recv().await {
            out.push(f);
        }
        (r, out)
    };
    r.unwrap();
    let text = logs.text();

    // Nothing of a ticket id or a cookie reaches a finding or a log line.
    for secret in [TGT, ST, TGC, "FAKE", "casuser"] {
        assert!(!text.contains(secret), "{secret} in the logs");
        for f in &findings {
            assert!(!format!("{f:?}").contains(secret), "{secret} in {f:?}");
        }
    }
    let found = located(&findings);
    for (db, object, field, _) in &found {
        assert_eq!(db, CAS_DB);
        assert!(
            object != "serviceTicketsCollection" && object != "sso_tickets_v2",
            "ticket registry sampled: {found:?}"
        );
        assert!(
            !field.starts_with("resourceOperatedUpon") && !field.contains("headers"),
            "audit credential field classified: {found:?}"
        );
        assert_ne!((object.as_str(), field.as_str()), ("app_refs", "ref"));
    }
    // Both ticket registries: metadata only, `Type` grouped like `type`
    // (review L5): 2 + 2 clear tickets, 1 encoded.
    assert_eq!(job.cas_guard().registries(), 2);
    assert_eq!(job.cas_guard().unencrypted(), 4);
    // The ticket id among the references trips the column; the invoice
    // numbers are dropped one by one and the addresses classified.
    assert_eq!(job.cas_guard().tripped(), 1);
    assert!(job.cas_guard().values_dropped() >= 6);
    assert!(found.contains(&(
        CAS_DB.to_owned(),
        "app_refs".to_owned(),
        "contact".to_owned(),
        "pii.email".to_owned()
    )));
    // Audit trails (built-in name, and renamed: recognized by the key
    // probe): the principal classified without masked samples.
    for object in ["MongoDbCasAuditRepository", "cas_audit_custom"] {
        let principal: Vec<_> = findings
            .iter()
            .filter(|f| {
                let l = f.location().unwrap();
                l.object.as_str() == object && l.field.as_str() == "principal"
            })
            .collect();
        assert!(!principal.is_empty(), "{object}: {found:?}");
        assert!(
            principal.iter().all(|f| f.masked_samples().is_empty()),
            "{principal:?}"
        );
    }

    // What the server ran for the guard account (its profiler).
    let ops = profiled_ops(&a).await;
    assert!(!ops.is_empty(), "the dev server profiles every operation");
    for (ns, op, command) in &ops {
        let coll = ns.strip_prefix(&format!("{CAS_DB}.")).unwrap_or("");
        let probe = contains(command, "$objectToArray");
        let group = contains(command, "$group");
        if coll == "serviceTicketsCollection" || coll == "sso_tickets_v2" {
            // The key probe and the `$group`, under the find-only grant.
            assert!(
                probe || group,
                "{ns}: {op} read a ticket registry ({:?})",
                String::from_utf8_lossy(command)
            );
        }
        if (coll == "MongoDbCasAuditRepository" || coll == "cas_audit_custom")
            && !probe
            && (op == "query" || contains(command, "aggregate"))
        {
            assert!(
                contains(command, "resourceOperatedUpon")
                    && contains(command, "clientInfo.headers"),
                "{ns}: {op} read without the audit projection"
            );
        }
    }
    assert!(
        ops.iter()
            .any(|(ns, _, c)| ns.ends_with(".sso_tickets_v2") && contains(c, "$Type")),
        "the renamed registry is grouped on its `Type` field"
    );

    // `check()` with the real roles: the database-wide `find` reads the
    // credentials of the two registries and the two audit trails (built-in
    // names listed, renamed ones known from the scan).
    let h = connector.check(&t).await;
    assert!(h.reachable, "{h:?}");
    let note = h
        .notes
        .iter()
        .find(|n| n.code() == NoteCode::PrivilegeTicketCredentialsReadable);
    assert_eq!(note.and_then(TargetNote::count), Some(4), "{:?}", h.notes);
    assert!(
        !codes(&h.notes).contains(&NoteCode::PrivilegeNotEvaluated.as_str()),
        "{:?} ({:?})",
        h.notes,
        h.detail
    );
    // `find` on one plain collection only: nothing readable.
    let (_dir2, narrow) = target(&a, NARROW_USER, IT_PASSWORD, "admin");
    let h = MongodbConnector::new().check(&narrow).await;
    assert!(h.reachable, "{h:?}");
    let got = codes(&h.notes);
    assert!(
        !got.contains(&NoteCode::PrivilegeTicketCredentialsReadable.as_str())
            && !got.contains(&NoteCode::PrivilegeNotEvaluated.as_str()),
        "{got:?} ({:?})",
        h.detail
    );

    let mut s = admin_session(&a).await;
    cleanup(&mut s).await;
    s.close().await;
}
