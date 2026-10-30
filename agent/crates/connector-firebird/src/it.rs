//! Integration tests against a real Firebird 4.0 / 5.0 server on loopback
//! (`dev/firebird/it.sh` starts a throwaway one from the pinned images,
//! seeds it and runs these tests; the full dev service is P10-B lot 2).
//!
//! Skipped unless `DATABASTION_IT_FIREBIRD=1`. Variables:
//! - `FIREBIRD_PORT` (default 3050) and `FIREBIRD_IT_PEER_UID` (the uid
//!   owning the server's sockets, default 84; 0 needs the root opt-in,
//!   which the tests then set);
//! - `FIREBIRD_IT_ATTACH`: the seeded database's path on the server;
//! - `FIREBIRD_IT_AGENT_PASSWORD_FILE`: a `0600` file holding the fake
//!   password of the seeded
//!   accounts `DATABASTION_AGENT` (minimal variant), `AGENT_EXT` (the
//!   extended variant's role) and `AGENT_NONE` (no grant);
//! - `FIREBIRD_IT_WRONG_PASSWORD_FILE`: a file with any other fake value;
//! - `FIREBIRD_IT_SYSDBA_PASSWORD_FILE` (optional): a file with the
//!   throwaway server's
//!   `SYSDBA` password (the refusal test only);
//! - `FIREBIRD_IT_MAJOR` (optional): the major version the server must
//!   report, so an entry cannot silently test another image;
//! - `FIREBIRD_IT_FORWARDER_PORT` and `FIREBIRD_IT_FORWARDER_UID`
//!   (optional): a loopback forwarder (`socat`) to the server and the uid
//!   owning its sockets, refused without `tunnel: true`;
//! - `FIREBIRD_IT_CHACHA_PORT`, `FIREBIRD_IT_ARC4_PORT`,
//!   `FIREBIRD_IT_NOCRYPT_PORT`, `FIREBIRD_IT_FB3_PORT` (optional): servers
//!   run as root (uid 0, with the root opt-in) offering ChaCha only, Arc4
//!   only, no wire encryption, and a Firebird 3.0 server, each seeded with
//!   the same accounts.
//!
//! - `FIREBIRD_IT_MAPPING_PORT` (optional): a server (run as root) whose
//!   seed adds the authentication mappings of review L2.
//!
//! Passwords reach the connector through `secret: {file: …}` only (review
//! L4): the variables name the files, never hold a password.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]

use databastion_core::config::TargetConfig;
use databastion_core::{AuditLevel, Connector, FailureCode, NoteCode, TargetHealth};

use crate::FirebirdConnector;

fn enabled() -> bool {
    std::env::var("DATABASTION_IT_FIREBIRD").as_deref() == Ok("1")
}

fn var(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn port() -> String {
    var("FIREBIRD_PORT", "3050")
}

fn peer_uid() -> String {
    var("FIREBIRD_IT_PEER_UID", "84")
}

fn attach() -> String {
    var("FIREBIRD_IT_ATTACH", "/var/lib/firebird/data/app.fdb")
}

/// A target for `account` whose password is in the file named by the
/// environment variable `secret_env`, with extra
/// `firebird` keys and a given database.
fn target_on(
    account: &str,
    secret_env: &str,
    extra: &str,
    port: &str,
    peer_uid: &str,
    attach: &str,
) -> TargetConfig {
    let root = if peer_uid == "0" {
        "peer_uid_root: true, "
    } else {
        ""
    };
    let secret_file = var(secret_env, "/nonexistent/databastion-it-secret");
    let yaml = format!(
        "{{console: {{url: \"https://c.example\"}}, state_dir: /tmp, targets: [{{id: fb-it, \
         engine: firebird, host: 127.0.0.1, port: {port}, account: {account}, \
         secret: {{file: \"{secret_file}\"}}, firebird: {{peer_uid: {peer_uid}, {root}{extra} \
         databases: [{{name: app, attach: \"{attach}\"}}]}}}}]}}"
    );
    databastion_core::AgentConfig::parse(&yaml)
        .unwrap_or_else(|e| panic!("{e}"))
        .targets
        .remove(0)
}

fn target(
    account: &str,
    secret_env: &str,
    extra: &str,
    port: &str,
    peer_uid: &str,
) -> TargetConfig {
    target_on(account, secret_env, extra, port, peer_uid, &attach())
}

fn agent(extra: &str) -> TargetConfig {
    target(
        "DATABASTION_AGENT",
        "FIREBIRD_IT_AGENT_PASSWORD_FILE",
        extra,
        &port(),
        &peer_uid(),
    )
}

fn codes(h: &TargetHealth) -> Vec<&'static str> {
    h.notes.iter().map(|n| n.code().as_str()).collect()
}

fn labels(h: &TargetHealth, code: NoteCode) -> Vec<String> {
    h.notes
        .iter()
        .find(|n| n.code() == code)
        .map(|n| n.labels().iter().map(|l| l.as_str()).collect())
        .unwrap_or_default()
}

/// The status the heartbeat would send, through the core's Firebird
/// rules, conforms to the contract's `firebird` branch (merge condition
/// C1), with registered codes only.
fn assert_contract(h: &TargetHealth, version: Option<&str>) {
    let json = databastion_core::test_support::contract_target_status_json(
        h,
        databastion_core::config::TargetEngine::Firebird,
        version,
    );
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let rules = databastion_core::contract_rules::branch("TargetStatus", "engine", "firebird");
    databastion_core::contract_rules::conforms(&rules, &value)
        .unwrap_or_else(|e| panic!("{e}: {value}"));
    for n in value["notes"].as_array().into_iter().flatten() {
        let code = n["code"].as_str().unwrap();
        assert!(NoteCode::ALL.iter().any(|c| c.as_str() == code), "{code}");
    }
}

#[tokio::test]
async fn the_minimal_account_is_reachable_with_no_privilege_note() {
    if !enabled() {
        return;
    }
    let c = FirebirdConnector::new();
    let t = agent("");
    let h = c.check(&t).await;
    assert!(h.reachable, "{:?} {:?}", h.detail, h.failure);
    assert_eq!(h.audit_level, AuditLevel::None);
    // NOGRANT: the reader role has no SELECT on it (decision 5).
    assert_eq!(
        codes(&h),
        [
            "coverage.relations_without_select",
            "audit.source_not_configured"
        ],
        "{:?}",
        h.detail
    );
    assert_eq!(count(&h, NoteCode::CoverageRelationsWithoutSelect), Some(1));
    let v = c.server_version(&t).unwrap();
    let major = crate::check::major_of(&v).unwrap();
    if let Ok(want) = std::env::var("FIREBIRD_IT_MAJOR")
        && !want.trim().is_empty()
    {
        assert_eq!(major.to_string(), want.trim(), "{v}");
    }
    assert!(!c.state.blocks("fb-it"));
    let detail = h.detail.clone().unwrap();
    assert!(detail.contains("ChaCha64"), "{detail}");
    assert_contract(&h, Some(&v));
}

#[tokio::test]
async fn the_extended_variant_and_the_server_configuration() {
    if !enabled() {
        return;
    }
    let c = FirebirdConnector::new();
    let ext = |extra: &str| {
        target(
            "AGENT_EXT",
            "FIREBIRD_IT_AGENT_PASSWORD_FILE",
            extra,
            &port(),
            &peer_uid(),
        )
    };
    // Without the flag: over-privilege, and RDB$CONFIG readable (R3).
    let h = c.check(&ext("")).await;
    assert!(h.reachable, "{:?}", h.detail);
    assert_eq!(
        labels(&h, NoteCode::PrivilegeGlobalPrivileges),
        ["select_any_object_in_database", "server_config_readable"],
        "{:?}",
        h.notes
    );
    assert!(!codes(&h).contains(&"privilege.refused"));
    // With it: the extended variant, and the configuration still noted.
    let h = c.check(&ext("extended_grants: true,")).await;
    assert_eq!(
        labels(&h, NoteCode::PrivilegeExtendedVariant),
        ["select_any_object_in_database"]
    );
    assert_eq!(
        labels(&h, NoteCode::PrivilegeGlobalPrivileges),
        ["server_config_readable"]
    );
    assert!(!c.state.blocks("fb-it"));
    assert_contract(&h, None);
}

#[tokio::test]
async fn an_account_without_grants_is_clean_and_sysdba_is_refused() {
    if !enabled() {
        return;
    }
    let c = FirebirdConnector::new();
    let none = target(
        "AGENT_NONE",
        "FIREBIRD_IT_AGENT_PASSWORD_FILE",
        "",
        &port(),
        &peer_uid(),
    );
    let h = c.check(&none).await;
    assert!(h.reachable, "{:?}", h.detail);
    assert_eq!(
        codes(&h),
        [
            "coverage.relations_without_select",
            "audit.source_not_configured"
        ],
        "{:?}",
        h.notes
    );
    assert_eq!(count(&h, NoteCode::CoverageRelationsWithoutSelect), Some(2));
    if std::env::var("FIREBIRD_IT_SYSDBA_PASSWORD_FILE").is_err() {
        return;
    }
    let sysdba = target(
        "SYSDBA",
        "FIREBIRD_IT_SYSDBA_PASSWORD_FILE",
        "",
        &port(),
        &peer_uid(),
    );
    let h = c.check(&sysdba).await;
    assert!(h.reachable, "{:?}", h.detail);
    assert_eq!(codes(&h)[0], "privilege.refused", "{:?}", h.notes);
    let refused = labels(&h, NoteCode::PrivilegeRefused);
    for l in ["sysdba", "rdb_admin", "database_owner"] {
        assert!(refused.contains(&l.to_owned()), "{l}: {refused:?}");
    }
    assert!(c.state.blocks("fb-it"));
    assert_contract(&h, None);
}

#[tokio::test]
async fn failures_are_closed_codes_at_their_stage() {
    if !enabled() {
        return;
    }
    let c = FirebirdConnector::new();
    // A wrong password: the server refuses the proof.
    if std::env::var("FIREBIRD_IT_WRONG_PASSWORD_FILE").is_ok() {
        let h = c
            .check(&target(
                "DATABASTION_AGENT",
                "FIREBIRD_IT_WRONG_PASSWORD_FILE",
                "",
                &port(),
                &peer_uid(),
            ))
            .await;
        assert_eq!(h.failure, Some(FailureCode::AuthenticationFailed));
        assert_eq!(codes(&h), ["check.stage_failed"]);
        assert_eq!(
            labels(&h, NoteCode::CheckStageFailed),
            ["stage_auth"],
            "{:?}",
            h.detail
        );
    }
    // Another uid owns the server's socket.
    let other = if peer_uid() == "4242" { "4243" } else { "4242" };
    let h = c
        .check(&target(
            "DATABASTION_AGENT",
            "FIREBIRD_IT_AGENT_PASSWORD_FILE",
            "",
            &port(),
            other,
        ))
        .await;
    assert_eq!(h.failure, Some(FailureCode::TargetUnreachable));
    assert_eq!(labels(&h, NoteCode::CheckStageFailed), ["stage_connect"]);
    assert!(h.detail.unwrap().contains("firebird.peer_uid"));
    // A forwarder in the path, refused without `tunnel: true`, accepted
    // with it (and the tunnel note).
    if let Ok(fwd) = std::env::var("FIREBIRD_IT_FORWARDER_PORT") {
        let fwd_uid = var("FIREBIRD_IT_FORWARDER_UID", "0");
        let h = c
            .check(&target(
                "DATABASTION_AGENT",
                "FIREBIRD_IT_AGENT_PASSWORD_FILE",
                "",
                &fwd,
                &fwd_uid,
            ))
            .await;
        assert_eq!(
            h.failure,
            Some(FailureCode::TargetUnreachable),
            "{:?}",
            h.detail
        );
        let detail = h.detail.unwrap_or_default();
        assert!(detail.contains("forwarder"), "{detail}");
        let h = c
            .check(&target(
                "DATABASTION_AGENT",
                "FIREBIRD_IT_AGENT_PASSWORD_FILE",
                "tunnel: true,",
                &fwd,
                &fwd_uid,
            ))
            .await;
        assert!(h.reachable, "{:?}", h.detail);
        assert_eq!(codes(&h)[0], "security.firebird_tunnel");
    }
}

#[tokio::test]
async fn an_unknown_database_is_an_unknown_target() {
    if !enabled() {
        return;
    }
    let c = FirebirdConnector::new();
    let t = target_on(
        "DATABASTION_AGENT",
        "FIREBIRD_IT_AGENT_PASSWORD_FILE",
        "",
        &port(),
        &peer_uid(),
        "/nonexistent/databastion-it.fdb",
    );
    let h = c.check(&t).await;
    assert_eq!(
        h.failure,
        Some(FailureCode::UnknownTarget),
        "{:?}",
        h.detail
    );
    assert_eq!(
        labels(&h, NoteCode::CheckStageFailed),
        ["stage_session_setup"]
    );
}

/// Many SRP exchanges with fresh values, so that `A` (and, by chance, `B`)
/// has a leading zero byte at least once in most runs: Firebird hashes
/// minimal bytes, not RFC 5054 padding (the deterministic case is the
/// unit test of `srp`).
#[tokio::test]
async fn many_exchanges_authenticate() {
    if !enabled() {
        return;
    }
    let t = agent("");
    let endpoint = crate::conn::Endpoint::of(&t).unwrap();
    let password = t.secret.read().unwrap();
    for i in 0..64 {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let s = crate::conn::connect(
            &endpoint,
            password.as_bytes(),
            &attach(),
            deadline,
            std::time::Duration::from_secs(3),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "exchange {i}: code {}, stage {}, gds {:?}, detail {}",
                e.code,
                e.stage.as_str(),
                e.gds,
                e.detail.map_or("none", crate::error::Detail::as_str)
            )
        });
        s.close().await;
    }
}

/// Decisions 1 to 3 against real servers: ChaCha when ChaCha64 is not
/// offered; Arc4 only and no wire encryption refused; Firebird 3.0 refused
/// at `op_connect`, before anything derived from the password is sent.
#[tokio::test]
async fn wire_encryption_variants_and_firebird_3() {
    if !enabled() {
        return;
    }
    let c = FirebirdConnector::new();
    let on = |port: &str| {
        target(
            "DATABASTION_AGENT",
            "FIREBIRD_IT_AGENT_PASSWORD_FILE",
            "",
            port,
            "0",
        )
    };
    if let Ok(p) = std::env::var("FIREBIRD_IT_CHACHA_PORT") {
        let h = c.check(&on(&p)).await;
        assert!(h.reachable, "{:?}", h.detail);
        let detail = h.detail.unwrap();
        assert!(
            detail.contains("wire encryption ChaCha") && !detail.contains("ChaCha64"),
            "{detail}"
        );
    }
    if let Ok(p) = std::env::var("FIREBIRD_IT_ARC4_PORT") {
        let h = c.check(&on(&p)).await;
        assert_eq!(
            h.failure,
            Some(FailureCode::TargetUnreachable),
            "{:?}",
            h.detail
        );
        assert_eq!(
            labels(&h, NoteCode::CheckStageFailed),
            ["stage_tls"],
            "{:?}",
            h.detail
        );
    }
    if let Ok(p) = std::env::var("FIREBIRD_IT_NOCRYPT_PORT") {
        let h = c.check(&on(&p)).await;
        assert!(!h.reachable, "{:?}", h.detail);
        assert_eq!(
            h.failure,
            Some(FailureCode::TargetUnreachable),
            "{:?}",
            h.detail
        );
        eprintln!("[it] no wire encryption: {:?}", h.detail);
    }
    if let Ok(p) = std::env::var("FIREBIRD_IT_FB3_PORT") {
        let h = c.check(&on(&p)).await;
        assert_eq!(h.failure, Some(FailureCode::Unsupported), "{:?}", h.detail);
        assert_eq!(labels(&h, NoteCode::CheckStageFailed), ["stage_connect"]);
        assert!(h.detail.unwrap().contains("protocol 16"));
    }
}

/// Decision 4: the per-version table of system-privilege bit positions,
/// checked against the image (the drift test): `dev/firebird/it.sh`
/// creates one role `DBI_P_<NAME>` per privilege of the version, and each
/// role's mask must hold exactly the bit the table gives it.
#[tokio::test]
async fn the_system_privilege_bits_are_the_tables() {
    if !enabled() {
        return;
    }
    let t = agent("");
    let endpoint = crate::conn::Endpoint::of(&t).unwrap();
    let password = t.secret.read().unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut s = crate::conn::connect(
        &endpoint,
        password.as_bytes(),
        &attach(),
        deadline,
        std::time::Duration::from_secs(3),
    )
    .await
    .unwrap();
    let rows = s
        .query(
            crate::sql::ROLE_PRIVILEGES,
            &[crate::sql::Col::Text(252), crate::sql::Col::Octets(8)],
            4096,
            deadline,
        )
        .await
        .unwrap();
    let version = s
        .query(
            crate::sql::VERSION,
            &[crate::sql::Col::Text(128)],
            1,
            deadline,
        )
        .await
        .unwrap();
    s.close().await;
    let major = crate::check::major_of(version.rows[0][0].as_text().unwrap()).unwrap();
    let known = crate::privileges::known_bits(major);
    let mut found = 0;
    for row in &rows.rows {
        let name = row[0].as_text().unwrap();
        let Some(privilege) = name.strip_prefix("DBI_P_") else {
            continue;
        };
        let mask = row[1].as_bytes().unwrap();
        let set: Vec<usize> = (0..64)
            .filter(|n| mask.get(n / 8).is_some_and(|b| b & (1 << (n % 8)) != 0))
            .collect();
        let position = crate::privileges::SYSTEM_PRIVILEGES
            .iter()
            .position(|p| p.eq_ignore_ascii_case(privilege))
            .unwrap_or_else(|| panic!("{privilege} is not in the table"));
        assert!(position < known, "{privilege} is past the table of {major}");
        assert_eq!(set, [position + 1], "{privilege}");
        found += 1;
    }
    assert_eq!(found, known, "roles DBI_P_* of dev/firebird/it.sh");
}

/// Decision 4 (M6): a refused system privilege held through a role the
/// account was granted (not `DEFAULT`, so not in use) and nested in
/// another role is still refused, through the role graph.
#[tokio::test]
async fn a_refused_privilege_through_a_role_not_in_use_is_refused() {
    if !enabled() {
        return;
    }
    let c = FirebirdConnector::new();
    let h = c
        .check(&target(
            "AGENT_NESTED",
            "FIREBIRD_IT_AGENT_PASSWORD_FILE",
            "",
            &port(),
            &peer_uid(),
        ))
        .await;
    assert!(h.reachable, "{:?}", h.detail);
    assert_eq!(codes(&h)[0], "privilege.refused", "{:?}", h.notes);
    assert_eq!(
        labels(&h, NoteCode::PrivilegeRefused),
        ["trace_any_attachment"]
    );
    assert!(c.state.blocks("fb-it"));
}

/// Review L2 against a real server: a mapping to SYSDBA through the `Srp`
/// plugin name and a global mapping to RDB$ADMIN restricted to another
/// database are refused; mappings of another user or of `Legacy_Auth` do
/// not refuse the account.
#[tokio::test]
async fn mappings_to_sysdba_or_rdb_admin_are_refused() {
    if !enabled() {
        return;
    }
    let Ok(p) = std::env::var("FIREBIRD_IT_MAPPING_PORT") else {
        return;
    };
    let c = FirebirdConnector::new();
    let on = |account: &str| target(account, "FIREBIRD_IT_AGENT_PASSWORD_FILE", "", &p, "0");
    let h = c.check(&on("DATABASTION_AGENT")).await;
    assert!(h.reachable, "{:?}", h.detail);
    assert!(!codes(&h).contains(&"privilege.refused"), "{:?}", h.notes);
    assert!(!c.state.blocks("fb-it"), "{:?}", h.detail);
    for (account, label) in [("MAP_LOCAL", "sysdba"), ("MAP_GLOBAL", "rdb_admin")] {
        let h = c.check(&on(account)).await;
        assert!(h.reachable, "{account}: {:?}", h.detail);
        eprintln!("[it] {account}: {:?}", h.detail);
        assert!(
            labels(&h, NoteCode::PrivilegeRefused).contains(&label.to_owned()),
            "{account}: {:?}",
            h.notes
        );
        assert!(c.state.blocks("fb-it"));
        assert_contract(&h, None);
    }
}

/// Review L5 against a real server: a role granted `WITH ADMIN OPTION`.
#[tokio::test]
async fn a_membership_with_the_admin_option_is_a_grant_option() {
    if !enabled() {
        return;
    }
    let c = FirebirdConnector::new();
    let h = c
        .check(&target(
            "AGENT_ADMIN_OPT",
            "FIREBIRD_IT_AGENT_PASSWORD_FILE",
            "",
            &port(),
            &peer_uid(),
        ))
        .await;
    assert!(h.reachable, "{:?}", h.detail);
    assert!(
        codes(&h).contains(&"privilege.grant_option"),
        "{:?}",
        h.notes
    );
}

/// ADR-0060 obligation 2, second half (decision 4): `op_cancel` sent at
/// the client deadline while an `op_fetch` is pending (a `COUNT(*)` that
/// the server computes during the first fetch) ends the statement with
/// `isc_cancelled`, within the 5 s the connector waits, and the attachment
/// stays usable.
#[tokio::test]
async fn op_cancel_ends_a_pending_fetch() {
    if !enabled() {
        return;
    }
    let t = agent("");
    let endpoint = crate::conn::Endpoint::of(&t).unwrap();
    let password = t.secret.read().unwrap();
    let mut s = crate::conn::connect(
        &endpoint,
        password.as_bytes(),
        &attach(),
        tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(30),
    )
    .await
    .unwrap();
    let start = std::time::Instant::now();
    let r = s
        .query_for_tests(
            "SELECT COUNT(*) FROM RDB$FIELDS A, RDB$FIELDS B, RDB$FIELDS C, RDB$FIELDS D",
            &[crate::sql::Col::Int],
            1,
            tokio::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await;
    let elapsed = start.elapsed();
    let e = r.unwrap_err();
    assert_eq!(e.code, FailureCode::Timeout, "{e:?}");
    let outcome = s.last_cancel.expect("no answer to op_cancel");
    eprintln!(
        "[measure] op_cancel during a pending fetch: answered {:?} after {} ms (statement ended \
         after {} ms)",
        outcome.gds,
        outcome.after.as_millis(),
        elapsed.as_millis()
    );
    assert_eq!(outcome.gds, Some(crate::error::gds::CANCELLED));
    assert!(outcome.after < std::time::Duration::from_secs(5));
    assert!(!s.is_broken());
    // The attachment is still usable.
    let rows = s
        .query(
            crate::sql::VERSION,
            &[crate::sql::Col::Text(128)],
            1,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(rows.rows.len(), 1);
    s.close().await;
    // The server-side statement timeout (decision 4) ends the same fetch
    // before the client's deadline: no op_cancel.
    let mut s = crate::conn::connect(
        &endpoint,
        password.as_bytes(),
        &attach(),
        tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(1),
    )
    .await
    .unwrap();
    let start = std::time::Instant::now();
    let e = s
        .query_for_tests(
            "SELECT COUNT(*) FROM RDB$FIELDS A, RDB$FIELDS B, RDB$FIELDS C, RDB$FIELDS D",
            &[crate::sql::Col::Int],
            1,
            tokio::time::Instant::now() + std::time::Duration::from_secs(10),
        )
        .await
        .unwrap_err();
    eprintln!(
        "[measure] server-side statement timeout of 1 s during a fetch: {:?} (first gds {:?}) \
         after {} ms",
        e.code,
        e.gds,
        start.elapsed().as_millis()
    );
    assert_eq!(e.code, FailureCode::Timeout, "{e:?}");
    assert!(s.last_cancel.is_none());
    assert!(!s.is_broken());
    s.close().await;
}

// ---------------------------------------------------------------------
// Discovery (lot 2): the seeded database `crm` (dev/seed/out/firebird.sql,
// loaded by dev/firebird/seed.sh), declared as `crm`, against the ground
// truth (dev/ground-truth.json). FIREBIRD_IT_CRM_ATTACH names its file.
// ---------------------------------------------------------------------

fn crm_attach() -> Option<String> {
    std::env::var("FIREBIRD_IT_CRM_ATTACH")
        .ok()
        .filter(|a| !a.is_empty())
}

fn crm(account: &str, extra: &str) -> TargetConfig {
    // Every seeded account has the agent's fake password.
    let secret_file = var(
        "FIREBIRD_IT_AGENT_PASSWORD_FILE",
        "/nonexistent/databastion-it-secret",
    );
    let yaml = format!(
        "{{console: {{url: \"https://c.example\"}}, state_dir: /tmp, targets: [{{id: fb-crm, \
         engine: firebird, host: 127.0.0.1, port: {}, account: {account}, \
         secret: {{file: \"{secret_file}\"}}, firebird: {{peer_uid: {}, {extra} \
         databases: [{{name: crm, attach: \"{}\"}}]}}}}]}}",
        port(),
        peer_uid(),
        crm_attach().unwrap_or_default()
    );
    databastion_core::AgentConfig::parse(&yaml)
        .unwrap_or_else(|e| panic!("{e}"))
        .targets
        .remove(0)
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

struct Scan {
    result: Result<(), databastion_core::ConnectorError>,
    findings: Vec<databastion_classifiers::masking::MaskedFinding>,
    coverage: databastion_core::ScanCoverage,
    job: databastion_core::ScanJob,
}

async fn scan(
    c: &FirebirdConnector,
    t: &TargetConfig,
    limits: databastion_core::config::Limits,
) -> Scan {
    let key =
        std::sync::Arc::new(databastion_classifiers::masking::HmacKey::new(&[7u8; 32]).unwrap());
    let job = databastion_core::ScanJob::new(
        databastion_core::ScanParams::contract_defaults(),
        t,
        &limits,
        key,
    );
    let (sink, mut rx) = databastion_core::FindingSink::channel(10_000);
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
        job,
    }
}

fn unpaced() -> databastion_core::config::Limits {
    databastion_core::config::Limits {
        discovery_duty_cycle_percent: 100,
        ..databastion_core::config::Limits::default()
    }
}

fn count(h: &TargetHealth, code: NoteCode) -> Option<u64> {
    h.notes
        .iter()
        .find(|n| n.code() == code)
        .and_then(|n| n.count())
}

/// Decision 5 against the seed of decision 9: every expected finding at
/// its location (names as stored, trailing spaces dropped, a value-bearing
/// name as `*`), no finding on a negative control or a fixture Discovery
/// must not sample, the coverage of the fixtures, and I2: no ground-truth
/// value (sampled or not, names included) in what the uplink would send.
#[tokio::test]
async fn discovery_matches_the_ground_truth_and_keeps_i2() {
    if !enabled() || crm_attach().is_none() {
        return;
    }
    let c = FirebirdConnector::new();
    let t = crm("DATABASTION_AGENT", "");
    let h = c.check(&t).await;
    eprintln!("[it] crm check: {:?} {:?}", codes(&h), h.detail);
    assert!(h.reachable, "{:?}", h.detail);
    assert!(!codes(&h).contains(&"privilege.refused"), "{:?}", h.notes);
    assert_eq!(count(&h, NoteCode::CoverageViewsNotSampled), Some(1));
    assert_eq!(
        count(&h, NoteCode::CoverageComputedColumnsNotSampled),
        Some(1)
    );
    assert_eq!(count(&h, NoteCode::CoverageExternalFileTables), Some(1));
    assert_eq!(count(&h, NoteCode::CoverageRelationsWithoutSelect), Some(1));
    // CAS_TICKETS: SELECT is per table in Firebird.
    assert_eq!(
        count(&h, NoteCode::PrivilegeTicketCredentialsReadable),
        Some(1)
    );
    assert!(codes(&h).contains(&"security.login_event_trigger"));
    assert!(!c.state.blocks("fb-crm"));
    assert_contract(&h, None);
    let s = scan(&c, &t, unpaced()).await;
    s.result.as_ref().unwrap();
    eprintln!("[it] crm coverage: {:?}", s.coverage);
    let got: Vec<String> = s
        .findings
        .iter()
        .map(|f| {
            let l = f.location().unwrap();
            assert!(l.schema.is_none());
            format!(
                "{}.{}.{} {}",
                l.database.as_str(),
                l.object.as_str(),
                l.field.as_str(),
                f.classifier().as_str()
            )
        })
        .collect();
    for g in &got {
        eprintln!("[it] finding {g}");
    }
    let truth = truth();
    let mut values: Vec<String> = Vec::new();
    let mut checked = 0;
    for loc in truth["locations"].as_array().unwrap() {
        if loc["engine"] != "firebird" {
            continue;
        }
        let name = |k: &str| loc[k].as_str().unwrap_or_default().to_owned();
        let object = loc["expected_normalized_name"].as_str().map_or_else(
            || {
                crate::discover::normalize(&name("object"))
                    .as_str()
                    .to_owned()
            },
            str::to_owned,
        );
        let field = crate::discover::normalize(&name("field"))
            .as_str()
            .to_owned();
        let at = format!("{}.{object}.{field}", name("database"));
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
    assert!(checked >= 20, "{checked}");
    // CUSTOMERS, Customer Notes, Legacy Contacts, LEGACY_1252,
    // PAYMENT_CARDS, RDB$CUSTOMER_ARCHIVE, EXPORT_…, LOGIN_REFS,
    // APP_CREDENTIALS, INVOICES.
    assert_eq!(s.coverage.sampled, 10, "{:?}", s.coverage);
    assert_eq!(s.coverage.remote, 1, "EXT_EXPORT: {:?}", s.coverage);
    assert_eq!(s.coverage.not_readable, 1, "HR_SALARIES: {:?}", s.coverage);
    assert_eq!(s.coverage.unsupported, 1, "CAS_TICKETS: {:?}", s.coverage);
    assert_eq!(s.coverage.error, 0, "{:?}", s.coverage);
    assert_eq!(s.coverage.limit, 0, "{:?}", s.coverage);
    // The CAS store guard: the registry's type counts, the tripwire on
    // LOGIN_REFS.SESSION_REF.
    assert_eq!(s.job.cas_guard().registries(), 1);
    assert_eq!(s.job.cas_guard().tripped(), 1);
    assert_eq!(s.job.cas_guard().unencrypted(), 6);
    let json = databastion_core::test_support::contract_findings_json(
        &s.findings,
        databastion_core::config::TargetEngine::Firebird,
    );
    assert!(json.contains("\"engine\":\"firebird\""));
    for v in &values {
        assert!(
            !json.contains(v.as_str()),
            "raw ground-truth value in the contract JSON"
        );
    }
}

/// ADR-0035 against the real server: at a 25 % duty cycle the scan pauses
/// about three times its query time; a scan whose window is too short for
/// its pauses stops and reports the objects left as `skipped_limit`.
#[tokio::test]
async fn discovery_is_paced() {
    if !enabled() || crm_attach().is_none() {
        return;
    }
    let c = FirebirdConnector::new();
    let t = crm("DATABASTION_AGENT", "");
    assert!(c.check(&t).await.reachable);
    let paced = databastion_core::config::Limits {
        discovery_duty_cycle_percent: 25,
        ..databastion_core::config::Limits::default()
    };
    let s = scan(&c, &t, paced).await;
    s.result.as_ref().unwrap();
    let (busy, paused) = s.job.pacer().totals();
    eprintln!(
        "[measure] Discovery of crm at 25 %: busy {} ms, paused {} ms",
        busy.as_millis(),
        paused.as_millis()
    );
    assert!(paused >= busy * 2, "{busy:?} {paused:?}");
    assert_eq!(s.coverage.sampled, 10, "{:?}", s.coverage);
    // 1 %, 2 s window: out of time.
    let short = databastion_core::config::Limits {
        discovery_duty_cycle_percent: 1,
        max_scan_duration_s: 2,
        ..databastion_core::config::Limits::default()
    };
    let started = std::time::Instant::now();
    let s = scan(&c, &t, short).await;
    s.result.as_ref().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert!(s.coverage.limit > 0, "{:?}", s.coverage);
    assert!(s.coverage.sampled < 10, "{:?}", s.coverage);
}

/// Open question 4: an account mapped to SYSDBA is refused by `check()`,
/// and Discovery does not run.
#[tokio::test]
async fn a_sysdba_mapped_account_is_refused_and_discovery_does_not_run() {
    if !enabled() || crm_attach().is_none() {
        return;
    }
    let c = FirebirdConnector::new();
    let t = crm("AGENT_SYSDBA_MAPPED", "");
    let h = c.check(&t).await;
    assert!(h.reachable, "{:?}", h.detail);
    assert_eq!(codes(&h)[0], "privilege.refused", "{:?}", h.notes);
    assert!(labels(&h, NoteCode::PrivilegeRefused).contains(&"sysdba".to_owned()));
    assert!(c.state.blocks("fb-crm"));
    let s = scan(&c, &t, unpaced()).await;
    assert!(matches!(
        s.result,
        Err(databastion_core::ConnectorError::Target {
            code: FailureCode::PermissionDenied,
            ..
        })
    ));
    assert!(s.findings.is_empty());
}

/// Decision 5, security review M5: every system relation of the image is
/// on the closed never-sampled list (the drift test of the list).
#[tokio::test]
async fn every_system_relation_is_never_sampled() {
    if !enabled() {
        return;
    }
    let t = agent("");
    let endpoint = crate::conn::Endpoint::of(&t).unwrap();
    let password = t.secret.read().unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut s = crate::conn::connect(
        &endpoint,
        password.as_bytes(),
        &attach(),
        deadline,
        std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    let rows = s
        .query_for_tests(
            "SELECT CAST(TRIM(TRAILING FROM RDB$RELATION_NAME) AS VARCHAR(63) CHARACTER SET UTF8) \
             FROM RDB$RELATIONS WHERE COALESCE(RDB$SYSTEM_FLAG, 0) <> 0",
            &[crate::sql::Col::Text(252)],
            4096,
            deadline,
        )
        .await
        .unwrap();
    s.close().await;
    assert!(rows.rows.len() > 40, "{}", rows.rows.len());
    for r in &rows.rows {
        let name = r[0].as_text().unwrap();
        assert!(
            crate::catalog::never_sampled(name),
            "system relation {name} is not on the never-sampled list"
        );
    }
}

/// Security review L5: every relation of the image's own security database
/// (`security<N>.fdb`, listed by `dev/firebird/it.sh` through an embedded
/// read: the agent account cannot attach it) is on the never-sampled list,
/// whatever its system flag (`PLG$SRP` and `PLG$USERS` have flag 0).
#[test]
fn every_security_database_relation_is_never_sampled() {
    if !enabled() {
        return;
    }
    let path = std::env::var("FIREBIRD_IT_SECDB_RELATIONS_FILE")
        .expect("dev/firebird/it.sh sets FIREBIRD_IT_SECDB_RELATIONS_FILE");
    let list = std::fs::read_to_string(path).unwrap();
    let names: Vec<&str> = list
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert!(names.len() > 40, "{}", names.len());
    for want in ["PLG$SRP", "PLG$USERS", "SEC$USERS"] {
        assert!(
            names.contains(&want),
            "{want} not in the security database list"
        );
    }
    for name in names {
        assert!(
            crate::catalog::never_sampled(name),
            "security database relation {name} is not on the never-sampled list"
        );
    }
}

/// The system audit trace of the main server (lot 3): its configuration
/// and the log of the `dev/firebird/it.sh` workload.
#[path = "it_audit.rs"]
mod audit;

/// The lot 3 texts on the agent's own attachment (R2 rule 1, R9, proof
/// 7): the resolved path, `Default` as the security-database kind of an
/// ordinary database, and one row for the read-back probe; the session's
/// attachment and credits reach the endpoint's ledger.
#[tokio::test]
async fn the_lot_3_texts_and_the_ledger() {
    if !enabled() {
        return;
    }
    let t = agent("");
    let endpoint = crate::conn::Endpoint::of(&t).unwrap();
    let password = t.secret.read().unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut s = crate::conn::connect(
        &endpoint,
        password.as_bytes(),
        &attach(),
        deadline,
        std::time::Duration::from_secs(3),
    )
    .await
    .unwrap();
    crate::check::prepare(&mut s, false, deadline)
        .await
        .unwrap();
    let rows = s
        .query(
            crate::sql::DATABASE_FILE,
            &[crate::sql::Col::Text(4080), crate::sql::Col::Text(28)],
            1,
            deadline,
        )
        .await
        .unwrap();
    let row = &rows.rows[0];
    let text = |i: usize| match &row[i] {
        crate::sql::Value::Text(t) => t.trim_end().to_owned(),
        other => panic!("{other:?}"),
    };
    assert_eq!(text(0), attach());
    assert_eq!(text(1), "Default");
    let probe = s
        .query(
            crate::sql::READ_BACK_PROBE,
            &[crate::sql::Col::Int],
            1,
            deadline,
        )
        .await
        .unwrap();
    assert_eq!(probe.rows.len(), 1);
    // R12 item 5: the two view-dependency texts run for the minimal
    // account, complete (no view of the seed depends on an
    // always-reported relation).
    let deps = crate::views::read(&mut s, deadline).await.unwrap();
    assert!(deps.complete, "{deps:?}");
    assert!(deps.dependent.is_empty());
    let ledger = crate::own::ledger_for(endpoint.addr);
    assert!(ledger.latest_id(&attach()).is_some());
    assert!(ledger.server_pid().is_some());
    s.close().await;
    // R9: the declared database is not excluded, before any probe.
    let mut s = crate::conn::connect(
        &endpoint,
        password.as_bytes(),
        &attach(),
        deadline,
        std::time::Duration::from_secs(3),
    )
    .await
    .unwrap();
    let a = crate::check::attached(&mut s, false, false, &attach(), None, deadline)
        .await
        .unwrap();
    assert!(matches!(a, crate::check::Attached::Checked { .. }));
    s.close().await;
}

/// The engine-matrix own-statement test of R20, phase 1 (`dev/firebird/
/// it.sh` runs it before it copies the server's trace log): `check()` and a
/// Discovery scan of the main database as the agent account, then the
/// view-dependency read and the read-back probe, every execution credited
/// in the endpoint's ledger; the ledger is written to
/// `FIREBIRD_IT_MATRIX_OUT` (attachment ids, ports, credit texts and
/// counts: catalog names only, no value) for phase 2
/// (`it_audit::the_agent_records_match_the_own_statement_table`).
#[tokio::test]
async fn own_reads_for_the_matrix() {
    let Ok(out) = std::env::var("FIREBIRD_IT_MATRIX_OUT") else {
        return;
    };
    if !enabled() {
        return;
    }
    let c = FirebirdConnector::new();
    let t = agent("");
    let h = c.check(&t).await;
    assert!(h.failure.is_none(), "{h:?}");
    let scan = scan(&c, &t, unpaced()).await;
    assert!(scan.result.is_ok(), "{:?}", scan.result);
    let endpoint = crate::conn::Endpoint::of(&t).unwrap();
    let password = t.secret.read().unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut s = crate::conn::connect(
        &endpoint,
        password.as_bytes(),
        &attach(),
        deadline,
        std::time::Duration::from_secs(3),
    )
    .await
    .unwrap();
    crate::check::prepare(&mut s, false, deadline)
        .await
        .unwrap();
    crate::views::read(&mut s, deadline).await.unwrap();
    let _ = s
        .query(
            crate::sql::READ_BACK_PROBE,
            &[crate::sql::Col::Int],
            1,
            deadline,
        )
        .await
        .unwrap();
    s.close().await;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .unwrap();
    f.write_all(crate::own::ledger_for(endpoint.addr).dump().as_bytes())
        .unwrap();
}

/// One text column of a test query (raw bytes, padding dropped).
fn octets(row: &[crate::sql::Value], i: usize) -> String {
    match row.get(i) {
        Some(crate::sql::Value::Bytes(b)) => String::from_utf8_lossy(b).trim_end().to_owned(),
        other => panic!("{other:?}"),
    }
}

/// Drift tests per image (item 5 of the lot 3 report, decision 9): the
/// virtual relations (relation type 3) are exactly what the stream classes
/// as virtual after a complete catalog read, every other system relation
/// is a system relation (noise), and every word of the statement
/// analysis's built-in list is a keyword of the server (`RDB$KEYWORDS`,
/// where the version has it): a word the server does not know as built in
/// could name user code the analysis would not report.
#[tokio::test]
async fn drift_of_the_virtual_relations_and_the_built_in_words() {
    use crate::trace_events::{Catalog as _, RelClass};
    if !enabled() {
        return;
    }
    let t = agent("");
    let endpoint = crate::conn::Endpoint::of(&t).unwrap();
    let password = t.secret.read().unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut s = crate::conn::connect(
        &endpoint,
        password.as_bytes(),
        &attach(),
        deadline,
        std::time::Duration::from_secs(3),
    )
    .await
    .unwrap();
    let rows = s
        .query_for_tests(
            "SELECT CAST(RDB$RELATION_NAME AS VARCHAR(252) CHARACTER SET OCTETS), \
             CAST(COALESCE(RDB$RELATION_TYPE, 0) AS INTEGER) FROM RDB$RELATIONS \
             WHERE COALESCE(RDB$SYSTEM_FLAG, 0) <> 0",
            &[crate::sql::Col::Octets(252), crate::sql::Col::Int],
            4096,
            deadline,
        )
        .await
        .unwrap();
    let classes = crate::audit::Classes::from_catalog(
        &crate::catalog::Catalog {
            relations: Some(Vec::new()),
            columns: Some(crate::catalog::Columns::default()),
            ..crate::catalog::Catalog::default()
        },
        crate::views::ViewDeps::default(),
    );
    let mut virtual_n = 0;
    for row in &rows.rows {
        let name = octets(row, 0);
        let virtual_rel = row.get(1).and_then(crate::sql::Value::as_int) == Some(3);
        let class = classes.class(&name);
        let want = if virtual_rel {
            virtual_n += 1;
            RelClass::Virtual
        } else {
            RelClass::System
        };
        assert_eq!(class, want, "{name}");
    }
    assert!(virtual_n >= 10, "{virtual_n} virtual relations");
    eprintln!(
        "[measure] system relations {}, virtual {virtual_n}",
        rows.rows.len()
    );
    match s
        .query_for_tests(
            "SELECT CAST(RDB$KEYWORD_NAME AS VARCHAR(252) CHARACTER SET OCTETS) FROM RDB$KEYWORDS",
            &[crate::sql::Col::Octets(252)],
            4096,
            deadline,
        )
        .await
    {
        Ok(k) => {
            let words: std::collections::BTreeSet<String> =
                k.rows.iter().map(|r| octets(r, 0)).collect();
            let missing: Vec<&str> = databastion_classifiers::query::firebird::builtin_words()
                .iter()
                .copied()
                .filter(|w| !words.contains(*w))
                .collect();
            eprintln!(
                "[measure] keywords {}, built-in words not keywords {missing:?}",
                words.len()
            );
            assert!(missing.is_empty(), "{missing:?}");
        }
        Err(e) => eprintln!(
            "[measure] RDB$KEYWORDS not readable on this version: {:?}",
            e.code
        ),
    }
    s.close().await;
}
