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
    assert_eq!(codes(&h), ["audit.source_not_configured"], "{:?}", h.detail);
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
    assert_eq!(codes(&h), ["audit.source_not_configured"], "{:?}", h.notes);
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
        assert!(h.detail.unwrap().contains("forwarder"));
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
    for _ in 0..64 {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let s = crate::conn::connect(
            &endpoint,
            password.as_bytes(),
            &attach(),
            deadline,
            std::time::Duration::from_secs(3),
        )
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
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
