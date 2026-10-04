//! Property tests (ADR-0041 decision 13): hostile definitions, audit lines,
//! URLs and times never panic and fail closed, and no input byte sequence
//! survives into a sampled value, an event or a debug line (what a log
//! line could print) except closed facts: credential fields, URL
//! credentials, `what` and ticket ids never do; principals and values only
//! leave through the masking path.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proptest::prelude::*;

use crate::audit::events::tests_support::key;
use crate::audit::events::{Builder, CasPrincipal};
use crate::config::{ClientAddrMode, UtcOffset};
use crate::parse::definition::{Seg, is_credential_key, parse_definition};
use crate::parse::record::parse_record;
use crate::parse::url::{service_of, strip_credentials};
use crate::parse::when::parse_when;
use crate::registry::field_name;

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Mutations of a valid input: truncation, byte flips, insertions.
fn mutate(mut bytes: Vec<u8>, edits: &[(usize, u8, u8)]) -> Vec<u8> {
    for &(pos, kind, value) in edits {
        if bytes.is_empty() {
            break;
        }
        let i = pos % bytes.len();
        match kind % 4 {
            0 => bytes[i] = value,
            1 => bytes.truncate(i),
            2 => bytes.insert(i, value),
            _ => {
                bytes.remove(i);
            }
        }
    }
    bytes
}

/// A JSON string literal of `s`.
fn lit(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

/// A marker that cannot occur by chance in the fixed parts of the inputs.
fn marker() -> impl Strategy<Value = String> {
    "[A-Z]{4}[0-9]{4}[a-z]{4}".prop_map(|s| format!("MRK{s}"))
}

fn definition(secret: &str, cred_key: &str, value: &str, user: &str) -> String {
    format!(
        r#"{{"@class": "org.apereo.cas.services.OidcRegisteredService",
            "serviceId": {sid}, "name": "App", "clientSecret": {secret},
            "description": {value},
            "properties": {{"@class": "java.util.HashMap", {cred_key}: {{"values": [{secret}]}}}},
            "nested": {{{cred_key}: [{secret}, {{"x": {secret}}}]}},
            "logoutUrl": {logout}}}"#,
        sid = lit(&format!(
            "^https://{user}:{user}@app.example.org/.*?t={user}#{user}"
        )),
        secret = lit(secret),
        cred_key = lit(cred_key),
        value = lit(value),
        logout = lit(&format!("https://app.example.org/logout?token={user}")),
    )
}

proptest! {
    #![proptest_config(config(512))]

    #[test]
    fn definitions_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_definition(&data);
    }

    #[test]
    fn mutated_definitions_never_panic(
        edits in proptest::collection::vec((any::<usize>(), any::<u8>(), any::<u8>()), 0..8),
    ) {
        let base = definition("fake-secret", "apiPassword", "jane.doe@example.org", "u");
        let _ = parse_definition(&mutate(base.into_bytes(), &edits));
    }

    #[test]
    fn credentials_never_reach_sampled_values(
        secret in marker(),
        user in marker(),
        word in prop::sample::select(vec![
            "secret", "PASSWORD", "passwd", "Key", "token", "credential", "jwk", "private", "keystore",
        ]),
        prefix in "[a-z]{0,6}",
        value in "[ -~]{0,40}",
    ) {
        let cred_key = format!("{prefix}{word}X");
        prop_assert!(is_credential_key(&cred_key));
        let doc = definition(&secret, &cred_key, &value, &user);
        let d = parse_definition(doc.as_bytes()).unwrap();
        for s in &d.values {
            prop_assert!(!s.value.contains(&secret));
            prop_assert!(!s.value.contains(&user));
            prop_assert!(!s.path.iter().any(|p| matches!(p, Seg::Key(k) if k == &cred_key)));
        }
        let dbg = format!("{d:?}");
        prop_assert!(!dbg.contains(&secret) && !dbg.contains(&user));
        // The description is kept (a value to classify).
        if !value.trim().is_empty() && !value.contains("://") {
            prop_assert!(d.values.iter().any(|s| *s.value == value));
        }
    }

    #[test]
    fn field_names_never_keep_values(email in "[a-z]{3,8}\\.[a-z]{3,8}@[a-z]{3,8}\\.(org|com)") {
        let name = field_name(&[
            Seg::Key("contacts".into()),
            Seg::Key(email.clone()),
            Seg::Key("phone".into()),
        ]);
        prop_assert_eq!(name.as_str(), "contacts.*.phone");
    }

    #[test]
    fn url_credentials_are_always_stripped(
        user in marker(),
        pass in marker(),
        special in proptest::collection::vec(prop::sample::select(vec!["/", "?", "#", "@", ":", "%", "%40", "%3A"]), 0..4),
        query in marker(),
        frag in marker(),
        relative in any::<bool>(),
        host in "[a-z]{1,10}(\\.[a-z]{2,6}){0,2}",
        path in "(/[a-z0-9]{0,6}){0,3}",
        before in "[ -~]{0,10}",
    ) {
        // A password holding URL delimiters (review of #138 M1).
        let pass = format!("{pass}{}{pass}", special.concat());
        let scheme = if relative { "" } else { "https:" };
        let text = format!("{before} {scheme}//{user}:{pass}@{host}{path}?q={query}#{frag} tail");
        let out = strip_credentials(&text);
        for m in [&user, &pass, &query, &frag] {
            prop_assert!(!out.contains(m.as_str()), "{} in {:?}", m, out);
        }
        prop_assert!(out.contains(&format!("//{host}{path}")), "{:?}", out);
        if !relative && !before.to_ascii_lowercase().contains("http") {
            let h = service_of(&text).unwrap();
            prop_assert_eq!(h.as_url(), format!("https://{host}/"));
        }
    }

    /// Mapped, compatible, 6to4 and Teredo addresses never keep more of
    /// the client than its IPv4 /24 (review of #138 L3).
    #[test]
    fn embedded_ipv4_addresses_are_reduced(v4 in any::<u32>(), low in any::<u64>(), mid in any::<u16>()) {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use databastion_classifiers::masking::ClientAddr;
        use crate::audit::events::reduce;
        let t = ClientAddrMode::Truncated;
        let ip4 = IpAddr::V4(Ipv4Addr::from(v4));
        let want = reduce(ip4, t);
        prop_assert_eq!(want, Some(ClientAddr::Ip(IpAddr::V4(Ipv4Addr::from(v4 & 0xffff_ff00)))));
        let mapped = IpAddr::V6(Ipv4Addr::from(v4).to_ipv6_mapped());
        prop_assert_eq!(reduce(mapped, t), want);
        if v4 > 1 {
            let compatible = IpAddr::V6(Ipv6Addr::from(u128::from(v4)));
            prop_assert_eq!(reduce(compatible, t), want);
        }
        let six_to_four = (0x2002u128 << 112) | (u128::from(v4) << 80) | (u128::from(mid) << 64) | u128::from(low);
        let expect = (0x2002u128 << 112) | (u128::from(v4 & 0xffff_ff00) << 80);
        prop_assert_eq!(
            reduce(IpAddr::V6(Ipv6Addr::from(six_to_four)), t),
            Some(ClientAddr::Ip(IpAddr::V6(Ipv6Addr::from(expect))))
        );
        let teredo = (0x2001_0000u128 << 96) | (u128::from(v4) << 64) | u128::from(low);
        match reduce(IpAddr::V6(Ipv6Addr::from(teredo)), t) {
            Some(ClientAddr::Ip(IpAddr::V6(r))) => prop_assert_eq!(u128::from(r) & ((1u128 << 72) - 1), 0),
            other => prop_assert!(false, "{:?}", other),
        }
    }

    #[test]
    fn hosts_are_closed_facts(text in "[ -~]{0,80}") {
        if let Some(h) = service_of(&text) {
            prop_assert!(text.to_ascii_lowercase().contains(&h.host));
            let closed = h.host.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b".-[]:".contains(&b)
            });
            prop_assert!(closed);
        }
        let _ = strip_credentials(&text);
    }

    #[test]
    fn times_never_panic(text in "[ -~]{0,40}", n in any::<i64>()) {
        let _ = parse_when(&text, UtcOffset(-3600));
        let _ = crate::parse::when::from_epoch(n);
    }

    #[test]
    fn audit_lines_never_panic(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parse_record(&data, UtcOffset(0));
    }

    #[test]
    fn mutated_audit_lines_never_panic(
        edits in proptest::collection::vec((any::<usize>(), any::<u8>(), any::<u8>()), 0..8),
    ) {
        let line = br#"{"who": "jdoe", "what": "ST-1-FAKE for https://a.example.org/", "action": "SERVICE_TICKET_CREATED", "when": "2026-10-04T12:00:00Z", "clientIpAddress": "192.0.2.1", "userAgent": "curl/8"}"#;
        let _ = parse_record(&mutate(line.to_vec(), &edits), UtcOffset(0));
    }

    #[test]
    fn only_closed_facts_reach_events(
        who in marker(),
        ticket in marker(),
        path in marker(),
        ua in marker(),
        action in prop::sample::select(vec![
            "AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILED", "SERVICE_TICKET_CREATED",
            "SERVICE_TICKET_VALIDATE_SUCCESS", "SAVE_SERVICE_SUCCESS", "TICKET_GRANTING_TICKET_CREATED",
        ]),
        clear in any::<bool>(),
        repeat in 1usize..40,
    ) {
        let line = format!(
            r#"{{"who": {w}, "what": {what}, "action": "{action}", "when": 1791115200000,
                "clientIpAddress": "203.0.113.7", "userAgent": {ua}, "headers": {{"Cookie": {t}}},
                "geoLocation": {t}, "application": {t}}}"#,
            w = lit(&who),
            what = lit(&format!(
                "TGT-1-{ticket} ST-2-{ticket} for https://app.example.org/{path}?ticket={ticket}"
            )),
            ua = lit(&format!("{ua} (X11; {ticket})")),
            t = lit(&ticket),
        );
        let r = parse_record(line.as_bytes(), UtcOffset(0)).unwrap();
        let clear_list = if clear { vec![who.clone()] } else { Vec::new() };
        let mut b = Builder::new(key(), &clear_list, ClientAddrMode::Truncated, None);
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut out = Vec::new();
        for _ in 0..repeat {
            b.push(&r, now, &mut out);
        }
        b.flush(SystemTime::now(), true, &mut out);
        let dbg = format!("{out:?} {r:?} {b:?}");
        for m in [&who, &ticket, &path] {
            prop_assert!(!dbg.contains(m.as_str()), "{} leaked", m);
        }
        for e in &out {
            prop_assert!(e.signals.len() <= 2);
            if let CasPrincipal::Account(p) = &e.principal {
                prop_assert!(!p.account_name().contains(&ticket));
                // Sent by name only when listed, never for a failure.
                prop_assert_eq!(p.send_name(), clear && action != "AUTHENTICATION_FAILED");
            }
            prop_assert!(e.application.as_deref().is_none_or(|a| a == ua));
        }
    }
}

proptest! {
    #![proptest_config(config(24))]

    /// The masking path: registry values only leave as masked samples
    /// and fingerprints.
    #[test]
    fn registry_values_only_leave_masked(
        locals in proptest::collection::vec("[a-z]{4,8}\\.[a-z]{4,8}", 1..6),
        phone in "\\+336[0-9]{8}",
        secret in marker(),
    ) {
        let dir = crate::fsread::tests::TempDir::new("prop-mask");
        let reg = dir.path().join("services");
        std::fs::create_dir(&reg).unwrap();
        let emails: Vec<String> = locals.iter().map(|l| format!("{l}@example.org")).collect();
        for (i, e) in emails.iter().enumerate() {
            let doc = format!(
                r#"{{"@class": "org.apereo.cas.services.CasRegisteredService", "id": {i},
                    "serviceId": "^https://a{i}.example.org/.*", "name": "App{i}",
                    "clientSecret": {s}, "privateKeyLocation": {s},
                    "contacts": [{{"email": {e}, "phone": {p}}}]}}"#,
                s = lit(&secret),
                e = lit(e),
                p = lit(&phone),
            );
            std::fs::write(reg.join(format!("App{i}-{i}.json")), doc).unwrap();
        }
        let settings = crate::config::CasSettings::from_yaml(
            &format!("{{service_registry: {{json_dir: {}}}}}", reg.display()),
            &[],
        )
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let findings = rt.block_on(async {
            let (sink, mut rx) = databastion_core::FindingSink::channel(256);
            let state = Arc::new(crate::state::CasState::default());
            crate::discover::discover_with(
                &settings,
                &databastion_core::ScanJob::default(),
                &sink,
                &state,
                crate::fsread::Policy::TESTS,
            )
            .await
            .unwrap();
            drop(sink);
            let mut out = Vec::new();
            while let Some(f) = rx.recv().await {
                out.push(f);
            }
            out
        });
        let dbg = format!("{findings:?}");
        for e in &emails {
            prop_assert!(!dbg.contains(e.as_str()));
        }
        prop_assert!(!dbg.contains(&phone[3..]));
        prop_assert!(!dbg.contains(&secret));
        for f in &findings {
            for s in f.masked_samples() {
                prop_assert!(databastion_classifiers::masking::masked_sample_conforms(s.as_str()));
            }
        }
    }
}
