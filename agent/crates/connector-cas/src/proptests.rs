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
        if !value.trim().is_empty() && *strip_credentials(&value) == value {
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
        let delimiters = special.iter().any(|c| matches!(*c, "/" | "?" | "#"));
        let encoded = special.iter().any(|c| c.contains('%'));
        if !relative && !delimiters && !before.to_ascii_lowercase().contains("http") {
            // An authority holding `%` names no service (review of #138);
            // otherwise the host after the last literal `@`.
            match service_of(&text) {
                Some(h) => {
                    prop_assert!(!encoded);
                    prop_assert_eq!(h.as_url(), format!("https://{host}/"));
                }
                None => prop_assert!(encoded),
            }
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

    /// Credentials outside the plain `scheme://` form (review of #138):
    /// JDBC, scheme-less userinfo, escaped `//`.
    #[test]
    fn other_credential_forms_are_stripped(
        user in marker(),
        pass in marker(),
        query in marker(),
        form in 0usize..6,
        upper in any::<bool>(),
        host in "[a-z]{1,10}\\.example\\.org",
    ) {
        let enc = if upper { "%2F%2F" } else { "%2f%2f" };
        let text = match form {
            0 => format!("jdbc:oracle:thin:{user}/{pass}@//{host}:1521/svc"),
            1 => format!("jdbc:oracle:thin:{user}/{pass}@{host}:1521:SID"),
            2 => format!("{user}:{pass}@{host}"),
            3 => format!("https:\\/\\/{user}:{pass}@{host}\\/x?q={query}"),
            4 => format!("https:{enc}{user}%3A{pass}%40{host}%2Fx%3Fq%3D{query}"),
            _ => format!("ldap://{user}:{pass}@{host}/o?{query}"),
        };
        let out = strip_credentials(&format!("x {text} y"));
        for m in [&user, &pass, &query] {
            prop_assert!(!out.contains(m.as_str()), "{} in {:?}", m, out);
        }
        prop_assert!(out.contains(&host));
    }

    /// An `@` or `%40` in the path, query or fragment never chooses the
    /// service host.
    #[test]
    fn query_at_signs_never_choose_the_host(
        other in "[a-z]{1,10}\\.example\\.com",
        sep in prop::sample::select(vec!["/", "/a?x=", "?x=", "#", "/a/"]),
        at in prop::sample::select(vec!["@", "%40", "%40%40", "@@"]),
    ) {
        let what = format!("ST-1 for https://hr.example.org{sep}{at}{other}");
        let got = service_of(&what).map(|h| h.as_url());
        prop_assert_eq!(got.as_deref(), Some("https://hr.example.org/"));
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
    fn mutated_object_what_lines_never_panic(
        edits in proptest::collection::vec((any::<usize>(), any::<u8>(), any::<u8>()), 0..8),
    ) {
        let line = br#"{"who": "jdoe", "what": {"service": "https://a.example.org/", "ticketId": "ST-1-****-cas01"}, "action": "SERVICE_TICKET_CREATED", "when": "2026-10-04T12:00:00Z"}"#;
        let _ = parse_record(&mutate(line.to_vec(), &edits), UtcOffset(0));
    }

    #[test]
    fn object_what_keeps_only_the_service_host(
        ticket in marker(),
        path in marker(),
        extra in proptest::collection::vec(("[a-zA-Z]{1,12}", 0u8..4), 0..6),
        service_first in any::<bool>(),
        nested_service in any::<bool>(),
    ) {
        // Random extra keys (never `service`) holding ticket markers as
        // strings, URLs, arrays and nested objects, before or after the
        // `service` key.
        let mut fields: Vec<String> = vec![format!(
            r#""ticketId": {}"#,
            lit(&format!("ST-1-{ticket}"))
        )];
        for (k, kind) in &extra {
            if k == "service" {
                continue;
            }
            let v = match kind {
                0 => lit(&format!("TGT-1-{ticket}")),
                1 => lit(&format!("https://evil.example.net/{ticket}")),
                2 => format!("[{}, {{\"service\": {}}}]", lit(&ticket), lit("https://evil.example.net/")),
                _ => format!(
                    "{{\"service\": {}, \"id\": {}}}",
                    lit(&format!("https://evil.example.net/{ticket}")),
                    lit(&ticket)
                ),
            };
            fields.push(format!("{}: {v}", lit(k)));
        }
        if nested_service {
            fields.push(format!(r#""principal": {{"service": {}}}"#, lit("https://evil.example.net/")));
        }
        let service = format!(
            r#""service": {}"#,
            lit(&format!("https://app.example.org/{path}?ticket={ticket}"))
        );
        if service_first {
            fields.insert(0, service);
        } else {
            fields.push(service);
        }
        let line = format!(
            r#"{{"who": "jdoe", "what": {{{}}}, "action": "SERVICE_TICKET_CREATED", "when": 1791115200000}}"#,
            fields.join(", ")
        );
        let r = parse_record(line.as_bytes(), UtcOffset(0));
        // Generated keys may repeat each other but never `service`.
        let r = r.unwrap();
        let host = r.service.as_ref().map(crate::parse::url::ServiceHost::as_url);
        prop_assert_eq!(host.as_deref(), Some("https://app.example.org/"));
        let mut b = Builder::new(key(), &[], ClientAddrMode::Truncated, None);
        let mut out = Vec::new();
        b.push(&r, UNIX_EPOCH + Duration::from_secs(1_800_000_000), &mut out);
        b.flush(SystemTime::now(), true, &mut out);
        let dbg = format!("{out:?} {r:?} {b:?}");
        for m in [&ticket, &path] {
            prop_assert!(!dbg.contains(m.as_str()), "{} leaked", m);
        }
        prop_assert!(!dbg.contains("evil"));
    }

    /// The object-form `what` with every kind of `service` value and
    /// duplicate `service` keys (escaped or not, among random other keys):
    /// a string names its host, any other JSON type names no service (the
    /// record is kept), and a second `service` key drops the record.
    #[test]
    fn object_what_service_kinds_and_duplicates(
        ticket in marker(),
        services in proptest::collection::vec((0u8..8, any::<bool>()), 0..4),
        extra in proptest::collection::vec("[a-zA-Z]{1,12}", 0..4),
        action in prop::sample::select(vec![
            "SERVICE_TICKET_CREATED", "OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED",
        ]),
    ) {
        // Kind 0 is a string (the only one naming a service); the others
        // are `null`, a number, a boolean, an array, an object, an empty
        // string and a string that is no URL.
        let value = |kind: u8| match kind {
            0 => lit(&format!("https://app.example.org/{ticket}?ticket=ST-1-{ticket}")),
            1 => "null".to_owned(),
            2 => "3".to_owned(),
            3 => "true".to_owned(),
            4 => format!("[{}]", lit("https://evil.example.net/")),
            5 => format!("{{\"service\": {}, \"id\": {}}}", lit("https://evil.example.net/"), lit(&ticket)),
            6 => lit(""),
            _ => lit(&format!("ST-1-{ticket}")),
        };
        let mut fields: Vec<String> = extra
            .iter()
            .filter(|k| k.as_str() != "service")
            .map(|k| format!("{}: {}", lit(k), lit(&format!("TGT-1-{ticket}"))))
            .collect();
        for (i, (kind, escaped)) in services.iter().enumerate() {
            let key = if *escaped { r#""serv\u0069ce""# } else { r#""service""# };
            fields.insert(i.min(fields.len()), format!("{key}: {}", value(*kind)));
        }
        let line = format!(
            r#"{{"who": "jdoe", "what": {{{}}}, "action": "{action}", "when": 1791115200000}}"#,
            fields.join(", ")
        );
        let r = parse_record(line.as_bytes(), UtcOffset(0));
        match services.as_slice() {
            [] => prop_assert!(r.unwrap().service.is_none()),
            [(kind, _)] => {
                let r = r.unwrap();
                let host = r.service.as_ref().map(crate::parse::url::ServiceHost::as_url);
                let expected = (*kind == 0).then(|| "https://app.example.org/".to_owned());
                prop_assert_eq!(host, expected);
                let dbg = format!("{r:?}");
                prop_assert!(!dbg.contains(&ticket));
            }
            _ => prop_assert_eq!(r.err(), Some(crate::parse::record::RecordError::Invalid)),
        }
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
    #![proptest_config(config(128))]

    /// ADR-0044 (I2): a token request's `code` (an authorization code or a
    /// refresh token id), its other skipped keys and the response's token
    /// values never reach an event, a contract body, a record's or the
    /// builder's debug line, whatever the grant; the client id itself
    /// leaves only as its registry entry's name.
    #[test]
    fn token_request_and_response_values_never_leave(
        code in marker(),
        token in marker(),
        scope in marker(),
        client_suffix in marker(),
        user in marker(),
        extra in "[a-z_]{1,12}",
        grant in prop::sample::select(vec![
            "refresh_token", "client_credentials", "password", "authorization_code",
            "urn:ietf:params:oauth:grant-type:device_code",
        ]),
        registered in any::<bool>(),
        code_first in any::<bool>(),
        gap_ms in 0u64..8000,
    ) {
        let client = format!("client-{client_suffix}");
        let registered_id = if registered { client.clone() } else { "someone-else".to_owned() };
        let def = crate::parse::definition::parse_definition(
            format!(
                r#"{{"@class": "org.apereo.cas.services.OidcRegisteredService", "name": "M2M",
                    "serviceId": "^https://m2m\\.example\\.org/cb$", "clientId": {}}}"#,
                lit(&registered_id)
            )
            .as_bytes(),
        )
        .unwrap();
        let idx = Arc::new(crate::registry::ServiceIndex::new([&def]));
        let code_kv = format!(r#""code": {}"#, lit(&format!("RT-1-{code}")));
        let extra_kv = if extra == "service" || extra == "grant_type" {
            format!(r#""x{extra}": {}"#, lit(&code))
        } else {
            format!(r#"{}: {{"service": {}, "grant_type": "password", "v": [{}]}}"#, lit(&extra), lit(&code), lit(&token))
        };
        let mut fields = vec![
            format!(r#""grant_type": {}"#, lit(grant)),
            format!(r#""service": {}"#, lit(&client)),
            format!(r#""scope": [{}, "openid"]"#, lit(&scope)),
            format!(r#""response_type": {}"#, lit(&code)),
            extra_kv,
        ];
        if code_first { fields.insert(0, code_kv) } else { fields.push(code_kv) }
        let request = format!(
            r#"{{"who": "audit:unknown", "what": {{{}}}, "action": "OAUTH2_ACCESS_TOKEN_REQUEST_CREATED",
                "when": 1791115200000, "clientIpAddress": "203.0.113.7", "serverIpAddress": "198.51.100.3",
                "userAgent": "python-requests/2.33.1", "headers": {{"Authorization": {}}}}}"#,
            fields.join(", "),
            lit(&format!("Basic {token}")),
        );
        let who = if grant == "client_credentials" { client.clone() } else { user.clone() };
        let response = format!(
            r#"{{"who": {}, "what": {{"access_token": {at}, "refresh_token": {rt}, "id_token": {it},
                "scope": {sc}, "token_type": "Bearer", "expires_in": "28800"}},
                "action": "OAUTH2_ACCESS_TOKEN_RESPONSE_CREATED", "when": {},
                "clientIpAddress": "203.0.113.7", "serverIpAddress": "198.51.100.3",
                "userAgent": "python-requests/2.33.1"}}"#,
            lit(&who),
            1_791_115_200_000u64 + gap_ms,
            at = lit(&format!("AT-1-{token}")),
            rt = lit(&format!("RT-1-{token}")),
            it = lit(&format!("eyJ{token}.{code}.sig")),
            sc = lit(&scope),
        );
        let recs: Vec<_> = [request, response]
            .iter()
            .map(|l| parse_record(l.as_bytes(), UtcOffset(0)).unwrap())
            .collect();
        let mut b = Builder::new(key(), &[], ClientAddrMode::Truncated, Some(idx));
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut out = Vec::new();
        for r in &recs {
            b.push(r, now, &mut out);
        }
        b.flush(SystemTime::now(), true, &mut out);
        prop_assert_eq!(out.len(), 1);
        let object = out[0].object.as_ref().map(|o| o.object().as_str().to_owned());
        let expect_named = registered
            && gap_ms <= 5000
            && matches!(grant, "refresh_token" | "client_credentials" | "password");
        prop_assert_eq!(object.as_deref(), Some(if expect_named { "M2M" } else { "*" }));
        let dbg = format!("{out:?} {recs:?} {b:?}");
        let masked: Vec<_> = out.into_iter().map(crate::audit::events::CasEvent::into_masked).collect();
        let hmac = databastion_classifiers::masking::HmacKey::new(&[9u8; 32]).unwrap();
        let sent = databastion_core::test_support::contract_events_json(&masked, &hmac);
        for m in [&code, &token, &scope, &client_suffix, &user] {
            prop_assert!(!dbg.contains(m.as_str()), "{} leaked in debug", m);
            prop_assert!(!sent.contains(m.as_str()), "{} leaked in the contract", m);
        }
        prop_assert!(!sent.contains("198.51.100.3"));
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

/// A YAML node of the generated documents (the pre-scanner's properties).
#[derive(Clone, Debug)]
enum Y {
    Plain(String),
    Single(String),
    Double(String),
    Block(Vec<String>),
    Flow(Vec<String>),
    Map(Vec<(String, Y)>),
    Seq(Vec<Y>),
}

/// What to put at the chosen node position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Inject {
    Nothing,
    Anchor,
    Alias,
}

/// Renders a document: the CAS class hint, then the root mapping. Node
/// positions (keys, values, sequence items, flow items) are numbered in
/// order; the one numbered `at` gets `inject`.
struct Render {
    out: String,
    n: usize,
    at: usize,
    inject: Inject,
}

impl Render {
    /// The property before a node (` &a`), or whether to replace it by an
    /// alias.
    fn position(&mut self) -> (String, bool) {
        let here = self.n == self.at;
        self.n += 1;
        match (here, self.inject) {
            (true, Inject::Anchor) => (" &a1".to_owned(), false),
            (true, Inject::Alias) => (String::new(), true),
            _ => (String::new(), false),
        }
    }

    fn doc(entries: &[(String, Y)], at: usize, inject: Inject) -> (String, usize) {
        let mut r = Self {
            out: "--- !<org.apereo.cas.services.CasRegisteredService>\n# &c *c\n".to_owned(),
            n: 0,
            at,
            inject,
        };
        r.map(entries, 0);
        (r.out, r.n)
    }

    fn map(&mut self, entries: &[(String, Y)], indent: usize) {
        let sp = " ".repeat(indent);
        for (k, v) in entries {
            let (prop, alias) = self.position();
            if alias {
                self.out.push_str(&format!("{sp}*a1 :"));
            } else {
                self.out.push_str(&format!(
                    "{sp}{}{k}:",
                    prop.trim_start().to_owned() + if prop.is_empty() { "" } else { " " }
                ));
            }
            self.value(v, indent);
        }
    }

    /// A value after `key:` or `-` (the parent's column is `indent`).
    fn value(&mut self, v: &Y, indent: usize) {
        let (prop, alias) = self.position();
        if alias {
            self.out.push_str(" *a1\n");
            return;
        }
        self.out.push_str(&prop);
        let sp = " ".repeat(indent + 2);
        match v {
            Y::Plain(s) => self.out.push_str(&format!(" {s} # &c\n")),
            Y::Single(s) => self
                .out
                .push_str(&format!(" '{}'\n", s.replace('\'', "''"))),
            Y::Double(s) => self.out.push_str(&format!(
                " \"{}\"\n",
                s.replace('\\', "\\\\").replace('"', "\\\"")
            )),
            Y::Block(lines) => {
                self.out.push_str(" |\n");
                for l in lines {
                    self.out.push_str(&format!("{sp}{l}\n"));
                }
            }
            Y::Flow(items) => {
                let mut parts = Vec::new();
                for i in items {
                    let (p, a) = self.position();
                    parts.push(if a {
                        "*a1".to_owned()
                    } else {
                        format!(
                            "{}{i}",
                            p.trim_start().to_owned() + if p.is_empty() { "" } else { " " }
                        )
                    });
                }
                self.out.push_str(&format!(" [{}]\n", parts.join(", ")));
            }
            Y::Map(entries) => {
                self.out.push('\n');
                self.map(entries, indent + 2);
            }
            Y::Seq(items) => {
                self.out.push('\n');
                for i in items {
                    self.out.push_str(&format!("{sp}-"));
                    self.value(i, indent + 2);
                }
            }
        }
    }
}

fn yaml_node() -> impl Strategy<Value = Y> {
    // Scalars hold the characters the pre-scanner must read as text.
    let plain = "[a-z][a-z0-9&*!'\"@./-]{0,6}( [a-z&*!'][a-z0-9&*!'\"@./-]{0,6}){0,2}";
    let quoted = "[a-z &*!#:,'\"\\[\\]{}<>%@-]{0,16}";
    let line = "[a-z&*!#'\"%@<-][a-z &*!#:'\"%@<>-]{0,12}";
    let flow_item = "[a-z][a-z0-9&*!.]{0,6}( [a-z&*!][a-z0-9&*!.]{0,4})?";
    let leaf = prop_oneof![
        plain.prop_map(Y::Plain),
        // A scalar starting with `<<` is refused as a merge key, quoted
        // or not (conservative).
        quoted.prop_map(|s| Y::Single(format!("x{s}"))),
        quoted.prop_map(|s| Y::Double(format!("x{s}"))),
        proptest::collection::vec(line, 1..4).prop_map(Y::Block),
        proptest::collection::vec(flow_item, 0..4).prop_map(Y::Flow),
    ];
    leaf.prop_recursive(4, 24, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(("k[a-z0-9]{0,5}", inner.clone()), 1..4).prop_map(Y::Map),
            proptest::collection::vec(inner, 1..4).prop_map(Y::Seq),
        ]
    })
}

fn yaml_doc() -> impl Strategy<Value = Vec<(String, Y)>> {
    proptest::collection::vec(("k[a-z0-9]{0,5}", yaml_node()), 1..5)
}

/// YAML-ish fragments, concatenated into hostile inputs.
fn yaml_ish() -> impl Strategy<Value = Vec<u8>> {
    let frags = prop::sample::select(vec![
        "--- !<a.B>\n",
        "\n",
        " ",
        "  ",
        "- ",
        ": ",
        ":",
        "? ",
        "&a",
        "*a",
        "!<x.Y>",
        "!<x.Y> ",
        "!!str ",
        "!",
        "<<",
        "'",
        "''",
        "\"",
        "\\",
        "\\\"",
        "#",
        " #",
        "|",
        "|-",
        ">",
        "[",
        "]",
        "{",
        "}",
        ",",
        "a",
        "key",
        "%",
        "...",
        "---",
        "\t",
        "\r\n",
        "\r",
        "é",
        "\u{2028}",
        "@",
        "`",
        "1",
    ]);
    proptest::collection::vec(frags, 0..64).prop_map(|v| v.concat().into_bytes())
}

proptest! {
    #![proptest_config(config(512))]

    /// Random YAML-ish inputs, with or without the class hint, never panic.
    #[test]
    fn yaml_prescan_and_parse_never_panic(data in yaml_ish(), head in any::<bool>()) {
        let mut bytes = if head {
            b"--- !<org.apereo.cas.services.CasRegisteredService>\n".to_vec()
        } else {
            Vec::new()
        };
        bytes.extend_from_slice(&data);
        let _ = crate::parse::yaml::prescan(&bytes);
        let _ = crate::parse::definition::parse_yaml_definition(&bytes);
    }

    #[test]
    fn mutated_yaml_definitions_never_panic(
        edits in proptest::collection::vec((any::<usize>(), any::<u8>(), any::<u8>()), 0..8),
    ) {
        let base = include_str!("../fixtures/registry/HR-Portal-10000003.yml");
        let bytes = mutate(base.as_bytes().to_vec(), &edits);
        let _ = crate::parse::definition::parse_yaml_definition(&bytes);
    }

    /// Generated documents are accepted (their `&`, `*`, `!`, `#` and
    /// quotes are text) and parse; the same document with an anchor or an
    /// alias at any node position is refused for it.
    #[test]
    fn anchors_and_aliases_in_node_position_are_always_refused(
        doc in yaml_doc(),
        at in any::<usize>(),
        alias in any::<bool>(),
    ) {
        use crate::parse::yaml::{Refusal, prescan};
        let (clean, positions) = Render::doc(&doc, usize::MAX, Inject::Nothing);
        let pre = prescan(clean.as_bytes());
        prop_assert!(pre.is_ok(), "{:?} for\n{}", pre.err(), clean);
        let parsed: Result<serde::de::IgnoredAny, _> =
            serde_yaml_ng::from_slice(&pre.unwrap().text);
        prop_assert!(parsed.is_ok(), "{:?} for\n{}", parsed.err(), clean);
        let inject = if alias { Inject::Alias } else { Inject::Anchor };
        let (hostile, _) = Render::doc(&doc, at % positions, inject);
        let want = if alias { Refusal::Alias } else { Refusal::Anchor };
        prop_assert_eq!(prescan(hostile.as_bytes()).err(), Some(want), "{}", hostile);
    }
}

/// The YAML form of [`definition`] (class hints as CAS 8.0.2 writes them).
fn yaml_definition(secret: &str, cred_key: &str, value: &str, user: &str) -> String {
    format!(
        "--- !<org.apereo.cas.services.OidcRegisteredService>\n\
         serviceId: {sid}\nname: App\nclientSecret: {secret}\ndescription: {value}\n\
         properties: !<java.util.HashMap>\n  {cred_key}:\n    values: [{secret}]\n\
         nested:\n  {cred_key}:\n  - {secret}\n  - x: {secret}\n\
         logoutUrl: {logout}\n",
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
    #![proptest_config(config(256))]

    #[test]
    fn yaml_credentials_never_reach_sampled_values(
        secret in marker(),
        user in marker(),
        word in prop::sample::select(vec![
            "secret", "PASSWORD", "passwd", "Key", "token", "credential", "jwk", "private", "keystore",
        ]),
        prefix in "[a-z]{0,6}",
        value in "[ -~]{0,40}",
    ) {
        use crate::parse::definition::{SecretForm, parse_yaml_definition};
        let cred_key = format!("{prefix}{word}X");
        let doc = yaml_definition(&secret, &cred_key, &value, &user);
        let d = match parse_yaml_definition(doc.as_bytes()) {
            Ok(d) => d,
            // JSON string literals are valid YAML double-quoted scalars,
            // but a value starting with `<<` is refused (merge key).
            Err(e) => {
                prop_assert!(value.starts_with("<<"), "{:?} for\n{}", e, doc);
                return Ok(());
            }
        };
        prop_assert_eq!(d.client_secret, SecretForm::Clear);
        for s in &d.values {
            prop_assert!(!s.value.contains(&secret));
            prop_assert!(!s.value.contains(&user));
            prop_assert!(!s.path.iter().any(|p| matches!(p, Seg::Key(k) if k == &cred_key)));
        }
        let dbg = format!("{d:?}");
        prop_assert!(!dbg.contains(&secret) && !dbg.contains(&user));
        let json = parse_definition(definition(&secret, &cred_key, &value, &user).as_bytes()).unwrap();
        let pairs = |d: &crate::parse::definition::Definition| {
            let mut v: Vec<(String, String)> = d.values.iter()
                .map(|s| (format!("{:?}", s.path), s.value.to_string()))
                .collect();
            v.sort();
            v
        };
        prop_assert_eq!(pairs(&d), pairs(&json));
    }
}
