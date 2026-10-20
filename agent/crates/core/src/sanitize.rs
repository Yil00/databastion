//! Per-item validation and sanitization before spooling (ADR-0009).
//! Crate-private.
//!
//! The generated protocol types enforce types, patterns and lengths, but not
//! the keywords listed in `crates/protocol/tests/fixtures.rs`
//! (`NOT_ENFORCED_BY_SERDE`). For the types the agent **sends**
//! (`FindingsBatch`, `EventsBatch`), this module enforces them item by item:
//!
//! | Keyword | Where | Here |
//! |---------|-------|------|
//! | `not` (Identifier) | location / object names | name replaced by `*` |
//! | `if` / `then` / `else` on `Location.engine` (`KeyPattern` for `redis` / `valkey`, `Identifier` otherwise) | location objects | name replaced by `*` (the `KeyPattern` pattern and every `not` rule, `keys::is_key_pattern`) |
//! | `ObjectName` by source (`KeyPattern` for the `redis_*` sources, `Identifier` otherwise) | event objects | name replaced by `*` (the `KeyPattern` pattern and every `not` rule) |
//! | `minimum` / `maximum` on numbers | `confidence` | item dropped (NaN, < 0, > 1) |
//! | `minimum` / `maximum` on integers | `sampled`, `matched`, `aggregated_count`, `Count` | item dropped, or optional field omitted |
//! | `maxItems` | `masked_samples` (5), `fingerprints` (50), `objects` (16), `signals` (16) | truncated |
//! | `uniqueItems` | `fingerprints`, `signals` | deduplicated |
//! | `if` / `then` | `read` / `write` events need an object | item dropped |
//! | cross-field | `matched <= sampled` | item dropped |
//! | `if` / `then` | `account_not_recorded` principal (Redis / Valkey sources only, never `auth_failure`) | item dropped |
//! | `minItems` / `maxItems` of the batch, 1 MiB | envelope | enforced by the batch builder in `uplink` |
//!
//! Raw strings that are not names (`db_user`, `application`) go through
//! [`clean_text`] / [`clean_application`] and fall back to the fingerprint
//! path: [`HmacFingerprints`] computes `db_user_fingerprint` with the agent
//! HMAC key, in the `db_user` domain (`HmacKey::fingerprint_db_user`), so
//! such an event carries a fingerprint instead of being dropped. An event is
//! only dropped (and counted) if no conforming principal can be built at all.

use std::collections::HashSet;

use databastion_classifiers::keys::is_key_pattern;
use databastion_classifiers::masking::{HmacKey, RawSample};
use databastion_classifiers::names::{is_forbidden_char, violates_numeric_rule};
use databastion_protocol::{
    AccessEvent, AccessEventAction, AuditSource, ClientAddress, Count, Engine, Finding,
    Fingerprint, Identifier, ObjectName, ObjectRef, Principal, PrincipalVariant0Application,
    PrincipalVariant0DbUser, PrincipalVariant1Application, PrincipalVariant2Application,
};

/// Contract `Count` maximum (JavaScript safe integer).
pub(crate) const MAX_COUNT: i64 = 9_007_199_254_740_991;
const MAX_SAMPLED: u64 = 10_000;
const MAX_MASKED_SAMPLES: usize = 5;
const MAX_FINGERPRINTS: usize = 50;
const MAX_OBJECTS: usize = 16;
const MAX_SIGNALS: usize = 16;
const MAX_AGGREGATED: u64 = 1_000_000;
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "event masking produces raw account names in P4")
)]
const MAX_DB_USER_CHARS: usize = 256;
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "event masking produces raw account names in P4")
)]
const MAX_APPLICATION_CHARS: usize = 64;

/// Strips control / format / private-use / separator characters and
/// truncates to `max_chars` on a character boundary.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "event masking produces raw account names in P4")
)]
pub(crate) fn clean_text(raw: &str, max_chars: usize) -> String {
    raw.chars()
        .filter(|c| !is_forbidden_char(*c))
        .take(max_chars)
        .collect()
}

/// Contract rule for `application`: every character outside
/// `[A-Za-z0-9 ._:/+-]` becomes `_`, at most 64 characters.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "event masking produces raw account names in P4")
)]
pub(crate) fn clean_application(raw: &str) -> String {
    raw.chars()
        .take(MAX_APPLICATION_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | ':' | '/' | '+' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Source of `db_user_fingerprint` values.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "event masking produces raw account names in P4")
)]
pub(crate) trait Fingerprinter {
    /// `hmac-sha256:` fingerprint of `value`, or `None` if unavailable.
    fn fingerprint(&self, value: &str) -> Option<Fingerprint>;
}

/// `db_user_fingerprint` with the agent HMAC key: exact bytes of the raw
/// account name, `db_user` domain (never equal to a value fingerprint).
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "event masking produces raw account names in P4")
)]
pub(crate) struct HmacFingerprints<'k>(pub(crate) &'k HmacKey);

impl Fingerprinter for HmacFingerprints<'_> {
    fn fingerprint(&self, value: &str) -> Option<Fingerprint> {
        let fp = self.0.fingerprint_db_user(&RawSample::new(value));
        Fingerprint::try_from(fp.as_str()).ok()
    }
}

/// Builds a conforming principal from raw engine strings. The account name
/// is sent as `db_user` only when `send_name` is true and the cleaned name
/// conforms; otherwise its fingerprint is sent. A non-conforming
/// `client_addr` is omitted. `None` if no conforming principal can be built.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "event masking produces raw account names in P4")
)]
pub(crate) fn principal(
    db_user: &str,
    send_name: bool,
    client_addr: Option<&str>,
    application: Option<&str>,
    fingerprints: &dyn Fingerprinter,
) -> Option<Principal> {
    let client_addr = client_addr.and_then(|a| {
        if a == "local" {
            serde_json::from_value::<ClientAddress>(serde_json::Value::from(a)).ok()
        } else {
            a.parse::<std::net::IpAddr>().ok().map(|ip| match ip {
                std::net::IpAddr::V4(v4) => ClientAddress::from(v4),
                std::net::IpAddr::V6(v6) => ClientAddress::from(v6),
            })
        }
    });
    let application = application.map(clean_application);
    let cleaned = clean_text(db_user, MAX_DB_USER_CHARS);
    let name = if send_name && cleaned == db_user {
        PrincipalVariant0DbUser::try_from(cleaned.as_str()).ok()
    } else {
        None
    };
    match name {
        Some(db_user) => Some(Principal::Variant0 {
            application: application.and_then(|a| PrincipalVariant0Application::try_from(a).ok()),
            client_addr,
            db_user,
        }),
        None => Some(Principal::Variant1 {
            application: application.and_then(|a| PrincipalVariant1Application::try_from(a).ok()),
            client_addr,
            db_user_fingerprint: fingerprints.fingerprint(db_user)?,
        }),
    }
}

/// The `account_not_recorded` principal (contract `Principal`, Redis /
/// Valkey only): a non-conforming `client_addr` or `application` is
/// omitted.
pub(crate) fn principal_not_recorded(
    client_addr: Option<&str>,
    application: Option<&str>,
) -> Principal {
    let client_addr = client_addr.and_then(|a| {
        if a == "local" {
            serde_json::from_value::<ClientAddress>(serde_json::Value::from(a)).ok()
        } else {
            a.parse::<std::net::IpAddr>().ok().map(|ip| match ip {
                std::net::IpAddr::V4(v4) => ClientAddress::from(v4),
                std::net::IpAddr::V6(v6) => ClientAddress::from(v6),
            })
        }
    });
    Principal::Variant2 {
        account_not_recorded: true,
        application: application
            .map(clean_application)
            .and_then(|a| PrincipalVariant2Application::try_from(a).ok()),
        client_addr,
    }
}

/// Whether events of `source` name their objects with a `KeyPattern` and
/// may carry `account_not_recorded` (the `redis_*` sources).
pub(crate) fn is_redis_source(source: AuditSource) -> bool {
    matches!(
        source,
        AuditSource::RedisSlowlog
            | AuditSource::RedisCommandlog
            | AuditSource::RedisAclLog
            | AuditSource::RedisSync
    )
}

fn wildcard() -> Option<Identifier> {
    Identifier::try_from("*").ok()
}

/// Applies the `Identifier` `not` rule: a violating name becomes `*`.
fn fix_identifier(id: &mut Identifier) -> bool {
    if violates_numeric_rule(id.as_str()) {
        match wildcard() {
            Some(w) => *id = w,
            None => return false,
        }
    }
    true
}

fn count_ok(c: &Count) -> bool {
    (0..=MAX_COUNT).contains(&c.0)
}

/// A contract `Count` from an unbounded counter, saturated at [`MAX_COUNT`]
/// (the JavaScript safe integer bound of the contract) rather than wrapped
/// or dropped. For every `Count` the agent builds itself (uptime, spool
/// state, and the `JobProgress` counters when they are produced).
pub(crate) fn clamped_count(n: u64) -> Count {
    Count(i64::try_from(n).map_or(MAX_COUNT, |v| v.min(MAX_COUNT)))
}

/// Sanitizes an object name in place outside a Redis / Valkey location or
/// event. An `Identifier` goes through [`fix_identifier`]. A name that is
/// only a `KeyPattern` becomes `*` (fail closed).
fn fix_object_name(name: &mut ObjectName) -> bool {
    match name {
        ObjectName::Variant0(id) => fix_identifier(id),
        ObjectName::Variant1(_) => match wildcard() {
            Some(w) => {
                *name = ObjectName::Variant0(w);
                true
            }
            None => false,
        },
    }
}

/// Whether a location of `engine` names its object with a `KeyPattern`
/// (contract `Location`: `if engine in [redis, valkey]`).
pub(crate) fn uses_key_patterns(engine: Engine) -> bool {
    matches!(engine, Engine::Redis | Engine::Valkey)
}

/// Sanitizes the object of a location in place, by its engine: a Redis /
/// Valkey object must be a contract `KeyPattern` (its pattern, length and
/// every `not` rule: digit runs per segment and across separators, IPv4,
/// IPv6, MAC, percent escapes, URL-scheme first segment), any other
/// engine's an `Identifier`; anything else becomes `*` (ADR-0009).
fn fix_location_object(name: &mut ObjectName, engine: Engine) -> bool {
    if !uses_key_patterns(engine) {
        return fix_object_name(name);
    }
    if is_key_pattern(&name.to_string()) {
        return true;
    }
    match wildcard() {
        Some(w) => {
            *name = ObjectName::Variant0(w);
            true
        }
        None => false,
    }
}

/// Validates and sanitizes a finding in place. `false`: drop it.
pub(crate) fn check_finding(f: &mut Finding) -> bool {
    let l = &mut f.location;
    let names_ok = fix_identifier(&mut l.database)
        && fix_location_object(&mut l.object, l.engine)
        && fix_identifier(&mut l.field)
        && l.schema.as_mut().is_none_or(fix_identifier);
    if !names_ok {
        return false;
    }
    if !f.confidence.is_finite() || !(0.0..=1.0).contains(&f.confidence) {
        return false;
    }
    let sampled = f.sampled.get();
    let Ok(matched) = u64::try_from(f.matched) else {
        return false;
    };
    if sampled > MAX_SAMPLED || matched > sampled {
        return false;
    }
    if f.estimated_rows.as_ref().is_some_and(|c| !count_ok(c)) {
        f.estimated_rows = None;
    }
    f.masked_samples.truncate(MAX_MASKED_SAMPLES);
    if let Some(fps) = f.fingerprints.as_mut() {
        let mut seen = HashSet::new();
        fps.retain(|fp| seen.insert(fp.as_str().to_owned()));
        fps.truncate(MAX_FINGERPRINTS);
        if fps.is_empty() {
            f.fingerprints = None;
        }
    }
    true
}

/// Whether an object is named `*` (an `Identifier` or a `KeyPattern`).
fn is_wildcard_object(o: &ObjectRef) -> bool {
    match &o.object {
        ObjectName::Variant0(id) => id.as_str() == "*",
        ObjectName::Variant1(p) => p.as_str() == "*",
    }
}

/// Keeps a `*` object in an event whose objects overflowed (ADR-0053
/// decision 1 item 3: the contract requires one) that covers the objects
/// the sanitizer itself left out. Fail closed: never clears the flag; adds `(<database>, -, *)` when every object it names
/// and every one left out (`left_out`, their databases) share a database,
/// `(*, -, *)` otherwise, in the last slot when the list is full (that
/// object is then left out too). The `MaskedEvent` invariant makes this a
/// no-op for events built by the core.
fn keep_overflow_wildcard(e: &mut AccessEvent, left_out: &[Identifier]) {
    // A `*` already there covers objects the sanitizer left out only when
    // its database is `*` or theirs (security review L4); any `*` covers
    // the connector's own overflow (the core's database rule).
    let covers = |o: &ObjectRef| {
        is_wildcard_object(o)
            && (left_out.is_empty()
                || o.database.as_str() == "*"
                || left_out.iter().all(|d| *d == o.database))
    };
    if e.objects.iter().any(covers) {
        return;
    }
    let Some(star) = wildcard() else {
        return;
    };
    let mut databases: Vec<Identifier> = left_out.to_vec();
    if e.objects.len() >= MAX_OBJECTS {
        databases.extend(e.objects.drain(MAX_OBJECTS - 1..).map(|o| o.database));
    }
    databases.extend(e.objects.iter().map(|o| o.database.clone()));
    let database = match databases.split_first() {
        Some((first, rest)) if rest.iter().all(|d| d == first) => first.clone(),
        _ => star.clone(),
    };
    e.objects.push(ObjectRef {
        database,
        schema: None,
        object: ObjectName::Variant0(star),
    });
}

/// Validates and sanitizes an access event in place. `false`: drop it.
pub(crate) fn check_event(e: &mut AccessEvent) -> bool {
    let redis = is_redis_source(e.source);
    // `account_not_recorded` is valid only on Redis / Valkey sources and
    // never on `auth_failure` (contract `Principal`, ADR-0052 decision 8).
    if let Principal::Variant2 {
        account_not_recorded,
        ..
    } = &e.principal
        && (!redis || !*account_not_recorded || e.action == AccessEventAction::AuthFailure)
    {
        return false;
    }
    // Objects past the contract bound are left out: the event then
    // overflowed (ADR-0053), whatever the connector said.
    // Their databases are kept (sanitized) for the `*` that stands for them.
    let mut left_out: Vec<Identifier> = Vec::new();
    if e.objects.len() > MAX_OBJECTS {
        left_out = e.objects.drain(MAX_OBJECTS..).map(|o| o.database).collect();
        e.objects_overflowed = Some(true);
    }
    if !left_out.iter_mut().all(fix_identifier) {
        return false;
    }
    for o in &mut e.objects {
        // A Redis / Valkey source names objects with a `KeyPattern`
        // (contract `ObjectRef`), any other source with an `Identifier`.
        let object_ok = if redis {
            fix_location_object(&mut o.object, Engine::Redis)
        } else {
            fix_object_name(&mut o.object)
        };
        let ok = fix_identifier(&mut o.database)
            && object_ok
            && o.schema.as_mut().is_none_or(fix_identifier);
        if !ok {
            return false;
        }
    }
    // The contract requires a `*` in a flagged event (ADR-0053 decision 1
    // item 3, contract review M2); after the names above were fixed.
    if e.objects_overflowed.is_some() {
        e.objects_overflowed = Some(true);
        keep_overflow_wildcard(e, &left_out);
    }
    if matches!(e.action, AccessEventAction::Read | AccessEventAction::Write)
        && e.objects.is_empty()
    {
        return false;
    }
    if e.aggregated_count.get() > MAX_AGGREGATED {
        return false;
    }
    if e.rows.as_ref().is_some_and(|c| !count_ok(c)) {
        e.rows = None;
    }
    if e.bytes.as_ref().is_some_and(|c| !count_ok(c)) {
        e.bytes = None;
    }
    if let Some(signals) = e.signals.as_mut() {
        let mut seen = HashSet::new();
        signals.retain(|s| seen.insert(s.as_str().to_owned()));
        signals.truncate(MAX_SIGNALS);
        if signals.is_empty() {
            e.signals = None;
        }
    }
    true
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    struct NoFingerprints;
    impl Fingerprinter for NoFingerprints {
        fn fingerprint(&self, _value: &str) -> Option<Fingerprint> {
            None
        }
    }

    fn key() -> HmacKey {
        HmacKey::new(&[7u8; 32]).unwrap()
    }

    pub(crate) fn finding() -> Finding {
        serde_json::from_value(serde_json::json!({
            "target_id": "pg-main",
            "location": {"engine": "postgres", "database": "crm", "schema": "public",
                         "object": "clients", "field": "email"},
            "classifier": "pii.email", "confidence": 0.9, "sampled": 10, "matched": 5,
            "masked_samples": ["***", "***", "***", "***", "***", "***"],
            "fingerprints": [format!("hmac-sha256:{}", "ab".repeat(32)),
                             format!("hmac-sha256:{}", "ab".repeat(32))]
        }))
        .unwrap()
    }

    pub(crate) fn event(action: &str, objects: usize) -> AccessEvent {
        let objs: Vec<_> = (0..objects)
            .map(|_| serde_json::json!({"database": "crm", "object": "123456789012"}))
            .collect();
        serde_json::from_value(serde_json::json!({
            "target_id": "pg-main", "ts": "2026-09-28T14:02:11Z",
            "principal": {"db_user": "backup"}, "action": action, "objects": objs,
            "signals": ["volume.above_baseline", "volume.above_baseline"],
            "source": "pgaudit", "aggregated_count": 1
        }))
        .unwrap()
    }

    #[test]
    fn out_of_range_event_counts_are_dropped() {
        for bad in [-1, MAX_COUNT + 1, i64::MAX] {
            let mut e = event("read", 1);
            e.rows = Some(Count(bad));
            e.bytes = Some(Count(bad));
            assert!(check_event(&mut e));
            assert!(e.rows.is_none() && e.bytes.is_none(), "{bad}");
        }
        let mut e = event("read", 1);
        e.rows = Some(Count(MAX_COUNT));
        e.bytes = Some(Count(0));
        assert!(check_event(&mut e));
        assert_eq!(e.rows.map(|c| c.0), Some(MAX_COUNT));
        assert_eq!(e.bytes.map(|c| c.0), Some(0));
    }

    fn redis_finding(engine: &str, object: &str) -> Finding {
        let mut f = finding();
        f.location = serde_json::from_value(serde_json::json!({
            "engine": engine, "database": "db0", "schema": "hash",
            "object": "x", "field": "#key"
        }))
        .unwrap();
        f.location.object = object.parse().unwrap();
        f
    }

    #[test]
    fn key_patterns_are_checked_by_engine() {
        for engine in ["redis", "valkey"] {
            for kept in [
                "user:*:email",
                "session:*",
                "cache:page:about",
                "orders",
                "*",
            ] {
                let mut f = redis_finding(engine, kept);
                assert!(check_finding(&mut f));
                assert_eq!(f.location.object.to_string(), kept, "{engine}");
            }
            // Valid under the generated pattern, refused by a `not` rule.
            for masked in [
                "host:10.0.0.1",
                "tel:06.12.34.56.78",
                "user:jane%40example",
                "javascript:x",
                "device:00:1a:2b:3c:4d:5e",
                "tel:06_12_34_56_78",
                "phone:\u{ff10}\u{ff16}\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}\u{ff17}",
                "123456789",
            ] {
                let mut f = redis_finding(engine, masked);
                assert!(check_finding(&mut f));
                assert_eq!(f.location.object.to_string(), "*", "{engine} {masked}");
            }
        }
        // Another engine: a key pattern is never sent as such.
        let mut f = redis_finding("mongodb", "user:*:email");
        assert!(check_finding(&mut f));
        assert_eq!(f.location.object.to_string(), "*");
    }

    /// The contract's `KeyPattern` `not` rule, compiled with `regress`.
    static NOT: std::sync::LazyLock<regress::Regex> = std::sync::LazyLock::new(|| {
        let yaml =
            std::fs::read_to_string(databastion_protocol_codegen::default_openapi_path()).unwrap();
        let schema = databastion_protocol_codegen::json_schema_from_openapi(&yaml).unwrap();
        let not = schema["$defs"]["KeyPattern"]["not"]["pattern"]
            .as_str()
            .unwrap()
            .to_owned();
        regress::Regex::with_flags(&not, "u").unwrap()
    });

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(1500))]

        /// A Redis / Valkey object is kept exactly when the contract accepts
        /// it (generated `KeyPattern` type, then the `not` rule); every
        /// object the sanitizer lets through is valid.
        #[test]
        fn sanitizer_mirrors_the_contract_key_pattern(
            pieces in proptest::collection::vec(proptest::sample::select(vec![
                "a", "Z", "f", "0", "7", "42", ":", "/", "|", ".", "-", "_", "+", " ", "%",
                "%4", "@", "*", "{", "#", "\u{ff10}", "\u{ff0e}", "\u{a0}", "\u{2010}",
                "http", "mailto", "00:1a", "db8", ",",
            ]), 1..20)
        ) {
            let s: String = pieces.concat();
            let Ok(object) = s.parse::<ObjectName>() else { return Ok(()); };
            let mut f = redis_finding("valkey", "x");
            f.location.object = object;
            proptest::prop_assert!(check_finding(&mut f));
            let out = f.location.object.to_string();
            let contract = databastion_protocol::KeyPattern::try_from(s.as_str()).is_ok()
                && NOT.find(&s).is_none();
            if contract {
                proptest::prop_assert_eq!(&out, &s);
            } else {
                proptest::prop_assert_eq!(out.as_str(), "*");
            }
        }
    }

    #[test]
    fn key_patterns_and_unrecorded_accounts_by_source() {
        let unrecorded = || -> Principal {
            serde_json::from_value(serde_json::json!({
                "account_not_recorded": true, "client_addr": "198.51.100.7"
            }))
            .unwrap()
        };
        // Another source: a key pattern object becomes `*`, an
        // `account_not_recorded` principal drops the event.
        let mut e = event("read", 1);
        e.objects[0].object = "session:*".parse().unwrap();
        assert!(check_event(&mut e));
        assert_eq!(e.objects[0].object.to_string(), "*");
        let mut e = event("read", 1);
        e.principal = unrecorded();
        assert!(matches!(e.principal, Principal::Variant2 { .. }));
        assert!(!check_event(&mut e));
        // A Redis / Valkey source: key patterns kept when they pass every
        // `not` rule, `*` otherwise; `account_not_recorded` kept, except
        // on `auth_failure`.
        for source in [
            AuditSource::RedisSlowlog,
            AuditSource::RedisCommandlog,
            AuditSource::RedisAclLog,
            AuditSource::RedisSync,
        ] {
            let mut e = event("read", 2);
            e.source = source;
            e.principal = unrecorded();
            e.objects[0].object = "session:*".parse().unwrap();
            e.objects[1].object = "user:123456789".parse().unwrap();
            assert!(check_event(&mut e));
            assert_eq!(e.objects[0].object.to_string(), "session:*");
            assert_eq!(e.objects[1].object.to_string(), "*");
            let mut e = event("auth_failure", 0);
            e.source = source;
            e.principal = unrecorded();
            assert!(!check_event(&mut e));
        }
    }

    #[test]
    fn built_counts_saturate_at_the_contract_bound() {
        assert_eq!(clamped_count(0).0, 0);
        assert_eq!(clamped_count(42).0, 42);
        assert_eq!(clamped_count(9_007_199_254_740_991).0, MAX_COUNT);
        assert_eq!(clamped_count(9_007_199_254_740_992).0, MAX_COUNT);
        assert_eq!(clamped_count(u64::MAX).0, MAX_COUNT);
    }

    #[test]
    fn text_is_stripped_and_truncated_on_char_boundary() {
        assert_eq!(clean_text("a\u{0}b\u{200B}c\u{202E}", 10), "abc");
        assert_eq!(clean_text("ééé", 2), "éé");
        assert_eq!(clean_application("psql\u{7}é;x"), "psql___x");
        assert_eq!(clean_application(&"a".repeat(100)).len(), 64);
    }

    #[test]
    fn finding_constraints_are_enforced() {
        let mut f = finding();
        assert!(check_finding(&mut f));
        assert_eq!(f.masked_samples.len(), 5);
        assert_eq!(f.fingerprints.as_ref().unwrap().len(), 1);

        let mut f = finding();
        f.location.object = Identifier::try_from("4111 1111 1111 1111").unwrap().into();
        assert!(check_finding(&mut f));
        assert_eq!(f.location.object.to_string(), "*");

        // A key pattern on a PostgreSQL location never leaves as such.
        let mut f = finding();
        f.location.object = "user:*:email".parse().unwrap();
        assert!(matches!(f.location.object, ObjectName::Variant1(_)));
        assert!(check_finding(&mut f));
        assert_eq!(f.location.object.to_string(), "*");

        for (confidence, matched) in [(1.5, 5), (-0.1, 5), (f64::NAN, 5), (0.5, 11)] {
            let mut f = finding();
            f.confidence = confidence;
            f.matched = matched;
            assert!(!check_finding(&mut f));
        }
        let mut f = finding();
        f.sampled = std::num::NonZeroU64::new(10_001).unwrap();
        assert!(!check_finding(&mut f));
        let mut f = finding();
        f.estimated_rows = Some(Count(-1));
        assert!(check_finding(&mut f));
        assert!(f.estimated_rows.is_none());
    }

    #[test]
    fn event_constraints_are_enforced() {
        let mut e = event("read", 20);
        assert!(check_event(&mut e));
        assert_eq!(e.objects.len(), 16);
        assert_eq!(e.objects[0].object.to_string(), "*");
        assert_eq!(e.signals.as_ref().unwrap().len(), 1);
        assert!(!check_event(&mut event("write", 0)));
        assert!(check_event(&mut event("connect", 0)));
        let mut e = event("connect", 0);
        e.aggregated_count = std::num::NonZeroU64::new(1_000_001).unwrap();
        assert!(!check_event(&mut e));
    }

    #[test]
    fn bad_account_names_take_the_fingerprint_path() {
        let p = principal(
            "backup",
            true,
            Some("192.0.2.14"),
            Some("pg_dump"),
            &NoFingerprints,
        );
        assert!(matches!(p, Some(Principal::Variant0 { .. })));
        // Control character: never sent as a name.
        let key = key();
        let fps = HmacFingerprints(&key);
        let p = principal("bob\u{7}", true, Some("host.example"), None, &fps);
        let Some(Principal::Variant1 {
            client_addr,
            db_user_fingerprint,
            ..
        }) = p
        else {
            panic!("expected a fingerprint")
        };
        assert!(client_addr.is_none(), "a host name is not a client address");
        // Exact bytes, `db_user` domain.
        assert_eq!(
            db_user_fingerprint.as_str(),
            key.fingerprint_db_user(&RawSample::new("bob\u{7}"))
                .as_str()
        );
        // Failed authentication with an unknown account: fingerprinted, the
        // raw name never appears.
        let p = principal("hunter2-SECRET", false, None, None, &fps).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("hunter2"), "{json}");
        assert!(json.contains("db_user_fingerprint"), "{json}");
        let email_fp = key
            .fingerprint(
                databastion_classifiers::masking::ClassifierId::Email,
                &RawSample::new("a@example.com"),
            )
            .unwrap();
        assert_ne!(
            fps.fingerprint("a@example.com").unwrap().as_str(),
            email_fp.as_str(),
            "domain separation"
        );
        // Without any fingerprint source the item cannot be built.
        assert!(principal("hunter2-SECRET", false, None, None, &NoFingerprints).is_none());
    }

    fn objects_of(e: &AccessEvent) -> Vec<(String, Option<String>, String)> {
        e.objects
            .iter()
            .map(|o| {
                (
                    o.database.as_str().to_owned(),
                    o.schema.as_ref().map(|s| s.as_str().to_owned()),
                    o.object.to_string(),
                )
            })
            .collect()
    }

    fn named(objects: &[(&str, &str)]) -> AccessEvent {
        let mut e = event("read", 0);
        e.objects = objects
            .iter()
            .map(|(d, o)| {
                serde_json::from_value(serde_json::json!({"database": d, "object": o})).unwrap()
            })
            .collect();
        e
    }

    /// Contract review M2 (ADR-0053 decision 1 item 3): a flagged event is
    /// never sent without a `*`. Fail closed: the `*` is added, the flag
    /// kept.
    #[test]
    fn a_flagged_event_always_names_a_wildcard() {
        let star = |d: &str| (d.to_owned(), None, "*".to_owned());
        // Room left: `(<database>, -, *)` appended.
        let mut e = named(&[("crm", "orders"), ("crm", "customers")]);
        e.objects_overflowed = Some(true);
        assert!(check_event(&mut e));
        assert_eq!(e.objects_overflowed, Some(true));
        assert_eq!(e.objects.len(), 3);
        assert_eq!(objects_of(&e)[2], star("crm"));
        // Full: the last named object makes room, and its database counts.
        let names: Vec<String> = (0..16).map(|i| format!("t{i}")).collect();
        let mut list: Vec<(&str, &str)> = names.iter().map(|n| ("crm", n.as_str())).collect();
        let mut e = named(&list);
        e.objects_overflowed = Some(true);
        assert!(check_event(&mut e));
        assert_eq!(e.objects.len(), 16);
        assert_eq!(objects_of(&e)[15], star("crm"));
        assert_eq!(objects_of(&e)[14].2, "t14");
        list[15] = ("billing", "t15");
        let mut e = named(&list);
        e.objects_overflowed = Some(true);
        assert!(check_event(&mut e));
        assert_eq!(objects_of(&e)[15], star("*"), "another database left out");
        // A `*` already there (here one with a schema) covers it: unchanged.
        let mut e = named(&[("crm", "orders")]);
        e.objects.push(
            serde_json::from_value(
                serde_json::json!({"database": "crm", "schema": "s", "object": "*"}),
            )
            .unwrap(),
        );
        e.objects_overflowed = Some(true);
        let before = objects_of(&e);
        assert!(check_event(&mut e));
        assert_eq!(objects_of(&e), before);
        // A name the sanitizer turns into `*` is a `*` too.
        let mut e = named(&[("crm", "123456789012")]);
        e.objects_overflowed = Some(true);
        assert!(check_event(&mut e));
        assert_eq!(objects_of(&e), [star("crm")]);
        // Without the flag nothing is added.
        let mut e = named(&[("crm", "orders")]);
        assert!(check_event(&mut e));
        assert_eq!((e.objects.len(), e.objects_overflowed), (1, None));
    }

    /// Objects past the contract bound are cut by the sanitizer only as a
    /// safety net (the core bounds events first): the cut event is flagged
    /// and names a `*` for what was left out, with sanitized databases.
    #[test]
    fn objects_cut_by_the_sanitizer_flag_the_event() {
        let names: Vec<String> = (0..20).map(|i| format!("t{i}")).collect();
        let mut list: Vec<(&str, &str)> = names.iter().map(|n| ("crm", n.as_str())).collect();
        let mut e = named(&list);
        assert!(check_event(&mut e));
        assert_eq!(e.objects.len(), 16);
        assert_eq!(e.objects_overflowed, Some(true));
        assert_eq!(objects_of(&e)[15], ("crm".to_owned(), None, "*".to_owned()));
        // A left-out object of another database, whose name breaks the
        // numeric rule: `(*, -, *)`, never its raw name.
        list[19] = ("123456789012", "t19");
        let mut e = named(&list);
        assert!(check_event(&mut e));
        assert_eq!(objects_of(&e)[15], ("*".to_owned(), None, "*".to_owned()));
        assert!(!serde_json::to_string(&e).unwrap().contains("123456789012"));
        // Security review L4: a `*` of another database does not cover the
        // objects cut here; `(*, -, *)` takes the last slot.
        let mut list: Vec<(&str, &str)> = names.iter().map(|n| ("crm", n.as_str())).collect();
        list[3] = ("billing", "*");
        let mut e = named(&list);
        assert!(check_event(&mut e));
        let objects = objects_of(&e);
        assert_eq!(objects.len(), 16);
        assert_eq!(objects[3], ("billing".to_owned(), None, "*".to_owned()));
        assert_eq!(objects[15], ("*".to_owned(), None, "*".to_owned()));
        // A `*` of their own database does.
        list[3] = ("crm", "*");
        let mut e = named(&list);
        assert!(check_event(&mut e));
        assert_eq!(objects_of(&e)[15].2, "t15");
    }
}
