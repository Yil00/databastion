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
//! | `minimum` / `maximum` on numbers | `confidence` | item dropped (NaN, < 0, > 1) |
//! | `minimum` / `maximum` on integers | `sampled`, `matched`, `aggregated_count`, `Count` | item dropped, or optional field omitted |
//! | `maxItems` | `masked_samples` (5), `fingerprints` (50), `objects` (16), `signals` (16) | truncated |
//! | `uniqueItems` | `fingerprints`, `signals` | deduplicated |
//! | `if` / `then` | `read` / `write` events need an object | item dropped |
//! | cross-field | `matched <= sampled` | item dropped |
//! | `minItems` / `maxItems` of the batch, 1 MiB | envelope | enforced by the batch builder in `uplink` |
//!
//! Raw strings that are not names (`db_user`, `application`) go through
//! [`clean_text`] / [`clean_application`] and fall back to the fingerprint
//! path: [`HmacFingerprints`] computes `db_user_fingerprint` with the agent
//! HMAC key, in the `db_user` domain (`HmacKey::fingerprint_db_user`), so
//! such an event carries a fingerprint instead of being dropped. An event is
//! only dropped (and counted) if no conforming principal can be built at all.

use std::collections::HashSet;

use databastion_classifiers::masking::{HmacKey, RawSample};
use databastion_classifiers::names::{is_forbidden_char, violates_numeric_rule};
use databastion_protocol::{
    AccessEvent, AccessEventAction, ClientAddress, Count, Finding, Fingerprint, Identifier,
    Principal, PrincipalVariant0Application, PrincipalVariant0DbUser, PrincipalVariant1Application,
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

/// Validates and sanitizes a finding in place. `false`: drop it.
pub(crate) fn check_finding(f: &mut Finding) -> bool {
    let l = &mut f.location;
    let names_ok = fix_identifier(&mut l.database)
        && fix_identifier(&mut l.object)
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

/// Validates and sanitizes an access event in place. `false`: drop it.
pub(crate) fn check_event(e: &mut AccessEvent) -> bool {
    e.objects.truncate(MAX_OBJECTS);
    for o in &mut e.objects {
        let ok = fix_identifier(&mut o.database)
            && fix_identifier(&mut o.object)
            && o.schema.as_mut().is_none_or(fix_identifier);
        if !ok {
            return false;
        }
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
        f.location.object = Identifier::try_from("4111 1111 1111 1111").unwrap();
        assert!(check_finding(&mut f));
        assert_eq!(f.location.object.as_str(), "*");

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
        assert_eq!(e.objects[0].object.as_str(), "*");
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
}
