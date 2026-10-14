//! The CAS store guard by key name and by value (ADR-0052 decision 6,
//! ADR-0041 decision 5, security review M6, re-review N5).
//!
//! A key whose name holds the ticket-id shape `[A-Z]{2,4}-<digits>-`
//! **anywhere** (the named prefixes `TGT`, `ST`, `PT`, `PGT`, `OC`, `AT`,
//! `RT` are among them), the CAS Redis ticket registry's prefix (the
//! `CAS_TICKET` family, compared without case; to confirm against CAS 8.0,
//! ADR-0052 open question 9) or a `cas_stores.ticket_registry` pattern is
//! never read and never reported, not even as a pattern. A value holding
//! the shape anywhere in its first 4 KiB guards **that key**: its values
//! are dropped before classification.

use databastion_core::cas_guard::CasStores;

/// Bytes of a value the tripwire looks at.
pub(crate) const VALUE_WINDOW: usize = 4096;

/// The CAS Redis ticket registry key family (open question 9).
const CAS_PREFIX: &[u8] = b"CAS_TICKET";

/// Whether `bytes` hold `[A-Z]{2,}-[0-9]+-` anywhere (an uppercase run of
/// at least 2 letters ending at a dash covers `[A-Z]{2,4}` and the named
/// prefixes).
pub(crate) fn has_ticket_shape(bytes: &[u8]) -> bool {
    bytes.iter().enumerate().any(|(i, &b)| {
        if b != b'-' {
            return false;
        }
        let before = bytes.get(..i).unwrap_or_default();
        let letters = before
            .iter()
            .rev()
            .take_while(|c| c.is_ascii_uppercase())
            .count();
        if letters < 2 {
            return false;
        }
        let after = bytes.get(i + 1..).unwrap_or_default();
        let digits = after.iter().take_while(|c| c.is_ascii_digit()).count();
        digits > 0 && after.get(digits) == Some(&b'-')
    })
}

fn contains_ignore_case(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Whether a key is guarded by its name.
pub(crate) fn key_guarded(key: &[u8], stores: Option<&CasStores>) -> bool {
    has_ticket_shape(key)
        || contains_ignore_case(key, CAS_PREFIX)
        || stores.is_some_and(|s| {
            s.ticket_registry
                .iter()
                .any(|p| crate::glob::matches(p.as_bytes(), key))
        })
}

/// Whether a value guards its key (the unanchored tripwire, N5).
pub(crate) fn value_trips(value: &[u8]) -> bool {
    has_ticket_shape(value.get(..VALUE_WINDOW.min(value.len())).unwrap_or(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_with_the_shape_anywhere_are_guarded() {
        for k in [
            &b"sso:TGT-3-dev-only-x"[..],
            b"TGT-1-x",
            b"cas:sessions:ST-12-abc",
            b"x|ABCD-9-y",
            b"CAS_TICKET:abc",
            b"cas_ticket_registry:1",
        ] {
            assert!(key_guarded(k, None), "{k:?}");
        }
        for k in [
            &b"user:42:email"[..],
            b"A-1-x",
            b"stats:visits:2026-09-03",
            b"ST-x-1",
        ] {
            assert!(!key_guarded(k, None), "{k:?}");
        }
        let stores = CasStores {
            ticket_registry: vec!["tickets:*".to_owned()],
            service_registry: Vec::new(),
            audit_trail: Vec::new(),
        };
        assert!(key_guarded(b"tickets:abc", Some(&stores)));
    }

    #[test]
    fn values_embedding_a_ticket_after_other_text_trip() {
        assert!(value_trips(b"{\"service\":\"x\",\"ticket\":\"ST-1-abc\"}"));
        assert!(value_trips(b"redirect?ticket=TGT-22-xyz"));
        assert!(!value_trips(b"jane.doe@example.com"));
        let mut long = vec![b'a'; VALUE_WINDOW];
        long.extend_from_slice(b"TGT-1-x");
        assert!(!value_trips(&long));
    }
}
