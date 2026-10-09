//! I/O-free parsers of CAS data (ADR-0041 decision 2, last item): the
//! service definition ([`definition`], JSON or YAML after the pre-scan of
//! [`yaml`]), the audit record ([`record`]), the
//! `what` reducer and URL credential stripping ([`url`]) and audit times
//! ([`when`]). The existing connectors can later reuse the service
//! definition parser for registries held in a database (ADR-0041 open
//! question 4) without depending on file reading.

pub mod definition;
pub mod record;
pub mod url;
pub mod when;
pub mod yaml;

pub(crate) use databastion_core::jtext;
use zeroize::Zeroizing;

/// `s` cut to at most `max` bytes on a character boundary, in a zeroizing
/// buffer.
pub(crate) fn bounded_owned(s: &str, max: usize) -> Zeroizing<String> {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Zeroizing::new(s.get(..end).unwrap_or("").to_owned())
}

/// Whether `s` is a Jackson type name (`java.util.ArrayList`), a
/// structural string never sampled.
pub(crate) fn is_java_type(s: &str) -> bool {
    (s.starts_with("java.") || s.starts_with("javax."))
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'$' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_cuts_on_a_boundary() {
        assert_eq!(&*bounded_owned("abcé", 4), "abc");
        assert_eq!(&*bounded_owned("abcé", 5), "abcé");
        assert_eq!(&*bounded_owned("", 0), "");
    }

    #[test]
    fn java_types() {
        assert!(is_java_type("java.util.ArrayList"));
        assert!(is_java_type("java.util.HashMap$Node"));
        assert!(!is_java_type("java.util.List<String>"));
        assert!(!is_java_type("javascript:alert"));
        assert!(!is_java_type("jane.doe@example.org"));
    }
}
