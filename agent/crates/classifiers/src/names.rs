//! Name normalization before the uplink (ADR-0009, contract
//! `x-databastion-normalized-name`).
//!
//! Object and field names are engine metadata, but they can embed values
//! (MongoDB dynamic keys, LDAP entry DNs, tables named after a customer).
//! [`NormalizedName`] can only be obtained through the functions of this
//! module, and always matches the contract `Identifier` schema: its pattern
//! **and** its `not` rule (no name or `.`-separated segment made only of 9
//! or more digits and separators).
//!
//! Skeleton status (P1-B): structural rules only.
//! - array indices (`orders.3.email`) become `[]` (`orders[].email`);
//! - segments that look like values become `*`: long numeric runs (the
//!   `Identifier` `not` rule), characters the pattern forbids (`@`, `=`,
//!   `:`…, so e-mail addresses and URLs), UUID / long hex keys;
//! - an LDAP entry DN is reduced to its parent container, attribute types
//!   are lowercased;
//! - anything that still does not conform becomes `*`.
//!
//! P2-A extends [`segment_looks_like_value`] with classifier matches (a
//! segment matched by a classifier becomes `*`).

use std::fmt;

/// Wildcard replacing a name or segment that may carry a value.
const WILDCARD: &str = "*";
/// Contract `Identifier.maxLength` (characters).
pub const MAX_IDENTIFIER_CHARS: usize = 256;
/// Largest input examined; longer names are replaced by `*` outright.
const MAX_INPUT_BYTES: usize = 4096;
/// Array indices up to this many digits become `[]`; longer digit runs are
/// treated as values.
const MAX_INDEX_DIGITS: usize = 6;
/// LDAP RDN types allowed in a container DN (contract `Identifier`).
const CONTAINER_TYPES: [&str; 6] = ["ou", "dc", "o", "c", "l", "st"];

/// A name that went through this module. Always matches the contract
/// `Identifier` schema. No public constructor from a string.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NormalizedName(String);

impl NormalizedName {
    /// The normalized name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `*` wildcard.
    #[must_use]
    pub fn wildcard() -> Self {
        Self(WILDCARD.to_owned())
    }

    fn checked(candidate: String) -> Self {
        if conforms(&candidate) {
            Self(candidate)
        } else {
            Self::wildcard()
        }
    }
}

impl fmt::Debug for NormalizedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NormalizedName").field(&self.0).finish()
    }
}

/// Control, format, private-use and line / paragraph separator characters
/// (`\p{Cc}`, `\p{Cf}`, `\p{Co}`, `\p{Zl}`, `\p{Zp}`). The `Cf` list covers
/// the assigned format characters (Unicode 15).
#[must_use]
pub fn is_forbidden_char(c: char) -> bool {
    let u = u32::from(c);
    c.is_control()
        || matches!(
            u,
            0x00AD
                | 0x0600..=0x0605
                | 0x061C
                | 0x06DD
                | 0x070F
                | 0x0890..=0x0891
                | 0x08E2
                | 0x180E
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x206F
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x13430..=0x1343F
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0001
                | 0xE0020..=0xE007F
                | 0xE000..=0xF8FF
                | 0xF0000..=0xFFFFD
                | 0x100000..=0x10FFFD
        )
}

/// Characters excluded from a plain `Identifier` name.
fn is_plain_excluded(c: char) -> bool {
    matches!(
        c,
        '@' | '=' | ':' | ';' | '/' | '\\' | '\'' | '"' | '`' | '<' | '>' | '(' | ')' | ','
    ) || is_forbidden_char(c)
}

/// `[0-9 +.-]` (whole name) / `[0-9 +-]` (segment) runs of 9 or more.
fn is_numeric_run(s: &str, allow_dot: bool) -> bool {
    s.chars().count() >= 9
        && s.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ' ' | '+' | '-') || (allow_dot && c == '.'))
}

/// The contract `Identifier` `not` rule: true when the name is rejected.
#[must_use]
pub fn violates_numeric_rule(name: &str) -> bool {
    is_numeric_run(name, true) || name.split('.').any(|seg| is_numeric_run(seg, false))
}

/// Full `Identifier` check (length, pattern, `not` rule).
#[must_use]
pub fn conforms(name: &str) -> bool {
    let len = name.chars().count();
    if len == 0 || len > MAX_IDENTIFIER_CHARS || violates_numeric_rule(name) {
        return false;
    }
    if !name.chars().any(is_plain_excluded) {
        return true;
    }
    // LDAP container DN: `(ou|dc|o|c|l|st)=value(,…)*`, values exclude `+`.
    name.split(',').all(|rdn| {
        rdn.split_once('=').is_some_and(|(ty, value)| {
            CONTAINER_TYPES.contains(&ty)
                && !value.is_empty()
                && !value.chars().any(|c| c == '+' || is_plain_excluded(c))
        })
    })
}

/// Whether a path segment looks like a value rather than a name.
///
/// Structural rules only; P2-A adds classifier matches here.
#[must_use]
pub fn segment_looks_like_value(segment: &str) -> bool {
    if segment.is_empty() || segment.chars().any(is_plain_excluded) {
        return true;
    }
    if is_numeric_run(segment, false) {
        return true;
    }
    // Long digit content, even mixed with letters (account numbers, IDs).
    if segment.chars().filter(char::is_ascii_digit).count() >= 9 {
        return true;
    }
    // UUIDs, ObjectIds, hashes: long hexadecimal keys.
    let hex = segment
        .chars()
        .filter(|c| *c != '-')
        .all(|c| c.is_ascii_hexdigit());
    hex && segment.len() >= 16 && segment.chars().any(|c| c.is_ascii_digit())
}

fn strip_forbidden(raw: &str) -> String {
    raw.chars().filter(|c| !is_forbidden_char(*c)).collect()
}

/// Normalizes a plain name or a `.`-separated field path (column, MongoDB
/// field path, collection, table…).
#[must_use]
pub fn normalize_path(raw: &str) -> NormalizedName {
    if raw.len() > MAX_INPUT_BYTES {
        return NormalizedName::wildcard();
    }
    let cleaned = strip_forbidden(raw);
    let mut out: Vec<String> = Vec::new();
    for segment in cleaned.split('.') {
        let digits_only = !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit());
        if digits_only && segment.len() <= MAX_INDEX_DIGITS {
            match out.last_mut() {
                Some(prev) => prev.push_str("[]"),
                None => out.push(WILDCARD.to_owned()),
            }
        } else if segment_looks_like_value(segment) {
            out.push(WILDCARD.to_owned());
        } else {
            out.push(segment.to_owned());
        }
    }
    NormalizedName::checked(out.join("."))
}

/// Normalizes an LDAP attribute type (lowercased).
#[must_use]
pub fn normalize_ldap_attribute(raw: &str) -> NormalizedName {
    normalize_path(&raw.to_ascii_lowercase())
}

/// Reduces an LDAP DN to its container: leading non-container RDNs (the
/// entry, e.g. `uid=jdoe` or `cn=Jane Doe`) are removed, attribute types are
/// lowercased, and a value that may carry data becomes `*`. Anything that
/// cannot be parsed simply (escapes, multi-valued RDNs) becomes `*`.
#[must_use]
pub fn normalize_ldap_dn(raw: &str) -> NormalizedName {
    if raw.len() > MAX_INPUT_BYTES || raw.contains('\\') || raw.contains('+') {
        return NormalizedName::wildcard();
    }
    let cleaned = strip_forbidden(raw);
    let mut rdns = Vec::new();
    for rdn in cleaned.split(',') {
        let Some((ty, value)) = rdn.split_once('=') else {
            return NormalizedName::wildcard();
        };
        rdns.push((ty.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let Some(start) = rdns
        .iter()
        .position(|(ty, _)| CONTAINER_TYPES.contains(&ty.as_str()))
    else {
        return NormalizedName::wildcard();
    };
    let mut parts = Vec::new();
    for (ty, value) in &rdns[start..] {
        if !CONTAINER_TYPES.contains(&ty.as_str()) {
            return NormalizedName::wildcard();
        }
        let bad = value.is_empty()
            || value.contains('=')
            || value.split('.').any(segment_looks_like_value);
        parts.push(format!("{ty}={}", if bad { WILDCARD } else { value }));
    }
    NormalizedName::checked(parts.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_examples() {
        assert_eq!(normalize_path("orders.3.email").as_str(), "orders[].email");
        assert_eq!(
            normalize_path("contacts.jane@example.com.phone").as_str(),
            // `jane@example` and `com` are separate segments: the first is a
            // value, the second a plain word (P2-A classifiers catch domains).
            "contacts.*.com.phone"
        );
        assert_eq!(
            normalize_ldap_dn("uid=jdoe,ou=people,dc=example,dc=com").as_str(),
            "ou=people,dc=example,dc=com"
        );
        assert_eq!(
            normalize_ldap_dn("CN=Jane Doe,OU=Staff,DC=x").as_str(),
            "ou=Staff,dc=x"
        );
        assert_eq!(
            normalize_ldap_attribute("mailAlternateAddress").as_str(),
            "mailalternateaddress"
        );
        assert_eq!(normalize_path("clients").as_str(), "clients");
        assert_eq!(normalize_path("matrix.1.2").as_str(), "matrix[][]");
    }

    #[test]
    fn values_as_names_become_wildcards() {
        for raw in [
            "4111111111111111",
            "+33 6 12 34 56 78",
            "users.0612345678.phone",
            "01920f60-3c1a-7b2e-9f00-5a1b2c3d4e5f",
            "https://x",
            "a=b",
            "",
        ] {
            let n = normalize_path(raw);
            assert!(conforms(n.as_str()), "{raw:?} -> {n:?}");
            assert!(!n.as_str().contains("0612345678"));
        }
        assert_eq!(normalize_path("4111111111111111").as_str(), "*");
        assert_eq!(
            normalize_path("users.0612345678.phone").as_str(),
            "users.*.phone"
        );
        assert_eq!(normalize_ldap_dn("uid=a,cn=b").as_str(), "*");
        assert_eq!(normalize_ldap_dn("ou=123456789,dc=x").as_str(), "ou=*,dc=x");
    }

    #[test]
    fn control_and_format_characters_are_stripped() {
        assert_eq!(
            normalize_path("cli\u{200B}ents\u{0007}").as_str(),
            "clients"
        );
        assert_eq!(normalize_path("\u{202E}").as_str(), "*");
    }

    #[test]
    fn conforms_matches_contract_examples() {
        assert!(conforms("ou=people,dc=example,dc=com"));
        assert!(!conforms("uid=jdoe,ou=people"));
        assert!(!conforms("jane@example.com"));
        assert!(!conforms("12345678901"));
        assert!(!conforms("a.123 456 789.b"));
        assert!(conforms("a.12345678.b"));
        assert!(!conforms(&"a".repeat(257)));
    }
}
