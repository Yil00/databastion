//! Frozen classifier identifiers (P2-A).
//!
//! The string forms are part of the agent ↔ console contract: they match the
//! `ClassifierId` pattern of `shared/protocol/openapi.yaml`
//! (`^[a-z]+(\.[a-z0-9_]+)+$`, 3..=64 characters) and the ids used by
//! `dev/ground-truth.json`. **Never rename one**: a rename is a new
//! classifier id in a new [`CLASSIFIERS_VERSION`], and the console keeps the
//! old one for existing findings.

use std::fmt;

/// Version of the classifier set implemented by this crate (`YYYY.MM.N`,
/// contract `ClassifiersVersion`). Bumped whenever an id is added or a
/// detector changes its decision rules.
pub const CLASSIFIERS_VERSION: &str = "2026.09.1";

/// Identifier of a classifier (e.g. `pii.email`).
///
/// Closed set owned by this crate: a connector can neither create a new one
/// nor smuggle a sampled value into a finding through the classifier name.
/// It implements neither `From<&str>`, `From<String>` nor `Deserialize`;
/// [`ClassifierId::parse`] only maps a known id back to its variant.
///
/// ```compile_fail
/// use databastion_classifiers::masking::ClassifierId;
/// let _ = ClassifierId("jane.doe@example.com");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ClassifierId {
    /// `pii.birth_date`: dates of birth (column-name hint required).
    BirthDate,
    /// `pii.card_number`: payment card numbers (Luhn + issuer prefix).
    CardNumber,
    /// `pii.email`: e-mail addresses.
    Email,
    /// `pii.iban`: IBANs (country length + mod 97).
    Iban,
    /// `pii.nir`: French social security numbers (NIR, with key).
    Nir,
    /// `pii.person_name`: person names (column-name hint required).
    PersonName,
    /// `pii.phone`: French national and international phone numbers.
    Phone,
    /// `pii.postal_address`: postal addresses (column-name hint required).
    PostalAddress,
    /// `secret.aws_key`: AWS access key ids (`AKIA` / `ASIA`) and, with a
    /// column-name hint, secret access keys.
    AwsKey,
    /// `secret.password_hash`: bcrypt, argon2, scrypt, pbkdf2, `crypt(3)`
    /// SHA-2 and LDAP `{SSHA}`-style password hashes.
    PasswordHash,
}

impl ClassifierId {
    /// Email addresses (kept for the P0-D call sites).
    pub const PII_EMAIL: Self = Self::Email;
    /// IBAN bank account numbers (kept for the P0-D call sites).
    pub const PII_IBAN: Self = Self::Iban;
    /// AWS access keys (kept for the P0-D call sites).
    pub const SECRET_AWS_KEY: Self = Self::AwsKey;

    /// Every known classifier, in the stable order used for results.
    pub const ALL: [Self; 10] = [
        Self::BirthDate,
        Self::CardNumber,
        Self::Email,
        Self::Iban,
        Self::Nir,
        Self::PersonName,
        Self::Phone,
        Self::PostalAddress,
        Self::AwsKey,
        Self::PasswordHash,
    ];

    /// Stable identifier, e.g. `pii.email`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BirthDate => "pii.birth_date",
            Self::CardNumber => "pii.card_number",
            Self::Email => "pii.email",
            Self::Iban => "pii.iban",
            Self::Nir => "pii.nir",
            Self::PersonName => "pii.person_name",
            Self::Phone => "pii.phone",
            Self::PostalAddress => "pii.postal_address",
            Self::AwsKey => "secret.aws_key",
            Self::PasswordHash => "secret.password_hash",
        }
    }

    /// Whether this is a `secret.*` classifier (a credential: never
    /// fingerprinted where the CAS store guard applies, ADR-0041
    /// decision 5).
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(self, Self::AwsKey | Self::PasswordHash)
    }

    /// Maps a known id (e.g. from a job's `classifiers` filter) back to its
    /// variant. `None` for an unknown id: the caller decides whether that
    /// rejects the job. Never returns caller-provided text.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == id)
    }
}

impl fmt::Display for ClassifierId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_classifiers_are_the_secret_prefix() {
        for c in ClassifierId::ALL {
            assert_eq!(c.is_secret(), c.as_str().starts_with("secret."), "{c}");
        }
    }

    /// Contract `ClassifierId` pattern `^[a-z]+(\.[a-z0-9_]+)+$`, 3..=64.
    fn matches_contract(id: &str) -> bool {
        let mut parts = id.split('.');
        let head_ok = parts
            .next()
            .is_some_and(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_lowercase()));
        let rest: Vec<&str> = parts.collect();
        (3..=64).contains(&id.len())
            && head_ok
            && !rest.is_empty()
            && rest.iter().all(|p| {
                !p.is_empty()
                    && p.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            })
    }

    #[test]
    fn ids_are_frozen() {
        let ids: Vec<&str> = ClassifierId::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            ids,
            [
                "pii.birth_date",
                "pii.card_number",
                "pii.email",
                "pii.iban",
                "pii.nir",
                "pii.person_name",
                "pii.phone",
                "pii.postal_address",
                "secret.aws_key",
                "secret.password_hash",
            ]
        );
    }

    #[test]
    fn ids_match_the_contract_pattern_and_round_trip() {
        for c in ClassifierId::ALL {
            assert!(matches_contract(c.as_str()), "{c}");
            assert_eq!(ClassifierId::parse(c.as_str()), Some(c));
            assert_eq!(c.to_string(), c.as_str());
        }
        assert_eq!(ClassifierId::parse("pii.unknown"), None);
        assert_eq!(ClassifierId::parse("PII.EMAIL"), None);
    }

    #[test]
    fn version_matches_the_contract_pattern() {
        let parts: Vec<&str> = CLASSIFIERS_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 4);
        assert_eq!(parts[1].len(), 2);
        assert!((1..=4).contains(&parts[2].len()));
        assert!(parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())));
    }
}
