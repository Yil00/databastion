//! Hand-written wrappers for the two credential schemas, `AgentSecret` and
//! `EnrollmentToken`. `databastion-protocol-codegen` substitutes them for
//! the typify output (see `SECRET_REPLACEMENTS`), so the generated
//! `EnrollRequest`, `EnrollResponse` and `RotateRequest` embed them.
//!
//! - `Debug` prints `[REDACTED]`; no `Display`, `Hash`, `Ord` or `Eq`
//!   (nothing needs to compare or index a credential).
//! - The buffer is zeroized on drop.
//! - Built only through a validating `TryFrom` (length and pattern of the
//!   contract), also used by `Deserialize`; errors never echo the value.
//! - [`AgentSecret::expose`] is the only way to read the value (for the
//!   `Authorization` header and the request bodies).

use std::fmt;

use zeroize::Zeroizing;

/// Error returned when a string is not a valid credential. Carries no part
/// of the rejected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCredential {
    kind: &'static str,
}

impl fmt::Display for InvalidCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {} (value redacted)", self.kind)
    }
}

impl std::error::Error for InvalidCredential {}

/// `^<prefix>[A-Za-z0-9_-]{43}$`, as in the contract.
fn is_valid(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 43
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

macro_rules! credential {
    ($(#[$doc:meta])* $name:ident, $prefix:literal, $kind:literal) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name(Zeroizing<String>);

        impl $name {
            /// The credential in clear. Never log it.
            #[must_use]
            pub fn expose(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }

        impl TryFrom<String> for $name {
            type Error = InvalidCredential;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                // Wrap first so that a rejected value is zeroized too.
                let value = Zeroizing::new(value);
                if is_valid(&value, $prefix) {
                    Ok(Self(value))
                } else {
                    Err(InvalidCredential { kind: $kind })
                }
            }
        }

        impl TryFrom<&str> for $name {
            type Error = InvalidCredential;
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::try_from(value.to_owned())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.expose())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::try_from(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

credential!(
    /// Agent secret: `dbs_` + 43 base64url characters.
    AgentSecret,
    "dbs_",
    "agent secret"
);
credential!(
    /// Single-use enrollment token: `dbe_` + 43 base64url characters.
    EnrollmentToken,
    "dbe_",
    "enrollment token"
);

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "dbs_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE0";

    #[test]
    fn valid_values_round_trip() {
        let secret = AgentSecret::try_from(SECRET).unwrap();
        assert_eq!(secret.expose(), SECRET);
        assert_eq!(
            serde_json::to_string(&secret).unwrap(),
            format!("\"{SECRET}\"")
        );
    }

    #[test]
    fn invalid_values_are_rejected_without_echo() {
        for bad in [
            "",
            "dbs_short",
            "dbe_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE0",
            "dbs_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE!",
            "dbs_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE00",
        ] {
            let err = AgentSecret::try_from(bad).unwrap_err();
            let json = serde_json::to_string(bad).unwrap();
            let de = serde_json::from_str::<AgentSecret>(&json).unwrap_err();
            for message in [err.to_string(), de.to_string()] {
                assert!(bad.is_empty() || !message.contains(bad), "{message}");
            }
        }
        assert!(EnrollmentToken::try_from(SECRET).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let secret = AgentSecret::try_from(SECRET).unwrap();
        assert_eq!(format!("{secret:?}"), "AgentSecret([REDACTED])");
    }
}
