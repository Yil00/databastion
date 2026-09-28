//! Column-name hints (FR + EN).
//!
//! A hint never produces a finding on its own: values must match too. Hints
//! raise the confidence of value-validated classifiers, and they are
//! **required** by the classifiers whose values cannot be recognized reliably
//! alone (`pii.person_name`, `pii.postal_address`, `pii.birth_date`, AWS
//! secret access keys).
//!
//! Names are split into lowercase tokens on non-alphanumeric characters and
//! camelCase boundaries (`accessKeyId` -> `access`, `key`, `id`;
//! `date_naissance` -> `date`, `naissance`). For a field path, every segment
//! contributes tokens (`name.first`, `address.street`).

use crate::id::ClassifierId;

/// Longest column name examined (bytes); longer names give no hint.
const MAX_NAME_BYTES: usize = 512;

/// Tokens that name a data type directly.
const DIRECT: &[(ClassifierId, &[&str])] = &[
    (
        ClassifierId::Email,
        &[
            "email",
            "mail",
            "courriel",
            "emailaddress",
            "mailaddress",
            "adressemail",
        ],
    ),
    (
        ClassifierId::Phone,
        &[
            "phone",
            "tel",
            "telephone",
            "téléphone",
            "mobile",
            "portable",
            "gsm",
            "fax",
            "cell",
            "cellphone",
            "msisdn",
            "telephonenumber",
            "phonenumber",
            "mobilephone",
            "homephone",
        ],
    ),
    (ClassifierId::Iban, &["iban", "rib", "bban"]),
    (
        ClassifierId::CardNumber,
        &[
            "card",
            "cardnumber",
            "pan",
            "cc",
            "ccnum",
            "carte",
            "cb",
            "creditcard",
        ],
    ),
    (
        ClassifierId::Nir,
        &[
            "nir",
            "secu",
            "sécu",
            "numsecu",
            "insee",
            "ssn",
            "securite",
            "sécurité",
        ],
    ),
    (
        ClassifierId::BirthDate,
        &[
            "dob",
            "birth",
            "birthdate",
            "birthday",
            "dateofbirth",
            "naissance",
            "datenaissance",
            "ddn",
        ],
    ),
    (
        ClassifierId::PersonName,
        &[
            "firstname",
            "lastname",
            "fullname",
            "givenname",
            "surname",
            "forename",
            "familyname",
            "middlename",
            "maidenname",
            "displayname",
            "prenom",
            "prénom",
            "patronyme",
            "cn",
            "sn",
            "holder",
            "cardholder",
            "titulaire",
        ],
    ),
    (
        ClassifierId::PostalAddress,
        &[
            "address",
            "addr",
            "adresse",
            "street",
            "rue",
            "voie",
            "streetaddress",
            "postaladdress",
            "homeaddress",
            "homepostaladdress",
            "registeredaddress",
            "addressline",
        ],
    ),
    (
        ClassifierId::PasswordHash,
        &[
            "password",
            "passwd",
            "pwd",
            "pass",
            "mdp",
            "motdepasse",
            "userpassword",
            "passwordhash",
            "pwhash",
            "hash",
        ],
    ),
    (
        ClassifierId::AwsKey,
        &[
            "aws",
            "accesskey",
            "accesskeyid",
            "secretkey",
            "secretaccesskey",
        ],
    ),
];

/// Generic name tokens that only hint at a person name when qualified
/// (`first_name`, `requester_name`, `nom_client`), or when they are the
/// whole column name.
const NAME_WORDS: &[&str] = &["name", "names", "nom", "noms"];
const PERSON_QUALIFIERS: &[&str] = &[
    "first",
    "last",
    "full",
    "given",
    "family",
    "middle",
    "maiden",
    "sur",
    "display",
    "legal",
    "birth",
    "requester",
    "customer",
    "client",
    "clients",
    "contact",
    "contacts",
    "holder",
    "owner",
    "person",
    "people",
    "employee",
    "patient",
    "member",
    "famille",
    "usage",
    "complet",
    "naissance",
];

/// Tokens of the **last** segment that turn a hint off for the hint-gated
/// classifiers: the column is about the data type, not the data itself
/// (`email_opt_in`, `phone_country`, `card_brand`, `postal_code`…).
const NEGATIVE: &[&str] = &[
    "id",
    "ids",
    "code",
    "zip",
    "city",
    "country",
    "verified",
    "opt",
    "optin",
    "brand",
    "type",
    "format",
    "count",
    "template",
    "extension",
    "ext",
    "status",
    "domain",
    "length",
    "flag",
    "enabled",
    "policy",
    "hint",
    "expiry",
    "expires",
    "at",
];

/// Hints derived from a column name or field path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameHints {
    hinted: Vec<ClassifierId>,
    negative: bool,
    aws_secret: bool,
    siret: bool,
}

impl NameHints {
    /// Computes the hints of a column name or field path.
    #[must_use]
    pub fn of(name: &str) -> Self {
        if name.len() > MAX_NAME_BYTES {
            return Self::default();
        }
        let segments: Vec<Vec<String>> = name.split('.').map(tokens).collect();
        let all: Vec<&str> = segments.iter().flatten().map(String::as_str).collect();
        let last: &[String] = segments.last().map_or(&[], Vec::as_slice);
        let has = |t: &str| all.contains(&t);

        let mut hinted = Vec::new();
        for (id, words) in DIRECT {
            if words.iter().any(|w| has(w)) {
                hinted.push(*id);
            }
        }
        let name_word = all.iter().any(|t| NAME_WORDS.contains(t));
        if name_word
            && (all.iter().any(|t| PERSON_QUALIFIERS.contains(t))
                || all.iter().all(|t| NAME_WORDS.contains(t)))
            && !hinted.contains(&ClassifierId::PersonName)
        {
            hinted.push(ClassifierId::PersonName);
        }
        // `access_key` split as `access`, `key`.
        let access_key = has("access") && has("key");
        if access_key && !hinted.contains(&ClassifierId::AwsKey) {
            hinted.push(ClassifierId::AwsKey);
        }
        let aws_secret = has("secretaccesskey")
            || has("secretkey")
            || (has("secret") && (has("key") || has("aws")));
        if aws_secret && !hinted.contains(&ClassifierId::AwsKey) {
            hinted.push(ClassifierId::AwsKey);
        }
        hinted.sort();
        let negative = last.iter().any(|t| NEGATIVE.contains(&t.as_str()));
        let siret = ["siret", "siren", "numsiret", "numsiren"]
            .iter()
            .any(|t| has(t));
        Self {
            hinted,
            negative,
            aws_secret,
            siret,
        }
    }

    /// Whether the name hints at this classifier.
    #[must_use]
    pub fn hints(&self, id: ClassifierId) -> bool {
        self.hinted.contains(&id)
    }

    /// Whether a hint-gated classifier may run: hinted, and the last segment
    /// does not describe metadata about the type (`phone_country`).
    #[must_use]
    pub fn gates(&self, id: ClassifierId) -> bool {
        self.hints(id) && !self.negative
    }

    /// Whether the name designates a French company number (SIRET / SIREN):
    /// 14-digit Luhn-valid values there are not card numbers.
    #[must_use]
    pub fn siret(&self) -> bool {
        self.siret
    }

    /// Whether the name designates an AWS secret access key.
    #[must_use]
    pub fn aws_secret(&self) -> bool {
        self.aws_secret && !self.negative
    }
}

/// Lowercase tokens of one name segment, plus their joined form.
fn tokens(segment: &str) -> Vec<String> {
    let mut out = word_tokens(segment);
    // Joined forms catch `e_mail`, `num_secu`, `date_naissance`, `pass_word`.
    let joined: String = out.concat();
    if out.len() > 1 && !out.contains(&joined) {
        out.push(joined);
    }
    out
}

/// Lowercase words of one name segment, split on non-alphanumeric
/// characters and camelCase boundaries (`archiveLucasMartin` -> `archive`,
/// `lucas`, `martin`).
pub(crate) fn word_tokens(segment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in segment.chars() {
        if c.is_alphanumeric() {
            if c.is_uppercase() && prev_lower && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = c.is_lowercase() || c.is_ascii_digit();
            cur.extend(c.to_lowercase());
        } else {
            prev_lower = false;
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ClassifierId as C;

    fn hinted(name: &str) -> Vec<ClassifierId> {
        let h = NameHints::of(name);
        C::ALL.into_iter().filter(|c| h.hints(*c)).collect()
    }

    #[test]
    fn tokenizer() {
        assert_eq!(
            tokens("accessKeyId"),
            ["access", "key", "id", "accesskeyid"]
        );
        assert_eq!(
            tokens("date_naissance"),
            ["date", "naissance", "datenaissance"]
        );
        assert_eq!(tokens("FIRSTNAME"), ["firstname"]);
        assert_eq!(tokens("Prénom"), ["prénom"]);
    }

    #[test]
    fn positive_hints() {
        for (name, want) in [
            ("email", C::Email),
            ("work_email", C::Email),
            ("mail", C::Email),
            ("e_mail", C::Email),
            ("iban", C::Iban),
            ("nir", C::Nir),
            ("num_secu", C::Nir),
            ("date_naissance", C::BirthDate),
            ("dob", C::BirthDate),
            ("birth_date", C::BirthDate),
            ("tel", C::Phone),
            ("phone", C::Phone),
            ("telephonenumber", C::Phone),
            ("mobile_phone", C::Phone),
            ("adresse", C::PostalAddress),
            ("home_address", C::PostalAddress),
            ("address.street", C::PostalAddress),
            ("nom", C::PersonName),
            ("prenom", C::PersonName),
            ("first_name", C::PersonName),
            ("name.first", C::PersonName),
            ("requester_name", C::PersonName),
            ("contacts.*.name", C::PersonName),
            ("givenname", C::PersonName),
            ("card_holder", C::PersonName),
            ("cards[].holder", C::PersonName),
            ("password", C::PasswordHash),
            ("pwd", C::PasswordHash),
            ("password_hash", C::PasswordHash),
            ("aws_access_key_id", C::AwsKey),
            ("credentials.secretAccessKey", C::AwsKey),
            ("card_number", C::CardNumber),
        ] {
            assert!(hinted(name).contains(&want), "{name} -> {want}");
        }
        assert!(NameHints::of("aws_secret_access_key").aws_secret());
        assert!(NameHints::of("credentials.secretAccessKey").aws_secret());
    }

    #[test]
    fn negative_hints() {
        assert!(hinted("key_name").is_empty());
        assert!(hinted("product_name").is_empty());
        assert!(hinted("created_at").is_empty());
        assert!(hinted("amount_cents").is_empty());
        assert!(hinted("status").is_empty());
        assert!(!NameHints::of("phone_country").gates(C::Phone));
        assert!(!NameHints::of("email_opt_in").gates(C::Email));
        assert!(!NameHints::of("address.postalCode").gates(C::PostalAddress));
        assert!(!NameHints::of("address.city").gates(C::PostalAddress));
        assert!(!NameHints::of("accessKeyId").aws_secret());
        assert!(hinted(&"a".repeat(600)).is_empty());
    }
}
