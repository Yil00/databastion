//! Value detectors.
//!
//! Two kinds:
//! - **token detectors** find validated tokens anywhere in a value, so they
//!   also work on free text (`Customer called from 01 99 00 27 59`):
//!   e-mail, IBAN, card number, NIR, phone, AWS access key id, password
//!   hash (whole value only);
//! - **whole-value detectors** recognize a value that is entirely a date,
//!   a person name, a postal address or an AWS secret access key. They are
//!   weak on their own and only run when the column name hints at them
//!   ([`crate::hints`]).
//!
//! All regexes run on the `regex` crate (finite automata, linear time: no
//! catastrophic backtracking on hostile values). Inputs longer than
//! [`MAX_SCAN_BYTES`] are only scanned up to that bound.
//!
//! Detectors return byte ranges into the scanned value; they never copy,
//! keep or log it.

use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use crate::id::ClassifierId;
use crate::validate;

/// Bytes of a value examined by the detectors (cut on a char boundary).
pub const MAX_SCAN_BYTES: usize = 8 * 1024;
/// Most tokens reported for one value.
const MAX_TOKENS_PER_VALUE: usize = 64;

/// A validated token found in a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Classifier that recognized the token.
    pub classifier: ClassifierId,
    /// Byte range in the scanned value.
    pub range: Range<usize>,
}

// Patterns are compile-time constants; `Regex::new` cannot fail on them
// (covered by the `patterns_compile` test). A failure disables the detector
// instead of panicking.
fn re(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

static EMAIL: LazyLock<Option<Regex>> =
    LazyLock::new(|| re(r"[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}\-]+(?:\.[\p{L}\p{N}\-]+)*\.\p{L}{2,}"));
static IBAN_START: LazyLock<Option<Regex>> = LazyLock::new(|| re(r"\b[A-Z]{2}[0-9]{2}"));
static CARD: LazyLock<Option<Regex>> = LazyLock::new(|| re(r"\b[0-9](?:[ \-]?[0-9]){11,22}\b"));
static NIR: LazyLock<Option<Regex>> = LazyLock::new(|| {
    re(
        r"\b[12][ .]?[0-9]{2}[ .]?[0-9]{2}[ .]?(?:[0-9]{2}|2[AB])[ .]?[0-9]{3}[ .]?[0-9]{3}[ .]?[0-9]{2}\b",
    )
});
static PHONE_FR: LazyLock<Option<Regex>> =
    LazyLock::new(|| re(r"\b0[1-9](?:[ .\-]?[0-9]{2}){4}\b"));
static PHONE_INTL: LazyLock<Option<Regex>> =
    LazyLock::new(|| re(r"\+(?:[0-9][ .\-]?){7,14}[0-9]\b"));
static AWS_ID: LazyLock<Option<Regex>> = LazyLock::new(|| re(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"));
static PASSWORD_HASH: LazyLock<Option<Regex>> = LazyLock::new(|| {
    re(concat!(
        r"^(?:",
        // bcrypt
        r"\$2[abxy]?\$[0-9]{2}\$[./A-Za-z0-9]{53}",
        // argon2 PHC
        r"|\$argon2(?:id|i|d)\$(?:v=[0-9]+\$)?m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*",
        // scrypt PHC and crypt $7$
        r"|\$scrypt\$ln=[0-9]+,r=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]+=*\$[A-Za-z0-9+/]+=*",
        r"|\$7\$[./A-Za-z0-9]{11,}\$[./A-Za-z0-9]{43}",
        // crypt(3) SHA-256 / SHA-512
        r"|\$5\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43}",
        r"|\$6\$(?:rounds=[0-9]+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}",
        // pbkdf2: PHC / passlib and Django
        r"|\$pbkdf2(?:-sha(?:1|256|512))?\$[^$\s]+\$[./A-Za-z0-9+]+=*\$[./A-Za-z0-9+]+=*",
        r"|pbkdf2_sha(?:1|256)\$[0-9]+\$[^$\s]+\$[A-Za-z0-9+/]+=*",
        // LDAP / RFC 2307 schemes
        r"|\{(?i:SSHA|SSHA256|SSHA384|SSHA512|SHA|SHA256|SHA512|SMD5|MD5|CRYPT|PBKDF2(?:-SHA(?:1|256|512))?|ARGON2)\}[A-Za-z0-9+/.$=,\-]{8,}",
        r")$"
    ))
});
static ISO_DATE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    re(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})(?:[T ]00:00(?::00(?:\.0+)?)?(?:Z|[+\-]00:?00)?)?$")
});
static FR_DATE: LazyLock<Option<Regex>> =
    LazyLock::new(|| re(r"^([0-9]{2})/([0-9]{2})/([0-9]{4})$"));

/// Cuts a value to [`MAX_SCAN_BYTES`] on a char boundary.
#[must_use]
pub fn bounded(value: &str) -> &str {
    if value.len() <= MAX_SCAN_BYTES {
        return value;
    }
    let mut end = MAX_SCAN_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn overlaps(taken: &[Token], r: &Range<usize>) -> bool {
    taken
        .iter()
        .any(|t| t.range.start < r.end && r.start < t.range.end)
}

fn prev_char(s: &str, at: usize) -> Option<char> {
    s[..at].chars().next_back()
}

fn next_char(s: &str, at: usize) -> Option<char> {
    s[at..].chars().next()
}

fn push(out: &mut Vec<Token>, classifier: ClassifierId, range: Range<usize>) {
    if out.len() < MAX_TOKENS_PER_VALUE && !overlaps(out, &range) {
        out.push(Token { classifier, range });
    }
}

/// Finds every validated token in a value. Tokens never overlap: detectors
/// run from the most to the least specific (AWS key id, password hash,
/// e-mail, IBAN, card, NIR, phone), so a phone-shaped group of digits
/// inside an IBAN is not reported as a phone. `enabled` restricts the
/// classifiers (job filter).
#[must_use]
pub fn scan_tokens(value: &str, enabled: &dyn Fn(ClassifierId) -> bool) -> Vec<Token> {
    let v = bounded(value);
    let mut out = Vec::new();
    // Every detector runs and claims its spans; the filter applies at the
    // end, so that a disabled IBAN detector does not turn IBAN digits into
    // phone numbers.

    if let Some(r) = AWS_ID.as_ref() {
        for m in r.find_iter(v) {
            push(&mut out, ClassifierId::AwsKey, m.range());
        }
    }
    let trimmed = v.trim();
    if let Some(r) = PASSWORD_HASH.as_ref()
        && r.is_match(trimmed)
    {
        let start = v.len() - v.trim_start().len();
        push(
            &mut out,
            ClassifierId::PasswordHash,
            start..start + trimmed.len(),
        );
    }
    if let Some(r) = EMAIL.as_ref() {
        for m in r.find_iter(v) {
            let s = m.as_str().trim_end_matches(['.', '-']);
            if validate::email_valid(s) {
                push(
                    &mut out,
                    ClassifierId::Email,
                    m.start()..m.start() + s.len(),
                );
            }
        }
    }
    for range in iban_tokens(v) {
        push(&mut out, ClassifierId::Iban, range);
    }
    if let Some(r) = CARD.as_ref() {
        for m in r.find_iter(v) {
            if let Some(range) = card_token(v, m.range()) {
                push(&mut out, ClassifierId::CardNumber, range);
            }
        }
    }
    if let Some(r) = NIR.as_ref() {
        for m in r.find_iter(v) {
            if validate::nir_valid(&compact(m.as_str())) {
                push(&mut out, ClassifierId::Nir, m.range());
            }
        }
    }
    for r in [PHONE_INTL.as_ref(), PHONE_FR.as_ref()]
        .into_iter()
        .flatten()
    {
        for m in r.find_iter(v) {
            let alnum_before = prev_char(v, m.start()).is_some_and(char::is_alphanumeric);
            let digits = m.as_str().chars().filter(char::is_ascii_digit).count();
            if !alnum_before && (8..=15).contains(&digits) {
                push(&mut out, ClassifierId::Phone, m.range());
            }
        }
    }
    out.retain(|t| enabled(t.classifier));
    out.sort_by_key(|t| t.range.start);
    out
}

/// Removes spaces, dots and hyphens.
#[must_use]
pub fn compact(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, ' ' | '.' | '-'))
        .collect()
}

/// IBAN tokens: `CCkk` at a word start, then alphanumerics with single
/// spaces, exactly the country length, ending at a token boundary.
fn iban_tokens(v: &str) -> Vec<Range<usize>> {
    let Some(start_re) = IBAN_START.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for m in start_re.find_iter(v) {
        let Some(len) = validate::iban_length(&m.as_str()[..2]) else {
            continue;
        };
        let mut compact = String::with_capacity(len);
        let mut end = m.start();
        let mut last_space = false;
        for (i, c) in v[m.start()..].char_indices() {
            if compact.len() == len {
                break;
            }
            if c == ' ' && !last_space && !compact.is_empty() {
                last_space = true;
                continue;
            }
            if c.is_ascii_uppercase() || c.is_ascii_digit() {
                compact.push(c);
                last_space = false;
                end = m.start() + i + c.len_utf8();
            } else {
                break;
            }
        }
        let boundary = next_char(v, end).is_none_or(|c| !c.is_alphanumeric());
        if compact.len() == len && boundary && validate::iban_valid(&compact) {
            out.push(m.start()..end);
        }
    }
    out
}

/// A card token inside a digit run: the longest prefix of separator groups
/// with 13..=19 digits that passes Luhn and the issuer-prefix check.
fn card_token(v: &str, range: Range<usize>) -> Option<Range<usize>> {
    let s = &v[range.clone()];
    // Group ends: byte offsets (exclusive) where a group of digits ends.
    let mut ends: Vec<usize> = s
        .char_indices()
        .filter(|(i, c)| {
            c.is_ascii_digit()
                && s[i + 1..]
                    .chars()
                    .next()
                    .is_none_or(|n| !n.is_ascii_digit())
        })
        .map(|(i, _)| i + 1)
        .collect();
    ends.reverse();
    for end in ends {
        let digits: String = s[..end].chars().filter(char::is_ascii_digit).collect();
        if (13..=19).contains(&digits.len())
            && validate::luhn_valid(&digits)
            && validate::card_prefix_valid(&digits)
        {
            return Some(range.start..range.start + end);
        }
    }
    None
}

/// A whole value that is a plausible date of birth (ISO `YYYY-MM-DD`,
/// optionally at midnight, or `DD/MM/YYYY`). Needs a column-name hint.
#[must_use]
pub fn is_birth_date(value: &str) -> bool {
    let v = value.trim();
    let parse = |s: &str| s.parse::<u32>().ok();
    if let Some(c) = ISO_DATE.as_ref().and_then(|r| r.captures(v)) {
        let (Some(y), Some(m), Some(d)) = (parse(&c[1]), parse(&c[2]), parse(&c[3])) else {
            return false;
        };
        return validate::birth_date_valid(y, m, d);
    }
    if let Some(c) = FR_DATE.as_ref().and_then(|r| r.captures(v)) {
        let (Some(d), Some(m), Some(y)) = (parse(&c[1]), parse(&c[2]), parse(&c[3])) else {
            return false;
        };
        return validate::birth_date_valid(y, m, d);
    }
    false
}

/// Lowercase particles allowed inside a person name.
const PARTICLES: &[&str] = &[
    "de", "du", "des", "la", "le", "van", "von", "der", "den", "di", "da", "del", "dos", "ben",
    "bin", "al", "y", "e",
];

/// A whole value shaped like a person name: 1 to 4 words, each word made
/// of letters with internal `-` / `'`, capitalized (`Anaïs`, `O'Connor`)
/// or all caps (`AIDEN EVANS`); lowercase particles allowed after the
/// first word. No digits, no `@`. Needs a column-name hint.
#[must_use]
pub fn is_person_name(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || v.chars().count() > 64 {
        return false;
    }
    let words: Vec<&str> = v.split(' ').collect();
    if words.len() > 4 {
        return false;
    }
    words.iter().enumerate().all(|(i, w)| {
        if i > 0 && PARTICLES.contains(w) {
            return true;
        }
        let parts: Vec<&str> = w.split(['-', '\'', '’']).collect();
        !w.is_empty()
            && parts.iter().all(|p| {
                let mut cs = p.chars();
                let Some(first) = cs.next() else {
                    return false;
                };
                let rest: Vec<char> = cs.collect();
                first.is_alphabetic()
                    && first.is_uppercase()
                    && rest.iter().all(|c| c.is_alphabetic())
                    && (rest.iter().all(|c| c.is_lowercase())
                        || rest.iter().all(|c| c.is_uppercase()))
            })
    })
}

/// Street-type words (FR, EN, DE, NL, ES, IT).
const STREET_WORDS: &[&str] = &[
    "rue",
    "avenue",
    "av",
    "boulevard",
    "bd",
    "allée",
    "allee",
    "impasse",
    "chemin",
    "place",
    "quai",
    "route",
    "cours",
    "square",
    "passage",
    "street",
    "st",
    "road",
    "rd",
    "lane",
    "drive",
    "way",
    "strasse",
    "straße",
    "str",
    "straat",
    "weg",
    "platz",
    "gasse",
    "via",
    "calle",
    "plaza",
];

/// A whole value shaped like a postal address: letters, and a leading house
/// number followed by a word, or a street-type word. LDAP `$` line
/// separators are accepted. Needs a column-name hint.
#[must_use]
pub fn is_postal_address(value: &str) -> bool {
    let v = value.trim();
    let len = v.chars().count();
    if !(5..=200).contains(&len) || v.contains('@') || !v.chars().any(char::is_alphabetic) {
        return false;
    }
    let words: Vec<String> = v
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | '$' | ';'))
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    let house_number = words.first().is_some_and(|w| {
        let digits = w.chars().take_while(char::is_ascii_digit).count();
        (1..=4).contains(&digits)
            && w[digits..]
                .chars()
                .all(|c| c.is_ascii_alphabetic() || c == '-')
            && w.len() - digits <= 3
    }) && words
        .get(1)
        .is_some_and(|w| w.chars().next().is_some_and(char::is_alphabetic));
    house_number || words.iter().any(|w| STREET_WORDS.contains(&w.as_str()))
}

/// A whole value shaped like an AWS secret access key: 40 characters of
/// `[A-Za-z0-9/+]` mixing upper case, lower case and digits. Needs a
/// column-name hint.
#[must_use]
pub fn is_aws_secret_key(value: &str) -> bool {
    let v = value.trim();
    v.len() == 40
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '/' || c == '+')
        && v.chars().any(|c| c.is_ascii_uppercase())
        && v.chars().any(|c| c.is_ascii_lowercase())
        && v.chars().any(|c| c.is_ascii_digit())
}

/// Whether a string (typically a name segment) contains a value recognized
/// by a token detector. Building block for the classifier-based name
/// normalization of ADR-0009 (wired in the core, P2-A part 2).
#[must_use]
pub fn contains_value(s: &str) -> bool {
    !scan_tokens(s, &|_| true).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ClassifierId as C;

    fn found(v: &str) -> Vec<(ClassifierId, &str)> {
        scan_tokens(v, &|_| true)
            .into_iter()
            .map(|t| (t.classifier, &v[t.range]))
            .collect()
    }

    fn only(v: &str) -> Option<ClassifierId> {
        match found(v).as_slice() {
            [(c, _)] => Some(*c),
            _ => None,
        }
    }

    #[test]
    fn patterns_compile() {
        for r in [
            &EMAIL,
            &IBAN_START,
            &CARD,
            &NIR,
            &PHONE_FR,
            &PHONE_INTL,
            &AWS_ID,
            &PASSWORD_HASH,
            &ISO_DATE,
            &FR_DATE,
        ] {
            assert!(r.is_some());
        }
    }

    #[test]
    fn emails() {
        assert_eq!(only("jane.doe@example.com"), Some(C::Email));
        assert_eq!(only("aiden.garcía@example.org"), Some(C::Email));
        assert_eq!(
            found("write to jane@example.com."),
            [(C::Email, "jane@example.com")]
        );
        for neg in [
            "example.com",
            "jane@",
            "@example.com",
            "a@b",
            "e-mail",
            "jane@@x.io",
        ] {
            assert!(found(neg).is_empty(), "{neg}");
        }
    }

    #[test]
    fn ibans() {
        for v in [
            "FR7630006000011234567890189",
            "FR76 3000 6000 0112 3456 7890 189",
            "DE89 3704 0044 0532 0130 00",
            "GB82WEST12345698765432",
        ] {
            assert_eq!(only(v), Some(C::Iban), "{v}");
        }
        assert_eq!(
            found("Please refund to IBAN DE89 3704 0044 0532 0130 00 as soon as possible."),
            [(C::Iban, "DE89 3704 0044 0532 0130 00")]
        );
        for neg in [
            "FR7630006000011234567890180",
            "DE",
            "Change of IBAN",
            "XX89370400440532013000",
            "DE89 3704 0044 0532 0130 001",
        ] {
            assert!(found(neg).is_empty(), "{neg}");
        }
    }

    #[test]
    fn cards() {
        for v in [
            "4111 1111 1111 1111",
            "4111111111111111",
            "5555-5555-5555-4444",
            "378282246310005",
        ] {
            assert_eq!(only(v), Some(C::CardNumber), "{v}");
        }
        assert_eq!(
            found("My card 4111 1111 1111 1111 was charged twice."),
            [(C::CardNumber, "4111 1111 1111 1111")]
        );
        // Luhn failure, unknown prefix, too short.
        for neg in [
            "4111 1111 1111 1112",
            "9111111111111111",
            "411111111111",
            "INV-2026-000123",
        ] {
            assert!(found(neg).is_empty(), "{neg}");
        }
    }

    fn nir_sample() -> String {
        let body = "2850578006048";
        let key = 97 - body.parse::<u64>().unwrap_or(0) % 97;
        format!("{body}{key:02}")
    }

    #[test]
    fn nirs() {
        let n = nir_sample();
        assert_eq!(only(&n), Some(C::Nir));
        let spaced = format!(
            "{} {} {} {} {} {} {}",
            &n[..1],
            &n[1..3],
            &n[3..5],
            &n[5..7],
            &n[7..10],
            &n[10..13],
            &n[13..]
        );
        assert_eq!(only(&spaced), Some(C::Nir));
        let bad_key = format!(
            "{}{:02}",
            &n[..13],
            (n[13..].parse::<u32>().unwrap_or(0) % 97) + 1
        );
        assert!(found(&bad_key).is_empty());
        assert!(found("385057800604812").is_empty());
    }

    #[test]
    fn phones() {
        for v in [
            "01 99 00 27 59",
            "0612345678",
            "06.12.34.56.78",
            "+33 6 12 34 56 78",
            "+1 202 555 0125",
            "+44 7700 900689",
        ] {
            assert_eq!(only(v), Some(C::Phone), "{v}");
        }
        assert_eq!(
            found("Customer called from 01 99 00 27 59 and asked to use jane@example.com."),
            [(C::Phone, "01 99 00 27 59"), (C::Email, "jane@example.com")]
        );
        for neg in [
            "1234",
            "12345678",
            "E00001",
            "1950-12-01",
            "INV-2026-000123",
            "+33",
            "9123456789012345",
        ] {
            assert!(found(neg).is_empty(), "{neg}");
        }
    }

    #[test]
    fn iban_digits_are_not_phones() {
        // `0336 6126 78` inside the IBAN is phone-shaped.
        let v = "DE07 9994 3094 0336 6126 78";
        let f = found(v);
        assert!(f.iter().all(|(c, _)| *c != C::Phone), "{f:?}");
    }

    #[test]
    fn aws_keys() {
        assert_eq!(only("AKIAIOSFODNN7EXAMPLE"), Some(C::AwsKey));
        assert_eq!(only("ASIA5J4PW3752EXAMPLE"), Some(C::AwsKey));
        for neg in [
            "AKIAIOSFODNN7EXAMPL",
            "AKIAIOSFODNN7EXAMPLEX",
            "BKIAIOSFODNN7EXAMPLE",
        ] {
            assert!(found(neg).is_empty(), "{neg}");
        }
        assert!(is_aws_secret_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
        assert!(!is_aws_secret_key(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE"
        ));
        assert!(!is_aws_secret_key(&"a".repeat(40)));
    }

    #[test]
    fn password_hashes() {
        for v in [
            "$2b$12$EjXXuZ0VGWGh0JSVANuaawsTPVLWNArLzyRPleGMlMiMsUopy5qt2",
            "$2y$10$abcdefghijklmnopqrstuuWx5rRjHn3dK0y4yU5Xz6.Yq8QeFvR1a",
            "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG",
            "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E",
            "$6$rounds=5000$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/",
            "$pbkdf2-sha256$29000$N2bMmZMSQug9Z6yVUsqZMw$Uv4mVNQpVYtvpu5qCBR7lcS5QP9n0Wkx4LJU8Z9iAdE",
            "pbkdf2_sha256$600000$saltsalt$HvZ3AOkF5r0WwFpSU7N8Dq3O3gXvKmRqLZnyXw0Gm2s=",
            "{SSHA}DnKiYrOFTEkn+VpML/5/mBX+VpPyx0J0rjW88Q==",
        ] {
            assert_eq!(only(v), Some(C::PasswordHash), "{v}");
        }
        for neg in ["$2b$12$short", "password123", "{SSHA}", "hash: $2b$12$x"] {
            assert!(found(neg).is_empty(), "{neg}");
        }
    }

    #[test]
    fn birth_dates() {
        for v in [
            "1950-12-01",
            "2004-02-29",
            "01/12/1950",
            "1980-05-17T00:00:00Z",
        ] {
            assert!(is_birth_date(v), "{v}");
        }
        for v in [
            "2024-05-03T10:22:00Z",
            "1899-01-01",
            "2003-02-29",
            "1980-13-01",
            "19800517",
            "E.164",
        ] {
            assert!(!is_birth_date(v), "{v}");
        }
    }

    #[test]
    fn person_names() {
        for v in [
            "Anaïs",
            "O'Connor",
            "AIDEN GARCÍA",
            "Jean-Pierre de la Fontaine",
            "Élodie Vincent",
        ] {
            assert!(is_person_name(v), "{v}");
        }
        for v in [
            "smtp_sender_domain",
            "jane@example.com",
            "Route 66",
            "strict",
            "oo-connor001",
            "a b c d e",
            "",
        ] {
            assert!(!is_person_name(v), "{v}");
        }
    }

    #[test]
    fn postal_addresses() {
        for v in [
            "10 rue des Lilas",
            "1 Voorbeeldstraat",
            "1 allée des Peupliers, 13006 Marseille",
            "160 Baker Street$NW1 6XE London",
            "12bis avenue Foch",
            "Place de l'Église",
        ] {
            assert!(is_postal_address(v), "{v}");
        }
        for v in ["75011", "Paris", "jane@example.com 1 rue", "12"] {
            assert!(!is_postal_address(v), "{v}");
        }
    }

    #[test]
    fn filter_keeps_claims() {
        // With IBAN disabled, IBAN digits still do not become phones.
        let v = "DE07 9994 3094 0336 6126 78";
        let t = scan_tokens(v, &|c| c != C::Iban);
        assert!(t.is_empty(), "{t:?}");
    }

    #[test]
    fn long_values_are_bounded() {
        let v = format!("{}jane@example.com", "x ".repeat(MAX_SCAN_BYTES));
        assert!(found(&v).is_empty());
        assert!(bounded(&"é".repeat(MAX_SCAN_BYTES)).len() <= MAX_SCAN_BYTES);
    }
}
