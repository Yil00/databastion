//! Name normalization before the uplink (ADR-0009, contract
//! `x-databastion-normalized-name`).
//!
//! Object and field names are engine metadata, but they can embed values
//! (MongoDB dynamic keys, LDAP entry DNs, tables named after a customer).
//! [`NormalizedName`] can only be obtained through the functions of this
//! module, and always matches the contract `Identifier` schema: its pattern
//! **and** its `not` rule (no name or `.`-separated segment made only of 9
//! or more digits and separators). That `not` rule is a gate: a candidate
//! that violates it, or keeps a run of more than [`MAX_INDEX_DIGITS`]
//! digits, becomes `*` whatever the rules below produced.
//!
//! Rules:
//! - array indices (`orders.3.email`) become `[]` (`orders[].email`);
//! - **classifier matches** (P2-A): every value recognized by a token
//!   detector of [`crate::detect`] (e-mail, IBAN, card, NIR, phone, AWS key
//!   id, password hash) is located in the **whole** name, not segment by
//!   segment, so a value split across dots is still found
//!   (`a.0612.345678` -> `a.*`). The name is scanned as is, and a second
//!   time with `.`, `_`, `-` and `/` read as spaces (`card_4111.1111.1111.1111`).
//!   Every segment a match touches becomes `*`, and consecutive such
//!   segments collapse into one `*`;
//! - an `@` masks the whole address around it: the local part extends left
//!   across dots (a dot-separated path cannot tell `contacts.jane@…` from
//!   `jane.doe@…`, so the conservative reading wins: use
//!   [`normalize_field_path`] with the real keys to keep `contacts`), the
//!   domain ends at the shortest valid address;
//! - digit runs split by single separators (`.`, `_`, `-`, space, `+`) with
//!   more than [`MAX_INDEX_DIGITS`] digits in total are values
//!   (`ab0612.34.5678`);
//! - segments that look like values become `*`: long numeric runs,
//!   characters the pattern forbids (`@`, `=`, `:`…), UUID / long hex keys,
//!   and words from a small list of common first names
//!   (`archive_lucas_martin`, `ou=Oliver Martin`), see [`is_first_name`];
//! - an LDAP entry DN is reduced to its parent container, attribute types
//!   are lowercased;
//! - anything that still does not conform becomes `*`.
//!
//! Known gap: a surname alone, or a first name missing from the list, is
//! not recognized (`archive_martin`). No detector recognizes arbitrary
//! person names in identifiers.

use std::fmt;
use std::ops::Range;

use crate::detect;
use crate::hints::word_tokens;
use crate::id::ClassifierId;

/// Wildcard replacing a name or segment that may carry a value.
const WILDCARD: &str = "*";
/// Contract `Identifier.maxLength` (characters).
pub const MAX_IDENTIFIER_CHARS: usize = 256;
/// Largest input examined; longer names are replaced by `*` outright.
const MAX_INPUT_BYTES: usize = 4096;
/// Array indices up to this many digits become `[]`. A segment with more
/// digits than this (consecutive or in total) is treated as a value: dates
/// (`19800101`), local phone numbers (`61234567`), customer numbers
/// (`cust_12345678`). Stricter than the contract `not` rule (9).
pub const MAX_INDEX_DIGITS: usize = 6;
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
        if conforms(&candidate) && longest_digit_run(&candidate) <= MAX_INDEX_DIGITS {
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

/// Longest run of consecutive ASCII digits.
#[must_use]
pub fn longest_digit_run(s: &str) -> usize {
    let (mut best, mut run) = (0, 0);
    for c in s.chars() {
        run = if c.is_ascii_digit() { run + 1 } else { 0 };
        best = best.max(run);
    }
    best
}

/// Common first names (FR + EN, lowercase, with and without accents),
/// matched as whole words of a name segment. Words that are also common
/// schema vocabulary (`mark`, `will`, `max`, `grace`, `may`, `rose`…) are
/// left out on purpose: they would mask ordinary column names.
const FIRST_NAMES: &[&str] = &[
    // dev seed (dev/seed/generate.py)
    "jean",
    "marie",
    "camille",
    "louis",
    "chloe",
    "chloé",
    "hugo",
    "lea",
    "léa",
    "lucas",
    "manon",
    "theo",
    "théo",
    "ines",
    "inès",
    "nathan",
    "zoe",
    "zoé",
    "gabriel",
    "elodie",
    "élodie",
    "raphael",
    "raphaël",
    "anais",
    "anaïs",
    "arthur",
    "jade",
    "noe",
    "noé",
    "olivia",
    "james",
    "amelia",
    "noah",
    "sophia",
    "liam",
    "emma",
    "oliver",
    "ava",
    "elijah",
    "hannah",
    "lukas",
    "mia",
    "mateo",
    "sofia",
    "aiden",
    // other common FR first names
    "pierre",
    "paul",
    "jacques",
    "michel",
    "nicolas",
    "thomas",
    "julien",
    "antoine",
    "alexandre",
    "maxime",
    "guillaume",
    "sebastien",
    "sébastien",
    "stephane",
    "stéphane",
    "christophe",
    "philippe",
    "francois",
    "françois",
    "olivier",
    "laurent",
    "vincent",
    "frederic",
    "frédéric",
    "patrick",
    "alain",
    "eric",
    "éric",
    "julie",
    "sophie",
    "nathalie",
    "isabelle",
    "sandrine",
    "celine",
    "céline",
    "valerie",
    "valérie",
    "christine",
    "catherine",
    "emilie",
    "émilie",
    "aurelie",
    "aurélie",
    "caroline",
    "helene",
    "hélène",
    "margaux",
    "mathilde",
    "juliette",
    "clement",
    "clément",
    "quentin",
    "romain",
    "baptiste",
    "adrien",
    "benoit",
    "benoît",
    "cedric",
    "cédric",
    "jerome",
    "jérôme",
    "thierry",
    "dominique",
    "sylvie",
    "martine",
    "francoise",
    "françoise",
    "monique",
    "brigitte",
    "lucie",
    "pauline",
    "charlotte",
    "louise",
    "alice",
    "clara",
    "enzo",
    "ethan",
    "timeo",
    "timéo",
    "leon",
    "léon",
    "jules",
    "adam",
    "sacha",
    // other common EN first names
    "john",
    "jane",
    "mary",
    "michael",
    "william",
    "robert",
    "richard",
    "david",
    "daniel",
    "joseph",
    "charles",
    "george",
    "henry",
    "edward",
    "matthew",
    "andrew",
    "joshua",
    "christopher",
    "jennifer",
    "jessica",
    "sarah",
    "elizabeth",
    "emily",
    "ashley",
    "amanda",
    "stephanie",
    "rebecca",
    "laura",
    "rachel",
    "megan",
    "samantha",
    "victoria",
    "isabella",
    "abigail",
    "madison",
    "benjamin",
    "alexander",
    "jacob",
    "mason",
    "logan",
    "jackson",
    "sebastian",
    "harper",
    "evelyn",
    "scarlett",
    "lily",
    "ella",
    "aria",
    "nora",
    "zoey",
    "riley",
];

/// Whether `word` (one lowercase word of a name) is a common first name.
#[must_use]
pub fn is_first_name(word: &str) -> bool {
    FIRST_NAMES.contains(&word)
}

/// Whether a path segment looks like a value rather than a name: structural
/// rules (forbidden characters, long digit runs, hex keys), a classifier
/// match anywhere in it, or a first name among its words.
#[must_use]
pub fn segment_looks_like_value(segment: &str) -> bool {
    if segment.is_empty() || segment.chars().any(is_plain_excluded) {
        return true;
    }
    if is_numeric_run(segment, false) {
        return true;
    }
    // Digit content beyond an array index, consecutive or mixed with
    // letters / separators (dates, phone and account numbers, IDs).
    if segment.chars().filter(char::is_ascii_digit).count() > MAX_INDEX_DIGITS {
        return true;
    }
    // UUIDs, ObjectIds, hashes: long hexadecimal keys.
    let hex = segment
        .chars()
        .filter(|c| *c != '-')
        .all(|c| c.is_ascii_hexdigit());
    if hex && segment.len() >= 16 && segment.chars().any(|c| c.is_ascii_digit()) {
        return true;
    }
    if segment.len() <= MAX_INPUT_BYTES && !value_spans(segment).is_empty() {
        return true;
    }
    word_tokens(segment).iter().any(|w| is_first_name(w))
}

/// Byte ranges of `s` that hold a value: classifier tokens (as is and with
/// `.`, `_`, `-`, `/` read as spaces), addresses around an `@`, and long
/// split digit runs. `s` is at most [`MAX_INPUT_BYTES`] long, below the
/// detectors' scan bound.
fn value_spans(s: &str) -> Vec<Range<usize>> {
    let mut spans = Vec::new();
    for t in detect::scan_tokens(s, &|_| true) {
        spans.push(if t.classifier == ClassifierId::Email {
            shortest_email(s, t.range)
        } else {
            t.range
        });
    }
    // Same byte length: ASCII separators replaced by an ASCII space.
    let spaced: String = s
        .chars()
        .map(|c| {
            if matches!(c, '.' | '_' | '-' | '/') {
                ' '
            } else {
                c
            }
        })
        .collect();
    spans.extend(
        detect::scan_tokens(&spaced, &|c| c != ClassifierId::Email)
            .into_iter()
            .map(|t| t.range),
    );
    spans.extend(address_spans(s));
    spans.extend(split_digit_runs(s));
    spans
}

/// Local-part characters of an address, read leniently.
fn is_local_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
}

/// Domain characters of an address.
fn is_domain_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-')
}

/// Shortens an e-mail token that swallowed the following path segments
/// (`jane@example.com.phone`) to the shortest valid address.
fn shortest_email(s: &str, range: Range<usize>) -> Range<usize> {
    let token = &s[range.clone()];
    let Some(at) = token.find('@') else {
        return range;
    };
    let local = token[..at].trim_start_matches(|c: char| !c.is_alphanumeric());
    let local_start = at - local.len();
    for (i, c) in token.char_indices().skip_while(|(i, _)| *i <= at) {
        if c == '.' && crate::validate::email_valid(&token[local_start..i]) {
            return range.start..range.start + i;
        }
    }
    range
}

/// Every `@` masks the address around it: the local part extends left over
/// local-part characters (dots included), the domain ends at the shortest
/// valid address, or at the end of its domain characters.
fn address_spans(s: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    for (at, _) in s.match_indices('@') {
        let start = s[..at]
            .char_indices()
            .rev()
            .take_while(|(_, c)| is_local_char(*c))
            .last()
            .map_or(at, |(i, _)| i);
        let domain_len: usize = s[at + 1..]
            .chars()
            .take_while(|c| is_domain_char(*c))
            .map(char::len_utf8)
            .sum();
        let full = start..at + 1 + domain_len;
        out.push(shortest_email(s, full));
    }
    out
}

/// Runs of ASCII digits separated by single `.`, `_`, `-`, space or `+`,
/// with more than [`MAX_INDEX_DIGITS`] digits in total: a value split
/// across segments (`0612.345678`, `ab4111_1111.1111.1111`).
fn split_digit_runs(s: &str) -> Vec<Range<usize>> {
    let b = s.as_bytes();
    let is_sep = |x: u8| matches!(x, b'.' | b'_' | b'-' | b' ' | b'+');
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i;
        let mut digits = 0usize;
        let mut j = i;
        loop {
            if j < b.len() && b[j].is_ascii_digit() {
                digits += 1;
                j += 1;
                end = j;
            } else if j + 1 < b.len() && is_sep(b[j]) && b[j + 1].is_ascii_digit() {
                j += 1;
            } else {
                break;
            }
        }
        if digits > MAX_INDEX_DIGITS {
            out.push(start..end);
        }
        i = end;
    }
    out
}

/// One part of a structured field path, as the connector walked it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPart<'a> {
    /// An object key (MongoDB document key, JSON key). May itself contain
    /// dots.
    Key(&'a str),
    /// An array element (the index itself is never kept).
    Index,
}

fn strip_forbidden(raw: &str) -> String {
    raw.chars().filter(|c| !is_forbidden_char(*c)).collect()
}

/// Normalizes a plain name or a `.`-separated field path (column, MongoDB
/// field path, collection, table…).
///
/// Digit-only segments of up to [`MAX_INDEX_DIGITS`] digits are read as
/// array indices. Values are located in the whole string, so one split
/// across dots is still found (`a.0612.345678` -> `a.*`). When the
/// connector knows the real keys, [`normalize_field_path`] is more precise.
#[must_use]
pub fn normalize_path(raw: &str) -> NormalizedName {
    if raw.len() > MAX_INPUT_BYTES {
        return NormalizedName::wildcard();
    }
    let cleaned = strip_forbidden(raw);
    let spans = value_spans(&cleaned);
    let mut out: Vec<String> = Vec::new();
    let mut in_value = false;
    let mut offset = 0;
    for segment in cleaned.split('.') {
        let range = offset..offset + segment.len();
        offset = range.end + 1;
        if overlaps(&spans, &range) {
            if !in_value {
                out.push(WILDCARD.to_owned());
            }
            in_value = true;
            continue;
        }
        in_value = false;
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

/// Whether a (possibly empty) segment range touches a value span.
fn overlaps(spans: &[Range<usize>], r: &Range<usize>) -> bool {
    spans
        .iter()
        .any(|s| s.start < r.end.max(r.start + 1) && r.start < s.end)
}

/// Normalizes a field path given as the keys and array levels the connector
/// walked (MongoDB documents). Preferred over [`normalize_path`] whenever
/// the keys are known:
/// - an array level becomes `[]`;
/// - a key that is digit-only (a map keyed by numbers: `hourly.13`), contains
///   a dot, or looks like a value by itself becomes `*` (dynamic key), so
///   `contacts` / `jane.doe@example.com` / `phone` gives `contacts.*.phone`;
/// - the remaining keys are then scanned **together** (joined with dots,
///   dynamic keys blanked), so a value split across nested keys
///   (`jane` / `doe@example` / `com`) is still masked; consecutive keys
///   touched by one value collapse into one `*`.
#[must_use]
pub fn normalize_field_path(parts: &[PathPart<'_>]) -> NormalizedName {
    let total: usize = parts
        .iter()
        .map(|p| match p {
            PathPart::Key(k) => k.len() + 1,
            PathPart::Index => 2,
        })
        .sum();
    if total > MAX_INPUT_BYTES {
        return NormalizedName::wildcard();
    }
    // Pass 1: keys that are dynamic or values on their own.
    let keys: Vec<Option<String>> = parts
        .iter()
        .map(|p| match p {
            PathPart::Key(k) => {
                let k = strip_forbidden(k);
                let dynamic = k.chars().all(|c| c.is_ascii_digit())
                    || k.contains('.')
                    || segment_looks_like_value(&k);
                Some((!dynamic).then_some(k))
            }
            PathPart::Index => None,
        })
        .map(Option::flatten)
        .collect();
    // Pass 2: the whole path. Keys holding a dot and indices are blanked
    // with `#` (no detector reads `#`): a key such as `jane.doe@example.com`
    // is a complete value, and its local part must not be read as extending
    // over the previous keys.
    let mut joined = String::with_capacity(total);
    let mut ranges = Vec::with_capacity(parts.len());
    for (part, key) in parts.iter().zip(&keys) {
        if !joined.is_empty() {
            joined.push('.');
        }
        let start = joined.len();
        match (part, key) {
            (PathPart::Key(_), Some(k)) => joined.push_str(k),
            (PathPart::Key(k), None) if k.contains('.') => {
                joined.push_str(&"#".repeat(k.len().max(1)));
            }
            (PathPart::Key(k), None) => joined.push_str(&strip_forbidden(k)),
            (PathPart::Index, _) => joined.push('#'),
        }
        ranges.push(start..joined.len());
    }
    let spans = value_spans(&joined);
    let mut out: Vec<String> = Vec::new();
    let mut in_value = false;
    for ((part, key), range) in parts.iter().zip(&keys).zip(&ranges) {
        match (part, key) {
            (PathPart::Index, _) => {
                in_value = false;
                match out.last_mut() {
                    Some(prev) => prev.push_str("[]"),
                    None => out.push(WILDCARD.to_owned()),
                }
            }
            (PathPart::Key(_), key) => {
                if overlaps(&spans, range) {
                    if !in_value {
                        out.push(WILDCARD.to_owned());
                    }
                    in_value = true;
                } else {
                    in_value = false;
                    out.push(key.clone().unwrap_or_else(|| WILDCARD.to_owned()));
                }
            }
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
            || !value_spans(value).is_empty()
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
            // A dotted path cannot tell `contacts` from a local part: the
            // conservative reading masks it. The key-level API keeps it.
            "*.phone"
        );
        assert_eq!(
            normalize_field_path(&[
                PathPart::Key("contacts"),
                PathPart::Key("jane@example.com"),
                PathPart::Key("phone"),
            ])
            .as_str(),
            "contacts.*.phone"
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
        // Review H1: 7-8 digit values.
        for (raw, want) in [
            ("users.19800101.dob", "users.*.dob"),
            ("by_phone.61234567", "by_phone.*"),
            ("12345678", "*"),
            ("cust_12345678", "*"),
            ("orders.1234567.email", "orders.*.email"),
            ("orders.123456.email", "orders[].email"),
        ] {
            assert_eq!(normalize_path(raw).as_str(), want, "{raw}");
        }
        assert_eq!(normalize_ldap_dn("ou=19800101,dc=x").as_str(), "ou=*,dc=x");
        assert_eq!(normalize_ldap_dn("uid=a,ou=c12345678").as_str(), "ou=*");
    }

    #[test]
    fn classifier_matches_become_wildcards() {
        for (raw, want) in [
            // Values split across dots (P1-D follow-up).
            ("a.0612.345678", "a.*"),
            ("a.06.12.34.56.78.b", "a.*.b"),
            ("users.4111.1111.1111.1111.x", "users.*.x"),
            ("card_4111_1111_1111_1111", "*"),
            ("iban.FR76.3000.6000.0112.3456.7890.189", "iban.*"),
            ("ab0612.34.5678", "*"),
            ("keys.AKIAIOSFODNN7EXAMPLE", "keys.*"),
            // Ground truth (dev/ground-truth.json, name_contains_value).
            ("export_client_0639988384", "*"),
            ("archive_lucas_martin", "*"),
            ("escalations_jean.richard@example.com", "*"),
            ("members.33199004673.points", "members.*.points"),
            ("contacts.mia.nielsen@example.net.phone", "*.phone"),
            ("jane.doe@example.co.uk", "*.uk"),
            ("archiveLucasMartin", "*"),
        ] {
            assert_eq!(normalize_path(raw).as_str(), want, "{raw}");
        }
        assert_eq!(
            normalize_ldap_dn("uid=x,ou=Oliver Martin,ou=teams,dc=example,dc=org").as_str(),
            "ou=*,ou=teams,dc=example,dc=org"
        );
        assert_eq!(
            normalize_ldap_dn("ou=0612.345678,dc=x").as_str(),
            "ou=*,dc=x"
        );
    }

    #[test]
    fn field_paths_use_the_real_keys() {
        use PathPart::{Index, Key};
        for (parts, want) in [
            (
                vec![Key("contacts"), Key("mia.nielsen@example.net"), Key("name")],
                "contacts.*.name",
            ),
            (
                vec![Key("members"), Key("33199004673"), Key("points")],
                "members.*.points",
            ),
            (vec![Key("hourly"), Key("13")], "hourly.*"),
            (vec![Key("cards"), Index, Key("number")], "cards[].number"),
            (vec![Key("phones"), Index], "phones[]"),
            (vec![Key("a"), Key("0612"), Key("345678")], "a.*"),
            // Split across nested keys (dotted update paths).
            (
                vec![
                    Key("contacts"),
                    Key("jane"),
                    Key("doe@example"),
                    Key("com"),
                    Key("phone"),
                ],
                "*.phone",
            ),
            (
                vec![
                    Key("x"),
                    Key("06"),
                    Key("12"),
                    Key("34"),
                    Key("56"),
                    Key("78"),
                ],
                "x.*",
            ),
            (vec![Key("by_year"), Key("2024"), Key("2025")], "by_year.*"),
            (vec![Key("name"), Key("first")], "name.first"),
            (
                vec![Key("credentials"), Key("accessKeyId")],
                "credentials.accessKeyId",
            ),
            (vec![Index, Key("a")], "*.a"),
        ] {
            assert_eq!(normalize_field_path(&parts).as_str(), want, "{parts:?}");
        }
    }

    #[test]
    fn ordinary_names_are_kept() {
        // Every non-value name of dev/ground-truth.json survives.
        for raw in [
            "first_name",
            "last_name",
            "email",
            "phone",
            "birth_date",
            "street",
            "nir",
            "email_opt_in",
            "phone_verified",
            "created_at",
            "customer_notes",
            "card_number",
            "card_holder",
            "iban",
            "card_brand",
            "iban_country",
            "tracking_ref",
            "invoice_number",
            "amount_cents",
            "email_template_id",
            "aws_access_key_id",
            "aws_secret_access_key",
            "owner_email",
            "password_hash",
            "service",
            "full_name",
            "work_email",
            "mobile_phone",
            "home_address",
            "salary_eur",
            "badge_id",
            "phone_extension",
            "bonus_by_year",
            "requester_name",
            "requester_email",
            "requester_phone",
            "subject",
            "status",
            "name.first",
            "address.street",
            "email_verified",
            "phone_country",
            "credentials.secretAccessKey",
            "address_books",
            "daily_stats",
            "loyalty",
            "inetOrgPerson",
            "groupOfNames",
            "givenname",
            "telephonenumber",
            "postaladdress",
            "employeenumber",
            "userpassword",
            "payment_methods",
            "app_credentials",
            "customers",
            "orders_2024",
            "v2.users",
            "events_2024_09",
        ] {
            assert_eq!(normalize_path(raw).as_str(), raw, "{raw}");
        }
        assert_eq!(
            normalize_ldap_dn("ou=people,dc=example,dc=org").as_str(),
            "ou=people,dc=example,dc=org"
        );
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
        // The contract allows 8 digits; the normalizer does not.
        assert!(conforms("a.12345678.b"));
        assert_eq!(normalize_path("a.12345678.b").as_str(), "a.*.b");
        assert!(!conforms(&"a".repeat(257)));
    }
}
